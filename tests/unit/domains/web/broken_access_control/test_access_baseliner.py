"""What counts as an object access, and what the baseliner records for it."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from talos.core.agent_contracts import DetectionContext
from talos.core.error_types import StorageError
from talos.domains.web.broken_access_control.access_baseliner import (
    AccessBaseliner,
    endpoint_template,
    is_object_access,
    object_id_of,
)
from talos.schemas.event_schema import NormalizedEvent


class RecordingStore:
    """Captures what the baseliner asked to record."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def get(self, account: str) -> Any | None:
        return None

    async def put(self, baseline: Any) -> None:
        return None

    async def record_access(self, account: str, **fields: Any) -> None:
        self.calls.append({"account": account, **fields})


class GetPutOnlyStore:
    """Satisfies ``BaselineReader`` and nothing more -- no locked read-modify-write."""

    async def get(self, account: str) -> Any | None:
        return None

    async def put(self, baseline: Any) -> None:
        return None


class FailingStore(RecordingStore):
    async def record_access(self, account: str, **fields: Any) -> None:
        raise StorageError("connection reset")


# --- what is an object access ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/api/orders/1002", "1002"),
        ("/api/orders/1002/", "1002"),
        ("/api/files/2f9d8c1e0000", "2f9d8c1e0000"),
        ("/api/orders", None),
        ("/search", None),
        ("/api/orders/summary", None),
        ("/", None),
    ],
)
def test_the_object_id_is_the_trailing_identifier(
    make_web_event: Callable[..., NormalizedEvent], path: str, expected: str | None
) -> None:
    assert object_id_of(make_web_event(path=path, account="alice")) == expected


def test_the_parsers_resource_id_wins_when_it_is_set(
    make_web_event: Callable[..., NormalizedEvent],
) -> None:
    """The parser has the real path; this is only a fallback for what it left alone."""
    event = make_web_event(path="/api/orders/1002", account="alice")
    event.target.resource_id = "9999"
    assert object_id_of(event) == "9999"


def test_an_access_needs_an_account_as_well_as_an_object(
    make_web_event: Callable[..., NormalizedEvent],
) -> None:
    """IDOR is about *whose* object it is, so an unauthenticated request has nothing to compare."""
    assert is_object_access(make_web_event(path="/api/orders/1002", account="alice"))
    assert not is_object_access(make_web_event(path="/api/orders/1002", account=None))
    assert not is_object_access(make_web_event(path="/search", account="alice"))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/api/orders/1002", "/api/orders"),
        ("/api/orders/1002/", "/api/orders"),
        ("/api/files/2f9d8c1e0000", "/api/files"),
        ("/api/orders", "/api/orders"),
        ("/1002", "/"),
        ("/search", "/search"),
    ],
)
def test_the_endpoint_template_drops_the_object_id(
    make_web_event: Callable[..., NormalizedEvent], path: str, expected: str
) -> None:
    """ "Has this account used this endpoint before" can only be asked of the template.

    Keying on the raw path makes every object access a novel endpoint forever, turns the
    ``novel_endpoint`` feature into a constant, and grows the bounded endpoints map by one entry
    per object until it evicts the real endpoints.
    """
    assert endpoint_template(make_web_event(path=path, account="alice")) == expected


# --- recording ------------------------------------------------------------------------------


def _ctx(detection_ctx: DetectionContext, store: Any) -> DetectionContext:
    detection_ctx.baseline_store = store
    return detection_ctx


def test_an_access_is_recorded_with_the_configured_bounds(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    store = RecordingStore()
    ctx = _ctx(detection_ctx, store)
    event = make_web_event(path="/api/orders/1002", account="alice")

    asyncio.run(AccessBaseliner().record(event, ctx))

    assert store.calls == [
        {
            "account": "alice",
            "object_id": "1002",
            # The template, not the raw path -- see test_the_endpoint_recorded_is_the_template.
            "endpoint": "/api/orders",
            "at": event.timestamp,
            "max_object_ids": ctx.settings.detection.idor.max_seen_object_ids,
            "max_endpoints": ctx.settings.detection.idor.max_endpoints,
        }
    ]


def test_the_endpoint_recorded_is_the_template_not_the_raw_path(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """Two accesses to different objects on one endpoint must count as one endpoint, twice."""
    store = RecordingStore()
    ctx = _ctx(detection_ctx, store)
    baseliner = AccessBaseliner()

    asyncio.run(baseliner.record(make_web_event(path="/api/orders/1002", account="alice"), ctx))
    asyncio.run(baseliner.record(make_web_event(path="/api/orders/1003", account="alice"), ctx))

    assert [call["endpoint"] for call in store.calls] == ["/api/orders", "/api/orders"]


def test_a_request_naming_no_object_records_nothing(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    store = RecordingStore()
    asyncio.run(
        AccessBaseliner().record(
            make_web_event(path="/search", account="alice"), _ctx(detection_ctx, store)
        )
    )
    assert store.calls == []


def test_an_unauthenticated_request_records_nothing(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    store = RecordingStore()
    asyncio.run(
        AccessBaseliner().record(
            make_web_event(path="/api/orders/1002", account=None), _ctx(detection_ctx, store)
        )
    )
    assert store.calls == []


def test_a_store_without_locked_updates_learns_nothing_rather_than_racing(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """``get`` then ``put`` is the lost-update race the locked store exists to prevent."""
    ctx = _ctx(detection_ctx, GetPutOnlyStore())
    event = make_web_event(path="/api/orders/1002", account="alice")

    asyncio.run(AccessBaseliner().record(event, ctx))  # must not raise


def test_a_storage_failure_does_not_take_the_pipeline_down(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """Fail-open for detection: one account loses accuracy, every other detector keeps working."""
    ctx = _ctx(detection_ctx, FailingStore())
    event = make_web_event(path="/api/orders/1002", account="alice")

    asyncio.run(AccessBaseliner().record(event, ctx))  # must not raise
