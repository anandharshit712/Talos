"""``NormalizedEvent`` is the contract every parser and every agent shares (LLD 2.1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from talos.schemas.event_schema import Actor, NormalizedEvent, Target, WebRequest


def test_round_trip_is_lossless(sample_event: NormalizedEvent) -> None:
    reloaded = NormalizedEvent.model_validate_json(sample_event.model_dump_json())
    assert reloaded == sample_event


def test_naive_timestamp_is_read_as_utc() -> None:
    event = NormalizedEvent(
        event_id="e1",
        timestamp=datetime(2026, 8, 19, 10, 15, 0),
        domain="web",
        telemetry_source="app_log",
        actor=Actor(source_ip="198.51.100.4"),
        target=Target(endpoint="/login"),
        raw="-",
    )
    assert event.timestamp == datetime(2026, 8, 19, 10, 15, 0, tzinfo=UTC)


def test_offset_timestamp_is_converted_to_utc() -> None:
    """Two sources on different clocks must be comparable inside one detection window."""
    ist = timezone(timedelta(hours=5, minutes=30))
    event = NormalizedEvent(
        event_id="e2",
        timestamp=datetime(2026, 8, 19, 15, 45, 0, tzinfo=ist),
        domain="web",
        telemetry_source="waf",
        actor=Actor(source_ip="198.51.100.4"),
        target=Target(endpoint="/login"),
        raw="-",
    )
    assert event.timestamp == datetime(2026, 8, 19, 10, 15, 0, tzinfo=UTC)


def test_web_request_defaults_are_not_shared() -> None:
    first = WebRequest()
    first.query_params["id"] = "1001"
    assert WebRequest().query_params == {}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("domain", "mainframe"),  # outside the Literal
        ("telemetry_source", ""),  # empty is not a source
        ("event_id", ""),
    ],
)
def test_invalid_field_is_rejected(field: str, value: str) -> None:
    payload = {
        "event_id": "e3",
        "timestamp": datetime(2026, 8, 19, 10, 15, 0, tzinfo=UTC),
        "domain": "web",
        "telemetry_source": "waf",
        "actor": Actor(source_ip="198.51.100.4"),
        "target": Target(endpoint="/login"),
        "raw": "-",
        field: value,
    }
    with pytest.raises(ValidationError):
        NormalizedEvent(**payload)


def test_unknown_field_is_rejected() -> None:
    """A parser inventing a field is a contract break, not a silently ignored extra."""
    with pytest.raises(ValidationError):
        Actor(source_ip="198.51.100.4", username="root")  # type: ignore[call-arg]
