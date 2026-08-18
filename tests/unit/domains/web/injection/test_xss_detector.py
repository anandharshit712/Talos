"""Pattern detection, the judge, and stored-versus-reflected from the event window (LLD 7.2)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.injection.xss_detector import (
    STATIC_CONFIDENCE,
    STORED_CONFIDENCE_FLOOR,
    XssDetector,
    infer_reflected,
)
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., NormalizedEvent]
SCRIPT = "<script>alert(1)</script>"
#: A handler-shaped attribute whose name is not on the known list. Actionable but not decisive,
#: which is exactly the case the judge exists for.
BORDERLINE = "<div onpointerdown=doSomething>"


def _run(ctx: DetectionContext, event: NormalizedEvent) -> Verdict | None:
    ctx.event_window.add(event)
    return asyncio.run(XssDetector().evaluate(event, ctx))


def test_script_payload_produces_a_scoped_verdict(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdict = _run(detection_ctx, make_web_event(path="/search", query={"q": SCRIPT}))
    assert verdict is not None
    assert verdict.detector == "xss_detector"
    assert verdict.technique == "xss"
    assert verdict.mitre.technique_id == "T1059.007"
    assert verdict.confidence == STATIC_CONFIDENCE
    assert verdict.scope.affected_endpoints == ["/search"]
    assert verdict.model.used_llm is False


def test_benign_markup_is_cleared_without_a_model(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    stub = StubModelRouter()
    detection_ctx.model_client = stub
    assert _run(detection_ctx, make_web_event(query={"text": "<b>bold</b>"})) is None
    assert stub.calls == []


def test_an_obfuscated_payload_is_put_to_the_judge(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    stub = StubModelRouter(
        replies={
            "xss_detector": {
                "is_xss": True,
                "confidence": 0.66,
                "reasoning": "entity-encoded handler",
            }
        }
    )
    detection_ctx.model_client = stub
    verdict = _run(detection_ctx, make_web_event(query={"q": BORDERLINE}))
    assert verdict is not None
    assert stub.calls
    assert verdict.model.used_llm is True
    assert verdict.confidence == 0.66


def test_the_judge_can_veto(detection_ctx: DetectionContext, make_web_event: EventFactory) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"xss_detector": {"is_xss": False, "confidence": 0.05}}
    )
    assert _run(detection_ctx, make_web_event(query={"q": BORDERLINE})) is None


def test_a_reflected_payload_scopes_only_its_own_endpoint(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdict = _run(detection_ctx, make_web_event(path="/search", query={"q": SCRIPT}))
    assert verdict is not None
    assert verdict.scope.affected_endpoints == ["/search"]
    assert any("reflected XSS" in item.detail for item in verdict.evidence)


def test_the_same_payload_at_a_second_endpoint_is_stored(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """Stored changes who is affected: every later visitor, not just the person who clicked."""
    planted = make_web_event(path="/comment", method="POST", body=SCRIPT, offset_seconds=0)
    detection_ctx.event_window.add(planted)
    rendered = make_web_event(path="/thread/12", query={"c": SCRIPT}, offset_seconds=30)

    verdict = _run(detection_ctx, rendered)
    assert verdict is not None
    assert verdict.confidence >= STORED_CONFIDENCE_FLOOR
    assert verdict.scope.affected_endpoints == ["/comment", "/thread/12"]
    assert any("stored XSS" in item.detail for item in verdict.evidence)
    assert "stored rather than reflected" in verdict.reasoning


def test_the_same_payload_at_the_same_endpoint_stays_reflected(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """A user retrying the same URL is not evidence the payload was persisted."""
    first = make_web_event(path="/search", query={"q": SCRIPT}, offset_seconds=0)
    detection_ctx.event_window.add(first)
    verdict = _run(
        detection_ctx, make_web_event(path="/search", query={"q": SCRIPT}, offset_seconds=5)
    )
    assert verdict is not None
    assert verdict.scope.affected_endpoints == ["/search"]


def test_a_different_payload_elsewhere_does_not_make_it_stored(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    other = make_web_event(path="/comment", body="<img src=x onerror=alert(9)>", offset_seconds=0)
    detection_ctx.event_window.add(other)
    verdict = _run(
        detection_ctx, make_web_event(path="/thread/12", query={"c": SCRIPT}, offset_seconds=5)
    )
    assert verdict is not None
    assert verdict.scope.affected_endpoints == ["/thread/12"]


@pytest.mark.parametrize(
    ("status", "expected"), [(200, True), (302, True), (403, False), (500, False)]
)
def test_reflection_is_read_from_the_response(
    make_web_event: EventFactory, status: int, expected: bool
) -> None:
    assert infer_reflected(make_web_event(status=status)) is expected


def test_a_non_web_event_is_ignored(
    detection_ctx: DetectionContext, sample_event: NormalizedEvent
) -> None:
    assert _run(detection_ctx, sample_event) is None
