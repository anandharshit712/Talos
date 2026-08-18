"""Static-first detection, the judge's veto, and scope from the response (LLD 7.1)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.injection.sql_injection_detector import (
    STATIC_CONFIDENCE,
    SqlInjectionDetector,
    infer_success,
)
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., NormalizedEvent]
UNION = "' UNION SELECT username,password FROM users--"
#: One ambiguous family and nothing else -- exactly the case the judge exists for.
#: Two families would clear the corroboration threshold and never reach a model.
BORDERLINE = "1 AND 1=3"


def _run(ctx: DetectionContext, event: NormalizedEvent) -> Verdict | None:
    ctx.event_window.add(event)
    return asyncio.run(SqlInjectionDetector().evaluate(event, ctx))


def test_decisive_payload_produces_a_scoped_verdict(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdict = _run(detection_ctx, make_web_event(path="/products", query={"id": UNION}))
    assert verdict is not None
    assert verdict.detector == "sql_injection_detector"
    assert verdict.technique == "sql_injection"
    assert verdict.category == "injection"
    assert verdict.mitre.technique_id == "T1190"
    assert verdict.confidence == STATIC_CONFIDENCE
    assert verdict.scope.affected_endpoints == ["/products"]
    assert verdict.scope.affected_objects == ["users"]  # table named in the payload


def test_a_decisive_payload_never_calls_a_model(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """The gate is measured with the model stubbed; escalating certainties would waste budget."""
    stub = StubModelRouter()
    detection_ctx.model_client = stub
    verdict = _run(detection_ctx, make_web_event(query={"id": UNION}))
    assert verdict is not None and verdict.model.used_llm is False
    assert stub.calls == []


def test_evidence_names_every_rule_and_quotes_the_line(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdict = _run(detection_ctx, make_web_event(query={"id": UNION}))
    assert verdict is not None
    kinds = {item.kind for item in verdict.evidence}
    assert kinds == {"matched_pattern", "log_line"}
    assert any("union/union_select" in item.detail for item in verdict.evidence)


def test_benign_content_is_cleared_without_a_model(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    stub = StubModelRouter()
    detection_ctx.model_client = stub
    assert _run(detection_ctx, make_web_event(query={"q": "O'Brien"})) is None
    assert stub.calls == []


def test_a_borderline_payload_is_put_to_the_judge(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    stub = StubModelRouter(
        replies={
            "sql_injection_detector": {
                "is_injection": True,
                "confidence": 0.72,
                "reasoning": "hex literal used to smuggle a string past a quote filter",
            }
        }
    )
    detection_ctx.model_client = stub
    verdict = _run(detection_ctx, make_web_event(query={"id": BORDERLINE}))
    assert verdict is not None
    assert stub.calls, "a borderline payload should reach the judge"
    assert verdict.model.used_llm is True
    assert verdict.confidence == 0.72
    assert "hex literal" in verdict.reasoning


def test_the_judge_can_veto(detection_ctx: DetectionContext, make_web_event: EventFactory) -> None:
    """The judge exists to say no; a borderline payload it clears must not become a verdict."""
    detection_ctx.model_client = StubModelRouter(
        replies={"sql_injection_detector": {"is_injection": False, "confidence": 0.1}}
    )
    assert _run(detection_ctx, make_web_event(query={"id": BORDERLINE})) is None


def test_no_model_makes_a_borderline_payload_a_lead_not_a_finding(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter()
    verdict = _run(detection_ctx, make_web_event(query={"id": BORDERLINE}))
    assert verdict is not None
    assert verdict.confidence < 0.5
    assert verdict.model.used_llm is False
    assert "lead rather than a finding" in verdict.reasoning


def test_a_fallback_judgement_costs_confidence(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"sql_injection_detector": {"is_injection": True, "confidence": 0.8}},
        confidence_multiplier=0.85,
    )
    verdict = _run(detection_ctx, make_web_event(query={"id": BORDERLINE}))
    assert verdict is not None
    assert verdict.confidence == round(0.8 * 0.85, 3)


def test_the_model_cannot_invent_the_scope(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={
            "sql_injection_detector": {
                "is_injection": True,
                "confidence": 0.9,
                "affected_endpoints": ["/admin"],
                "succeeded": True,
            }
        }
    )
    verdict = _run(detection_ctx, make_web_event(path="/products", query={"id": UNION}))
    assert verdict is not None
    assert verdict.scope.affected_endpoints == ["/products"]


@pytest.mark.parametrize(
    ("status", "expected"),
    [(200, True), (201, True), (500, True), (403, False), (400, False), (429, False), (304, None)],
)
def test_success_is_read_from_the_response(
    make_web_event: EventFactory, status: int, expected: bool | None
) -> None:
    """A blocked 403 and a 200 that returned rows are the same attack, different incidents."""
    assert infer_success(make_web_event(status=status)) is expected


def test_a_body_payload_is_detected_too(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdict = _run(
        detection_ctx, make_web_event(method="POST", path="/login", body=f"user=admin{UNION}")
    )
    assert verdict is not None
    assert any(item.detail.startswith("union/") for item in verdict.evidence)


def test_a_non_web_event_is_not_this_detector_s_business(
    detection_ctx: DetectionContext, sample_event: NormalizedEvent
) -> None:
    assert _run(detection_ctx, sample_event) is None
