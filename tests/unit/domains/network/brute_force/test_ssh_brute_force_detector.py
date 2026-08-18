"""The first leaf detector: verdict shape, confidence curve, and what it refuses to touch."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.network.brute_force.ssh_brute_force_detector import SshBruteForceDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


def _run(ctx: DetectionContext, events: list[NormalizedEvent]) -> Verdict | None:
    detector = SshBruteForceDetector()
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(detector.evaluate(events[-1], ctx))


def test_burst_produces_a_scoped_verdict(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    assert verdict.detector == "ssh_brute_force_detector"
    assert verdict.technique == "brute_force"
    assert verdict.category == "network_brute_force"
    assert verdict.mitre.technique_id == "T1110"
    assert verdict.attack_detected is True
    assert verdict.scope.attempt_count == 12
    assert verdict.scope.affected_accounts == ["root"]
    assert verdict.scope.affected_hosts == ["bastion-01"]
    assert verdict.scope.source_diversity == 1
    assert verdict.scope.succeeded is False


def test_unreachable_model_falls_back_to_the_template(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """No model configured is an ordinary path: the verdict still ships, marked as statistical."""
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    assert verdict.model.used_llm is False
    assert verdict.model.name == "none"
    assert "12 failed SSH authentications" in verdict.reasoning


def test_evidence_quotes_the_statistic_and_the_lines(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    kinds = [item.kind for item in verdict.evidence]
    assert "statistic" in kinds
    assert "log_line" in kinds
    assert any("threshold 8" in item.detail for item in verdict.evidence)


def test_below_threshold_is_silent(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    assert _run(detection_ctx, ssh_events(7)) is None


def test_confidence_grows_with_the_burst(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    small = _run(detection_ctx, ssh_events(8))
    assert small is not None and small.confidence == 0.70
    bigger = _run(detection_ctx, ssh_events(20, account="admin"))
    assert bigger is not None and bigger.confidence > small.confidence


def test_confidence_is_capped(detection_ctx: DetectionContext, ssh_events: EventFactory) -> None:
    verdict = _run(detection_ctx, ssh_events(200))
    assert verdict is not None
    assert verdict.confidence == 0.95


def test_trailing_success_raises_confidence_and_scope(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, ssh_events(9, succeeded=True))
    assert verdict is not None
    assert verdict.scope.succeeded is True
    assert verdict.confidence >= 0.90
    assert "probable initial access" in verdict.reasoning


def test_non_ssh_auth_is_left_to_other_detectors(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    events = ssh_events(12)
    last = events[-1]
    rdp = last.model_copy(update={"auth": last.auth.model_copy(update={"protocol": "rdp"})})  # type: ignore[union-attr]
    for event in events:
        detection_ctx.event_window.add(event)
    assert asyncio.run(SshBruteForceDetector().evaluate(rdp, detection_ctx)) is None


def test_thresholds_come_from_configuration(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Tuning is a config change, never a code change (standards 2.3)."""
    detection_ctx.settings.detection.ssh_brute_force.fail_threshold = 3
    verdict = _run(detection_ctx, ssh_events(4))
    assert verdict is not None
    assert verdict.scope.attempt_count == 4


def test_model_narrative_replaces_the_template(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"ssh_brute_force_detector": {"narrative": "Twelve failed logins, then success."}},
        model_name="meta/llama-3.1-8b-instruct",
        route_reason="nano tier via nim",
    )
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    assert verdict.reasoning == "Twelve failed logins, then success."
    assert verdict.model.used_llm is True
    assert verdict.model.name == "meta/llama-3.1-8b-instruct"
    assert verdict.model.route_reason == "nano tier via nim"


def test_a_fallback_answer_costs_confidence(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """The report must show a degraded answer as less certain, not equally certain."""
    detection_ctx.model_client = StubModelRouter(
        replies={"ssh_brute_force_detector": {"narrative": "spare model wrote this"}},
        confidence_multiplier=0.85,
    )
    verdict = _run(detection_ctx, ssh_events(8))
    assert verdict is not None
    assert verdict.confidence == round(0.70 * 0.85, 3)


def test_an_empty_narrative_falls_back_to_the_template(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """A model that answers with nothing must not produce a verdict that says nothing."""
    detection_ctx.model_client = StubModelRouter(
        replies={"ssh_brute_force_detector": {"narrative": "   "}}
    )
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    assert verdict.model.used_llm is False
    assert "12 failed SSH authentications" in verdict.reasoning


def test_the_model_cannot_change_the_detection(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Detection is the threshold's decision; the model only words it."""
    detection_ctx.model_client = StubModelRouter(
        replies={
            "ssh_brute_force_detector": {
                "narrative": "benign",
                "attack_detected": False,
                "confidence": 0.0,
                "attempt_count": 0,
            }
        }
    )
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    assert verdict.attack_detected is True
    assert verdict.confidence >= 0.70
    assert verdict.scope.attempt_count == 12
