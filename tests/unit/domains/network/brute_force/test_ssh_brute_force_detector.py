"""The first leaf detector: verdict shape, confidence curve, and what it refuses to touch."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

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


def test_verdict_is_statistical_not_generated(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """P2 has no LLM at all, and the statistical path is a supported mode, not a fallback."""
    verdict = _run(detection_ctx, ssh_events(12))
    assert verdict is not None
    assert verdict.model.used_llm is False
    assert verdict.model.name == "none"
    assert verdict.reasoning
    assert detection_ctx.model_client.prompts == []  # type: ignore[attr-defined]


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
