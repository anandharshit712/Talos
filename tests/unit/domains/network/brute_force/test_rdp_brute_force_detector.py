"""RDP brute force: the same maths as SSH over Windows telemetry, and the filter between them."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.network.brute_force.rdp_brute_force_detector import RdpBruteForceDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


def _run(ctx: DetectionContext, events: list[NormalizedEvent]) -> Verdict | None:
    detector = RdpBruteForceDetector()
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(detector.evaluate(events[-1], ctx))


def test_a_burst_produces_a_scoped_verdict(
    detection_ctx: DetectionContext, rdp_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, rdp_events(10))
    assert verdict is not None
    assert verdict.detector == "rdp_brute_force_detector"
    assert verdict.domain == "network"
    assert verdict.category == "network_brute_force"
    assert verdict.technique == "brute_force"
    assert verdict.mitre.technique_id == "T1110"
    assert verdict.scope.attempt_count == 10
    assert verdict.scope.affected_accounts == ["administrator"]
    assert verdict.scope.affected_hosts == ["jump-01"]
    assert verdict.scope.succeeded is False


def test_below_the_threshold_nothing_fires(
    detection_ctx: DetectionContext, rdp_events: EventFactory
) -> None:
    """The default RDP threshold is 8 failed logons."""
    assert _run(detection_ctx, rdp_events(7)) is None


def test_ssh_telemetry_belongs_to_the_other_detector(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Both detectors share the ``(host, account)`` key, so only the filter separates them."""
    assert _run(detection_ctx, ssh_events(12)) is None


def test_a_trailing_logon_success_reads_as_initial_access(
    detection_ctx: DetectionContext, rdp_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, rdp_events(10, succeeded=True))
    assert verdict is not None
    assert verdict.scope.succeeded is True
    assert verdict.confidence >= 0.90
    assert "ransomware" in verdict.reasoning


def test_the_statistical_path_quotes_real_windows_events(
    detection_ctx: DetectionContext, rdp_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, rdp_events(10))
    assert verdict is not None
    assert verdict.model.used_llm is False
    assert "failed RDP logons" in verdict.reasoning
    quoted = [item.detail for item in verdict.evidence if item.kind == "log_line"]
    assert quoted and all('"EventID": 4625' in line for line in quoted)


def test_a_model_narrative_cannot_change_the_counts(
    detection_ctx: DetectionContext, rdp_events: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"rdp_brute_force_detector": {"narrative": "Ten RDP logons failed."}}
    )
    verdict = _run(detection_ctx, rdp_events(10))
    assert verdict is not None
    assert verdict.reasoning == "Ten RDP logons failed."
    assert verdict.model.used_llm is True
    assert verdict.scope.attempt_count == 10
