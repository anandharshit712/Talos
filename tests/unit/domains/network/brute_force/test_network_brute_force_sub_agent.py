"""Sub-agent dispatch, and the isolation that keeps one broken detector from taking the rest."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext, Detector
from talos.domains.network.brute_force.network_brute_force_sub_agent import (
    NetworkBruteForceSubAgent,
)
from talos.domains.network.brute_force.ssh_brute_force_detector import SshBruteForceDetector
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import MitreMapping, Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


class _ExplodingDetector(Detector):
    detector_name = "exploding_detector"
    technique = "brute_force"
    mitre: MitreMapping = mitre_for("brute_force")

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        raise RuntimeError("regex compiled at import time and it was wrong")


def _handle(
    ctx: DetectionContext, events: list[NormalizedEvent], sub_agent: NetworkBruteForceSubAgent
) -> list[Verdict]:
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(sub_agent.handle(events[-1], ctx))


def test_category_matches_its_package_name() -> None:
    """Classifier output == sub-agent category == package name (LLD 6)."""
    assert NetworkBruteForceSubAgent.category == "network_brute_force"


def test_collects_verdicts_from_its_detectors(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    verdicts = _handle(detection_ctx, ssh_events(12), NetworkBruteForceSubAgent())
    assert [verdict.detector for verdict in verdicts] == ["ssh_brute_force_detector"]


def test_quiet_traffic_produces_nothing(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    assert _handle(detection_ctx, ssh_events(3), NetworkBruteForceSubAgent()) == []


def test_a_raising_detector_does_not_silence_its_siblings(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Fail-open for detection: the working detector still reports (LLD 11)."""
    sub_agent = NetworkBruteForceSubAgent(detectors=[_ExplodingDetector(), SshBruteForceDetector()])
    verdicts = _handle(detection_ctx, ssh_events(12), sub_agent)
    assert [verdict.detector for verdict in verdicts] == ["ssh_brute_force_detector"]
