"""The ``network_brute_force`` sub-agent: dispatch to child detectors, collect verdicts (LLD 3).

Detectors run concurrently and are isolated from each other. A detector that raises is caught
here, logged with its traceback, and skipped -- fail-open for detection, so one bad detector
cannot silence the ones beside it. The domain agent above adds the same guard one level up.
"""

from __future__ import annotations

import asyncio
import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext, Detector
from talos.core.constants import CATEGORY_NETWORK_BRUTE_FORCE
from talos.domains.network.brute_force.ssh_brute_force_detector import SshBruteForceDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

_log = logging.getLogger(__name__)


class NetworkBruteForceSubAgent(AttackTypeSubAgent):
    """Owns SSH (P2) and RDP (P5) brute force for the network domain."""

    category = CATEGORY_NETWORK_BRUTE_FORCE

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = detectors if detectors is not None else [SshBruteForceDetector()]

    async def handle(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        results = await asyncio.gather(
            *(self._evaluate(detector, event, ctx) for detector in self.detectors)
        )
        return [verdict for verdict in results if verdict is not None]

    async def _evaluate(
        self, detector: Detector, event: NormalizedEvent, ctx: DetectionContext
    ) -> Verdict | None:
        try:
            return await detector.evaluate(event, ctx)
        except Exception:
            _log.exception(
                "detector raised, skipping it for this event",
                extra={"detector": detector.detector_name, "event_id": event.event_id},
            )
            return None
