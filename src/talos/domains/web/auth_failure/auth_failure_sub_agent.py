"""The ``auth_failure`` sub-agent: dispatch to child detectors, collect verdicts (LLD 3).

Both children read the same window and may both answer on the same event -- that is intended.
Depth and breadth are different claims about the same failures, and an analyst wants to be told
"this account is being ground" and "this source is walking a dump" separately when both are
true. What must not happen is one attack arriving twice under two techniques, and the key
functions are what prevent it: per account for brute force, per source for stuffing.

Detectors run concurrently and are isolated from each other. A detector that raises is caught
here, logged with its traceback, and skipped -- fail-open for detection, so one bad detector
cannot silence the one beside it.
"""

from __future__ import annotations

import asyncio
import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext, Detector
from talos.core.constants import CATEGORY_AUTH_FAILURE
from talos.domains.web.auth_failure.brute_force_detector import BruteForceDetector
from talos.domains.web.auth_failure.credential_stuffing_detector import CredentialStuffingDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

_log = logging.getLogger(__name__)


class AuthFailureSubAgent(AttackTypeSubAgent):
    """Owns web brute force and credential stuffing."""

    category = CATEGORY_AUTH_FAILURE

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = (
            detectors
            if detectors is not None
            else [BruteForceDetector(), CredentialStuffingDetector()]
        )

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
