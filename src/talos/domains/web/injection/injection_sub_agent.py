"""The ``injection`` sub-agent: SQL injection and XSS over the same request (LLD 3).

Both detectors run on every injection-classified event, concurrently and independently. A request
can carry both — a payload in one parameter and a script in another — and the aggregator is built
to merge two verdicts about one event, so there is no reason to stop at the first hit.

A detector that raises is caught here, logged, and skipped. Fail-open: one broken pattern table
must not take the other detector with it.
"""

from __future__ import annotations

import asyncio
import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext, Detector
from talos.core.constants import CATEGORY_INJECTION
from talos.domains.web.injection.sql_injection_detector import SqlInjectionDetector
from talos.domains.web.injection.xss_detector import XssDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

_log = logging.getLogger(__name__)


class InjectionSubAgent(AttackTypeSubAgent):
    """Owns the injection category for the web domain."""

    category = CATEGORY_INJECTION

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = (
            detectors if detectors is not None else [SqlInjectionDetector(), XssDetector()]
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
