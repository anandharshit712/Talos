"""The ``broken_access_control`` sub-agent: score the access, then learn from it (LLD 3, 7.4).

Unlike the injection sub-agent, this one has an **order** rather than a fan-out, and both halves
of it are deliberate:

1. **Score first.** Folding the current access into the baseline before scoring would put its
   object id inside the learned range, so ``outside_range`` would be false by construction and
   the detector could never fire on the event that should trip it.
2. **Learn only from what scored clean.** An enumeration run is precisely the traffic that would
   teach the baseline that walking the id space is normal for this account. Recording an access
   the scorer just flagged is how a detector trains itself to stop detecting.

A cold-start verdict does not fire, and that access *is* learned from -- that is how a baseline
matures in the first place.

A detector that raises is caught, logged and skipped. Fail-open: a storage hiccup must not take
the pipeline down with it.
"""

from __future__ import annotations

import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext
from talos.core.constants import CATEGORY_BROKEN_ACCESS_CONTROL
from talos.domains.web.broken_access_control.access_baseliner import AccessBaseliner
from talos.domains.web.broken_access_control.deviation_scorer import DeviationScorer
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

_log = logging.getLogger(__name__)


class BrokenAccessControlSubAgent(AttackTypeSubAgent):
    """Owns the broken access control category for the web domain."""

    category = CATEGORY_BROKEN_ACCESS_CONTROL

    def __init__(
        self, scorer: DeviationScorer | None = None, baseliner: AccessBaseliner | None = None
    ) -> None:
        self.scorer = scorer or DeviationScorer()
        self.baseliner = baseliner or AccessBaseliner()

    async def handle(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        verdict = await self._score(event, ctx)

        if verdict is None or not verdict.attack_detected:
            # Clean traffic, or an account with no history yet. Both are what the baseline is
            # supposed to be built from.
            await self.baseliner.record(event, ctx)

        return [verdict] if verdict is not None else []

    async def _score(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        try:
            return await self.scorer.evaluate(event, ctx)
        except Exception:
            _log.exception(
                "detector raised, skipping it for this event",
                extra={"detector": self.scorer.detector_name, "event_id": event.event_id},
            )
            return None
