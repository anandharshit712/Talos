"""The network domain agent: classify, then hand off to the category's sub-agent (LLD 3, 11).

The orchestrator above knows domains only. This agent knows categories only. Neither knows
techniques -- that is what lets P5 add RDP without either of them changing.

Sub-agent failures are caught here as well as inside the sub-agent, because a sub-agent can
break before it ever reaches a detector. Fail-open: the pipeline keeps processing events.
"""

from __future__ import annotations

import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext, DomainAgent
from talos.core.constants import CATEGORY_UNCLASSIFIED, DOMAIN_NETWORK
from talos.domains.network.brute_force.network_brute_force_sub_agent import (
    NetworkBruteForceSubAgent,
)
from talos.domains.network.network_type_classifier import NetworkTypeClassifier
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

_log = logging.getLogger(__name__)


class NetworkDomainAgent(DomainAgent):
    """Owns sshd/RDP telemetry: routing within the domain, nothing about techniques."""

    domain = DOMAIN_NETWORK

    def __init__(
        self,
        classifier: NetworkTypeClassifier | None = None,
        sub_agents: dict[str, AttackTypeSubAgent] | None = None,
    ) -> None:
        self.classifier = classifier or NetworkTypeClassifier()
        if sub_agents is None:
            brute_force = NetworkBruteForceSubAgent()
            sub_agents = {brute_force.category: brute_force}
        self.sub_agents = sub_agents

    async def process(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        category, confidence = await self.classifier.classify(event, ctx)
        if category == CATEGORY_UNCLASSIFIED:
            return []

        sub_agent = self.sub_agents.get(category)
        if sub_agent is None:
            # The classifier emitted a category nobody is registered for. That is a wiring
            # bug, not an attack: say so loudly in the log, drop nothing else on the floor.
            _log.warning(
                "no sub-agent registered for category",
                extra={"category": category, "domain": self.domain},
            )
            return []

        _log.debug(
            "routed event",
            extra={
                "event_id": event.event_id,
                "domain": self.domain,
                "category": category,
                "classifier_confidence": confidence,
            },
        )
        try:
            return await sub_agent.handle(event, ctx)
        except Exception:
            _log.exception(
                "sub-agent raised, dropping its verdicts for this event",
                extra={"category": category, "event_id": event.event_id},
            )
            return []
