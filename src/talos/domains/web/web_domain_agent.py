"""The web domain agent: classify, then hand off to the category's sub-agent (LLD 3, 11).

Identical in shape to the network agent, which is the point — the orchestrator above knows only
domains, this knows only categories, and neither knows a technique. Registering the web agent is
what makes the whole web branch reachable; nothing else changes.

P4 registers the injection sub-agent. Auth failure arrives in P5 and broken access control in P6,
each as one more entry in the same map.
"""

from __future__ import annotations

import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext, DomainAgent
from talos.core.constants import CATEGORY_UNCLASSIFIED, DOMAIN_WEB
from talos.domains.web.injection.injection_sub_agent import InjectionSubAgent
from talos.domains.web.web_type_classifier import WebTypeClassifier
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

_log = logging.getLogger(__name__)


class WebDomainAgent(DomainAgent):
    """Owns HTTP telemetry: routing within the domain, nothing about techniques."""

    domain = DOMAIN_WEB

    def __init__(
        self,
        classifier: WebTypeClassifier | None = None,
        sub_agents: dict[str, AttackTypeSubAgent] | None = None,
    ) -> None:
        self.classifier = classifier or WebTypeClassifier()
        if sub_agents is None:
            injection = InjectionSubAgent()
            sub_agents = {injection.category: injection}
        self.sub_agents = sub_agents

    async def process(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        category, confidence = await self.classifier.classify(event, ctx)
        if category == CATEGORY_UNCLASSIFIED:
            return []

        sub_agent = self.sub_agents.get(category)
        if sub_agent is None:
            # A category with no sub-agent yet is the normal state mid-build: auth_failure lands
            # in P5, broken_access_control in P6. Log it at debug so it is visible without
            # pretending a wiring bug.
            _log.debug(
                "no sub-agent registered for category yet",
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
