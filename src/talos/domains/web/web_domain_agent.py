"""The web domain agent: classify, then hand off to the category's sub-agent (LLD 3, 11).

Identical in shape to the network agent, which is the point — the orchestrator above knows only
domains, this knows only categories, and neither knows a technique. Registering the web agent is
what makes the whole web branch reachable; nothing else changes.

P4 registered the injection sub-agent, P5 auth failure, and P6 broken access control -- each
one more entry in the same map, and nothing else changed to add them.
"""

from __future__ import annotations

import logging

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext, DomainAgent
from talos.core.constants import CATEGORY_UNCLASSIFIED, DOMAIN_WEB
from talos.domains.web.auth_failure.auth_failure_sub_agent import AuthFailureSubAgent
from talos.domains.web.broken_access_control.broken_access_control_sub_agent import (
    BrokenAccessControlSubAgent,
)
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
            registered: list[AttackTypeSubAgent] = [
                InjectionSubAgent(),
                AuthFailureSubAgent(),
                BrokenAccessControlSubAgent(),
            ]
            sub_agents = {sub_agent.category: sub_agent for sub_agent in registered}
        self.sub_agents = sub_agents

    async def process(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        category, confidence = await self.classifier.classify(event, ctx)
        if category == CATEGORY_UNCLASSIFIED:
            return []

        sub_agent = self.sub_agents.get(category)
        if sub_agent is None:
            # Every category the classifier can emit now has a sub-agent. This stays as the
            # guard for a future category: log at debug rather than pretending a wiring bug.
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
