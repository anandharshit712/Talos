"""Web domain routing: classify, dispatch, contain failures (LLD 3, 11)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext
from talos.domains.web.web_domain_agent import WebDomainAgent
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., NormalizedEvent]
UNION = "' UNION SELECT a FROM users--"


class _ExplodingSubAgent(AttackTypeSubAgent):
    category = "injection"

    def __init__(self) -> None:
        self.detectors = []

    async def handle(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        raise RuntimeError("sub-agent broke before it reached a detector")


def _process(ctx: DetectionContext, event: NormalizedEvent, agent: WebDomainAgent) -> list[Verdict]:
    ctx.event_window.add(event)
    return asyncio.run(agent.process(event, ctx))


def test_an_injection_payload_reaches_its_sub_agent(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdicts = _process(detection_ctx, make_web_event(query={"id": UNION}), WebDomainAgent())
    assert [v.category for v in verdicts] == ["injection"]


def test_ordinary_browsing_goes_nowhere(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    assert _process(detection_ctx, make_web_event(path="/about"), WebDomainAgent()) == []


def test_a_category_without_a_sub_agent_yet_is_not_an_error(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """auth_failure lands in P5 and broken_access_control in P6; until then, routing there is
    a no-op rather than a crash."""
    event = make_web_event(path="/login", method="POST", body="user=alice&pw=hunter2")
    assert _process(detection_ctx, event, WebDomainAgent()) == []


def test_a_raising_sub_agent_is_contained(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    agent = WebDomainAgent(sub_agents={"injection": _ExplodingSubAgent()})
    assert _process(detection_ctx, make_web_event(query={"id": UNION}), agent) == []


def test_the_agent_knows_its_domain_and_nothing_about_techniques() -> None:
    agent = WebDomainAgent()
    assert agent.domain == "web"
    assert set(agent.sub_agents) == {"injection"}
