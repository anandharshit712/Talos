"""Domain-level routing: classify, dispatch, and never let a failure stop the stream."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import AttackTypeSubAgent, DetectionContext
from talos.domains.network.network_domain_agent import NetworkDomainAgent
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


class _ExplodingSubAgent(AttackTypeSubAgent):
    category = "network_brute_force"

    def __init__(self) -> None:
        self.detectors = []

    async def handle(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        raise RuntimeError("sub-agent broke before it reached a detector")


def _process(
    ctx: DetectionContext, events: list[NormalizedEvent], agent: NetworkDomainAgent
) -> list[Verdict]:
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(agent.process(events[-1], ctx))


def test_routes_a_burst_to_the_brute_force_sub_agent(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    verdicts = _process(detection_ctx, ssh_events(12), NetworkDomainAgent())
    assert len(verdicts) == 1
    assert verdicts[0].category == "network_brute_force"


def test_unclassified_events_go_nowhere(
    detection_ctx: DetectionContext, make_ssh_event: Callable[..., NormalizedEvent]
) -> None:
    flow = make_ssh_event().model_copy(update={"auth": None})
    assert _process(detection_ctx, [flow], NetworkDomainAgent()) == []


def test_unregistered_category_is_a_logged_miss_not_a_crash(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """A classifier emitting a category nobody owns is a wiring bug, not an outage."""
    agent = NetworkDomainAgent(sub_agents={})
    assert _process(detection_ctx, ssh_events(12), agent) == []


def test_a_raising_sub_agent_is_contained(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    agent = NetworkDomainAgent(sub_agents={"network_brute_force": _ExplodingSubAgent()})
    assert _process(detection_ctx, ssh_events(12), agent) == []


def test_agent_knows_its_domain_and_nothing_about_techniques() -> None:
    agent = NetworkDomainAgent()
    assert agent.domain == "network"
    assert set(agent.sub_agents) == {"network_brute_force"}
