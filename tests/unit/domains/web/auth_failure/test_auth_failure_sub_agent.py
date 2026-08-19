"""The auth-failure sub-agent: both children run, and a broken one cannot silence the other."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext, Detector
from talos.domains.web.auth_failure.auth_failure_sub_agent import AuthFailureSubAgent
from talos.domains.web.auth_failure.brute_force_detector import BruteForceDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


class ExplodingDetector(Detector):
    """A detector with a bug in it. Every pipeline has one eventually."""

    detector_name = "exploding_detector"
    technique = "brute_force"

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        raise RuntimeError("threshold config read off the end of a list")


def test_it_registers_both_children_by_default() -> None:
    agent = AuthFailureSubAgent()
    assert agent.category == "auth_failure"
    assert {detector.detector_name for detector in agent.detectors} == {
        "brute_force_detector",
        "credential_stuffing_detector",
    }


def test_a_raising_detector_is_skipped_not_propagated(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """Fail-open for detection: the working detector still reports."""
    events = web_auth_events(accounts=1, fails_each=12)
    for event in events:
        detection_ctx.event_window.add(event)

    agent = AuthFailureSubAgent(detectors=[ExplodingDetector(), BruteForceDetector()])
    verdicts = asyncio.run(agent.handle(events[-1], detection_ctx))
    assert [verdict.detector for verdict in verdicts] == ["brute_force_detector"]


def test_an_event_no_child_answers_on_yields_no_verdicts(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    event = make_web_event(path="/login", method="POST", status=401, account="alice")
    detection_ctx.event_window.add(event)
    assert asyncio.run(AuthFailureSubAgent().handle(event, detection_ctx)) == []
