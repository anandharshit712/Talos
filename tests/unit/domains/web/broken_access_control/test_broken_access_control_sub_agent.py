"""The two ordering rules, which are the whole reason this sub-agent is not a fan-out.

Both are the kind of mistake that produces a detector which passes every unit test and never
fires in production, so each has a test that fails if the order is swapped.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.broken_access_control.broken_access_control_sub_agent import (
    BrokenAccessControlSubAgent,
)
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict


class TracingScorer:
    """Records when it was called relative to the baseliner, and returns a staged verdict."""

    detector_name = "deviation_scorer"

    def __init__(self, trace: list[str], verdict: Verdict | None) -> None:
        self.trace = trace
        self.verdict = verdict

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        self.trace.append("score")
        return self.verdict


class RaisingScorer:
    detector_name = "deviation_scorer"

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        raise RuntimeError("pattern table is corrupt")


class TracingBaseliner:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    async def record(self, event: NormalizedEvent, ctx: DetectionContext) -> None:
        self.trace.append("learn")


def _verdict(*, attack_detected: bool) -> Verdict:
    return Verdict(
        verdict_id="v1",
        event_ids=["e1"],
        detector="deviation_scorer",
        domain="web",
        category="broken_access_control",
        technique="idor",
        attack_detected=attack_detected,
        confidence=0.8 if attack_detected else 0.2,
        mitre=mitre_for("idor"),
        scope=Scope(affected_objects=["9999"]),
        evidence=[Evidence(kind="statistic", detail="something", references=["e1"])],
        reasoning="staged verdict for the ordering tests",
        model=ModelInfo(name="none", route_reason="test", used_llm=False),
    )


def _run(
    ctx: DetectionContext, event: NormalizedEvent, verdict: Verdict | None
) -> tuple[list[Verdict], list[str]]:
    trace: list[str] = []
    sub_agent = BrokenAccessControlSubAgent(
        scorer=TracingScorer(trace, verdict),  # type: ignore[arg-type]
        baseliner=TracingBaseliner(trace),  # type: ignore[arg-type]
    )
    return asyncio.run(sub_agent.handle(event, ctx)), trace


def test_clean_traffic_is_scored_before_it_is_learned_from(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """Learning first would put the current id inside the learned range, so ``outside_range``
    would be false by construction and the detector could never fire on the tripping event."""
    event = make_web_event(path="/api/orders/1002", account="alice")

    verdicts, trace = _run(detection_ctx, event, None)

    assert verdicts == []
    assert trace == ["score", "learn"]


def test_flagged_traffic_is_not_learned_from(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """**Baseline poisoning.** An enumeration run is exactly the traffic that would teach the
    baseline that walking the id space is normal for this account."""
    event = make_web_event(path="/api/orders/9999", account="alice")

    verdicts, trace = _run(detection_ctx, event, _verdict(attack_detected=True))

    assert len(verdicts) == 1
    assert trace == ["score"], "a flagged access must not reach the baseline"


def test_a_cold_start_access_is_learned_from(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """The non-firing verdict is how a baseline matures in the first place."""
    event = make_web_event(path="/api/orders/1002", account="alice")

    verdicts, trace = _run(detection_ctx, event, _verdict(attack_detected=False))

    assert len(verdicts) == 1 and verdicts[0].attack_detected is False
    assert trace == ["score", "learn"]


def test_a_scorer_that_raises_does_not_take_the_pipeline_with_it(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """Fail-open for detection. The access is still learned from, because nothing flagged it."""
    trace: list[str] = []
    sub_agent = BrokenAccessControlSubAgent(
        scorer=RaisingScorer(),  # type: ignore[arg-type]
        baseliner=TracingBaseliner(trace),  # type: ignore[arg-type]
    )

    verdicts = asyncio.run(
        sub_agent.handle(make_web_event(path="/api/orders/1002", account="alice"), detection_ctx)
    )

    assert verdicts == []
    assert trace == ["learn"]


def test_the_category_matches_the_package_name() -> None:
    """A hard contract: classifier output == sub-agent category == package name."""
    assert BrokenAccessControlSubAgent.category == "broken_access_control"


def test_the_default_wiring_needs_no_arguments() -> None:
    """What the domain agent actually constructs."""
    sub_agent = BrokenAccessControlSubAgent()
    assert sub_agent.scorer.detector_name == "deviation_scorer"
    assert sub_agent.baseliner.component_name == "access_baseliner"
