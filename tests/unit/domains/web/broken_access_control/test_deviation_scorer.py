"""The four deviation features, the cold-start policy, and the object-level scope.

The discriminator is what matters here, exactly as it was for brute force versus stuffing: an
enumeration walk must score high and a legitimate user opening a new record must not. A detector
that fires on both is a false-positive generator with good marketing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.detection.baseline.access_baseline import AccessBaseline, new_baseline, observe
from talos.domains.web.broken_access_control.deviation_scorer import DeviationScorer
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

AT = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
BOUNDS = {"max_object_ids": 500, "max_endpoints": 50}


class StoreWith:
    """Serves one prepared baseline, for one account."""

    def __init__(self, baseline: AccessBaseline | None) -> None:
        self.baseline = baseline

    async def get(self, account: str) -> AccessBaseline | None:
        if self.baseline is None or self.baseline.account != account:
            return None
        return self.baseline

    async def put(self, baseline: AccessBaseline) -> None:
        self.baseline = baseline


def mature_baseline(
    account: str = "alice",
    *,
    ids: range | None = None,
    endpoints: tuple[str, ...] = ("/api/orders",),
    observations: int = 60,
) -> AccessBaseline:
    """A baseline past the maturity threshold, holding ids 1000-1019 on ``/api/orders``."""
    baseline = new_baseline(account, AT)
    for endpoint in endpoints:
        for object_id in ids if ids is not None else range(1000, 1020):
            baseline = observe(
                baseline, object_id=str(object_id), endpoint=endpoint, at=AT, **BOUNDS
            )
    return baseline.model_copy(update={"observations": observations})


def scored(
    ctx: DetectionContext,
    events: list[NormalizedEvent],
    baseline: AccessBaseline | None,
) -> Verdict | None:
    """Push events through the window, score the last one."""
    ctx.baseline_store = StoreWith(baseline)  # type: ignore[assignment]
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(DeviationScorer().evaluate(events[-1], ctx))


def enumeration(
    make_web_event: Callable[..., NormalizedEvent],
    *,
    start: int = 2000,
    count: int = 8,
    account: str = "alice",
    status: int = 200,
) -> list[NormalizedEvent]:
    """A walk through consecutive ids, one per second."""
    return [
        make_web_event(
            path=f"/api/orders/{start + index}",
            account=account,
            status=status,
            offset_seconds=index,
        )
        for index in range(count)
    ]


# --- events that are not object accesses ----------------------------------------------------


def test_a_request_naming_no_object_is_not_scored(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    event = make_web_event(path="/search", account="alice")
    assert scored(detection_ctx, [event], mature_baseline()) is None


def test_an_unauthenticated_object_access_is_not_scored(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """With no account there is no baseline to deviate from."""
    event = make_web_event(path="/api/orders/9999", account=None)
    assert scored(detection_ctx, [event], mature_baseline()) is None


# --- cold start -----------------------------------------------------------------------------


def test_an_unknown_account_yields_a_verdict_that_does_not_fire(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """An account Talos has never seen is not a suspicious account."""
    events = enumeration(make_web_event)
    verdict = scored(detection_ctx, events, None)

    assert verdict is not None
    assert verdict.attack_detected is False
    assert verdict.confidence == detection_ctx.settings.detection.idor.immature_confidence
    assert "baseline immature" in verdict.evidence[0].detail


def test_an_immature_baseline_says_how_far_off_it_is(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    baseline = mature_baseline(observations=10)
    verdict = scored(detection_ctx, enumeration(make_web_event), baseline)

    assert verdict is not None and verdict.attack_detected is False
    assert "10 of 50 observations" in verdict.evidence[0].detail


def test_maturity_is_reached_at_the_threshold_exactly(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """One below the threshold is cold; the threshold itself is measurable."""
    floor = detection_ctx.settings.detection.idor.min_baseline_observations

    below = scored(
        detection_ctx, enumeration(make_web_event), mature_baseline(observations=floor - 1)
    )
    assert below is not None and below.attack_detected is False

    at = scored(detection_ctx, enumeration(make_web_event), mature_baseline(observations=floor))
    assert at is not None and at.attack_detected is True


def test_a_non_firing_verdict_produces_no_incident(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """The cold-start verdict is a record, not an alert -- the aggregator must drop it."""
    events = enumeration(make_web_event)
    verdict = scored(detection_ctx, events, None)
    assert verdict is not None

    aggregator = VerdictAggregator(detection_ctx.settings)
    assert aggregator.aggregate(events[-1], [verdict]) is None


# --- the discriminator ----------------------------------------------------------------------


def test_a_sequential_walk_scores_high(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    verdict = scored(detection_ctx, enumeration(make_web_event), mature_baseline())

    assert verdict is not None
    assert verdict.attack_detected is True
    assert verdict.confidence >= 0.6
    assert verdict.technique == "idor"


def test_a_legitimate_user_opening_one_new_record_does_not_fire(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """**The condition that makes the claim honest.** One unfamiliar id is not a breach."""
    event = make_web_event(path="/api/orders/1020", account="alice")
    assert scored(detection_ctx, [event], mature_baseline()) is None


def test_an_id_inside_the_learned_range_on_a_known_endpoint_does_not_fire(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    event = make_web_event(path="/api/orders/1005", account="alice")
    assert scored(detection_ctx, [event], mature_baseline()) is None


def test_a_short_burst_of_adjacent_ids_stays_below_the_run_threshold(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """Paging through a list the account owns looks like this, so it must not fire."""
    events = enumeration(make_web_event, start=1005, count=3)
    assert scored(detection_ctx, events, mature_baseline()) is None


def test_the_run_threshold_has_a_test_at_its_exact_edge(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """One below fires nothing; the threshold itself fires. The P4 unreachable-branch lesson."""
    run_len = detection_ctx.settings.detection.idor.sequential_run_len
    baseline = mature_baseline()

    below = scored(
        detection_ctx, enumeration(make_web_event, start=1005, count=run_len - 1), baseline
    )
    at = scored(detection_ctx, enumeration(make_web_event, start=1005, count=run_len), baseline)

    assert below is None
    assert at is not None and at.attack_detected is True


def test_ids_from_another_account_do_not_build_a_run(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """The window is keyed per account, so two users paging their own lists is not enumeration."""
    events = [
        make_web_event(
            path=f"/api/orders/{2000 + index}",
            account="alice" if index % 2 else "bob",
            offset_seconds=index,
        )
        for index in range(10)
    ]
    events.append(make_web_event(path="/api/orders/1006", account="alice", offset_seconds=11))

    assert scored(detection_ctx, events, mature_baseline()) is None


# --- scope ----------------------------------------------------------------------------------


def test_scope_lists_exactly_the_ids_in_the_run(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """Object-level scope is the deliverable: which objects, not "some objects"."""
    verdict = scored(
        detection_ctx, enumeration(make_web_event, start=2000, count=8), mature_baseline()
    )

    assert verdict is not None
    assert verdict.scope is not None
    assert verdict.scope.affected_objects == [str(2000 + index) for index in range(8)]
    assert verdict.scope.affected_accounts == ["alice"]


def test_scope_excludes_ids_the_account_was_not_walking(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """A gap breaks the run, so an unrelated access does not get scoped into the incident."""
    events = enumeration(make_web_event, start=2000, count=8)
    events.insert(0, make_web_event(path="/api/orders/5555", account="alice", offset_seconds=0))

    verdict = scored(detection_ctx, events, mature_baseline())

    assert verdict is not None and verdict.scope is not None
    assert "5555" not in verdict.scope.affected_objects


def test_a_served_object_is_recorded_as_succeeded(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    verdict = scored(detection_ctx, enumeration(make_web_event, status=200), mature_baseline())
    assert verdict is not None and verdict.scope is not None
    assert verdict.scope.succeeded is True


def test_a_blocked_object_is_still_reported_but_not_as_a_success(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """A 403 is the control working. The attempt is still worth an operator's attention."""
    verdict = scored(detection_ctx, enumeration(make_web_event, status=403), mature_baseline())
    assert verdict is not None and verdict.scope is not None
    assert verdict.scope.succeeded is False
    assert verdict.attack_detected is True


# --- evidence and the model -----------------------------------------------------------------


def test_evidence_is_never_empty_and_names_the_features(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    verdict = scored(detection_ctx, enumeration(make_web_event), mature_baseline())

    assert verdict is not None
    details = " ".join(item.detail for item in verdict.evidence)
    assert "consecutive object ids" in details
    assert "deterministic deviation score" in details
    assert any(item.kind == "log_line" for item in verdict.evidence)


def test_the_statistical_path_needs_no_model(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """``used_llm=False`` with a templated narrative is a supported mode, not a degraded one."""
    verdict = scored(detection_ctx, enumeration(make_web_event), mature_baseline())

    assert verdict is not None
    assert verdict.model.used_llm is False
    assert "score" in verdict.reasoning


def test_an_agreeing_judge_moves_the_confidence_and_is_credited(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={
            "deviation_scorer": {
                "is_idor": True,
                "confidence": 0.98,
                "reasoning": "Eight consecutive order ids in eight seconds.",
            }
        }
    )
    verdict = scored(detection_ctx, enumeration(make_web_event), mature_baseline())

    assert verdict is not None
    assert verdict.model.used_llm is True
    assert "Eight consecutive order ids" in verdict.reasoning


def test_a_disagreeing_judge_caps_the_finding_rather_than_vetoing_it(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """The deterministic layer decides; a model that disagrees turns a finding into a lead."""
    detection_ctx.model_client = StubModelRouter(
        replies={"deviation_scorer": {"is_idor": False, "confidence": 0.9}}
    )
    verdict = scored(detection_ctx, enumeration(make_web_event), mature_baseline())

    assert verdict is not None
    assert verdict.confidence <= detection_ctx.settings.detection.idor.low_score_floor


def test_a_malformed_judge_reply_leaves_the_statistical_score_standing(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"deviation_scorer": {"is_idor": True, "confidence": "very high"}}
    )
    verdict = scored(detection_ctx, enumeration(make_web_event), mature_baseline())

    assert verdict is not None
    assert 0.0 <= verdict.confidence <= 1.0


def test_a_novel_endpoint_alone_is_not_enough_to_fire(
    detection_ctx: DetectionContext, make_web_event: Callable[..., NormalizedEvent]
) -> None:
    """The lightest feature by design: a user reaching a new part of the app looks like this."""
    event = make_web_event(path="/api/invoices/1005", account="alice")
    assert scored(detection_ctx, [event], mature_baseline()) is None


@pytest.mark.parametrize("object_id", ["2f9d8c1e0000", "abcdef123456"])
def test_opaque_ids_produce_no_run_and_so_no_finding(
    detection_ctx: DetectionContext,
    make_web_event: Callable[..., NormalizedEvent],
    object_id: str,
) -> None:
    """Non-numeric ids cannot be walked, and inventing a range for them is how UUIDs get flagged."""
    events = [
        make_web_event(path=f"/api/files/{object_id}", account="alice", offset_seconds=index)
        for index in range(8)
    ]
    assert scored(detection_ctx, events, mature_baseline()) is None
