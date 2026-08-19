"""**The P5 gate.** Depth and breadth must be told apart, in both directions.

Two detectors read the same failed logins out of the same window. If either one fires on the
other's corpus, the report tells an analyst the wrong story about what is happening -- "someone
is guessing Alice's password" when a leaked dump is being walked, or the reverse -- and the
MITRE technique on the incident is wrong with it (T1110 against T1110.004).

Asserting only that each detector fires on its own corpus would pass with two detectors that
both fire on everything, so every case here asserts the negative as well.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.auth_failure.auth_failure_sub_agent import AuthFailureSubAgent
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


def _verdicts(ctx: DetectionContext, events: list[NormalizedEvent]) -> list[Verdict]:
    """Feed the window, then run the sub-agent on the last event, as the orchestrator does."""
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(AuthFailureSubAgent().handle(events[-1], ctx))


def _techniques(verdicts: list[Verdict]) -> set[str]:
    return {verdict.technique for verdict in verdicts}


def test_narrow_and_deep_is_brute_force_only(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """One account, 40 failures: brute force fires, credential stuffing must stay silent."""
    verdicts = _verdicts(detection_ctx, web_auth_events(accounts=1, fails_each=40))
    assert _techniques(verdicts) == {"brute_force"}
    assert verdicts[0].scope.affected_accounts == ["alice"]
    assert verdicts[0].scope.attempt_count == 40
    assert verdicts[0].mitre.technique_id == "T1110"


def test_broad_and_shallow_is_credential_stuffing_only(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """30 accounts, 2 failures each: stuffing fires, brute force must stay silent."""
    verdicts = _verdicts(detection_ctx, web_auth_events(accounts=30, fails_each=2))
    assert _techniques(verdicts) == {"credential_stuffing"}
    assert len(verdicts[0].scope.affected_accounts) == 30
    assert verdicts[0].scope.attempt_count == 60
    assert verdicts[0].mitre.technique_id == "T1110.004"


def test_a_deep_run_inside_a_broad_one_is_not_stuffing(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """The condition that makes the claim honest: one account past the per-account ceiling.

    Breadth alone is satisfied here -- 20 accounts from one source -- but one of them is being
    ground 12 times, which is not what replaying a dump looks like. Without the per-account
    ceiling this window would be reported as stuffing.
    """
    events = web_auth_events(accounts=20, fails_each=2) + web_auth_events(
        accounts=1, fails_each=12, spacing_seconds=1
    )
    verdicts = _verdicts(detection_ctx, events)
    assert "credential_stuffing" not in _techniques(verdicts)


def test_both_fire_when_both_shapes_are_genuinely_present(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """Two attacks from two sources are two verdicts, not a choice between them.

    The deep run comes from its own address, so the stuffing window (keyed per source) never
    sees it and the brute-force window (keyed per account) never sees the shallow one.
    """
    stuffing = web_auth_events(accounts=30, fails_each=2, source_ip="203.0.113.9")
    grinding = web_auth_events(accounts=1, fails_each=40, source_ip="198.51.100.7")
    for event in stuffing + grinding:
        detection_ctx.event_window.add(event)

    agent = AuthFailureSubAgent()
    from_grinding = asyncio.run(agent.handle(grinding[-1], detection_ctx))
    from_stuffing = asyncio.run(agent.handle(stuffing[-1], detection_ctx))
    assert _techniques(from_grinding) == {"brute_force"}
    assert _techniques(from_stuffing) == {"credential_stuffing"}


def test_a_successful_login_after_a_stuffing_run_names_the_account(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """Which account fell is the most useful line in the report, so it must be in the evidence."""
    events = web_auth_events(accounts=30, fails_each=2, succeeded_account="user007")
    verdicts = _verdicts(detection_ctx, events)
    assert verdicts[0].scope.succeeded is True
    assert verdicts[0].confidence >= 0.90
    assert any("user007" in item.detail for item in verdicts[0].evidence)


def test_a_quiet_login_page_produces_nothing(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """Three people mistyping a password is not an incident, in either shape."""
    events = web_auth_events(accounts=3, fails_each=2)
    assert _verdicts(detection_ctx, events) == []
