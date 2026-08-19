"""Credential stuffing: the breadth conditions, and the edges of both of them."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.auth_failure.credential_stuffing_detector import CredentialStuffingDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]


def _run(ctx: DetectionContext, events: list[NormalizedEvent]) -> Verdict | None:
    detector = CredentialStuffingDetector()
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(detector.evaluate(events[-1], ctx))


def test_many_accounts_few_tries_each_produces_a_verdict(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, web_auth_events(accounts=20, fails_each=2))
    assert verdict is not None
    assert verdict.detector == "credential_stuffing_detector"
    assert verdict.domain == "web"
    assert verdict.category == "auth_failure"
    assert verdict.technique == "credential_stuffing"
    assert verdict.mitre.technique_id == "T1110.004"
    assert len(verdict.scope.affected_accounts) == 20
    assert verdict.scope.attempt_count == 40
    assert verdict.scope.source_diversity == 1


def test_one_account_short_of_the_threshold_stays_silent(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """The default threshold is 15 distinct accounts, and 14 is below it."""
    assert _run(detection_ctx, web_auth_events(accounts=14, fails_each=2)) is None


def test_the_account_threshold_is_reachable_exactly(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """A threshold no corpus can sit exactly on is a threshold nobody has tested."""
    verdict = _run(detection_ctx, web_auth_events(accounts=15, fails_each=1))
    assert verdict is not None
    assert len(verdict.scope.affected_accounts) == 15


def test_one_account_over_the_per_account_ceiling_rejects_the_window(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """Four tries against one account is depth, and the ceiling is three."""
    events = web_auth_events(accounts=20, fails_each=2) + web_auth_events(
        accounts=1, fails_each=4, spacing_seconds=1
    )
    assert _run(detection_ctx, events) is None


def test_the_evidence_states_both_halves_of_the_shape(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """Breadth and shallowness are both claims, so both belong in the evidence."""
    verdict = _run(detection_ctx, web_auth_events(accounts=20, fails_each=2))
    assert verdict is not None
    statistic = next(item for item in verdict.evidence if item.kind == "statistic")
    assert "20 distinct accounts" in statistic.detail
    assert "at most 2 attempt(s) against any one account" in statistic.detail


def test_confidence_is_read_from_the_account_count_not_the_failure_total(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """A run over more accounts is worse, and a run that retried more is not."""
    wide = _run(detection_ctx, web_auth_events(accounts=40, fails_each=1))
    narrow_ctx_events = web_auth_events(accounts=20, fails_each=3, source_ip="198.51.100.4")
    deep = _run(detection_ctx, narrow_ctx_events)
    assert wide is not None and deep is not None
    assert deep.scope.attempt_count > wide.scope.attempt_count
    assert wide.confidence > deep.confidence


def test_ssh_telemetry_is_not_this_detector_s_business(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    assert _run(detection_ctx, ssh_events(20)) is None


def test_the_statistical_path_needs_no_model(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, web_auth_events(accounts=20, fails_each=2))
    assert verdict is not None
    assert verdict.model.used_llm is False
    assert "20 distinct" in verdict.reasoning
    assert "credential dump" in verdict.reasoning


def test_a_model_narrative_cannot_change_the_finding(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"credential_stuffing_detector": {"narrative": "A dump was replayed."}}
    )
    verdict = _run(detection_ctx, web_auth_events(accounts=20, fails_each=2))
    assert verdict is not None
    assert verdict.reasoning == "A dump was replayed."
    assert verdict.attack_detected is True
    assert verdict.technique == "credential_stuffing"
