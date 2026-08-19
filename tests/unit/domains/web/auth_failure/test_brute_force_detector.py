"""Web brute force: what it fires on, what it refuses, and how it words the result."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.auth_failure.brute_force_detector import BruteForceDetector
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict

EventFactory = Callable[..., list[NormalizedEvent]]
SingleEventFactory = Callable[..., NormalizedEvent]


def _run(ctx: DetectionContext, events: list[NormalizedEvent]) -> Verdict | None:
    detector = BruteForceDetector()
    for event in events:
        ctx.event_window.add(event)
    return asyncio.run(detector.evaluate(events[-1], ctx))


def test_a_burst_against_one_account_produces_a_scoped_verdict(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, web_auth_events(accounts=1, fails_each=12))
    assert verdict is not None
    assert verdict.detector == "brute_force_detector"
    assert verdict.domain == "web"
    assert verdict.category == "auth_failure"
    assert verdict.technique == "brute_force"
    assert verdict.mitre.technique_id == "T1110"
    assert verdict.scope.attempt_count == 12
    assert verdict.scope.affected_accounts == ["alice"]
    assert verdict.scope.affected_endpoints == ["/login"]
    assert verdict.scope.source_diversity == 1
    assert verdict.scope.succeeded is False


def test_below_the_threshold_nothing_fires(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    """The default threshold is 10 failures; nine is a person who forgot their password."""
    assert _run(detection_ctx, web_auth_events(accounts=1, fails_each=9)) is None


def test_a_trailing_success_floors_the_confidence_and_names_the_account(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    verdict = _run(
        detection_ctx, web_auth_events(accounts=1, fails_each=12, succeeded_account="alice")
    )
    assert verdict is not None
    assert verdict.scope.succeeded is True
    assert verdict.confidence >= 0.90
    assert any("alice" in item.detail for item in verdict.evidence)
    assert "account takeover" in verdict.reasoning


def test_ssh_telemetry_is_not_this_detector_s_business(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Protocol filters are what keep one rate detector out of another's window."""
    assert _run(detection_ctx, ssh_events(12)) is None


def test_a_login_with_no_account_named_produces_no_verdict(
    detection_ctx: DetectionContext, make_web_event: SingleEventFactory
) -> None:
    """No account means no key to count against -- a documented limit, not a crash."""
    events = [
        make_web_event(path="/login", method="POST", status=401, offset_seconds=index)
        for index in range(12)
    ]
    assert _run(detection_ctx, events) is None


def test_the_statistical_path_needs_no_model(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    verdict = _run(detection_ctx, web_auth_events(accounts=1, fails_each=12))
    assert verdict is not None
    assert verdict.model.used_llm is False
    assert verdict.model.name == "none"
    assert "12 HTTP login attempts" in verdict.reasoning
    assert [item.kind for item in verdict.evidence].count("log_line") == 3


def test_a_model_narrative_replaces_the_template_without_changing_the_counts(
    detection_ctx: DetectionContext, web_auth_events: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"brute_force_detector": {"narrative": "Alice was ground for twelve tries."}}
    )
    verdict = _run(detection_ctx, web_auth_events(accounts=1, fails_each=12))
    assert verdict is not None
    assert verdict.reasoning == "Alice was ground for twelve tries."
    assert verdict.model.used_llm is True
    assert verdict.attack_detected is True
    assert verdict.scope.attempt_count == 12
