"""Routing by domain only, and the ordering the whole pipeline depends on (LLD 4.2)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext
from talos.domains.network.network_domain_agent import NetworkDomainAgent
from talos.orchestrator.agent_registry import AgentRegistry
from talos.orchestrator.event_orchestrator import EventOrchestrator
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport

EventFactory = Callable[..., list[NormalizedEvent]]


def _orchestrator(ctx: DetectionContext) -> EventOrchestrator:
    registry = AgentRegistry()
    registry.register_domain_agent(NetworkDomainAgent())
    return EventOrchestrator(registry, VerdictAggregator(ctx.settings), ctx)


def _submit_all(
    ctx: DetectionContext, events: list[NormalizedEvent]
) -> list[IncidentReport | None]:
    orchestrator = _orchestrator(ctx)

    async def run() -> list[IncidentReport | None]:
        return [await orchestrator.submit(event) for event in events]

    return asyncio.run(run())


def test_quiet_stream_produces_no_incidents(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    assert all(report is None for report in _submit_all(detection_ctx, ssh_events(5)))


def test_burst_produces_an_incident_once_the_threshold_is_crossed(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    reports = _submit_all(detection_ctx, ssh_events(10))
    assert reports[6] is None  # seventh failure, still under the threshold of 8
    assert reports[7] is not None
    assert reports[7].category == "network_brute_force"


def test_the_event_is_in_the_window_before_the_agents_run(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Off-by-one here means the detector never sees the event that completes the burst."""
    reports = _submit_all(detection_ctx, ssh_events(8))
    assert reports[-1] is not None
    assert reports[-1].aggregate_scope.attempt_count == 8


def test_incidents_are_persisted_to_the_verdict_log(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    _submit_all(detection_ctx, ssh_events(10))
    recorded = detection_ctx.verdict_log.reports  # type: ignore[attr-defined]
    assert recorded
    assert recorded[0].incident_id


def test_event_from_an_unregistered_domain_is_a_logged_miss(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    orchestrator = EventOrchestrator(
        AgentRegistry(), VerdictAggregator(detection_ctx.settings), detection_ctx
    )
    event = ssh_events(1)[0]
    assert asyncio.run(orchestrator.submit(event)) is None
    assert detection_ctx.verdict_log.reports == []  # type: ignore[attr-defined]


def test_ongoing_burst_is_reported_once_not_once_per_event(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """One 12-attempt burst is one incident, not five. Alert spam is a detection defect."""
    reports = [report for report in _submit_all(detection_ctx, ssh_events(12)) if report]
    assert len(reports) == 1
    assert reports[0].aggregate_scope.attempt_count == 8  # the crossing, reported immediately


def test_a_burst_that_succeeds_is_reported_again(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    """Suppression never hides an escalation: a trailing success is new information."""
    reports = [
        report for report in _submit_all(detection_ctx, ssh_events(10, succeeded=True)) if report
    ]
    assert len(reports) == 2
    assert reports[0].aggregate_scope.succeeded is False
    assert reports[1].aggregate_scope.succeeded is True
    assert reports[1].severity == "high"


def test_a_burst_that_doubles_is_reported_again(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    reports = [report for report in _submit_all(detection_ctx, ssh_events(20)) if report]
    assert [report.aggregate_scope.attempt_count for report in reports] == [8, 16]


def test_suppression_can_be_switched_off(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    detection_ctx.settings.aggregation.suppress_duplicates = False
    reports = [report for report in _submit_all(detection_ctx, ssh_events(12)) if report]
    assert len(reports) == 5  # every event past the threshold of 8


def test_a_different_account_is_a_different_incident(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    events = ssh_events(10) + ssh_events(10, account="admin")
    reports = [report for report in _submit_all(detection_ctx, events) if report]
    assert len(reports) == 2
    assert [report.aggregate_scope.affected_accounts for report in reports] == [["root"], ["admin"]]


def test_no_llm_is_reachable_in_this_phase(
    detection_ctx: DetectionContext, ssh_events: EventFactory
) -> None:
    reports = _submit_all(detection_ctx, ssh_events(12))
    fired = [report for report in reports if report is not None]
    assert fired
    assert all(verdict.model.used_llm is False for report in fired for verdict in report.verdicts)
