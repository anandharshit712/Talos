"""``EventOrchestrator`` -- the entry point every event passes through (LLD 4.2).

It routes by **domain only**. It has never heard of brute force, injection, or IDOR, and adding
a technique must not change a line of it (HLD P7/NFR-4).

Order matters: the event enters the window *before* the agents run, so a windowed detector
evaluating this event sees this event. Persisting the report is the last step, after the
verdicts are final.
"""

from __future__ import annotations

import logging

from talos.core.agent_contracts import DetectionContext
from talos.orchestrator.agent_registry import AgentRegistry
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport

_log = logging.getLogger(__name__)

#: How many incident signatures the duplicate filter remembers.
# ponytail: a plain dict with a size cap. Swap for a TTL map if a long-running process ever
# shows this evicting signatures that are still active.
MAX_TRACKED_INCIDENTS = 2048


class EventOrchestrator:
    """Window, route, aggregate, persist."""

    def __init__(
        self, registry: AgentRegistry, aggregator: VerdictAggregator, ctx: DetectionContext
    ) -> None:
        self.registry = registry
        self.aggregator = aggregator
        self.ctx = ctx
        self._reported: dict[tuple[str, ...], tuple[int, bool]] = {}
        """Incident signature -> (attempt count, succeeded) as last reported."""

    async def submit(self, event: NormalizedEvent) -> IncidentReport | None:
        """Process one event. ``None`` means nothing fired -- not an empty incident."""
        self.ctx.event_window.add(event)

        agent = self.registry.get(event.domain)
        if agent is None:
            _log.warning(
                "no domain agent registered, event not analysed",
                extra={"domain": event.domain, "event_id": event.event_id},
            )
            return None

        verdicts = await agent.process(event, self.ctx)
        if not verdicts:
            return None

        report = self.aggregator.aggregate(event, verdicts)
        if report is None:
            return None

        if self._is_duplicate(report):
            _log.debug(
                "incident already reported, suppressing repeat",
                extra={"category": report.category, "event_id": event.event_id},
            )
            return None

        self.ctx.verdict_log.append(report)
        _log.info(
            "incident reported",
            extra={
                "incident_id": report.incident_id,
                "category": report.category,
                "severity": report.severity,
                "confidence": report.confidence,
                "verdicts": len(report.verdicts),
            },
        )
        return report

    def _is_duplicate(self, report: IncidentReport) -> bool:
        """True when this incident was already reported and has not escalated since.

        A windowed detector fires again on every event past its threshold, so one 40-attempt
        burst would otherwise become 32 identical incidents. An attack is reported when it is
        first seen, and again only when it materially changes: it succeeded, or it grew by the
        configured factor. Everything is still recorded in the event window and the verdicts;
        what is suppressed is the repeated *alert*.
        """
        settings = self.ctx.settings.aggregation
        if not settings.suppress_duplicates:
            return False

        scope = report.aggregate_scope
        signature = (
            report.domain,
            report.category,
            *sorted({verdict.technique for verdict in report.verdicts}),
            *scope.affected_accounts,
            *scope.affected_hosts,
            *scope.affected_endpoints,
        )
        attempts = scope.attempt_count or 0
        succeeded = bool(scope.succeeded)

        previous = self._reported.get(signature)
        escalated = previous is None or (
            (succeeded and not previous[1])
            or attempts >= previous[0] * settings.escalation_attempt_factor
        )
        if not escalated:
            return True

        if len(self._reported) >= MAX_TRACKED_INCIDENTS:
            self._reported.clear()
        self._reported[signature] = (attempts, succeeded)
        return False
