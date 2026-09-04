"""``EventOrchestrator`` -- the entry point every event passes through (LLD 4.2).

It routes by **domain only**. It has never heard of brute force, injection, or IDOR, and adding
a technique must not change a line of it (HLD P7/NFR-4).

Order matters: the event enters the window *before* the agents run, so a windowed detector
evaluating this event sees this event. Persisting the report is the last step, after the
verdicts are final.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timedelta

from talos.core.agent_contracts import DetectionContext
from talos.orchestrator.agent_registry import AgentRegistry
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport

_log = logging.getLogger(__name__)

#: One remembered incident: when it was last reported (event time), and what it looked like.
_Reported = tuple[datetime, int, bool]


class EventOrchestrator:
    """Window, route, aggregate, persist."""

    def __init__(
        self, registry: AgentRegistry, aggregator: VerdictAggregator, ctx: DetectionContext
    ) -> None:
        self.registry = registry
        self.aggregator = aggregator
        self.ctx = ctx
        self._reported: OrderedDict[tuple[str, ...], _Reported] = OrderedDict()
        """Signature -> (event time, attempt count, succeeded) as last reported.

        A TTL map, and ordered so eviction takes the oldest rather than everything. The
        previous version cleared the whole dict when it hit its cap, which on a long-running
        server means a burst of unrelated signatures wipes the memory of an attack still in
        progress -- and every one of those attacks then re-alerts.
        """

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

        await self.ctx.verdict_log.append(report)
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

        now = scope.window_end or report.created_at
        self._forget_expired(now, settings.suppression_ttl_seconds)

        previous = self._reported.get(signature)
        escalated = previous is None or (
            (succeeded and not previous[2])
            or attempts >= previous[1] * settings.escalation_attempt_factor
        )
        if not escalated:
            return True

        self._remember(signature, (now, attempts, succeeded), settings.max_tracked_incidents)
        return False

    def _forget_expired(self, now: datetime, ttl_seconds: int) -> None:
        """Drop signatures older than the TTL, in event time.

        Event time, not wall clock, for the same reason the event window uses it: replaying a
        historical log then behaves exactly like reading a live stream.
        """
        cutoff = now - timedelta(seconds=ttl_seconds)
        for signature in [key for key, value in self._reported.items() if value[0] < cutoff]:
            del self._reported[signature]

    def _remember(self, signature: tuple[str, ...], state: _Reported, cap: int) -> None:
        """Record a reported incident, evicting the **oldest** entry if the cap is reached."""
        self._reported[signature] = state
        self._reported.move_to_end(signature)
        while len(self._reported) > cap:
            self._reported.popitem(last=False)
