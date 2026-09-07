"""Build the annotated pipeline trace behind ``talos demo`` (LLD 4, HLD P9).

The demo's whole point is the *reasoning*, not the verdict: a WAF prints "blocked", Talos shows why.
So this runs a log through the **real** pipeline -- parser, classifier, sub-agent, detector,
aggregator -- and records, for every event, what each stage decided: the category it was routed to,
the verdicts with their evidence and confidence, and the incident it aggregated into.

It is the one computation both faces of the demo share. ``talos demo`` renders the trace to a
terminal; the P9 trace-visualiser serves the same structure as JSON to a browser. Neither owns the
reasoning -- this does -- so the two can never drift.

The model is off by default (``use_llm=False``): the demo cannot depend on a free-tier endpoint
being reachable, and detection is statistical anyway (the model only words the narrative).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from talos.core.agent_contracts import DetectionContext, DomainAgent
from talos.core.settings import TalosSettings
from talos.ingestion.parser_contract import BaseParser
from talos.orchestrator.agent_registry import AgentRegistry
from talos.orchestrator.event_orchestrator import EventOrchestrator
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Verdict
from talos.storage.event_window_store import EventWindowStore


@dataclass
class EvidenceView:
    kind: str
    detail: str


@dataclass
class VerdictView:
    """One detector's opinion of one event, flattened for display."""

    detector: str
    category: str
    technique: str
    attack_detected: bool
    confidence: float
    used_llm: bool
    reasoning: str
    evidence: list[EvidenceView] = field(default_factory=list)

    @classmethod
    def of(cls, verdict: Verdict) -> VerdictView:
        return cls(
            detector=verdict.detector,
            category=verdict.category,
            technique=verdict.technique,
            attack_detected=verdict.attack_detected,
            confidence=round(verdict.confidence, 3),
            used_llm=verdict.model.used_llm,
            reasoning=verdict.reasoning,
            evidence=[EvidenceView(kind=e.kind, detail=e.detail) for e in verdict.evidence],
        )


@dataclass
class IncidentView:
    """The aggregated incident, reduced to what an analyst reads first."""

    incident_id: str
    category: str
    severity: str
    confidence: float
    summary: str
    mitre: list[str] = field(default_factory=list)
    affected_accounts: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, report: IncidentReport) -> IncidentView:
        scope = report.aggregate_scope
        return cls(
            incident_id=report.incident_id,
            category=report.category,
            severity=report.severity,
            confidence=round(report.confidence, 3),
            summary=report.summary,
            mitre=[m.technique_id for m in report.mitre_techniques],
            affected_accounts=list(scope.affected_accounts),
            affected_endpoints=list(scope.affected_endpoints),
            affected_hosts=list(scope.affected_hosts),
            recommended_actions=list(report.recommended_actions),
        )


@dataclass
class TraceStep:
    """One event, and everything the pipeline concluded about it."""

    index: int
    raw: str
    domain: str
    source: str
    summary: str
    verdicts: list[VerdictView] = field(default_factory=list)
    incident: IncidentView | None = None


@dataclass
class Trace:
    """The whole run, ready to render to a terminal or serialise to a browser."""

    title: str
    events: int = 0
    skipped: int = 0
    incidents: int = 0
    used_llm: bool = False
    steps: list[TraceStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Recorder:
    """Wraps a domain agent to keep the verdicts from the most recent event.

    The orchestrator hands back only the aggregated incident; the per-event verdicts -- the middle
    of the reasoning the demo exists to show -- are visible only here, as they leave the agent. A
    plain wrapper rather than a ``DomainAgent`` subclass: ``domain`` is a ``ClassVar`` on the ABC
    and this needs the inner agent's value, so it is a structural stand-in the registry accepts.
    """

    def __init__(self, inner: DomainAgent) -> None:
        self._inner = inner
        self.domain = inner.domain
        self.last: list[Verdict] = []

    async def process(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        self.last = await self._inner.process(event, ctx)
        return self.last


def _event_summary(event: NormalizedEvent) -> str:
    """One line an analyst reads without opening the raw log."""
    if event.request is not None:
        status = event.request.status_code
        return f"{event.request.method} {event.target.endpoint} -> {status}"
    if event.auth is not None:
        who = event.actor.account or "?"
        return f"auth {event.auth.protocol} {who}@{event.target.host} -> {event.auth.outcome}"
    return event.telemetry_source


def build_trace(
    title: str,
    lines: list[str],
    parser: BaseParser,
    settings: TalosSettings,
    *,
    baseline_store: Any,
) -> Trace:
    """Run a log through the real pipeline and record what each stage decided.

    Synchronous on purpose: a demo runs one short log to completion, and an ``asyncio.run`` per
    call keeps the CLI and any caller free of an event loop of their own.
    """
    import asyncio

    trace = Trace(title=title)
    registry = AgentRegistry()
    recorders = [_Recorder(agent) for agent in _domain_agents()]
    for recorder in recorders:
        registry.register_domain_agent(recorder)  # type: ignore[arg-type]
    ctx = DetectionContext(
        event_window=EventWindowStore(
            ttl_seconds=settings.storage.event_window_ttl_seconds,
            max_events_per_key=settings.storage.event_window_max_events,
        ),
        baseline_store=baseline_store,
        model_client=_offline_router(settings),
        settings=settings,
        verdict_log=_NullVerdictLog(),
    )
    orchestrator = EventOrchestrator(registry, VerdictAggregator(settings), ctx)
    by_domain = {r.domain: r for r in recorders}

    async def run() -> None:
        for raw in lines:
            if not raw.strip():
                continue
            event = parser.parse_line(raw)
            if event is None:
                trace.skipped += 1
                continue
            trace.events += 1
            report = await orchestrator.submit(event)
            verdicts = by_domain[event.domain].last if event.domain in by_domain else []
            trace.used_llm = trace.used_llm or any(v.model.used_llm for v in verdicts)
            if report is not None:
                trace.incidents += 1
            trace.steps.append(
                TraceStep(
                    index=trace.events,
                    raw=raw.strip(),
                    domain=event.domain,
                    source=event.actor.source_ip,
                    summary=_event_summary(event),
                    verdicts=[VerdictView.of(v) for v in verdicts],
                    incident=IncidentView.of(report) if report is not None else None,
                )
            )

    asyncio.run(run())
    return trace


def _domain_agents() -> list[DomainAgent]:
    """The registered domain agents, imported here to keep this module import-light."""
    from talos.domains.network.network_domain_agent import NetworkDomainAgent
    from talos.domains.web.web_domain_agent import WebDomainAgent

    return [NetworkDomainAgent(), WebDomainAgent()]


def _offline_router(settings: TalosSettings) -> Any:
    """The real router with the model switched off, so every detector takes its templated path."""
    from talos.llm.model_router import build_router

    offline = settings.model_copy(deep=True)
    offline.llm.enabled = False
    return build_router(offline)


class _NullVerdictLog:
    """The demo never persists -- it shows the reasoning and exits."""

    async def append(self, report: IncidentReport) -> None:
        return None
