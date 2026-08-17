"""The extension contracts: four ABCs plus ``DetectionContext`` (LLD 3).

Adding a capability means implementing an ``AttackTypeSubAgent`` and one or more ``Detector``s
and registering them -- never editing the orchestrator (HLD P7/NFR-4). All five live in one
module because they are a single cohesive contract surface: they change together, and
splitting them would force circular imports.

**The methods are ``async``.** The LLD's 3 sketch shows plain ``def`` while its 4.2 orchestrator
writes ``await agent.process(...)`` and its 12 states that detector calls are awaited
concurrently. Concurrency wins: every detector on the LLM path awaits a model call, and a
synchronous contract would serialise exactly the work worth overlapping. Statistical detectors
simply never await. Recorded in LLD 16.2.

**Services are Protocols.** ``DetectionContext`` is frozen in P1, but ``EventWindowStore``
(P2), ``ModelClient`` (P3), and ``BaselineStore`` (P6) do not exist yet. Structural types let
the context be precisely typed now and satisfied later without an import of a module that has
not been written -- and they keep detectors testable against in-memory doubles, which is the
point of the context existing at all (LLD 14).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol

from talos.core.settings import TalosSettings
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import MitreMapping, Verdict

# ---------------------------------------------------------------------------
# Services carried by the detection context
# ---------------------------------------------------------------------------


class EventWindow(Protocol):
    """Rolling TTL buffer of recent events, keyed for O(1) lookup (LLD 12)."""

    def add(self, event: NormalizedEvent) -> None: ...

    def query(self, *, key: str, within: int) -> list[NormalizedEvent]:
        """Events for ``key`` seen in the last ``within`` seconds, oldest first."""
        ...


class BaselineReader(Protocol):
    """Per-account access baselines, persisted across runs (LLD 7.4)."""

    def get(self, account: str) -> Any | None: ...

    def put(self, baseline: Any) -> None: ...


class ModelCaller(Protocol):
    """Outbound LLM access, already routed to a model (LLD 8.1)."""

    async def complete(
        self,
        *,
        model: str,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int,
        timeout_s: float,
    ) -> dict[str, Any]: ...


class VerdictRecorder(Protocol):
    """Audit trail of everything the pipeline concluded (LLD 4.2)."""

    def append(self, report: IncidentReport) -> None: ...


@dataclass
class DetectionContext:
    """Shared services handed to detectors, so the detectors themselves stay stateless."""

    event_window: EventWindow
    baseline_store: BaselineReader
    model_client: ModelCaller
    settings: TalosSettings
    verdict_log: VerdictRecorder


# ---------------------------------------------------------------------------
# Agent contracts
# ---------------------------------------------------------------------------


class TypeClassifier(ABC):
    """Routes an event to an attack category within one domain (LLD 6)."""

    domain: ClassVar[str]

    @abstractmethod
    async def classify(self, event: NormalizedEvent, ctx: DetectionContext) -> tuple[str, float]:
        """Return ``(category, confidence)``.

        The category is a hard contract: it equals the registered
        ``AttackTypeSubAgent.category`` and the package name under ``domains/<domain>/``.
        Return ``constants.CATEGORY_UNCLASSIFIED`` rather than guessing.
        """


class Detector(ABC):
    """A leaf detector: confirms one technique and scopes it (LLD 7)."""

    detector_name: ClassVar[str]
    """Also the routing key in ``config/model_routing.yaml`` (LLD 8.2)."""
    technique: ClassVar[str]
    """Resolves through ``knowledge/mitre_mapping.py``."""
    mitre: ClassVar[MitreMapping]

    @abstractmethod
    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        """Return a verdict, or ``None`` when this detector does not apply to the event.

        ``None`` means "not my technique", never "probably fine": a detector that has an
        opinion emits it with a confidence attached.
        """


class AttackTypeSubAgent(ABC):
    """Owns one attack category and dispatches to its child detectors (LLD 3)."""

    category: ClassVar[str]
    detectors: list[Detector]

    @abstractmethod
    async def handle(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        """Run the child detectors and collect whatever fired."""


class DomainAgent(ABC):
    """Owns one telemetry domain: classify, then route to the matching sub-agent."""

    domain: ClassVar[str]
    classifier: TypeClassifier
    sub_agents: dict[str, AttackTypeSubAgent]
    """Category -> sub-agent. The orchestrator knows domains; only this map knows techniques."""

    @abstractmethod
    async def process(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        """Classify the event and return every verdict its category's sub-agent produced.

        A detector that raises is caught here and degraded to a low-confidence verdict:
        fail-open for detection, so one broken detector cannot silence the pipeline (LLD 11).
        """
