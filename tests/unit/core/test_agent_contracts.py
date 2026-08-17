"""The extension contracts: implementable in isolation, with in-memory services (LLD 3, 14).

If a detector cannot be exercised here -- no orchestrator, no network, no database -- then the
context abstraction has failed at the only job it has.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from talos.core.agent_contracts import (
    AttackTypeSubAgent,
    DetectionContext,
    Detector,
    DomainAgent,
    TypeClassifier,
)
from talos.core.settings import TalosSettings
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import MitreMapping, Verdict


class _MemoryWindow:
    def __init__(self) -> None:
        self.events: list[NormalizedEvent] = []

    def add(self, event: NormalizedEvent) -> None:
        self.events.append(event)

    def query(self, *, key: str, within: int) -> list[NormalizedEvent]:
        return list(self.events)


class _MemoryBaselines:
    def __init__(self) -> None:
        self.written: list[Any] = []

    def get(self, account: str) -> Any | None:
        return None

    def put(self, baseline: Any) -> None:
        self.written.append(baseline)


class _StubModel:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def complete(
        self,
        *,
        model: str,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int,
        timeout_s: float,
    ) -> dict[str, Any]:
        self.prompts.append(prompt)
        return {"confidence": 0.5, "reasoning": "stub"}


class _MemoryVerdictLog:
    def __init__(self) -> None:
        self.reports: list[IncidentReport] = []

    def append(self, report: IncidentReport) -> None:
        self.reports.append(report)


@pytest.fixture
def ctx(tmp_path: Any) -> DetectionContext:
    return DetectionContext(
        event_window=_MemoryWindow(),
        baseline_store=_MemoryBaselines(),
        model_client=_StubModel(),
        settings=TalosSettings.load(config_dir=tmp_path / "absent"),
        verdict_log=_MemoryVerdictLog(),
    )


class _FixedDetector(Detector):
    detector_name = "ssh_brute_force_detector"
    technique = "brute_force"
    mitre: MitreMapping = mitre_for("brute_force")

    def __init__(self, verdict: Verdict) -> None:
        self._verdict = verdict

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        return self._verdict if event.auth is not None else None


class _BruteForceSubAgent(AttackTypeSubAgent):
    category = "network_brute_force"

    def __init__(self, detector: Detector) -> None:
        self.detectors = [detector]

    async def handle(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        results = await asyncio.gather(*(d.evaluate(event, ctx) for d in self.detectors))
        return [v for v in results if v is not None]


def test_detector_runs_against_in_memory_services(
    ctx: DetectionContext, sample_event: NormalizedEvent, sample_verdict: Verdict
) -> None:
    detector = _FixedDetector(sample_verdict)
    assert asyncio.run(detector.evaluate(sample_event, ctx)) == sample_verdict


def test_detector_returns_none_when_not_applicable(
    ctx: DetectionContext, sample_event: NormalizedEvent, sample_verdict: Verdict
) -> None:
    detector = _FixedDetector(sample_verdict)
    non_auth = sample_event.model_copy(update={"auth": None})
    assert asyncio.run(detector.evaluate(non_auth, ctx)) is None


def test_sub_agent_collects_child_verdicts(
    ctx: DetectionContext, sample_event: NormalizedEvent, sample_verdict: Verdict
) -> None:
    sub_agent = _BruteForceSubAgent(_FixedDetector(sample_verdict))
    assert asyncio.run(sub_agent.handle(sample_event, ctx)) == [sample_verdict]


def test_category_matches_the_verdict_it_produces(sample_verdict: Verdict) -> None:
    """Classifier output == sub-agent category == package name (LLD 6)."""
    assert _BruteForceSubAgent.category == sample_verdict.category


def test_context_carries_every_service(
    ctx: DetectionContext, sample_event: NormalizedEvent
) -> None:
    ctx.event_window.add(sample_event)
    assert ctx.event_window.query(key="bastion-01|root", within=120) == [sample_event]
    assert ctx.baseline_store.get("root") is None
    assert ctx.settings.detection.ssh_brute_force.fail_threshold == 8


@pytest.mark.parametrize("contract", [Detector, AttackTypeSubAgent, DomainAgent, TypeClassifier])
def test_contracts_cannot_be_instantiated(contract: type) -> None:
    with pytest.raises(TypeError):
        contract()


def test_incomplete_implementation_is_rejected() -> None:
    class _NoEvaluate(Detector):
        detector_name = "broken_detector"
        technique = "brute_force"
        mitre: MitreMapping = mitre_for("brute_force")

    with pytest.raises(TypeError):
        _NoEvaluate()  # type: ignore[abstract]
