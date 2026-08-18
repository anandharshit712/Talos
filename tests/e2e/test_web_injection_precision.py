"""**The P4 gate.** Precision and recall on the labelled web corpus, with no model available.

The gate is measured with the model unreachable on purpose (plan P4): the deterministic layer has
to carry the numbers alone, because a precision figure that depends on a free-tier endpoint being
up is not a property of the detector.

Targets: **precision >= 0.90, recall >= 0.85** for SQL injection and XSS.

The benign corpus is the half that matters. Every line in it is a lookalike chosen to defeat a
lazy rule -- `O'Brien`, `select a plan`, `union square hotel`, `<b>bold</b>`, the word `onerror`
in a bug report, `5 > 3`, a hyphenated sentence, a base64 image URI. A recall number without a
precision number over content like this is not a result.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import pytest
from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.web_domain_agent import WebDomainAgent
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.schemas.verdict_schema import Verdict

pytestmark = pytest.mark.e2e

LOGS = Path(__file__).resolve().parents[1] / "fixtures" / "logs"
SQLI_LOG = LOGS / "web_sql_injection_mixed_waf.log"
XSS_LOG = LOGS / "web_xss_mixed_combined.log"
BENIGN_LOG = LOGS / "web_benign_traffic_combined.log"

PRECISION_TARGET = 0.90
RECALL_TARGET = 0.85


@dataclass
class Scored:
    """Counts for one technique over the whole corpus."""

    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0

    @property
    def precision(self) -> float:
        found = self.true_positives + self.false_positives
        return 1.0 if found == 0 else self.true_positives / found

    @property
    def recall(self) -> float:
        actual = self.true_positives + self.false_negatives
        return 1.0 if actual == 0 else self.true_positives / actual


def _verdicts_for(path: Path, ctx: DetectionContext) -> list[list[Verdict]]:
    """Run every line of a log through the web domain agent, one result list per event."""
    agent = WebDomainAgent()
    parser = WebLogParser()

    async def run() -> list[list[Verdict]]:
        results = []
        for event in parser.parse_stream(path.read_text(encoding="utf-8").splitlines()):
            ctx.event_window.add(event)
            results.append(await agent.process(event, ctx))
        return results

    return asyncio.run(run())


@pytest.fixture
def offline_ctx(detection_ctx: DetectionContext) -> DetectionContext:
    """No model replies configured, so every borderline call falls back to the static answer."""
    detection_ctx.model_client = StubModelRouter()
    return detection_ctx


def _score(technique: str, ctx: DetectionContext, attack_log: Path) -> Scored:
    scored = Scored()
    for verdicts in _verdicts_for(attack_log, ctx):
        if any(v.technique == technique and v.attack_detected for v in verdicts):
            scored.true_positives += 1
        else:
            scored.false_negatives += 1
    for verdicts in _verdicts_for(BENIGN_LOG, ctx):
        scored.false_positives += sum(
            1 for v in verdicts if v.technique == technique and v.attack_detected
        )
    return scored


def test_sql_injection_meets_the_gate(offline_ctx: DetectionContext) -> None:
    scored = _score("sql_injection", offline_ctx, SQLI_LOG)
    assert scored.precision >= PRECISION_TARGET, f"precision {scored.precision:.2f}"
    assert scored.recall >= RECALL_TARGET, f"recall {scored.recall:.2f}"


def test_xss_meets_the_gate(offline_ctx: DetectionContext) -> None:
    scored = _score("xss", offline_ctx, XSS_LOG)
    assert scored.precision >= PRECISION_TARGET, f"precision {scored.precision:.2f}"
    assert scored.recall >= RECALL_TARGET, f"recall {scored.recall:.2f}"


def test_the_benign_corpus_produces_no_verdicts_at_all(offline_ctx: DetectionContext) -> None:
    """Not "few false positives" -- none. Every line here is a deliberate lookalike."""
    fired = [
        (verdicts[0].technique, verdicts[0].evidence[0].detail)
        for verdicts in _verdicts_for(BENIGN_LOG, offline_ctx)
        if verdicts
    ]
    assert fired == []


def test_the_gate_is_met_without_any_model_call(offline_ctx: DetectionContext) -> None:
    """The deterministic layer carries the numbers; the model is an enhancement, not a crutch."""
    _score("sql_injection", offline_ctx, SQLI_LOG)
    _score("xss", offline_ctx, XSS_LOG)
    stub = offline_ctx.model_client
    assert isinstance(stub, StubModelRouter)
    judged = [call.component for call in stub.calls if call.component.endswith("_detector")]
    assert judged == [], f"static layer should have decided everything, but escalated: {judged}"


def test_every_attack_verdict_is_evidenced_and_statistical(offline_ctx: DetectionContext) -> None:
    for log in (SQLI_LOG, XSS_LOG):
        for verdicts in _verdicts_for(log, offline_ctx):
            for verdict in verdicts:
                assert verdict.evidence
                assert any(e.kind == "matched_pattern" for e in verdict.evidence)
                assert verdict.model.used_llm is False
                assert 0.0 <= verdict.confidence <= 1.0
