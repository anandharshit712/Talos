"""**The P8 measurement.** Precision, recall, F1, calibration and latency over the whole corpus.

This is the library; ``test_corpus_metrics_gate.py`` drives it and asserts the gate. Run
``pytest tests/e2e/test_corpus_metrics_gate.py -s`` to see the tables.

Three things are measured, because they answer three different questions:

* **Per-detector precision / recall / F1** -- is the detector any good? Scored over *logs*, not
  lines, for windowed detectors, and over lines for payload detectors. See the labelling rules.
* **Calibration** -- when a verdict says 0.9, is it right about nine times in ten (NFR-3)? Scored
  over every verdict emitted, including the ones that never escalated into an incident.
* **Latency** -- p50/p95/max milliseconds per event through the real orchestrator.

**The labelling rules, which are the whole result.** Getting these wrong produces a number that
looks like a measurement and is not one:

1. A **benign** log must produce nothing. Any incident from any detector is a false positive.
   Not "few" -- none. Every line in the benign corpus is a deliberate lookalike.
2. On an **attack** log, an incident carrying the expected technique is a true positive; its
   absence is a false negative.
3. On an attack log, an incident carrying a *different* technique is **not** counted as a false
   positive. The traffic is genuinely malicious, so a second detector having an opinion about it
   is not an error -- it is reported separately as ``collateral`` and judged by eye.
4. Windowed detectors (brute force, stuffing, IDOR) are scored **per log**: eleven failed
   logins *should not* fire, so counting them as misses would make recall meaningless. Payload
   detectors (SQLi, XSS) are scored **per line**, because there every line is itself an attack.

The model is off by default. A precision figure that depends on a free-tier endpoint being
reachable is not a property of the detector (the same reasoning as the P4 gate).
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from memory_baseline_store import MemoryBaselineStore

from talos.cli.main_cli import build_orchestrator
from talos.core.agent_contracts import DetectionContext, DomainAgent
from talos.core.settings import TalosSettings
from talos.ingestion.parser_contract import BaseParser
from talos.ingestion.parsers.network_log_parser import NetworkLogParser
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.orchestrator.agent_registry import AgentRegistry
from talos.orchestrator.event_orchestrator import EventOrchestrator
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
LOGS = REPO_ROOT / "tests" / "fixtures" / "logs"
CONFIG_DIR = REPO_ROOT / "config"

#: Confidence bucket width for the calibration table. Ten buckets over [0, 1].
BUCKET_WIDTH = 0.1


@dataclass(frozen=True)
class Case:
    """One corpus file and what it is supposed to produce."""

    log: str
    domain: str
    technique: str | None
    """``None`` marks a benign counterpart: anything it fires is a false positive."""
    per_line: bool = False
    """True for payload detectors, where every line is independently an attack (rule 4)."""

    @property
    def path(self) -> Path:
        return LOGS / self.log

    @property
    def is_benign(self) -> bool:
        return self.technique is None


#: The labelled corpus. Every attack case needs a benign counterpart in the same domain, or its
#: precision figure is unmeasurable -- see plan P8.
CORPUS: tuple[Case, ...] = (
    # Network stays synthetic: SSH/RDP brute force cannot be captured without standing up a live
    # sshd/RDP service and a brute-force tool, which is not worth the exposure on a dev box.
    Case("network_ssh_brute_force_sshd.log", "network", "brute_force"),
    Case("network_rdp_brute_force_security.log", "network", "brute_force"),
    Case("web_credential_stuffing_access.log", "web", "credential_stuffing"),
    Case("web_idor_enumeration_combined.log", "web", "idor"),
    # The captured windowed fixtures: real login bursts and an IDOR walk through nginx, so the
    # timing and format are authentic. Made by scripts/capture_web_attack_corpus.py, 2026-09-07.
    Case("web_brute_force_captured_access.log", "web", "brute_force"),
    Case("web_credential_stuffing_captured_access.log", "web", "credential_stuffing"),
    Case("web_idor_captured_access.log", "web", "idor"),
    # The hand-built payload fixtures: small, and every line hand-chosen. They stay because the
    # P4 gate is measured against them and they must not silently change.
    Case("web_sql_injection_mixed_waf.log", "web", "sql_injection", per_line=True),
    Case("web_xss_mixed_combined.log", "web", "xss", per_line=True),
    # The captured payload fixtures: real attack strings fired through nginx over a real HTTP
    # round-trip, so the pattern matcher meets encodings it did not author. These are what turned
    # the payload-detector recall from a smoke test into a measurement -- see the feature
    # testing.md. Provenance: scripts/capture_web_attack_corpus.py, 2026-09-07.
    Case("web_sql_injection_captured_access.log", "web", "sql_injection", per_line=True),
    Case("web_xss_captured_access.log", "web", "xss", per_line=True),
    Case("web_benign_traffic_combined.log", "web", None),
    Case("web_benign_captured_access.log", "web", None),
    Case("web_idor_benign_access_combined.log", "web", None),
    # Captured benign counterparts: an ordinary mistype-then-succeed login, and an account reading
    # its own records rather than walking them. Both must stay silent.
    Case("web_benign_auth_captured_access.log", "web", None),
    Case("web_benign_access_captured_access.log", "web", None),
)


@dataclass
class Score:
    """Counts for one technique across the corpus, and the three figures they produce."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    detectors: set[str] = field(default_factory=set)
    """Which detector names actually emitted this technique -- discovered, never declared."""

    @property
    def precision(self) -> float:
        fired = self.true_positives + self.false_positives
        return 1.0 if fired == 0 else self.true_positives / fired

    @property
    def recall(self) -> float:
        actual = self.true_positives + self.false_negatives
        return 1.0 if actual == 0 else self.true_positives / actual

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 0.0 if total == 0 else 2 * self.precision * self.recall / total


@dataclass
class Bucket:
    """One confidence band, and how often verdicts in it turned out to be right."""

    lower: float
    verdicts: int = 0
    correct: int = 0
    """Emitted on an attack log. On a benign log every verdict is wrong by construction."""

    @property
    def observed(self) -> float:
        return 0.0 if self.verdicts == 0 else self.correct / self.verdicts

    @property
    def claim(self) -> float:
        """What a verdict in this band is asserting about itself."""
        return self.lower + BUCKET_WIDTH / 2

    @property
    def error(self) -> float:
        """How far the bucket's claim is from what actually happened, either direction."""
        return abs(self.observed - self.claim)

    @property
    def overconfidence(self) -> float:
        """Only the dangerous direction: claiming 0.9 and being right 0.6 of the time.

        The other direction is a different animal. A bucket claiming 0.75 that is right every
        time is *under*-confident -- conservative, not wrong -- and it is what a corpus with no
        false positives produces by construction, since with nothing to be wrong about every
        band reads 1.00. Asserting on the absolute distance would therefore fail a detector for
        being careful, and pass one whose corpus was too small to catch it out.
        """
        return max(0.0, self.claim - self.observed)


@dataclass
class Measurement:
    """Everything one corpus run produced."""

    scores: dict[str, Score] = field(default_factory=dict)
    buckets: dict[float, Bucket] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)
    collateral: list[tuple[str, str]] = field(default_factory=list)
    """(log, technique) pairs from rule 3 -- a second detector firing on real attack traffic."""
    false_positive_detail: list[tuple[str, str, float]] = field(default_factory=list)
    """(log, technique, confidence) for every rule-1 violation, so a failure names itself."""
    events: int = 0
    incidents: int = 0
    used_llm: bool = False

    def score_for(self, technique: str) -> Score:
        return self.scores.setdefault(technique, Score())

    @property
    def false_positives(self) -> int:
        return len(self.false_positive_detail)

    def percentile(self, fraction: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = min(int(fraction * len(ordered)), len(ordered) - 1)
        return ordered[index]

    @property
    def worst_bucket(self) -> Bucket | None:
        """The populated bucket claiming most and delivering least -- what NFR-3 is judged on."""
        populated = [b for b in self.buckets.values() if b.verdicts]
        return max(populated, key=lambda b: b.overconfidence) if populated else None

    @property
    def wrong_verdicts(self) -> int:
        """Verdicts that fired on benign traffic. Calibration is unmeasurable while this is 0.

        Not a pass/fail figure -- it is the sample size for the calibration question. Every
        bucket reads 1.00 when nothing was ever wrong, whatever the confidences said.
        """
        return sum(b.verdicts - b.correct for b in self.buckets.values())

    def as_dict(self) -> dict[str, Any]:
        """The shape written to disk for ``Talos_Evaluation_Results.md`` to quote."""
        return {
            "corpus": {
                "logs": len(CORPUS),
                "attack_logs": sum(1 for case in CORPUS if not case.is_benign),
                "benign_logs": sum(1 for case in CORPUS if case.is_benign),
                "events": self.events,
                "incidents": self.incidents,
            },
            "used_llm": self.used_llm,
            "detectors": {
                technique: {
                    "detectors": sorted(score.detectors),
                    "true_positives": score.true_positives,
                    "false_positives": score.false_positives,
                    "false_negatives": score.false_negatives,
                    "precision": round(score.precision, 4),
                    "recall": round(score.recall, 4),
                    "f1": round(score.f1, 4),
                }
                for technique, score in sorted(self.scores.items())
            },
            "calibration": [
                {
                    "bucket": f"{bucket.lower:.1f}-{bucket.lower + BUCKET_WIDTH:.1f}",
                    "verdicts": bucket.verdicts,
                    "correct": bucket.correct,
                    "observed": round(bucket.observed, 4),
                    "claim": round(bucket.claim, 4),
                    "error": round(bucket.error, 4),
                    "overconfidence": round(bucket.overconfidence, 4),
                }
                for _, bucket in sorted(self.buckets.items())
                if bucket.verdicts
            ],
            "calibration_measurable": self.wrong_verdicts > 0,
            "latency_ms": {
                "p50": round(self.percentile(0.50), 3),
                "p95": round(self.percentile(0.95), 3),
                "max": round(max(self.latencies_ms), 3) if self.latencies_ms else 0.0,
            },
            "false_positives": [
                {"log": log, "technique": technique, "confidence": round(confidence, 4)}
                for log, technique, confidence in self.false_positive_detail
            ],
            "collateral": [
                {"log": log, "technique": technique} for log, technique in self.collateral
            ],
        }


class _RecordingAgent:
    """Wraps a domain agent to capture every verdict on its way out.

    The alternative was re-implementing ``EventOrchestrator.submit`` here to see the verdicts
    before aggregation, which would measure a pipeline that does not exist. This way the real
    orchestrator runs, and calibration still sees the verdicts that never escalated.
    """

    def __init__(self, inner: DomainAgent) -> None:
        self._inner = inner
        self.verdicts: list[Verdict] = []

    @property
    def domain(self) -> str:
        return self._inner.domain

    async def process(self, event: NormalizedEvent, ctx: DetectionContext) -> list[Verdict]:
        verdicts = await self._inner.process(event, ctx)
        self.verdicts.extend(verdicts)
        return verdicts


class _Collector:
    """A sink that keeps the incidents instead of printing them."""

    name = "collector"

    def __init__(self) -> None:
        self.reports: list[IncidentReport] = []

    def emit(self, report: IncidentReport) -> None:
        self.reports.append(report)


def _parser_for(domain: str) -> BaseParser:
    return WebLogParser() if domain == "web" else NetworkLogParser(default_year=2026)


def _build(settings: TalosSettings) -> tuple[EventOrchestrator, list[_RecordingAgent]]:
    """A fresh pipeline per case, with every domain agent wrapped for recording.

    Fresh per case on purpose: the event window and the duplicate-suppression map are stateful,
    so one shared orchestrator would let one log's traffic change another log's verdicts.
    """
    orchestrator = build_orchestrator(settings, _RecordingVerdictLog(), MemoryBaselineStore())
    recorders = [
        _RecordingAgent(agent)
        for agent in (orchestrator.registry.get(d) for d in orchestrator.registry.domains())
        if agent is not None
    ]
    registry = AgentRegistry()
    for recorder in recorders:
        registry.register_domain_agent(recorder)  # type: ignore[arg-type]
    orchestrator.registry = registry
    return orchestrator, recorders


class _RecordingVerdictLog:
    """The audit trail, in memory. The live round-trip has its own suite in tests/integration/."""

    def __init__(self) -> None:
        self.reports: list[IncidentReport] = []

    async def append(self, report: IncidentReport) -> None:
        self.reports.append(report)


def _settings(*, use_llm: bool) -> TalosSettings:
    """The repository's real thresholds, with the model switched off unless asked for."""
    settings = TalosSettings.load(config_dir=CONFIG_DIR)
    settings.llm.enabled = use_llm
    return settings


async def _run_case(case: Case, settings: TalosSettings, out: Measurement) -> None:
    """Stream one log through a fresh pipeline and fold the result into ``out``."""
    orchestrator, recorders = _build(settings)
    parser = _parser_for(case.domain)
    collector = _Collector()

    lines = case.path.read_text(encoding="utf-8").splitlines()
    fired_lines: set[str] = set()
    for event in parser.parse_stream(lines):
        started = time.perf_counter()
        report = await orchestrator.submit(event)
        out.latencies_ms.append((time.perf_counter() - started) * 1000)
        out.events += 1
        if report is not None:
            out.incidents += 1
            collector.emit(report)

    verdicts = [verdict for recorder in recorders for verdict in recorder.verdicts]
    # Lines that fired the case's *own* technique, kept per-technique. A payload line that trips a
    # different detector (an XSS string the SQLi rules also match) is collateral, not a true
    # positive for this case -- counting it as one would inflate recall with the wrong detector.
    fired_lines = {
        event_id
        for verdict in verdicts
        if verdict.attack_detected and verdict.technique == case.technique
        for event_id in verdict.event_ids
    }
    for verdict in verdicts:
        if verdict.model.used_llm:
            out.used_llm = True
        _bucket(out, verdict, attack_log=not case.is_benign)

    _score_case(case, collector.reports, verdicts, len(fired_lines), out)


def _bucket(out: Measurement, verdict: Verdict, *, attack_log: bool) -> None:
    """Fold one verdict into its confidence band. Rule 1 makes benign verdicts wrong outright."""
    if not verdict.attack_detected:
        return
    lower = min(int(verdict.confidence / BUCKET_WIDTH) * BUCKET_WIDTH, 1.0 - BUCKET_WIDTH)
    lower = round(lower, 1)
    bucket = out.buckets.setdefault(lower, Bucket(lower=lower))
    bucket.verdicts += 1
    if attack_log:
        bucket.correct += 1


def _score_case(
    case: Case,
    reports: list[IncidentReport],
    verdicts: list[Verdict],
    fired_line_count: int,
    out: Measurement,
) -> None:
    """Apply the four labelling rules to one case."""
    fired = {
        verdict.technique: verdict
        for report in reports
        for verdict in report.verdicts
        if verdict.attack_detected
    }

    if case.is_benign:
        for technique, verdict in fired.items():  # rule 1
            out.score_for(technique).false_positives += 1
            out.score_for(technique).detectors.add(verdict.detector)
            out.false_positive_detail.append((case.log, technique, verdict.confidence))
        return

    assert case.technique is not None
    score = out.score_for(case.technique)
    score.detectors.update(
        verdict.detector for verdict in verdicts if verdict.technique == case.technique
    )

    if case.per_line:  # rule 4, payload detectors
        all_lines = case.path.read_text(encoding="utf-8").splitlines()
        attack_lines = sum(1 for line in all_lines if line.strip())
        score.true_positives += fired_line_count
        score.false_negatives += max(attack_lines - fired_line_count, 0)
    elif case.technique in fired:  # rule 2, windowed detectors
        score.true_positives += 1
    else:
        score.false_negatives += 1

    for technique in fired:  # rule 3
        if technique != case.technique:
            out.collateral.append((case.log, technique))


def measure(*, use_llm: bool = False, corpus: tuple[Case, ...] = CORPUS) -> Measurement:
    """Run the whole corpus and return every figure. The entry point tests and scripts call."""
    settings = _settings(use_llm=use_llm)
    out = Measurement()

    async def run() -> None:
        for case in corpus:
            await _run_case(case, settings, out)

    asyncio.run(run())
    return out


def render(out: Measurement) -> str:
    """The tables a human reads. Sparse buckets are shown, never hidden -- see the docstring."""
    lines = [
        "",
        f"corpus: {out.events} events over {len(CORPUS)} logs -> {out.incidents} incidents "
        f"(used_llm={out.used_llm})",
        "",
        f"{'TECHNIQUE':<22}{'TP':>5}{'FP':>5}{'FN':>5}{'PREC':>8}{'RECALL':>8}{'F1':>8}  DETECTORS",
        "-" * 100,
    ]
    for technique, score in sorted(out.scores.items()):
        lines.append(
            f"{technique:<22}{score.true_positives:>5}{score.false_positives:>5}"
            f"{score.false_negatives:>5}{score.precision:>8.2f}{score.recall:>8.2f}"
            f"{score.f1:>8.2f}  {','.join(sorted(score.detectors))}"
        )

    header = (
        f"{'CONFIDENCE':<14}{'VERDICTS':>10}{'CORRECT':>9}"
        f"{'CLAIM':>8}{'OBSERVED':>10}{'OVERCONF':>10}"
    )
    lines += ["", header, "-" * len(header)]
    for _, bucket in sorted(out.buckets.items()):
        if bucket.verdicts:
            band = f"{bucket.lower:.1f}-{bucket.lower + BUCKET_WIDTH:.1f}"
            lines.append(
                f"{band:<14}{bucket.verdicts:>10}{bucket.correct:>9}{bucket.claim:>8.2f}"
                f"{bucket.observed:>10.2f}{bucket.overconfidence:>10.2f}"
            )
    if out.wrong_verdicts == 0:
        lines.append(
            "  calibration is NOT measurable on this corpus: 0 verdicts were ever wrong, so "
            "every band reads 1.00 whatever it claimed. Needs hard negatives -- P8 open item."
        )

    mean = statistics.mean(out.latencies_ms) if out.latencies_ms else 0.0
    lines += [
        "",
        f"latency per event: p50 {out.percentile(0.50):.2f}ms  p95 {out.percentile(0.95):.2f}ms  "
        f"mean {mean:.2f}ms  max {max(out.latencies_ms, default=0.0):.2f}ms",
    ]
    if out.false_positive_detail:
        lines += ["", "FALSE POSITIVES (rule 1 -- the benign corpus must stay silent):"]
        lines += [
            f"  {log}: {technique} @ {confidence:.2f}"
            for log, technique, confidence in out.false_positive_detail
        ]
    if out.collateral:
        lines += ["", "collateral (rule 3 -- a second detector on real attack traffic):"]
        lines += [f"  {log}: {technique}" for log, technique in out.collateral]
    return "\n".join(lines) + "\n"
