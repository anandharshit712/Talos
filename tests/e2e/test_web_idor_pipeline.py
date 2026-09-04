"""**The P6 gate.** An enumeration walk in an access log, and a benign log that must stay silent.

Two corpora, run through the same pipeline with the same settings. Recall without precision is
not a result, so the benign counterpart is not a nice-to-have here -- IDOR is the category with
no payload, and a detector that fires on "a user opened a record" would be worse than nothing.

Every layer is real: parser, event window, classifier, sub-agent, baseliner, scorer, aggregator.
The baseline lives in memory rather than PostgreSQL (``MemoryBaselineStore`` runs the real
``observe``); the locked read-modify-write has its own live suite in ``tests/integration/``.

No model is reachable, so every verdict here is statistical by construction.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from memory_baseline_store import MemoryBaselineStore

from talos.cli.main_cli import build_orchestrator, scan_file
from talos.core.settings import TalosSettings
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.schemas.report_schema import IncidentReport

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ENUMERATION_LOG = FIXTURES / "logs" / "web_idor_enumeration_combined.log"
BENIGN_LOG = FIXTURES / "logs" / "web_idor_benign_access_combined.log"
EXPECTED = FIXTURES / "expected" / "web_idor_enumeration_report.json"

pytestmark = pytest.mark.e2e


def run_scan(log: Path, tmp_path: Path, verdict_log: Any) -> tuple[list[IncidentReport], Any]:
    """Stream one fixture through the whole pipeline; return the incidents and the baselines."""
    settings = TalosSettings.load(config_dir=tmp_path / "absent")
    settings.output.report_dir = tmp_path / "reports"
    baseline_store = MemoryBaselineStore()

    collected: list[IncidentReport] = []

    class _Collector:
        name = "collector"

        def emit(self, report: IncidentReport) -> None:
            collected.append(report)

    orchestrator = build_orchestrator(settings, verdict_log, baseline_store)
    result = asyncio.run(
        scan_file(log, WebLogParser(), orchestrator, [_Collector()])  # type: ignore[list-item]
    )
    assert result.events > 0, "the fixture produced no parsed events at all"
    return collected, baseline_store


@pytest.fixture
def enumeration(tmp_path: Path, verdict_log: Any) -> list[IncidentReport]:
    reports, _ = run_scan(ENUMERATION_LOG, tmp_path, verdict_log)
    return reports


@pytest.fixture
def benign(tmp_path: Path, verdict_log: Any) -> list[IncidentReport]:
    reports, _ = run_scan(BENIGN_LOG, tmp_path, verdict_log)
    return reports


# --- recall ---------------------------------------------------------------------------------


def test_the_enumeration_run_is_detected(enumeration: list[IncidentReport]) -> None:
    assert enumeration, "twelve consecutive order ids by one account must produce an incident"


def test_the_incident_matches_the_expected_shape(enumeration: list[IncidentReport]) -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    final = enumeration[-1]

    assert final.domain == expected["domain"]
    assert final.category == expected["category"]
    assert final.severity == expected["severity"]
    assert final.confidence >= expected["min_confidence"]
    assert final.aggregate_scope.affected_accounts == expected["affected_accounts"]
    assert final.aggregate_scope.affected_endpoints == expected["affected_endpoints"]
    assert [technique.technique_id for technique in final.mitre_techniques] == expected[
        "mitre_techniques"
    ]


def test_scope_names_exactly_the_walked_object_ids(enumeration: list[IncidentReport]) -> None:
    """**Object-level scope is the deliverable.** These ids, not "some objects".

    Both directions matter. Every scoped id must be one the account actually walked -- a scope
    that over-reports sends an operator after objects nobody touched -- and the scope must be
    the run itself, in order.
    """
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    walked = set(expected["walked_object_ids"])
    scoped = enumeration[-1].aggregate_scope.affected_objects

    assert scoped == expected["final_affected_objects"]
    assert set(scoped) <= walked, f"scoped ids nobody walked: {sorted(set(scoped) - walked)}"


def test_the_last_ids_of_the_run_reach_no_report(enumeration: list[IncidentReport]) -> None:
    """Documented, not accidental: suppression reports per escalation, not per campaign.

    The run crosses the threshold at five ids and escalates at ten, when the count doubles.
    8011 and 8012 double nothing, so no report names them. That is the cadence
    ``talos.aggregation.suppress_duplicates`` buys, and whether it is the right one is a P8
    calibration question -- this test exists so the cost is visible rather than discovered in
    a demo.
    """
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert len(enumeration) == expected["incidents"]

    every_scoped = {
        object_id for report in enumeration for object_id in report.aggregate_scope.affected_objects
    }
    assert {"8011", "8012"} & every_scoped == set()


def test_the_other_accounts_traffic_is_not_scoped_in(enumeration: list[IncidentReport]) -> None:
    """bob's own order sits in the middle of the run's timeframe and must stay out of it."""
    assert enumeration[-1].aggregate_scope.affected_accounts == ["mallory"]
    assert "1006" not in enumeration[-1].aggregate_scope.affected_objects


def test_the_verdict_is_statistical(enumeration: list[IncidentReport]) -> None:
    """No model reachable in the suite, and the statistical path is a supported mode."""
    for verdict in enumeration[-1].verdicts:
        assert verdict.model.used_llm is False


def test_the_evidence_explains_the_finding(enumeration: list[IncidentReport]) -> None:
    details = " ".join(
        item.detail for verdict in enumeration[-1].verdicts for item in verdict.evidence
    )
    assert "consecutive object ids" in details
    assert "outside the learned pattern" in details


def test_the_unparseable_line_is_counted_not_fatal() -> None:
    """The fixture carries one junk line on purpose: a bad line is skipped, not fatal."""
    parser = WebLogParser()
    with ENUMERATION_LOG.open(encoding="utf-8") as handle:
        list(parser.parse_stream(handle))
    assert parser.parse_errors > 0


# --- precision ------------------------------------------------------------------------------


def test_the_benign_corpus_produces_no_incident(benign: list[IncidentReport]) -> None:
    """**The half that makes the claim honest.**

    The benign log contains, on purpose, the three cases most likely to be mistaken for IDOR:
    an account paging three adjacent ids it owns, the same account opening a part of the
    application it has never used, and one genuinely new object id outside everything it has
    touched. None of them is a breach.
    """
    assert not benign, f"false positives on benign traffic: {[r.summary for r in benign]}"


def test_the_benign_corpus_still_matured_a_baseline(tmp_path: Path, verdict_log: Any) -> None:
    """Silence must be the detector deciding, not the pipeline never reaching it."""
    _, baselines = run_scan(BENIGN_LOG, tmp_path, verdict_log)
    alice = asyncio.run(baselines.get("alice"))

    assert alice is not None
    assert alice.observations >= 50, "the baseline never matured, so nothing was ever scored"
    assert alice.endpoints, "the endpoint template never reached the baseline"
