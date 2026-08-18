"""**The P2 gate.** A log file goes in, a correct ``IncidentReport`` comes out, no LLM involved.

Every layer runs for real -- parser, event window, orchestrator, domain agent, classifier,
sub-agent, detector, aggregator, verdict log. The only thing this test fakes is nothing.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from apply_migrations import apply_pending

from talos.cli.main_cli import build_orchestrator, scan_file
from talos.core.settings import TalosSettings
from talos.ingestion.parsers.network_log_parser import NetworkLogParser
from talos.schemas.report_schema import IncidentReport
from talos.storage.verdict_log_store import VerdictLogStore

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SSH_LOG = FIXTURES / "logs" / "network_ssh_brute_force_sshd.log"
EXPECTED = FIXTURES / "expected" / "network_ssh_brute_force_report.json"

pytestmark = pytest.mark.e2e


@pytest.fixture
def reports(tmp_path: Path) -> list[IncidentReport]:
    """Run the fixture log through the whole pipeline and collect what it produced."""
    db_path = tmp_path / "talos.db"
    apply_pending(db_path)
    settings = TalosSettings.load(config_dir=tmp_path / "absent")
    settings.output.report_dir = tmp_path / "reports"

    collected: list[IncidentReport] = []

    class _Collector:
        name = "collector"

        def emit(self, report: IncidentReport) -> None:
            collected.append(report)

    with VerdictLogStore(db_path) as verdict_log:
        orchestrator = build_orchestrator(settings, verdict_log)
        result = asyncio.run(
            scan_file(SSH_LOG, NetworkLogParser(default_year=2026), orchestrator, [_Collector()])  # type: ignore[list-item]
        )
        assert result.events > 0
        assert result.skipped_lines > 0  # the fixture contains noise on purpose
        assert asyncio.run(verdict_log.recent()), "incidents must reach the audit trail"
    return collected


def test_pipeline_produces_an_incident(reports: list[IncidentReport]) -> None:
    assert reports, "the fixture contains a 12-failure burst; something must fire"


def test_incident_matches_the_expected_shape(reports: list[IncidentReport]) -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    final = reports[-1]
    assert final.domain == expected["domain"]
    assert final.category == expected["category"]
    assert final.severity == expected["severity"]
    assert final.confidence >= expected["min_confidence"]
    assert final.aggregate_scope.attempt_count == expected["attempt_count"]
    assert final.aggregate_scope.succeeded is expected["succeeded"]
    assert final.aggregate_scope.affected_accounts == expected["affected_accounts"]
    assert final.aggregate_scope.affected_hosts == expected["affected_hosts"]
    assert [m.technique_id for m in final.mitre_techniques] == expected["mitre_techniques"]


def test_every_verdict_is_evidenced_and_statistical(reports: list[IncidentReport]) -> None:
    """The P2 gate proper: real evidence, real confidence, and ``used_llm`` false throughout."""
    for report in reports:
        for verdict in report.verdicts:
            assert verdict.evidence
            assert 0.0 <= verdict.confidence <= 1.0
            assert verdict.model.used_llm is False


def test_the_successful_login_is_scoped(reports: list[IncidentReport]) -> None:
    """The fixture ends with an accepted password: the trailing success must be reported."""
    assert any(report.aggregate_scope.succeeded for report in reports)
    landed = [report for report in reports if report.aggregate_scope.succeeded]
    assert landed[-1].severity == "high"
    assert any("rotate credentials" in action for action in landed[-1].recommended_actions)


def test_report_serialises_for_a_siem(reports: list[IncidentReport]) -> None:
    payload = reports[-1].model_dump_json()
    assert IncidentReport.model_validate_json(payload) == reports[-1]
