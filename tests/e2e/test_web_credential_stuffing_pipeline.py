"""A stuffing run in an access log, through every layer, to an ``IncidentReport``.

The unit tests build events; this one starts from log lines, so it is the only test that proves
the chain the P5 web work actually added: a status code and a form body become an ``AuthEvent``,
the classifier routes on it, and the breadth detector reads it. Any one of those three failing
leaves this test with an empty report list.

No model is reachable, so every verdict here is statistical by construction.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from talos.cli.main_cli import build_orchestrator, scan_file
from talos.core.settings import TalosSettings
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.schemas.report_schema import IncidentReport

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ACCESS_LOG = FIXTURES / "logs" / "web_credential_stuffing_access.log"
EXPECTED = FIXTURES / "expected" / "web_credential_stuffing_report.json"

pytestmark = pytest.mark.e2e


@pytest.fixture
def reports(tmp_path: Path, verdict_log: Any) -> list[IncidentReport]:
    """Run the fixture log through the whole pipeline and collect what it produced."""
    settings = TalosSettings.load(config_dir=tmp_path / "absent")
    settings.output.report_dir = tmp_path / "reports"

    collected: list[IncidentReport] = []

    class _Collector:
        name = "collector"

        def emit(self, report: IncidentReport) -> None:
            collected.append(report)

    orchestrator = build_orchestrator(settings, verdict_log)
    result = asyncio.run(
        scan_file(ACCESS_LOG, WebLogParser(), orchestrator, [_Collector()])  # type: ignore[list-item]
    )
    assert result.events > 0
    assert result.skipped_lines == 1  # the fixture carries one unreadable line on purpose
    assert verdict_log.reports, "incidents must reach the audit trail"
    return collected


def test_the_run_is_detected(reports: list[IncidentReport]) -> None:
    assert reports, "20 accounts from one source in one window must produce an incident"


def test_it_is_reported_as_stuffing_not_brute_force(reports: list[IncidentReport]) -> None:
    """Two failures per account is below every brute-force threshold, and must stay below it."""
    techniques = {verdict.technique for report in reports for verdict in report.verdicts}
    assert techniques == {"credential_stuffing"}


def test_the_incident_matches_the_expected_shape(reports: list[IncidentReport]) -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    final = reports[-1]
    assert final.domain == expected["domain"]
    assert final.category == expected["category"]
    assert final.severity == expected["severity"]
    assert final.confidence >= expected["min_confidence"]
    assert len(final.aggregate_scope.affected_accounts) == expected["distinct_accounts"]
    assert final.aggregate_scope.succeeded is expected["succeeded"]
    assert [m.technique_id for m in final.mitre_techniques] == expected["mitre_techniques"]


def test_the_compromised_account_is_named_in_the_evidence(
    reports: list[IncidentReport],
) -> None:
    """The one credential that worked is the whole point of the report."""
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    landed = [report for report in reports if report.aggregate_scope.succeeded]
    assert landed, "the fixture ends with a successful login"
    details = [item.detail for verdict in landed[-1].verdicts for item in verdict.evidence]
    assert any(expected["succeeded_account"] in detail for detail in details)
    assert any("rotate credentials" in action for action in landed[-1].recommended_actions)


def test_the_benign_logins_raise_nothing(reports: list[IncidentReport]) -> None:
    """Two ordinary people signing in, one after a typo, are in the corpus deliberately."""
    reported = {
        account
        for report in reports
        for verdict in report.verdicts
        for account in verdict.scope.affected_accounts
    }
    assert "hazel" not in reported, "a clean login must not be scoped into the incident"
    assert "ivan" not in reported, "one typo then a success is not an attack"
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    for report in reports:
        for verdict in report.verdicts:
            statistic = next(item for item in verdict.evidence if item.kind == "statistic")
            assert expected["source"] in statistic.detail


def test_every_verdict_is_evidenced_and_statistical(reports: list[IncidentReport]) -> None:
    for report in reports:
        for verdict in report.verdicts:
            assert verdict.evidence
            assert 0.0 <= verdict.confidence <= 1.0
            assert verdict.model.used_llm is False


def test_report_serialises_for_a_siem(reports: list[IncidentReport]) -> None:
    payload = reports[-1].model_dump_json()
    assert IncidentReport.model_validate_json(payload) == reports[-1]
