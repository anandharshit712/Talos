"""An RDP burst in an exported Windows Security log, through every layer, to a report.

The SSH pipeline test proved the shape; this one proves the second telemetry format reaches it.
The fixture interleaves the noise a real export carries -- a privileged-logon event, a network
logon that shares the same event id, a logoff, and a stray syslog line from another collector --
so parsing the burst out of it is part of what is under test.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from talos.cli.main_cli import build_orchestrator, scan_file
from talos.core.settings import TalosSettings
from talos.ingestion.parsers.network_log_parser import NetworkLogParser
from talos.schemas.report_schema import IncidentReport

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
RDP_LOG = FIXTURES / "logs" / "network_rdp_brute_force_security.log"
EXPECTED = FIXTURES / "expected" / "network_rdp_brute_force_report.json"

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
        scan_file(RDP_LOG, NetworkLogParser(default_year=2026), orchestrator, [_Collector()])  # type: ignore[list-item]
    )
    assert result.events > 0
    assert result.skipped_lines > 0  # the fixture contains noise on purpose
    assert verdict_log.reports, "incidents must reach the audit trail"
    return collected


def test_the_burst_is_detected(reports: list[IncidentReport]) -> None:
    assert reports, "ten failed RemoteInteractive logons must produce an incident"


def test_the_incident_matches_the_expected_shape(reports: list[IncidentReport]) -> None:
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


def test_only_the_rdp_detector_answered(reports: list[IncidentReport]) -> None:
    """The SSH detector shares the key function, so the protocol filter is load-bearing."""
    detectors = {verdict.detector for report in reports for verdict in report.verdicts}
    assert detectors == {"rdp_brute_force_detector"}


def test_the_network_logon_noise_is_not_counted(reports: list[IncidentReport]) -> None:
    """A 4625 with logon type 3 is a real failure for another service, not part of this burst."""
    for report in reports:
        assert report.aggregate_scope.affected_accounts == ["administrator"]
        assert "svc_sql" not in json.dumps(report.model_dump(mode="json"))


def test_the_trailing_logon_success_is_reported(reports: list[IncidentReport]) -> None:
    landed = [report for report in reports if report.aggregate_scope.succeeded]
    assert landed, "the fixture ends with a 4624 for the same account"
    assert landed[-1].severity == "high"
    assert any("rotate credentials" in action for action in landed[-1].recommended_actions)


def test_every_verdict_is_evidenced_and_statistical(reports: list[IncidentReport]) -> None:
    for report in reports:
        for verdict in report.verdicts:
            assert verdict.evidence
            assert 0.0 <= verdict.confidence <= 1.0
            assert verdict.model.used_llm is False


def test_report_serialises_for_a_siem(reports: list[IncidentReport]) -> None:
    payload = reports[-1].model_dump_json()
    assert IncidentReport.model_validate_json(payload) == reports[-1]
