"""One JSON file per incident, and a loud failure when the directory cannot be written."""

from __future__ import annotations

from pathlib import Path

import pytest

from talos.core.error_types import StorageError
from talos.output.sinks.json_file_sink import JsonFileSink
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Verdict


def _report(verdict: Verdict, incident_id: str = "incident-1") -> IncidentReport:
    return IncidentReport(
        incident_id=incident_id,
        domain="network",
        category="network_brute_force",
        summary="brute force on bastion-01",
        severity="high",
        confidence=0.91,
        verdicts=[verdict],
        aggregate_scope=verdict.scope,
    )


def test_report_is_written_under_its_incident_id(tmp_path: Path, sample_verdict: Verdict) -> None:
    sink = JsonFileSink(tmp_path / "reports")
    report = _report(sample_verdict)
    sink.emit(report)
    written = tmp_path / "reports" / "incident-1.json"
    assert IncidentReport.model_validate_json(written.read_text(encoding="utf-8")) == report


def test_directory_is_created_on_demand(tmp_path: Path, sample_verdict: Verdict) -> None:
    JsonFileSink(tmp_path / "deep" / "nested" / "reports").emit(_report(sample_verdict))
    assert (tmp_path / "deep" / "nested" / "reports" / "incident-1.json").is_file()


def test_each_incident_gets_its_own_file(tmp_path: Path, sample_verdict: Verdict) -> None:
    sink = JsonFileSink(tmp_path)
    sink.emit(_report(sample_verdict, "one"))
    sink.emit(_report(sample_verdict, "two"))
    assert {path.name for path in tmp_path.glob("*.json")} == {"one.json", "two.json"}


def test_unwritable_destination_is_reported_not_swallowed(
    tmp_path: Path, sample_verdict: Verdict
) -> None:
    """Fail-safe for reporting: a report that cannot be written must be heard about."""
    blocker = tmp_path / "reports"
    blocker.write_text("a file where the directory should be", encoding="utf-8")
    with pytest.raises(StorageError):
        JsonFileSink(blocker).emit(_report(sample_verdict))
