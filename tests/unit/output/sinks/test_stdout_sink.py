"""Reports on stdout as JSON Lines, so ``talos scan file.log | jq`` needs no filter."""

from __future__ import annotations

import io
import json

from talos.output.sinks.stdout_sink import StdoutSink
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Verdict


def _report(verdict: Verdict) -> IncidentReport:
    return IncidentReport(
        incident_id="incident-1",
        domain="network",
        category="network_brute_force",
        summary="brute force on bastion-01",
        severity="high",
        confidence=0.91,
        verdicts=[verdict],
        aggregate_scope=verdict.scope,
    )


def test_report_is_one_parseable_line(sample_verdict: Verdict) -> None:
    stream = io.StringIO()
    StdoutSink(stream=stream).emit(_report(sample_verdict))
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["incident_id"] == "incident-1"


def test_two_reports_stay_on_separate_lines(sample_verdict: Verdict) -> None:
    stream = io.StringIO()
    sink = StdoutSink(stream=stream)
    sink.emit(_report(sample_verdict))
    sink.emit(_report(sample_verdict))
    assert len(stream.getvalue().splitlines()) == 2


def test_pretty_mode_indents_for_a_human(sample_verdict: Verdict) -> None:
    stream = io.StringIO()
    StdoutSink(stream=stream, indent=2).emit(_report(sample_verdict))
    assert '\n  "incident_id"' in stream.getvalue()


def test_round_trips_back_into_the_contract(sample_verdict: Verdict) -> None:
    stream = io.StringIO()
    report = _report(sample_verdict)
    StdoutSink(stream=stream).emit(report)
    assert IncidentReport.model_validate_json(stream.getvalue()) == report
