"""``IncidentReport`` carries its verdicts verbatim -- the trace is the deliverable (LLD 2.3)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from talos.knowledge.mitre_mapping import mitre_all
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Scope, Verdict


def _report(verdict: Verdict) -> IncidentReport:
    return IncidentReport(
        incident_id="33333333-3333-4333-8333-333333333333",
        domain=verdict.domain,
        category=verdict.category,
        summary="12 failed ssh logins for root@bastion-01 from 203.0.113.7",
        severity="high",
        confidence=verdict.confidence,
        verdicts=[verdict],
        aggregate_scope=verdict.scope,
        mitre_techniques=mitre_all(verdict.technique),
        recommended_actions=["block source IP 203.0.113.7"],
    )


def test_round_trip_is_lossless(sample_verdict: Verdict) -> None:
    report = _report(sample_verdict)
    reloaded = IncidentReport.model_validate_json(report.model_dump_json())
    assert reloaded == report
    assert reloaded.verdicts[0] == sample_verdict


def test_report_without_verdicts_is_not_representable(sample_verdict: Verdict) -> None:
    """Nothing fired means the orchestrator returns None, not an empty report (LLD 11)."""
    payload = _report(sample_verdict).model_dump() | {"verdicts": []}
    with pytest.raises(ValidationError):
        IncidentReport.model_validate(payload)


def test_severity_is_a_closed_vocabulary(sample_verdict: Verdict) -> None:
    payload = _report(sample_verdict).model_dump() | {"severity": "catastrophic"}
    with pytest.raises(ValidationError):
        IncidentReport.model_validate(payload)


def test_aggregate_scope_survives_serialisation(sample_verdict: Verdict) -> None:
    report = _report(sample_verdict)
    reloaded = IncidentReport.model_validate_json(report.model_dump_json())
    assert reloaded.aggregate_scope == Scope.model_validate(sample_verdict.scope.model_dump())
    assert reloaded.aggregate_scope.attempt_count == 12
