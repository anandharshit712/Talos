"""The contract strings several components must agree on, character for character."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from talos.core.constants import (
    CATEGORIES,
    CATEGORY_UNCLASSIFIED,
    DOMAINS,
    SEVERITIES,
)
from talos.schemas.event_schema import Actor, NormalizedEvent, Target
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Scope, Verdict


@pytest.mark.parametrize("domain", DOMAINS)
def test_every_domain_constant_is_accepted_by_the_event_contract(domain: str) -> None:
    """A constant the schema rejects is worse than no constant at all."""
    event = NormalizedEvent(
        event_id="e1",
        timestamp=datetime(2026, 8, 19, 10, 15, tzinfo=UTC),
        domain=domain,  # type: ignore[arg-type]
        telemetry_source="app_log",
        actor=Actor(source_ip="198.51.100.4"),
        target=Target(),
        raw="-",
    )
    assert event.domain == domain


@pytest.mark.parametrize("severity", SEVERITIES)
def test_every_severity_constant_is_accepted_by_the_report_contract(
    severity: str, sample_verdict: Verdict
) -> None:
    report = IncidentReport(
        incident_id="i1",
        domain="network",
        category="network_brute_force",
        summary="-",
        severity=severity,  # type: ignore[arg-type]
        confidence=0.5,
        verdicts=[sample_verdict],
        aggregate_scope=Scope(),
    )
    assert report.severity == severity


def test_categories_are_unique_and_snake_case() -> None:
    assert len(set(CATEGORIES)) == len(CATEGORIES)
    assert all(category.islower() and " " not in category for category in CATEGORIES)


def test_unclassified_is_a_category_but_never_a_package() -> None:
    """It is the classifier's "route nowhere" answer, so no sub-agent may claim it."""
    assert CATEGORY_UNCLASSIFIED in CATEGORIES


def test_severities_run_least_to_most_severe() -> None:
    assert SEVERITIES.index("info") < SEVERITIES.index("high") < SEVERITIES.index("critical")
