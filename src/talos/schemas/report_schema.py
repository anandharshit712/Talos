"""``IncidentReport`` -- the SIEM/SOAR-consumable output of ``VerdictAggregator`` (LLD 2.3).

The report carries every contributing verdict verbatim rather than a summary of them: the
pipeline trace is the differentiator, so nothing that produced the conclusion is discarded on
the way out.

A report with no verdicts is not representable. When nothing fires, the orchestrator returns
``None`` -- an empty report would read as "we looked and found nothing", which is a different
claim from "no detector had anything to say" (LLD 11).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from talos.schemas.event_schema import UtcDatetime
from talos.schemas.verdict_schema import MitreMapping, Scope, Verdict


class IncidentReport(BaseModel):
    """One incident: the merged, scored view over a set of corroborating verdicts."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    created_at: UtcDatetime = Field(default_factory=lambda: datetime.now(UTC))
    domain: str = Field(min_length=1)
    category: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    """One line an analyst can read without opening the verdicts."""
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    """Aggregate confidence across the contributing verdicts."""
    verdicts: list[Verdict] = Field(min_length=1)
    aggregate_scope: Scope
    """Union of the verdict scopes -- accounts, endpoints, objects, hosts, and success."""
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    """e.g. ``block source IP 203.0.113.7``, ``force password reset for alice``."""
