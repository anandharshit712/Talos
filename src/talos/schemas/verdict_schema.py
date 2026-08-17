"""``Verdict`` -- what a leaf detector emits (LLD 2.2). This is the transparency contract.

Two invariants are enforced by the model rather than left to detector discipline, because
"fail-safe for reporting" means a verdict that cannot justify itself must not exist:

* ``confidence`` is a float in ``[0, 1]``. Never a bare boolean -- a detector that cannot say
  how sure it is has not finished detecting.
* ``evidence`` is non-empty. A verdict with no artifact behind it is an assertion, and an
  analyst cannot action an assertion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from talos.schemas.event_schema import UtcDatetime


class MitreMapping(BaseModel):
    """One ATT&CK technique, resolved through ``knowledge/mitre_mapping.py``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str = Field(min_length=1)
    """e.g. ``T1110``."""
    technique_name: str = Field(min_length=1)
    tactic: str = Field(min_length=1)


class Evidence(BaseModel):
    """One concrete artifact supporting a verdict."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["log_line", "matched_pattern", "statistic", "baseline_deviation"]
    detail: str = Field(min_length=1)
    """The artifact itself: the raw line, the regex hit, the computed statistic."""
    references: list[str] = Field(default_factory=list)
    """``event_id`` / object-id values this artifact came from."""


class Scope(BaseModel):
    """Blast radius. The answer to "how bad, and how far did it get?"."""

    model_config = ConfigDict(extra="forbid")

    affected_accounts: list[str] = Field(default_factory=list)
    affected_endpoints: list[str] = Field(default_factory=list)
    affected_objects: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    attempt_count: int | None = Field(default=None, ge=0)
    source_diversity: int | None = Field(default=None, ge=0)
    """Distinct source IPs behind the activity."""
    succeeded: bool | None = None
    """Did the attack succeed? The highest-value scoping signal in the report."""
    window_start: UtcDatetime | None = None
    window_end: UtcDatetime | None = None


class ModelInfo(BaseModel):
    """Which model produced this verdict, if any, and why that one."""

    model_config = ConfigDict(extra="forbid")

    name: str
    """Resolved model id, or a marker such as ``none`` for a purely statistical verdict."""
    route_reason: str
    """Why this model was chosen -- including fallback and its confidence penalty."""
    used_llm: bool
    """False for a pure statistical or static verdict. A supported mode, not a degraded one."""


class Verdict(BaseModel):
    """One detector's judgement about one technique, over one or many events."""

    model_config = ConfigDict(extra="forbid")

    verdict_id: str = Field(min_length=1)
    event_ids: list[str] = Field(min_length=1)
    """One id, or many when a windowed detector spans events."""
    detector: str = Field(min_length=1)
    """``detector_name``, e.g. ``sql_injection_detector``."""
    domain: str = Field(min_length=1)
    category: str = Field(min_length=1)
    """Classifier output; equals the sub-agent package name (LLD 6)."""
    technique: str = Field(min_length=1)
    """e.g. ``sql_injection``, ``brute_force``, ``idor``."""
    attack_detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    mitre: MitreMapping
    scope: Scope
    evidence: list[Evidence] = Field(min_length=1)
    reasoning: str = Field(min_length=1)
    """Human-readable, model- or template-generated."""
    model: ModelInfo
    created_at: UtcDatetime = Field(default_factory=lambda: datetime.now(UTC))
