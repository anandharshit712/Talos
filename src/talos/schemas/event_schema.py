"""``NormalizedEvent`` -- the single contract produced by ingestion (LLD 2.1).

Every parser emits this shape and every agent consumes it, so the field names here are
canonical and shared verbatim with the DFD data dictionary (``Talos_DFD.md`` 7).

Timestamps are normalised to UTC on the way in. Log sources report local time, naive time,
and offsets in the same corpus; rate detectors compare timestamps across events from
different files, so a window comparison against a naive datetime is a real defect rather than
a theoretical one. The normalisation happens once, here, instead of in every detector.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _to_utc(value: datetime) -> datetime:
    """Interpret a naive datetime as UTC; convert an aware one into UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


#: A datetime guaranteed to be timezone-aware and expressed in UTC. Shared by every contract
#: module so the guarantee is identical across events, verdicts, and reports.
UtcDatetime = Annotated[datetime, AfterValidator(_to_utc)]


class Actor(BaseModel):
    """Who or what generated the event."""

    model_config = ConfigDict(extra="forbid")

    source_ip: str = Field(min_length=1)
    account: str | None = None
    """Username or login target when the telemetry names one."""
    session_id: str | None = None
    user_agent: str | None = None


class Target(BaseModel):
    """What the event was aimed at."""

    model_config = ConfigDict(extra="forbid")

    host: str | None = None
    endpoint: str | None = None
    resource_id: str | None = None
    """Object id, the raw material for IDOR reasoning."""
    port: int | None = Field(default=None, ge=0, le=65535)


class WebRequest(BaseModel):
    """HTTP detail, populated for ``domain == "web"``."""

    model_config = ConfigDict(extra="forbid")

    method: str | None = None
    path: str | None = None
    query_params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    status_code: int | None = None


class AuthEvent(BaseModel):
    """Authentication detail, populated for any auth-bearing event."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["ssh", "rdp", "http"] | None = None
    outcome: Literal["success", "failure"] | None = None
    reason: str | None = None
    """Source-reported cause, e.g. ``invalid_password``, ``unknown_user``."""


class NormalizedEvent(BaseModel):
    """One parsed telemetry record, in the only shape the pipeline knows."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: UtcDatetime
    domain: Literal["web", "network"]
    telemetry_source: str = Field(min_length=1)
    """``waf`` | ``app_log`` | ``sshd`` | ``rdp`` | ``netflow``."""
    actor: Actor
    target: Target
    request: WebRequest | None = None
    auth: AuthEvent | None = None
    raw: str
    """The original log line, verbatim -- the evidence a verdict quotes."""
    meta: dict[str, Any] = Field(default_factory=dict)
    """Parser-specific extras that no contract field covers."""
