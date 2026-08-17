"""``RateEngine`` -- the statistical core behind every brute-force-shaped detector (LLD 7.3).

Same maths for SSH, RDP, web auth brute force, and credential stuffing; what differs is the key
function and the telemetry filter. Building it once, in P2, is what lets P5 add three detectors
in two days (HLD 5.5).

The engine is deliberately dumb: it counts failures in a window and reports what it saw. It does
not decide severity, wording, or confidence -- those belong to the detector, which knows its own
technique and its own thresholds.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from talos.core.agent_contracts import EventWindow
from talos.schemas.event_schema import NormalizedEvent


@dataclass(frozen=True)
class RateConfig:
    """What counts as "one target", and how many failures over what span is too many."""

    window_seconds: int
    fail_threshold: int
    key_fn: Callable[[NormalizedEvent], str | None]
    """Maps an event to its event-window key -- account, source IP, or host+account."""


@dataclass(frozen=True)
class RateSignal:
    """What the window held when the threshold was crossed."""

    key: str
    count: int
    """Failures inside the window."""
    sources: tuple[str, ...]
    """Distinct source IPs behind those failures, sorted."""
    accounts: tuple[str, ...]
    hosts: tuple[str, ...]
    succeeded: bool
    """A successful authentication after the burst began -- the highest-value analyst signal."""
    window_start: datetime
    window_end: datetime
    event_ids: tuple[str, ...]
    """Every failure event, plus the trailing success when there is one. Evidence references."""
    sample_lines: tuple[str, ...]
    """A few raw log lines, quoted verbatim into the verdict's evidence."""


#: How many raw lines a signal carries. Enough to read, not enough to bloat a report.
SAMPLE_LINE_COUNT = 3


class RateEngine:
    """Counts authentication failures per key inside a rolling window."""

    def evaluate(
        self, event: NormalizedEvent, window: EventWindow, config: RateConfig
    ) -> RateSignal | None:
        """Return a signal when the window holds enough failures for ``key_fn(event)``.

        ``None`` means "below threshold" or "not an auth event" -- both are the normal case on
        the overwhelming majority of lines.
        """
        if event.auth is None:
            return None
        key = config.key_fn(event)
        if key is None:
            return None

        recent = window.query(key=key, within=config.window_seconds)
        failures = [e for e in recent if e.auth is not None and e.auth.outcome == "failure"]
        if len(failures) < config.fail_threshold:
            return None

        burst_start = min(failure.timestamp for failure in failures)
        successes = [
            e
            for e in recent
            if e.auth is not None and e.auth.outcome == "success" and e.timestamp >= burst_start
        ]
        contributing = sorted(failures + successes, key=lambda e: e.timestamp)

        return RateSignal(
            key=key,
            count=len(failures),
            sources=_distinct(e.actor.source_ip for e in failures),
            accounts=_distinct(e.actor.account for e in failures),
            hosts=_distinct(e.target.host for e in failures),
            succeeded=bool(successes),
            window_start=contributing[0].timestamp,
            window_end=contributing[-1].timestamp,
            event_ids=tuple(e.event_id for e in contributing),
            sample_lines=tuple(e.raw for e in contributing[:SAMPLE_LINE_COUNT]),
        )


def _distinct(values: Iterable[str | None]) -> tuple[str, ...]:
    """Sorted unique non-empty strings, so scope fields are stable across runs."""
    return tuple(sorted({value for value in values if value}))
