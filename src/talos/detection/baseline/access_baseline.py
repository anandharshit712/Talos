"""What one account's normal object access looks like, and how it learns (LLD 7.4).

IDOR has no payload to match. A request for `/api/orders/1002` is identical whether it belongs to
the caller or to someone else, so the only signal is *deviation from what this account has done
before* -- which means the detector needs a memory, and the memory needs to be per account.

This module is the model and the update rule. It reads no configuration and touches no database:
bounds arrive as arguments, persistence is :mod:`talos.storage.baseline_store`, and the scoring
that reads a baseline is P6.2. Keeping the three apart is what lets the update rule be tested
without a server.

**Cold start is a first-class state.** A baseline below its observation threshold is *immature*,
and an immature baseline must produce a low-confidence "not enough history" verdict rather than
a confident accusation. An account Talos has never seen is not a suspicious account.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from talos.schemas.event_schema import UtcDatetime


class AccessBaseline(BaseModel):
    """One account's learned access pattern, persisted across runs."""

    model_config = ConfigDict(extra="forbid")

    account: str = Field(min_length=1)

    seen_object_ids: list[str] = Field(default_factory=list)
    """Distinct object ids, oldest first, bounded.

    A list rather than the set the LLD sketched, for two reasons. Eviction needs an order --
    dropping an arbitrary element when the cap is reached would eventually forget an id the
    account touched yesterday while keeping one from last month -- and ``jsonb`` has no set, so
    a set round-trips through the store as a list anyway (LLD rev 1.11).
    """

    numeric_min: int | None = None
    numeric_max: int | None = None
    """The observed id range, over ids that parse as integers.

    Kept separately from ``seen_object_ids`` and never narrowed, so eviction cannot make an
    account's historical range look smaller than it was and turn an old id into an outlier.
    """

    endpoints: dict[str, int] = Field(default_factory=dict)
    """Endpoint -> access count, bounded. Novelty of an endpoint is one deviation feature."""

    observations: int = Field(default=0, ge=0)
    """Total accesses recorded, which is what maturity is measured against.

    Not in the LLD's sketch, and not derivable from the fields that are: both collections are
    bounded, so summing them undercounts a busy account back below its own threshold and the
    baseline would oscillate between mature and immature (LLD rev 1.11).
    """

    updated_at: UtcDatetime


def numeric_id(object_id: str) -> int | None:
    """The integer value of an id, or ``None`` when it is not a plain integer.

    Deliberately strict: ``"1002"`` is an enumerable id, ``"order-1002"`` and a UUID are not.
    A loose parse that dug digits out of any string would invent a numeric range for opaque
    ids and then report every one of them as out of range.
    """
    stripped = object_id.strip()
    if not stripped.isdigit() and not (stripped.startswith("-") and stripped[1:].isdigit()):
        return None
    return int(stripped)


def observe(
    baseline: AccessBaseline,
    *,
    object_id: str,
    endpoint: str | None,
    at: UtcDatetime,
    max_object_ids: int,
    max_endpoints: int,
) -> AccessBaseline:
    """Fold one access into a baseline, returning the updated copy.

    Pure, so the caller decides when the result is written -- the store applies it inside the
    per-account lock that makes the read-modify-write safe.
    """
    seen = _remember(baseline.seen_object_ids, object_id, max_object_ids)
    endpoints = (
        baseline.endpoints
        if endpoint is None
        else _count_endpoint(baseline.endpoints, endpoint, max_endpoints)
    )
    value = numeric_id(object_id)

    return baseline.model_copy(
        update={
            "seen_object_ids": seen,
            "endpoints": endpoints,
            "numeric_min": _lower(baseline.numeric_min, value),
            "numeric_max": _upper(baseline.numeric_max, value),
            "observations": baseline.observations + 1,
            "updated_at": at,
        }
    )


def new_baseline(account: str, at: UtcDatetime) -> AccessBaseline:
    """An empty baseline for an account never seen before. Immature by construction."""
    return AccessBaseline(account=account, updated_at=at)


def is_mature(baseline: AccessBaseline, min_observations: int) -> bool:
    """Whether the baseline has seen enough to be accused of knowing what normal looks like."""
    return baseline.observations >= min_observations


def outside_numeric_range(baseline: AccessBaseline, object_id: str) -> bool:
    """Whether a numeric id falls outside every id this account has been seen to touch.

    ``False`` for a non-numeric id and for a baseline that has never seen a numeric one: an
    unanswerable question is not evidence.
    """
    value = numeric_id(object_id)
    if value is None or baseline.numeric_min is None or baseline.numeric_max is None:
        return False
    return value < baseline.numeric_min or value > baseline.numeric_max


def _remember(seen: list[str], object_id: str, cap: int) -> list[str]:
    """Move an id to the newest position, evicting the oldest once the cap is reached."""
    remaining = [existing for existing in seen if existing != object_id]
    remaining.append(object_id)
    return remaining[-cap:] if cap > 0 else []


def _count_endpoint(endpoints: dict[str, int], endpoint: str, cap: int) -> dict[str, int]:
    """Increment an endpoint's count, evicting the least-used one once the cap is reached.

    Least-used rather than oldest: an endpoint touched once is the one whose loss costs the
    least, and the field exists to answer "is this endpoint novel for this account".
    """
    counted = dict(endpoints)
    counted[endpoint] = counted.get(endpoint, 0) + 1
    while len(counted) > cap > 0:
        # Never the endpoint just counted: on a full baseline it is the least-used by
        # definition, so evicting it would mean a novel endpoint is never learned at all.
        candidates = [name for name in counted if name != endpoint]
        if not candidates:
            break
        del counted[min(candidates, key=lambda name: (counted[name], name))]
    return counted


def _lower(current: int | None, value: int | None) -> int | None:
    if value is None:
        return current
    return value if current is None else min(current, value)


def _upper(current: int | None, value: int | None) -> int | None:
    if value is None:
        return current
    return value if current is None else max(current, value)
