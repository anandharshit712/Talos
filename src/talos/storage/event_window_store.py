"""``EventWindowStore`` -- the rolling buffer every rate detector reads (LLD 12).

Two decisions worth stating, because both are load-bearing:

**Keys are derived by the store, not passed in.** The orchestrator adds an event without knowing
which detector will want it, so the store indexes each event under every key it can derive --
account, source IP, and host+account. A detector then asks for exactly the slice it reasons
about. Keys are namespaced (``account:root`` vs ``ip:root``) so a username that happens to look
like an address cannot collide with one.

**TTL is measured in event time, not wall-clock time.** Replaying a log from last week must
behave exactly like reading a live stream; a wall-clock TTL would evict every historical event
on arrival and the detector would never see a burst. The reference point is the newest event
held for that key.

Bounded in both directions -- TTL and per-key count -- so a long replay cannot grow without
limit (NFR-7).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from talos.schemas.event_schema import NormalizedEvent


def account_key(event: NormalizedEvent) -> str | None:
    """Everything aimed at one username, wherever it came from."""
    return f"account:{event.actor.account}" if event.actor.account else None


def source_ip_key(event: NormalizedEvent) -> str:
    """Everything from one source address."""
    return f"ip:{event.actor.source_ip}"


def host_account_key(event: NormalizedEvent) -> str | None:
    """One account on one host -- the key SSH and RDP brute force reason about."""
    if not (event.actor.account and event.target.host):
        return None
    return f"host_account:{event.target.host}|{event.actor.account}"


#: Every key an event is indexed under on ``add``.
KEY_BUILDERS = (account_key, source_ip_key, host_account_key)


class EventWindowStore:
    """In-memory, TTL-bounded, per-key event buffer."""

    def __init__(self, ttl_seconds: int = 900, max_events_per_key: int = 2000) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._max_events = max_events_per_key
        self._by_key: dict[str, deque[NormalizedEvent]] = defaultdict(deque)

    def add(self, event: NormalizedEvent) -> None:
        """Index one event under every key derivable from it, then prune those keys."""
        for build_key in KEY_BUILDERS:
            key = build_key(event)
            if key is None:
                continue
            bucket = self._by_key[key]
            bucket.append(event)
            self._prune(bucket)

    def query(self, *, key: str, within: int) -> list[NormalizedEvent]:
        """Events for ``key`` within ``within`` seconds of the newest one, oldest first."""
        bucket = self._by_key.get(key)
        if not bucket:
            return []
        cutoff = bucket[-1].timestamp - timedelta(seconds=within)
        return [event for event in bucket if event.timestamp >= cutoff]

    def keys(self) -> list[str]:
        """Every key currently holding events. Diagnostics only."""
        return [key for key, bucket in self._by_key.items() if bucket]

    def __len__(self) -> int:
        """Total events held across all keys, counting an event once per key it lives under."""
        return sum(len(bucket) for bucket in self._by_key.values())

    def _prune(self, bucket: deque[NormalizedEvent]) -> None:
        """Drop what has aged out of the TTL, then what exceeds the count bound."""
        cutoff = bucket[-1].timestamp - self._ttl
        while bucket and bucket[0].timestamp < cutoff:
            bucket.popleft()
        while len(bucket) > self._max_events:
            bucket.popleft()
