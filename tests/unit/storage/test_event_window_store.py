"""Window bounds and key derivation -- the store every rate detector reads (LLD 12)."""

from __future__ import annotations

from collections.abc import Callable

from talos.schemas.event_schema import NormalizedEvent
from talos.storage.event_window_store import (
    EventWindowStore,
    account_key,
    host_account_key,
    source_ip_key,
)

EventFactory = Callable[..., NormalizedEvent]


def test_event_is_indexed_under_every_derivable_key(make_ssh_event: EventFactory) -> None:
    store = EventWindowStore()
    event = make_ssh_event()
    store.add(event)
    for key in (account_key(event), source_ip_key(event), host_account_key(event)):
        assert key is not None
        assert store.query(key=key, within=60) == [event]


def test_keys_are_namespaced_so_a_username_cannot_look_like_an_address(
    make_ssh_event: EventFactory,
) -> None:
    store = EventWindowStore()
    store.add(make_ssh_event(account="203.0.113.7", source_ip="10.0.0.1"))
    assert store.query(key="account:203.0.113.7", within=60) != []
    assert store.query(key="ip:203.0.113.7", within=60) == []


def test_missing_account_yields_no_account_key(make_ssh_event: EventFactory) -> None:
    event = make_ssh_event()
    stripped = event.model_copy(update={"actor": event.actor.model_copy(update={"account": None})})
    assert account_key(stripped) is None
    assert host_account_key(stripped) is None


def test_query_window_is_relative_to_the_newest_event(make_ssh_event: EventFactory) -> None:
    """Replaying last week's log must behave like a live stream, so TTL is in event time."""
    store = EventWindowStore()
    for offset in (0, 30, 200):
        store.add(make_ssh_event(offset_seconds=offset))
    recent = store.query(key="account:root", within=60)
    assert len(recent) == 1  # only the newest, the others are 170s+ behind it


def test_ttl_evicts_what_aged_out(make_ssh_event: EventFactory) -> None:
    store = EventWindowStore(ttl_seconds=60)
    store.add(make_ssh_event(offset_seconds=0))
    store.add(make_ssh_event(offset_seconds=30))
    assert len(store.query(key="account:root", within=3600)) == 2
    store.add(make_ssh_event(offset_seconds=200))
    assert len(store.query(key="account:root", within=3600)) == 1


def test_per_key_count_bound_holds(make_ssh_event: EventFactory) -> None:
    """One noisy source must not be able to grow the buffer without limit (NFR-7)."""
    store = EventWindowStore(max_events_per_key=5)
    for offset in range(20):
        store.add(make_ssh_event(offset_seconds=offset))
    assert len(store.query(key="account:root", within=3600)) == 5


def test_unknown_key_is_empty_not_an_error(make_ssh_event: EventFactory) -> None:
    assert EventWindowStore().query(key="account:nobody", within=60) == []


def test_keys_and_len_report_what_is_held(make_ssh_event: EventFactory) -> None:
    store = EventWindowStore()
    store.add(make_ssh_event())
    assert sorted(store.keys()) == [
        "account:root",
        "host_account:bastion-01|root",
        "ip:203.0.113.7",
    ]
    assert len(store) == 3  # one event, three indexes
