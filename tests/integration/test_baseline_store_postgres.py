"""The baseline store against a real PostgreSQL server -- including the race it exists to stop.

Skipped unless ``TALOS_TEST_DB_DSN`` names a database the suite may write to. See
``test_verdict_log_postgres.py`` for the setup, and why it is a separate variable from
``TALOS_DB_DSN``.

**The concurrency test here is the P6 storage gate.** Every object access is a read-modify-write
of one account's baseline. Without a per-account lock, two simultaneous accesses both read the
old value and the second write silently discards the first observation -- which does not raise,
does not fail a unit test, and quietly stops the baseline from ever maturing under load. This is
the behaviour SQLite could not provide, and the reason the engine changed.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from talos.core.settings import DatabaseSettings
from talos.detection.baseline.access_baseline import new_baseline, observe
from talos.storage.baseline_store import BaselineStore
from talos.storage.postgres_connection_pool import PostgresConnectionPool

DSN_ENV = "TALOS_TEST_DB_DSN"
DSN = os.environ.get(DSN_ENV, "").strip()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason=f"{DSN_ENV} is not set; see this module's docstring"),
]

#: Accounts this module writes carry the run id, so cleanup never touches anyone else's rows.
RUN_ID = uuid.uuid4().hex[:8]

AT = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
BOUNDS = {"max_object_ids": 100, "max_endpoints": 10}


def _account(name: str) -> str:
    return f"it-{RUN_ID}-{name}"


@pytest.fixture
def store() -> Iterator[BaselineStore]:
    """A store on the live server, with this run's rows removed afterwards."""
    pool = PostgresConnectionPool(DSN, DatabaseSettings(pool_max_size=10))
    try:
        yield BaselineStore(pool)
    finally:

        async def cleanup() -> None:
            async with pool.acquire() as connection:
                await connection.execute(
                    "DELETE FROM access_baseline WHERE account LIKE $1", f"it-{RUN_ID}-%"
                )
            await pool.close()

        asyncio.run(cleanup())


def test_an_unseen_account_reads_as_none(store: BaselineStore) -> None:
    assert asyncio.run(store.get(_account("never-seen"))) is None


def test_a_baseline_round_trips_through_postgres(store: BaselineStore) -> None:
    account = _account("round-trip")
    baseline = observe(
        new_baseline(account, AT), object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
    )
    asyncio.run(store.put(baseline))

    assert asyncio.run(store.get(account)) == baseline


def test_record_access_accumulates_across_calls(store: BaselineStore) -> None:
    account = _account("accumulating")

    async def five_accesses() -> None:
        for index in range(5):
            await store.record_access(
                account, object_id=str(1000 + index), endpoint="/api/orders", at=AT, **BOUNDS
            )

    asyncio.run(five_accesses())

    stored = asyncio.run(store.get(account))
    assert stored is not None
    assert stored.observations == 5
    assert stored.seen_object_ids == ["1000", "1001", "1002", "1003", "1004"]
    assert (stored.numeric_min, stored.numeric_max) == (1000, 1004)


def test_concurrent_accesses_to_one_account_lose_nothing(store: BaselineStore) -> None:
    """**The gate.** Twenty simultaneous accesses, twenty observations -- no lost update.

    Without the per-account advisory lock this returns some number below twenty, and nothing
    raises. Run it against a store with the lock removed to see it fail.
    """
    account = _account("contended")
    ids = [str(2000 + index) for index in range(20)]

    async def all_at_once() -> None:
        await asyncio.gather(
            *(
                store.record_access(
                    account, object_id=object_id, endpoint="/api/orders", at=AT, **BOUNDS
                )
                for object_id in ids
            )
        )

    asyncio.run(all_at_once())

    stored = asyncio.run(store.get(account))
    assert stored is not None
    assert stored.observations == 20, "a lost update; the per-account lock is not holding"
    assert sorted(stored.seen_object_ids) == sorted(ids)
    assert stored.endpoints == {"/api/orders": 20}


def test_different_accounts_do_not_serialise_on_one_lock(store: BaselineStore) -> None:
    """Per-account, not global: ten accounts updating at once each end with their own count.

    A database-wide write lock -- SQLite's behaviour -- still produces the right numbers here.
    What this pins is that the lock key is the account, so a correct global lock cannot be
    mistaken for a correct per-account one: the previous test would pass either way.
    """
    accounts = [_account(f"parallel-{index}") for index in range(10)]

    async def all_at_once() -> None:
        await asyncio.gather(
            *(
                store.record_access(
                    account, object_id="3001", endpoint="/api/invoices", at=AT, **BOUNDS
                )
                for account in accounts
            )
        )

    asyncio.run(all_at_once())

    for account in accounts:
        stored = asyncio.run(store.get(account))
        assert stored is not None and stored.observations == 1


def test_the_bounds_hold_in_the_stored_row(store: BaselineStore) -> None:
    """The cap exists so the hot path never reads a row that grows forever."""
    account = _account("bounded")

    async def many_accesses() -> None:
        for index in range(12):
            await store.record_access(
                account,
                object_id=str(4000 + index),
                endpoint=f"/api/thing-{index}",
                at=AT,
                max_object_ids=5,
                max_endpoints=3,
            )

    asyncio.run(many_accesses())

    stored = asyncio.run(store.get(account))
    assert stored is not None
    assert len(stored.seen_object_ids) == 5
    assert len(stored.endpoints) == 3
    assert stored.observations == 12
    # Eviction must not narrow the range, or an old id becomes an outlier.
    assert (stored.numeric_min, stored.numeric_max) == (4000, 4011)
