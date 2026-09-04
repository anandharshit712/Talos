"""The baseline store against a real PostgreSQL server -- including the race it exists to stop.

Skipped unless ``TALOS_TEST_DB_DSN`` names a database the suite may write to. See
``test_verdict_log_postgres.py`` for the setup, why it is a separate variable from
``TALOS_DB_DSN``, and why each test owns its event loop.

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
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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
PREFIX = f"it-{RUN_ID}-"

AT = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
BOUNDS = {"max_object_ids": 100, "max_endpoints": 10}


def _account(name: str) -> str:
    return f"{PREFIX}{name}"


@asynccontextmanager
async def opened_store(pool_max_size: int = 10) -> AsyncIterator[BaselineStore]:
    """A store on the live server for the life of one event loop, its rows removed after."""
    pool = PostgresConnectionPool(DSN, DatabaseSettings(pool_max_size=pool_max_size))
    try:
        yield BaselineStore(pool)
    finally:
        async with pool.acquire() as connection:
            await connection.execute(
                "DELETE FROM access_baseline WHERE account LIKE $1", f"{PREFIX}%"
            )
        await pool.close()


def test_an_unseen_account_reads_as_none() -> None:
    async def body() -> None:
        async with opened_store() as store:
            assert await store.get(_account("never-seen")) is None

    asyncio.run(body())


def test_a_baseline_round_trips_through_postgres() -> None:
    async def body() -> None:
        async with opened_store() as store:
            account = _account("round-trip")
            baseline = observe(
                new_baseline(account, AT),
                object_id="1001",
                endpoint="/api/orders",
                at=AT,
                **BOUNDS,
            )
            await store.put(baseline)

            assert await store.get(account) == baseline

    asyncio.run(body())


def test_record_access_accumulates_across_calls() -> None:
    async def body() -> None:
        async with opened_store() as store:
            account = _account("accumulating")
            for index in range(5):
                await store.record_access(
                    account,
                    object_id=str(1000 + index),
                    endpoint="/api/orders",
                    at=AT,
                    **BOUNDS,
                )

            stored = await store.get(account)
            assert stored is not None
            assert stored.observations == 5
            assert stored.seen_object_ids == ["1000", "1001", "1002", "1003", "1004"]
            assert (stored.numeric_min, stored.numeric_max) == (1000, 1004)

    asyncio.run(body())


def test_concurrent_accesses_to_one_account_lose_nothing() -> None:
    """**The gate.** Twenty simultaneous accesses, twenty observations -- no lost update.

    Without the per-account advisory lock this returns some number below twenty, and nothing
    raises. Remove the lock from ``record_access`` to watch it fail.
    """

    async def body() -> None:
        async with opened_store() as store:
            account = _account("contended")
            ids = [str(2000 + index) for index in range(20)]

            await asyncio.gather(
                *(
                    store.record_access(
                        account, object_id=object_id, endpoint="/api/orders", at=AT, **BOUNDS
                    )
                    for object_id in ids
                )
            )

            stored = await store.get(account)
            assert stored is not None
            assert stored.observations == 20, "a lost update; the per-account lock is not holding"
            assert sorted(stored.seen_object_ids) == sorted(ids)
            assert stored.endpoints == {"/api/orders": 20}

    asyncio.run(body())


def test_different_accounts_each_keep_their_own_count() -> None:
    """Per-account, not global: ten accounts updating at once each end with their own count.

    A database-wide lock -- SQLite's behaviour -- would also produce the right numbers here, so
    this is not a proof of parallelism. What it pins is that the lock key is the account, so a
    baseline update for one account cannot land on another's row.
    """

    async def body() -> None:
        async with opened_store() as store:
            accounts = [_account(f"parallel-{index}") for index in range(10)]

            await asyncio.gather(
                *(
                    store.record_access(
                        account, object_id="3001", endpoint="/api/invoices", at=AT, **BOUNDS
                    )
                    for account in accounts
                )
            )

            for account in accounts:
                stored = await store.get(account)
                assert stored is not None and stored.observations == 1

    asyncio.run(body())


def test_the_bounds_hold_in_the_stored_row() -> None:
    """The cap exists so the hot path never reads a row that grows forever."""

    async def body() -> None:
        async with opened_store() as store:
            account = _account("bounded")
            for index in range(12):
                await store.record_access(
                    account,
                    object_id=str(4000 + index),
                    endpoint=f"/api/thing-{index}",
                    at=AT,
                    max_object_ids=5,
                    max_endpoints=3,
                )

            stored = await store.get(account)
            assert stored is not None
            assert len(stored.seen_object_ids) == 5
            assert len(stored.endpoints) == 3
            assert stored.observations == 12
            # Eviction must not narrow the range, or an old id becomes an outlier.
            assert (stored.numeric_min, stored.numeric_max) == (4000, 4011)

    asyncio.run(body())
