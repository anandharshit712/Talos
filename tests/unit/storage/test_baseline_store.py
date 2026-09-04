"""The baseline store's statements: what it locks, in what order, and what it writes.

Driven through a fake connection. What is worth pinning without a server is the sequence --
lock the account *before* reading it, inside a transaction, then write once -- because that
order is the whole reason the store exists. The live behaviour, including two writers racing on
one account, is ``tests/integration/test_baseline_store_postgres.py``.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import asyncpg
import pytest

from talos.core.error_types import StorageError
from talos.detection.baseline.access_baseline import new_baseline, observe
from talos.storage.baseline_store import BaselineStore

AT = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
BOUNDS = {"max_object_ids": 100, "max_endpoints": 10}


class FakeConnection:
    """Records statements in order and returns a staged row."""

    def __init__(self, row: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.row = row
        self.raises: Exception | None = None
        self.transactions = 0

    async def _record(self, sql: str, *parameters: Any) -> None:
        self.calls.append((sql, parameters))
        if self.raises is not None:
            raise self.raises

    async def execute(self, sql: str, *parameters: Any) -> str:
        await self._record(sql, *parameters)
        return "OK"

    async def fetchrow(self, sql: str, *parameters: Any) -> dict[str, Any] | None:
        await self._record(sql, *parameters)
        return self.row

    @asynccontextmanager
    async def transaction(self) -> Any:
        self.transactions += 1
        yield

    @property
    def statements(self) -> list[str]:
        return [sql for sql, _ in self.calls]


class FakePool:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    @asynccontextmanager
    async def acquire(self) -> Any:
        yield self.connection


def _store(connection: FakeConnection) -> BaselineStore:
    return BaselineStore(FakePool(connection))  # type: ignore[arg-type]


def _row(account: str = "alice", **overrides: Any) -> dict[str, Any]:
    baseline = observe(
        new_baseline(account, AT), object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
    )
    row = {
        "account": baseline.account,
        "numeric_min": baseline.numeric_min,
        "numeric_max": baseline.numeric_max,
        "observations": baseline.observations,
        "seen_object_ids": json.dumps(baseline.seen_object_ids),
        "endpoints": json.dumps(baseline.endpoints),
        "updated_at": baseline.updated_at,
    }
    row.update(overrides)
    return row


# --- reading --------------------------------------------------------------------------------


def test_an_unseen_account_reads_as_none() -> None:
    connection = FakeConnection(row=None)
    assert asyncio.run(_store(connection).get("nobody")) is None


def test_a_stored_row_becomes_a_baseline() -> None:
    connection = FakeConnection(row=_row())
    baseline = asyncio.run(_store(connection).get("alice"))

    assert baseline is not None
    assert baseline.account == "alice"
    assert baseline.seen_object_ids == ["1001"]
    assert baseline.endpoints == {"/api/orders": 1}
    assert baseline.observations == 1


def test_reads_are_not_locked() -> None:
    """Scoring must not serialise behind learning: a read one observation stale scores the same."""
    connection = FakeConnection(row=_row())
    asyncio.run(_store(connection).get("alice"))

    assert not any("advisory" in sql for sql in connection.statements)


# --- learning -------------------------------------------------------------------------------


def test_record_access_locks_the_account_before_reading_it() -> None:
    """Reading first would leave a window where another writer's update is read and discarded."""
    connection = FakeConnection(row=None)
    asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )

    def kind(sql: str) -> str:
        if "advisory" in sql:
            return "lock"
        return "read" if sql.lstrip().startswith("SELECT") else "write"

    assert [kind(sql) for sql in connection.statements] == ["lock", "read", "write"]


def test_the_lock_read_and_write_share_one_transaction() -> None:
    """An advisory *xact* lock is released when the transaction ends -- without one, it would be
    held for the life of the connection, which the pool then hands to somebody else."""
    connection = FakeConnection(row=None)
    asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )
    assert connection.transactions == 1


def test_the_lock_is_keyed_on_the_account() -> None:
    connection = FakeConnection(row=None)
    asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )
    lock_sql, lock_parameters = connection.calls[0]
    assert "hashtext" in lock_sql
    assert lock_parameters == ("alice",)


def test_a_first_access_creates_the_baseline() -> None:
    connection = FakeConnection(row=None)
    updated = asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )
    assert updated.observations == 1
    assert updated.seen_object_ids == ["1001"]


def test_a_later_access_folds_into_what_was_stored() -> None:
    connection = FakeConnection(row=_row())
    updated = asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1002", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )
    assert updated.observations == 2
    assert updated.seen_object_ids == ["1001", "1002"]
    assert updated.endpoints == {"/api/orders": 2}


def test_the_write_upserts_rather_than_failing_on_a_known_account() -> None:
    connection = FakeConnection(row=_row())
    asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1002", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )
    assert "ON CONFLICT (account) DO UPDATE" in connection.statements[-1]


def test_the_collections_are_written_as_json_text() -> None:
    """The columns are jsonb and asyncpg has no codec for a dict, so they are serialised here."""
    connection = FakeConnection(row=None)
    asyncio.run(
        _store(connection).record_access(
            "alice", object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
        )
    )
    _, parameters = connection.calls[-1]
    assert json.loads(parameters[4]) == ["1001"]
    assert json.loads(parameters[5]) == {"/api/orders": 1}


def test_put_writes_the_baseline_whole() -> None:
    connection = FakeConnection()
    baseline = observe(
        new_baseline("alice", AT), object_id="1001", endpoint="/api/orders", at=AT, **BOUNDS
    )
    asyncio.run(_store(connection).put(baseline))

    sql, parameters = connection.calls[0]
    assert "ON CONFLICT (account) DO UPDATE" in sql
    assert parameters[0] == "alice"


# --- failure ---------------------------------------------------------------------------------


def test_missing_schema_names_the_fix() -> None:
    """src/ never issues DDL, so a missing table means migrations were not applied."""
    connection = FakeConnection(row=None)
    connection.raises = asyncpg.UndefinedTableError('relation "access_baseline" does not exist')

    with pytest.raises(StorageError) as caught:
        asyncio.run(_store(connection).get("alice"))

    assert "apply_migrations" in str(caught.value)
