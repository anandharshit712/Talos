"""The pool opens late, opens once, and turns driver failures into Talos errors.

No live server here: ``asyncpg.create_pool`` is replaced, because what these tests pin is the
lifecycle -- when the socket is opened and who closes it -- not PostgreSQL's behaviour.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

import asyncpg
import pytest

from talos.core.error_types import ConfigError, StorageError
from talos.core.settings import DatabaseSettings
from talos.storage import postgres_connection_pool as pool_module
from talos.storage.postgres_connection_pool import PostgresConnectionPool

DSN = "postgresql://talos@localhost:5432/talos"


class FakeAsyncpgPool:
    def __init__(self) -> None:
        self.closed = False
        self.acquired = 0

    @asynccontextmanager
    async def acquire(self) -> Any:
        self.acquired += 1
        yield object()

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def created(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture every ``create_pool`` call instead of opening a socket."""
    calls: list[dict[str, Any]] = []

    async def fake_create_pool(dsn: str, **kwargs: Any) -> FakeAsyncpgPool:
        calls.append({"dsn": dsn, **kwargs})
        return FakeAsyncpgPool()

    monkeypatch.setattr(pool_module.asyncpg, "create_pool", fake_create_pool)
    return calls


def test_construction_opens_nothing(created: list[dict[str, Any]]) -> None:
    """Building settings must not touch the network -- and a pool needs a running loop."""
    PostgresConnectionPool(DSN, DatabaseSettings())
    assert created == []


def test_start_is_idempotent(created: list[dict[str, Any]]) -> None:
    pool = PostgresConnectionPool(DSN, DatabaseSettings())

    async def start_twice() -> None:
        await pool.start()
        await pool.start()

    asyncio.run(start_twice())
    assert len(created) == 1


def test_configured_bounds_reach_the_driver(created: list[dict[str, Any]]) -> None:
    config = DatabaseSettings(pool_min_size=2, pool_max_size=7, connect_timeout_seconds=3.0)
    asyncio.run(PostgresConnectionPool(DSN, config).start())

    assert created[0]["min_size"] == 2
    assert created[0]["max_size"] == 7
    assert created[0]["timeout"] == 3.0


def test_acquire_opens_the_pool_on_first_use(created: list[dict[str, Any]]) -> None:
    pool = PostgresConnectionPool(DSN, DatabaseSettings())

    async def borrow() -> None:
        async with pool.acquire():
            pass

    asyncio.run(borrow())
    assert len(created) == 1


def test_unreachable_server_is_a_storage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refused connection is actionable operator news, not a driver traceback."""

    async def refuse(dsn: str, **kwargs: Any) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(pool_module.asyncpg, "create_pool", refuse)
    pool = PostgresConnectionPool(DSN, DatabaseSettings())

    with pytest.raises(StorageError) as caught:
        asyncio.run(pool.start())
    assert "cannot connect" in str(caught.value)


def test_a_driver_failure_mid_statement_is_a_storage_error(created: list[dict[str, Any]]) -> None:
    pool = PostgresConnectionPool(DSN, DatabaseSettings())

    async def borrow_and_fail() -> None:
        async with pool.acquire():
            raise asyncpg.PostgresConnectionError("server closed the connection")

    with pytest.raises(StorageError):
        asyncio.run(borrow_and_fail())


def test_close_without_start_is_harmless(created: list[dict[str, Any]]) -> None:
    asyncio.run(PostgresConnectionPool(DSN, DatabaseSettings()).close())
    assert created == []


def test_close_releases_the_driver_pool(created: list[dict[str, Any]]) -> None:
    pool = PostgresConnectionPool(DSN, DatabaseSettings())

    async def open_then_close() -> Any:
        await pool.start()
        opened = pool._pool
        await pool.close()
        return opened

    assert asyncio.run(open_then_close()).closed


def test_reopening_after_close_creates_a_fresh_pool(created: list[dict[str, Any]]) -> None:
    pool = PostgresConnectionPool(DSN, DatabaseSettings())

    async def cycle() -> None:
        await pool.start()
        await pool.close()
        await pool.start()

    asyncio.run(cycle())
    assert len(created) == 2


def test_from_settings_reads_the_named_variable(
    created: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TALOS_TEST_DSN", DSN)
    pool = PostgresConnectionPool.from_settings(DatabaseSettings(dsn_env="TALOS_TEST_DSN"))
    asyncio.run(pool.start())
    assert created[0]["dsn"] == DSN


def test_a_missing_dsn_names_the_variable_and_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Failing at startup beats detecting into a database that was never reachable."""
    monkeypatch.delenv("TALOS_TEST_DSN", raising=False)

    with pytest.raises(ConfigError) as caught:
        PostgresConnectionPool.from_settings(DatabaseSettings(dsn_env="TALOS_TEST_DSN"))

    assert "TALOS_TEST_DSN" in str(caught.value)
    assert ".env" in str(caught.value)
