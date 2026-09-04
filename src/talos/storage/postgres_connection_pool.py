"""The PostgreSQL connection pool every store borrows from (LLD 16.5).

One pool per process, shared by ``VerdictLogStore`` and -- from P6.1 -- ``BaselineStore``. Two
independent pools would double the connection count for no gain, and PostgreSQL charges a
backend process per connection.

**Reconnection is asyncpg's job, not ours.** ``asyncpg`` discards a connection that failed and
opens a replacement on the next acquire, which is precisely the behaviour the P2 store lacked
(it held one ``sqlite3`` connection from ``__init__`` and never recovered). Re-implementing that
here would be a second, worse copy.

The pool is created on first use rather than in ``__init__``: constructing settings must not
open a socket, and an ``asyncpg`` pool has to be built inside a running event loop.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncpg

from talos.core.error_types import StorageError
from talos.core.settings import DatabaseSettings


class PostgresConnectionPool:
    """Lazily-opened ``asyncpg`` pool with Talos error semantics."""

    def __init__(self, dsn: str, config: DatabaseSettings) -> None:
        self._dsn = dsn
        self._config = config
        self._pool: Any | None = None

    @classmethod
    def from_settings(cls, config: DatabaseSettings) -> PostgresConnectionPool:
        """Build from configuration, reading the DSN out of the named environment variable."""
        return cls(config.resolve_dsn(), config)

    async def start(self) -> None:
        """Open the pool. Idempotent, so a caller may pre-warm without checking first."""
        if self._pool is not None:
            return
        try:
            self._pool = await asyncpg.create_pool(
                self._dsn,
                min_size=self._config.pool_min_size,
                max_size=self._config.pool_max_size,
                timeout=self._config.connect_timeout_seconds,
                command_timeout=self._config.command_timeout_seconds,
            )
        except (OSError, asyncpg.PostgresError) as exc:
            raise StorageError(f"cannot connect to PostgreSQL: {exc}") from exc

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[Any]:
        """Borrow a connection for the duration of the block.

        A connection that died while idle is replaced transparently; a connection that dies
        mid-statement surfaces as :class:`StorageError`, because the caller's write did not
        happen and pretending otherwise loses an incident.
        """
        await self.start()
        assert self._pool is not None  # start() either sets it or raises
        try:
            async with self._pool.acquire() as connection:
                yield connection
        except (OSError, asyncpg.PostgresError) as exc:
            raise StorageError(f"PostgreSQL request failed: {exc}") from exc

    async def close(self) -> None:
        """Release every connection. Safe to call on a pool that was never opened."""
        if self._pool is None:
            return
        pool, self._pool = self._pool, None
        await pool.close()

    async def __aenter__(self) -> PostgresConnectionPool:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
