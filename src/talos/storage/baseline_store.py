"""``BaselineStore`` -- per-account access baselines, persisted and safely updated (LLD 7.4).

**This store is why the engine is PostgreSQL** (HLD §7.1, LLD §16.5). Every object access does a
read-modify-write of one account's baseline, on the per-event hot path. Two concurrent accesses
for the same account must not both read the old value and write back a copy that loses the
other's observation. That needs a lock scoped to the account -- and SQLite's write lock is
database-wide, so on SQLite the "per-account" lock would serialise the whole pipeline and every
verdict append along with it.

:meth:`BaselineStore.record_access` is the operation that matters: lock the account, read, fold
in one access, write, all in one transaction. ``get``/``put`` exist because the
:class:`~talos.core.agent_contracts.BaselineReader` Protocol names them and the scorer only ever
reads -- but a detector that calls ``get`` and then ``put`` has re-created the race this store
exists to prevent, so the baseliner calls ``record_access`` instead.

**This store never creates its schema** (standards §4.4 rule 5). A missing table means migrations
were not applied.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable
from typing import Any

import asyncpg

from talos.core.error_types import StorageError
from talos.detection.baseline.access_baseline import AccessBaseline, new_baseline, observe
from talos.schemas.event_schema import UtcDatetime
from talos.storage.postgres_connection_pool import PostgresConnectionPool

TABLE_NAME = "access_baseline"

_MIGRATION_HINT = (
    f"table '{TABLE_NAME}' does not exist -- apply migrations first: "
    f"python scripts/apply_migrations.py --engine postgres"
)

_SELECT_SQL = f"""
SELECT account, numeric_min, numeric_max, observations, seen_object_ids, endpoints, updated_at
FROM {TABLE_NAME}
WHERE account = $1
"""

_UPSERT_SQL = f"""
INSERT INTO {TABLE_NAME}
    (account, numeric_min, numeric_max, observations, seen_object_ids, endpoints, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)
ON CONFLICT (account) DO UPDATE SET
    numeric_min     = EXCLUDED.numeric_min,
    numeric_max     = EXCLUDED.numeric_max,
    observations    = EXCLUDED.observations,
    seen_object_ids = EXCLUDED.seen_object_ids,
    endpoints       = EXCLUDED.endpoints,
    updated_at      = EXCLUDED.updated_at
"""

# hashtext() maps the account to the int the advisory-lock API takes. Two accounts can collide
# on one lock, which costs a little contention and never costs correctness -- a collision means
# two accounts serialise against each other, not that either update is lost.
_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext($1))"


async def _guarded(statement: Awaitable[Any]) -> Any:
    """Await one driver call, translating a missing schema into an actionable error."""
    try:
        return await statement
    except asyncpg.UndefinedTableError as exc:
        raise StorageError(_MIGRATION_HINT) from exc


def _to_baseline(row: Any) -> AccessBaseline:
    """One row back into the model. ``jsonb`` arrives as text from asyncpg by default."""
    return AccessBaseline(
        account=row["account"],
        numeric_min=row["numeric_min"],
        numeric_max=row["numeric_max"],
        observations=row["observations"],
        seen_object_ids=json.loads(row["seen_object_ids"]),
        endpoints=json.loads(row["endpoints"]),
        updated_at=row["updated_at"],
    )


def _upsert_parameters(baseline: AccessBaseline) -> tuple[Any, ...]:
    return (
        baseline.account,
        baseline.numeric_min,
        baseline.numeric_max,
        baseline.observations,
        json.dumps(baseline.seen_object_ids),
        json.dumps(baseline.endpoints),
        baseline.updated_at,
    )


class BaselineStore:
    """Per-account access baselines over ``asyncpg``, with per-account advisory locking.

    The pool is borrowed, not owned: one pool serves every store in the process.
    """

    def __init__(self, pool: PostgresConnectionPool) -> None:
        self._pool = pool

    async def get(self, account: str) -> AccessBaseline | None:
        """The stored baseline, or ``None`` for an account never seen.

        Unlocked on purpose. A scorer reading a baseline one observation out of date reaches the
        same verdict; taking the account's lock on every read would serialise scoring behind
        learning for no gain.
        """
        async with self._pool.acquire() as connection:
            row = await _guarded(connection.fetchrow(_SELECT_SQL, account))
        return None if row is None else _to_baseline(row)

    async def put(self, baseline: AccessBaseline) -> None:
        """Write a baseline whole, replacing any stored version.

        Part of the ``BaselineReader`` Protocol, and a last-writer-wins overwrite: it cannot see
        a concurrent update, so it is for restoring or seeding a baseline, not for learning.
        Learning goes through :meth:`record_access`.
        """
        async with self._pool.acquire() as connection:
            await _guarded(connection.execute(_UPSERT_SQL, *_upsert_parameters(baseline)))

    async def record_access(
        self,
        account: str,
        *,
        object_id: str,
        endpoint: str | None,
        at: UtcDatetime,
        max_object_ids: int,
        max_endpoints: int,
    ) -> AccessBaseline:
        """Fold one object access into the account's baseline and return the new value.

        Lock, read, fold, write -- one transaction, so two accesses for the same account cannot
        both read the old baseline and write back a copy missing the other's observation. The
        lock is released by the transaction ending, including when it ends by rolling back.
        """
        async with self._pool.acquire() as connection, connection.transaction():
            await _guarded(connection.execute(_LOCK_SQL, account))
            row = await _guarded(connection.fetchrow(_SELECT_SQL, account))
            current = new_baseline(account, at) if row is None else _to_baseline(row)
            updated = observe(
                current,
                object_id=object_id,
                endpoint=endpoint,
                at=at,
                max_object_ids=max_object_ids,
                max_endpoints=max_endpoints,
            )
            await _guarded(connection.execute(_UPSERT_SQL, *_upsert_parameters(updated)))
        return updated
