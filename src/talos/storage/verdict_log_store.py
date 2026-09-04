"""``VerdictLogStore`` -- the PostgreSQL audit trail of everything the pipeline concluded (LLD 4.2).

The full report is stored verbatim as ``jsonb`` alongside the few columns worth querying on. The
report is the record; the columns exist so "what did we conclude about this host last week" does
not require reading every row.

**PostgreSQL from P6, SQLite before it** (HLD 7.1, LLD 16.5). The engine moved because
``BaselineStore`` needs per-account locking and SQLite's write lock is database-wide; porting
this store at the same time keeps one engine in the process rather than two. Nothing above this
module changed: ``VerdictRecorder`` was already ``async`` (LLD 16.6), so no agent, detector, or
orchestrator file was touched by the port.

**This store never creates its schema.** ``src/`` issues no DDL at all (standards 4.4 rule 5), so
a missing table means migrations were not applied, and saying that plainly beats silently
creating a table that then drifts from ``db/migrations/``.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import asyncpg

from talos.core.error_types import StorageError
from talos.schemas.report_schema import IncidentReport
from talos.storage.postgres_connection_pool import PostgresConnectionPool

TABLE_NAME = "verdict_log"

_MIGRATION_HINT = (
    f"table '{TABLE_NAME}' does not exist -- apply migrations first: "
    f"python scripts/apply_migrations.py --engine postgres"
)

# ON CONFLICT DO UPDATE, not DO NOTHING: an incident is re-recorded when it escalates, and the
# escalated report is the one worth keeping (the P2 SQLite store said INSERT OR REPLACE).
_APPEND_SQL = f"""
INSERT INTO {TABLE_NAME}
    (incident_id, created_at, domain, category, severity, confidence, summary,
     verdict_count, report_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
ON CONFLICT (incident_id) DO UPDATE SET
    created_at    = EXCLUDED.created_at,
    domain        = EXCLUDED.domain,
    category      = EXCLUDED.category,
    severity      = EXCLUDED.severity,
    confidence    = EXCLUDED.confidence,
    summary       = EXCLUDED.summary,
    verdict_count = EXCLUDED.verdict_count,
    report_json   = EXCLUDED.report_json
"""


async def _guarded(statement: Awaitable[Any]) -> Any:
    """Await one driver call, translating a missing schema into an actionable error.

    Every other driver failure is left to the pool, which owns connection-level errors.
    """
    try:
        return await statement
    except asyncpg.UndefinedTableError as exc:
        raise StorageError(_MIGRATION_HINT) from exc


class VerdictLogStore:
    """Append-only incident history, backed by PostgreSQL.

    The pool is borrowed, not owned: the process opens one pool and every store shares it, so
    closing this object must not close connections another store is using.
    """

    def __init__(self, pool: PostgresConnectionPool) -> None:
        self._pool = pool

    async def append(self, report: IncidentReport) -> None:
        """Record one incident. Re-recording the same ``incident_id`` replaces it."""
        async with self._pool.acquire() as connection:
            await _guarded(
                connection.execute(
                    _APPEND_SQL,
                    report.incident_id,
                    report.created_at,
                    report.domain,
                    report.category,
                    report.severity,
                    report.confidence,
                    report.summary,
                    len(report.verdicts),
                    report.model_dump_json(),
                )
            )

    async def get(self, incident_id: str) -> IncidentReport | None:
        """Return one recorded incident, or ``None`` if it was never written."""
        async with self._pool.acquire() as connection:
            row = await _guarded(
                connection.fetchval(
                    f"SELECT report_json FROM {TABLE_NAME} WHERE incident_id = $1",
                    incident_id,
                )
            )
        return None if row is None else IncidentReport.model_validate_json(row)

    async def prune(self, older_than_days: int) -> int:
        """Delete incidents older than ``older_than_days``; return how many went.

        ``0`` keeps everything, which is the honest reading of "no retention policy" and stays
        available for anyone who needs the full history. Called on server start rather than on a
        timer: a scan should not delete anything, and one dated delete at startup is enough at
        this size. Partitioning is the answer if the table ever outgrows it.
        """
        if older_than_days <= 0:
            return 0
        async with self._pool.acquire() as connection:
            status = await _guarded(
                connection.execute(
                    f"DELETE FROM {TABLE_NAME} "
                    f"WHERE created_at < now() - make_interval(days => $1)",
                    older_than_days,
                )
            )
        # asyncpg returns the command tag, e.g. "DELETE 12".
        return int(str(status).rsplit(" ", 1)[-1] or 0)

    async def recent(self, limit: int = 50) -> list[IncidentReport]:
        """The newest incidents first. Backs the report listing endpoint (P7)."""
        async with self._pool.acquire() as connection:
            rows = await _guarded(
                connection.fetch(
                    f"SELECT report_json FROM {TABLE_NAME} ORDER BY created_at DESC LIMIT $1",
                    limit,
                )
            )
        return [IncidentReport.model_validate_json(row["report_json"]) for row in rows]
