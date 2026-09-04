"""The audit trail against a real PostgreSQL server.

Skipped unless ``TALOS_TEST_DB_DSN`` names a database the suite may write to. A *separate*
variable from ``TALOS_DB_DSN`` on purpose: running the suite must never be able to write test
rows into the database an operator is actually using.

    $env:TALOS_TEST_DB_DSN = "postgresql://talos:...@localhost:5432/talos_test"
    python scripts/apply_migrations.py --dsn $env:TALOS_TEST_DB_DSN
    python -m pytest tests/integration

**One ``asyncio.run`` per test, and the pool lives inside it.** An asyncpg connection belongs to
the event loop that created it, so a pool opened in one ``asyncio.run`` cannot be borrowed from
the next -- the pool says so plainly rather than failing inside the driver.

Testcontainers is not an option here -- it needs Docker, which this cycle excludes (plan scope
note). CI provisions PostgreSQL as a GitHub Actions service instead.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from talos.core.settings import DatabaseSettings
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Scope, Verdict
from talos.storage.postgres_connection_pool import PostgresConnectionPool
from talos.storage.verdict_log_store import VerdictLogStore

DSN_ENV = "TALOS_TEST_DB_DSN"
DSN = os.environ.get(DSN_ENV, "").strip()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason=f"{DSN_ENV} is not set; see this module's docstring"),
]

#: Every row this module writes carries the run id, so cleanup never touches anyone else's data.
RUN_ID = uuid.uuid4().hex[:8]
PREFIX = f"it-{RUN_ID}-"


def _report(verdict: Verdict, suffix: str) -> IncidentReport:
    return IncidentReport(
        incident_id=f"{PREFIX}{suffix}",
        domain=verdict.domain,
        category=verdict.category,
        summary="12 failed ssh logins for root@bastion-01",
        severity="high",
        confidence=verdict.confidence,
        verdicts=[verdict],
        aggregate_scope=verdict.scope or Scope(),
    )


@asynccontextmanager
async def opened_store() -> AsyncIterator[tuple[VerdictLogStore, PostgresConnectionPool]]:
    """A store on the live server for the life of one event loop, its rows removed after."""
    pool = PostgresConnectionPool(DSN, DatabaseSettings())
    try:
        yield VerdictLogStore(pool), pool
    finally:
        async with pool.acquire() as connection:
            await connection.execute(
                "DELETE FROM verdict_log WHERE incident_id LIKE $1", f"{PREFIX}%"
            )
        await pool.close()


def test_report_round_trips_through_postgres(sample_verdict: Verdict) -> None:
    async def body() -> None:
        async with opened_store() as (store, _):
            report = _report(sample_verdict, "round-trip")
            await store.append(report)
            assert await store.get(report.incident_id) == report

    asyncio.run(body())


def test_unknown_incident_is_none() -> None:
    async def body() -> None:
        async with opened_store() as (store, _):
            assert await store.get(f"{PREFIX}never-written") is None

    asyncio.run(body())


def test_reappending_the_same_incident_replaces_it(sample_verdict: Verdict) -> None:
    """ON CONFLICT DO UPDATE: an escalated re-report overwrites, it does not duplicate or raise."""

    async def body() -> None:
        async with opened_store() as (store, _):
            report = _report(sample_verdict, "escalating")
            await store.append(report)
            await store.append(report.model_copy(update={"severity": "critical"}))

            stored = await store.get(report.incident_id)
            assert stored is not None
            assert stored.severity == "critical"

            ours = [r for r in await store.recent(limit=200) if r.incident_id == report.incident_id]
            assert len(ours) == 1

    asyncio.run(body())


def test_recent_returns_newest_first(sample_verdict: Verdict) -> None:
    async def body() -> None:
        async with opened_store() as (store, _):
            older = _report(sample_verdict, "older")
            newer = _report(sample_verdict, "newer").model_copy(
                update={"created_at": older.created_at.replace(year=older.created_at.year + 1)}
            )
            await store.append(older)
            await store.append(newer)

            ours = [
                report.incident_id
                for report in await store.recent(limit=200)
                if report.incident_id.startswith(PREFIX)
            ]
            assert ours.index(newer.incident_id) < ours.index(older.incident_id)

    asyncio.run(body())


def test_concurrent_writers_do_not_block_each_other(sample_verdict: Verdict) -> None:
    """The reason the engine changed: SQLite's write lock is database-wide, PostgreSQL's is not.

    Twenty simultaneous appends over a pool is the shape ``BaselineStore``'s per-account
    read-modify-write needs, and the shape SQLite could not serve.
    """

    async def body() -> None:
        async with opened_store() as (store, _):
            reports = [_report(sample_verdict, f"concurrent-{index}") for index in range(20)]
            await asyncio.gather(*(store.append(report) for report in reports))

            written = {report.incident_id for report in await store.recent(limit=200)}
            assert {report.incident_id for report in reports} <= written

    asyncio.run(body())


def test_jsonb_column_is_queryable_not_just_stored(sample_verdict: Verdict) -> None:
    """jsonb rather than text: the GIN index only pays off if containment actually matches."""

    async def body() -> None:
        async with opened_store() as (store, pool):
            report = _report(sample_verdict, "queryable")
            await store.append(report)

            async with pool.acquire() as connection:
                matched = await connection.fetchval(
                    "SELECT count(*) FROM verdict_log "
                    "WHERE incident_id = $1 AND report_json @> $2::jsonb",
                    report.incident_id,
                    f'{{"category": "{report.category}"}}',
                )
            assert matched == 1

    asyncio.run(body())
