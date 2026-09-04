"""The audit trail against a real PostgreSQL server.

Skipped unless ``TALOS_TEST_DB_DSN`` names a database the suite may write to. A *separate*
variable from ``TALOS_DB_DSN`` on purpose: running the suite must never be able to write test
rows into the database an operator is actually using.

    $env:TALOS_TEST_DB_DSN = "postgresql://talos:...@localhost:5432/talos_test"
    python scripts/apply_migrations.py --dsn $env:TALOS_TEST_DB_DSN
    python -m pytest tests/integration -m integration

Testcontainers is not an option here -- it needs Docker, which this cycle excludes (plan scope
note). CI provisions PostgreSQL as a GitHub Actions service instead.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator

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


def _report(verdict: Verdict, suffix: str) -> IncidentReport:
    return IncidentReport(
        incident_id=f"it-{RUN_ID}-{suffix}",
        domain=verdict.domain,
        category=verdict.category,
        summary="12 failed ssh logins for root@bastion-01",
        severity="high",
        confidence=verdict.confidence,
        verdicts=[verdict],
        aggregate_scope=verdict.scope or Scope(),
    )


@pytest.fixture
def store() -> Iterator[VerdictLogStore]:
    """A store on the live server, with this run's rows removed afterwards."""
    pool = PostgresConnectionPool(DSN, DatabaseSettings())
    try:
        yield VerdictLogStore(pool)
    finally:

        async def cleanup() -> None:
            async with pool.acquire() as connection:
                await connection.execute(
                    "DELETE FROM verdict_log WHERE incident_id LIKE $1", f"it-{RUN_ID}-%"
                )
            await pool.close()

        asyncio.run(cleanup())


def test_report_round_trips_through_postgres(
    store: VerdictLogStore, sample_verdict: Verdict
) -> None:
    report = _report(sample_verdict, "round-trip")
    asyncio.run(store.append(report))
    assert asyncio.run(store.get(report.incident_id)) == report


def test_unknown_incident_is_none(store: VerdictLogStore) -> None:
    assert asyncio.run(store.get(f"it-{RUN_ID}-never-written")) is None


def test_reappending_the_same_incident_replaces_it(
    store: VerdictLogStore, sample_verdict: Verdict
) -> None:
    """ON CONFLICT DO UPDATE: an escalated re-report overwrites, it does not duplicate or raise."""
    report = _report(sample_verdict, "escalating")
    asyncio.run(store.append(report))
    asyncio.run(store.append(report.model_copy(update={"severity": "critical"})))

    stored = asyncio.run(store.get(report.incident_id))
    assert stored is not None
    assert stored.severity == "critical"


def test_recent_returns_newest_first(store: VerdictLogStore, sample_verdict: Verdict) -> None:
    older = _report(sample_verdict, "older")
    newer = _report(sample_verdict, "newer").model_copy(
        update={"created_at": older.created_at.replace(year=older.created_at.year + 1)}
    )
    asyncio.run(store.append(older))
    asyncio.run(store.append(newer))

    ours = [
        report.incident_id
        for report in asyncio.run(store.recent(limit=200))
        if report.incident_id.startswith(f"it-{RUN_ID}-")
    ]
    assert ours.index(newer.incident_id) < ours.index(older.incident_id)


def test_concurrent_writers_do_not_block_each_other(
    store: VerdictLogStore, sample_verdict: Verdict
) -> None:
    """The reason the engine changed: SQLite's write lock is database-wide, PostgreSQL's is not.

    Twenty simultaneous appends over a pool is the shape ``BaselineStore``'s per-account
    read-modify-write needs in P6.1, and the shape SQLite could not serve.
    """
    reports = [_report(sample_verdict, f"concurrent-{index}") for index in range(20)]

    async def append_all() -> None:
        await asyncio.gather(*(store.append(report) for report in reports))

    asyncio.run(append_all())

    stored = asyncio.run(store.recent(limit=200))
    written = {report.incident_id for report in stored}
    assert {report.incident_id for report in reports} <= written


def test_jsonb_column_is_queryable_not_just_stored(
    store: VerdictLogStore, sample_verdict: Verdict
) -> None:
    """jsonb rather than text: the GIN index only pays off if containment actually matches."""
    report = _report(sample_verdict, "queryable")
    asyncio.run(store.append(report))

    async def find_by_category() -> int:
        pool = PostgresConnectionPool(DSN, DatabaseSettings())
        try:
            async with pool.acquire() as connection:
                return int(
                    await connection.fetchval(
                        "SELECT count(*) FROM verdict_log "
                        "WHERE incident_id = $1 AND report_json @> $2::jsonb",
                        report.incident_id,
                        f'{{"category": "{report.category}"}}',
                    )
                )
        finally:
            await pool.close()

    assert asyncio.run(find_by_category()) == 1
