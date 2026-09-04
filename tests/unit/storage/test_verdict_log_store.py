"""The audit trail writes what it claims to, and says so plainly when the schema is missing.

These tests drive the store through a fake connection rather than a live database: what is
worth pinning here is the SQL and the parameter order, and those are the same whether or not
PostgreSQL is running. The round-trip against a real server is
``tests/integration/storage/test_verdict_log_store_postgres.py``, which skips without a DSN.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any

import asyncpg
import pytest

from talos.core.error_types import StorageError
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Scope, Verdict
from talos.storage.verdict_log_store import VerdictLogStore


def _report(verdict: Verdict, incident_id: str = "incident-1") -> IncidentReport:
    return IncidentReport(
        incident_id=incident_id,
        domain=verdict.domain,
        category=verdict.category,
        summary="12 failed ssh logins for root@bastion-01",
        severity="high",
        confidence=verdict.confidence,
        verdicts=[verdict],
        aggregate_scope=verdict.scope or Scope(),
    )


class FakeConnection:
    """Records the statements it was handed and returns whatever the test staged."""

    def __init__(self, *, fetchval: Any = None, fetch: list[Any] | None = None) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self._fetchval = fetchval
        self._fetch = fetch or []
        self.raises: Exception | None = None

    async def _record(self, sql: str, *parameters: Any) -> None:
        self.calls.append((sql, parameters))
        if self.raises is not None:
            raise self.raises

    async def execute(self, sql: str, *parameters: Any) -> str:
        await self._record(sql, *parameters)
        return "INSERT 0 1"

    async def fetchval(self, sql: str, *parameters: Any) -> Any:
        await self._record(sql, *parameters)
        return self._fetchval

    async def fetch(self, sql: str, *parameters: Any) -> list[Any]:
        await self._record(sql, *parameters)
        return self._fetch


class FakePool:
    """Hands out one connection. Enough surface for the store, which only ever acquires."""

    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    @asynccontextmanager
    async def acquire(self) -> Any:
        yield self.connection


def _store(connection: FakeConnection) -> VerdictLogStore:
    return VerdictLogStore(FakePool(connection))  # type: ignore[arg-type]


def test_append_upserts_rather_than_failing_on_a_re_report(sample_verdict: Verdict) -> None:
    """An incident is re-recorded when it escalates, so the second write must not raise."""
    connection = FakeConnection()
    asyncio.run(_store(connection).append(_report(sample_verdict)))

    sql, _ = connection.calls[0]
    assert "ON CONFLICT (incident_id) DO UPDATE" in sql


def test_append_sends_the_columns_in_declaration_order(sample_verdict: Verdict) -> None:
    connection = FakeConnection()
    report = _report(sample_verdict)
    asyncio.run(_store(connection).append(report))

    _, parameters = connection.calls[0]
    assert parameters[:5] == (
        report.incident_id,
        report.created_at,
        report.domain,
        report.category,
        report.severity,
    )
    assert parameters[7] == len(report.verdicts)


def test_append_stores_the_report_verbatim(sample_verdict: Verdict) -> None:
    """The columns exist to query on; the JSON is the record, so it must survive intact."""
    connection = FakeConnection()
    report = _report(sample_verdict)
    asyncio.run(_store(connection).append(report))

    _, parameters = connection.calls[0]
    assert json.loads(parameters[8])["incident_id"] == report.incident_id
    assert IncidentReport.model_validate_json(parameters[8]) == report


def test_created_at_is_passed_as_a_datetime_not_a_string(sample_verdict: Verdict) -> None:
    """The column is timestamptz. An ISO string would order lexically and lose the offset."""
    connection = FakeConnection()
    report = _report(sample_verdict)
    asyncio.run(_store(connection).append(report))

    _, parameters = connection.calls[0]
    assert parameters[1] is report.created_at
    assert parameters[1].tzinfo is not None


def test_get_parses_the_stored_report(sample_verdict: Verdict) -> None:
    report = _report(sample_verdict)
    connection = FakeConnection(fetchval=report.model_dump_json())
    assert asyncio.run(_store(connection).get("incident-1")) == report


def test_unknown_incident_is_none() -> None:
    connection = FakeConnection(fetchval=None)
    assert asyncio.run(_store(connection).get("never-written")) is None


def test_recent_asks_for_newest_first_and_honours_the_limit(sample_verdict: Verdict) -> None:
    report = _report(sample_verdict)
    connection = FakeConnection(fetch=[{"report_json": report.model_dump_json()}])

    assert asyncio.run(_store(connection).recent(limit=5)) == [report]
    sql, parameters = connection.calls[0]
    assert "ORDER BY created_at DESC" in sql
    assert parameters == (5,)


def test_missing_schema_names_the_fix(sample_verdict: Verdict) -> None:
    """src/ never issues DDL, so a missing table means migrations were not applied."""
    connection = FakeConnection()
    connection.raises = asyncpg.UndefinedTableError('relation "verdict_log" does not exist')

    with pytest.raises(StorageError) as caught:
        asyncio.run(_store(connection).append(_report(sample_verdict)))

    assert "apply_migrations" in str(caught.value)
    assert "--engine postgres" in str(caught.value)
