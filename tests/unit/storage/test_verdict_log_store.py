"""The audit trail round-trips reports, and says so plainly when the schema is missing."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest
from apply_migrations import apply_pending

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


@pytest.fixture
def migrated_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "talos.db"
    apply_pending(db_path)
    return db_path


def test_report_round_trips_through_sqlite(migrated_db: Path, sample_verdict: Verdict) -> None:
    with VerdictLogStore(migrated_db) as store:
        report = _report(sample_verdict)
        asyncio.run(store.append(report))
        assert asyncio.run(store.get("incident-1")) == report


def test_unknown_incident_is_none(migrated_db: Path) -> None:
    with VerdictLogStore(migrated_db) as store:
        assert asyncio.run(store.get("never-written")) is None


def test_recent_returns_newest_first(migrated_db: Path, sample_verdict: Verdict) -> None:
    with VerdictLogStore(migrated_db) as store:
        older = _report(sample_verdict, "incident-old")
        newer = _report(sample_verdict, "incident-new").model_copy(
            update={"created_at": older.created_at.replace(year=older.created_at.year + 1)}
        )
        asyncio.run(store.append(older))
        asyncio.run(store.append(newer))
        assert [report.incident_id for report in asyncio.run(store.recent())] == [
            "incident-new",
            "incident-old",
        ]


def test_reappending_the_same_incident_replaces_it(
    migrated_db: Path, sample_verdict: Verdict
) -> None:
    with VerdictLogStore(migrated_db) as store:
        asyncio.run(store.append(_report(sample_verdict)))
        asyncio.run(
            store.append(_report(sample_verdict).model_copy(update={"severity": "critical"}))
        )
        assert len(asyncio.run(store.recent())) == 1
        stored = asyncio.run(store.get("incident-1"))
        assert stored is not None and stored.severity == "critical"


def test_missing_schema_names_the_fix(tmp_path: Path, sample_verdict: Verdict) -> None:
    """src/ never issues DDL, so a missing table means migrations were not applied."""
    with VerdictLogStore(tmp_path / "empty.db") as store, pytest.raises(StorageError) as caught:
        asyncio.run(store.append(_report(sample_verdict)))
    assert "apply_migrations" in str(caught.value)


def test_migration_creates_the_expected_table(migrated_db: Path) -> None:
    with sqlite3.connect(migrated_db) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
    assert "verdict_log" in tables
    assert "schema_migrations" in tables
