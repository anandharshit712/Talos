"""``VerdictLogStore`` -- the SQLite audit trail of everything the pipeline concluded (LLD 4.2).

The full report is stored verbatim as JSON alongside the few columns worth querying on. The
report is the record; the columns exist so "what did we conclude about this host last week"
does not require reading every row.

**This store never creates its schema.** `src/` issues no DDL at all (standards 4.4 rule 5), so
a missing table means migrations were not applied, and saying that plainly beats silently
creating a table that then drifts from `db/migrations/`.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from talos.core.error_types import StorageError
from talos.schemas.report_schema import IncidentReport

TABLE_NAME = "verdict_log"

_MIGRATION_HINT = (
    f"table '{TABLE_NAME}' does not exist -- apply migrations first: "
    f"python scripts/apply_migrations.py --db <path>"
)


class VerdictLogStore:
    """Append-only incident history, backed by SQLite."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._connection = sqlite3.connect(self.db_path)
        self._connection.row_factory = sqlite3.Row

    def append(self, report: IncidentReport) -> None:
        """Record one incident. Re-recording the same ``incident_id`` replaces it."""
        self._execute(
            f"INSERT OR REPLACE INTO {TABLE_NAME} "
            "(incident_id, created_at, domain, category, severity, confidence, summary, "
            " verdict_count, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report.incident_id,
                report.created_at.isoformat(),
                report.domain,
                report.category,
                report.severity,
                report.confidence,
                report.summary,
                len(report.verdicts),
                report.model_dump_json(),
            ),
        )
        self._connection.commit()

    def get(self, incident_id: str) -> IncidentReport | None:
        """Return one recorded incident, or ``None`` if it was never written."""
        cursor = self._execute(
            f"SELECT report_json FROM {TABLE_NAME} WHERE incident_id = ?", (incident_id,)
        )
        row = cursor.fetchone()
        return None if row is None else IncidentReport.model_validate_json(row["report_json"])

    def recent(self, limit: int = 50) -> list[IncidentReport]:
        """The newest incidents first. Backs the report listing endpoint (P7)."""
        cursor = self._execute(
            f"SELECT report_json FROM {TABLE_NAME} ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [IncidentReport.model_validate_json(row["report_json"]) for row in cursor.fetchall()]

    def close(self) -> None:
        self._connection.close()

    def _execute(self, sql: str, parameters: tuple[object, ...]) -> sqlite3.Cursor:
        """Run one statement, translating a missing schema into an actionable error."""
        try:
            return self._connection.execute(sql, parameters)
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                raise StorageError(_MIGRATION_HINT) from exc
            raise StorageError(f"{self.db_path}: {exc}") from exc

    def __enter__(self) -> VerdictLogStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
