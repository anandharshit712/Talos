"""R4.3/R4.4 hold inside every migration set, not only the top-level one (standards 4.3).

A second engine gets its own baseline set under `db/migrations/<engine>/`, because a DDL dialect
is not portable. Before this, the checker globbed `db/migrations/*.sql` only — so an entire
PostgreSQL set could ship unpaired and unheaded while the gate reported success. A checker that
silently stops covering new files is worse than one that fails loudly.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from check_naming import migration_sets, run

HEADER = (
    "-- Migration: create_probe_table\n"
    "-- Created:   2026-08-18 12:00:00 UTC\n"
    "-- Purpose:   probe\n"
    "-- Reversible: yes\n"
)
STAMPED = "create_probe_table_20260818_120000.sql"


def rules(violations: list) -> set[str]:  # type: ignore[type-arg]
    return {v.rule for v in violations}


def test_unpaired_migration_in_an_engine_set_fails(
    write_file: Callable[..., Path], fake_repo: Path
) -> None:
    write_file(fake_repo / "db" / "migrations" / "postgres" / STAMPED, HEADER)
    violations = run(fake_repo)
    assert rules(violations) == {"R4.3"}
    assert "db/migrations/postgres/rollback/" in violations[0].message


def test_missing_header_in_an_engine_set_fails(
    write_file: Callable[..., Path], fake_repo: Path
) -> None:
    write_file(fake_repo / "db" / "migrations" / "postgres" / STAMPED, "CREATE TABLE p();\n")
    write_file(
        fake_repo / "db" / "migrations" / "postgres" / "rollback" / STAMPED, "DROP TABLE p;\n"
    )
    assert rules(run(fake_repo)) == {"R4.4"}


def test_an_orphan_rollback_in_an_engine_set_fails(
    write_file: Callable[..., Path], fake_repo: Path
) -> None:
    write_file(fake_repo / "db" / "migrations" / "postgres" / "rollback" / STAMPED, HEADER)
    assert rules(run(fake_repo)) == {"R4.3"}


def test_a_complete_engine_set_passes(write_file: Callable[..., Path], fake_repo: Path) -> None:
    write_file(fake_repo / "db" / "migrations" / "postgres" / STAMPED, HEADER)
    write_file(fake_repo / "db" / "migrations" / "postgres" / "rollback" / STAMPED, HEADER)
    assert run(fake_repo) == []


def test_the_rollback_directory_is_not_mistaken_for_an_engine(
    write_file: Callable[..., Path], fake_repo: Path
) -> None:
    """`db/migrations/rollback/` holds the SQLite set's rollbacks, not a set of its own."""
    write_file(fake_repo / "db" / "migrations" / STAMPED, HEADER)
    write_file(fake_repo / "db" / "migrations" / "rollback" / STAMPED, HEADER)
    assert run(fake_repo) == []


def test_sets_are_discovered_not_hardcoded(
    write_file: Callable[..., Path], fake_repo: Path
) -> None:
    """The P6 set must be checked the day it appears, without editing the checker."""
    write_file(fake_repo / "db" / "migrations" / "postgres" / STAMPED, HEADER)
    write_file(fake_repo / "db" / "migrations" / "duckdb" / STAMPED, HEADER)
    discovered = {path.name for path in migration_sets(fake_repo)}
    assert discovered == {"migrations", "postgres", "duckdb"}
