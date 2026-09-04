"""The migration runner: ordering, the ledger, and rollback.

The SQLite path is exercised here because it needs no server -- and the two engines share the
ordering and discovery code, which is where the interesting mistake lives.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from apply_migrations import (
    applied_names,
    apply_pending,
    migration_files,
    migration_stamp,
    resolve_dsn,
    roll_back,
)

HEADER = "-- Migration: {name}\n-- Created: 2026-09-04 00:00:00 UTC\n"


def _write(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.sql"
    path.write_text(HEADER.format(name=name) + body, encoding="utf-8")
    return path


# --- ordering ---------------------------------------------------------------------------------


def test_the_stamp_is_read_off_the_end_of_the_name() -> None:
    assert migration_stamp(Path("create_access_baseline_table_20260904_105455.sql")) == (
        "20260904_105455"
    )


def test_a_file_with_no_stamp_is_refused_rather_than_guessed() -> None:
    """Silently falling back to filename order is how a migration runs before its dependency."""
    with pytest.raises(SystemExit) as caught:
        migration_stamp(Path("nostamp.sql"))
    assert "R4.1" in str(caught.value)


def test_migrations_are_ordered_by_stamp_not_by_filename(tmp_path: Path) -> None:
    """The real case that exposed this: 'access' sorts before 'verdict', but its stamp is later.

    Sorting by filename would have run the 10:54 migration before the 09:11 one, so a migration
    altering what an earlier one created would go first (standards 4.3).
    """
    _write(tmp_path, "create_access_baseline_table_20260904_105455", "SELECT 1;")
    _write(tmp_path, "create_verdict_log_table_20260904_091113", "SELECT 1;")

    assert [migration_stamp(path) for path in migration_files(tmp_path)] == [
        "20260904_091113",
        "20260904_105455",
    ]


def test_same_day_migrations_order_by_time(tmp_path: Path) -> None:
    _write(tmp_path, "zzz_last_alphabetically_20260904_010000", "SELECT 1;")
    _write(tmp_path, "aaa_first_alphabetically_20260904_020000", "SELECT 1;")

    assert [path.stem.split("_")[0] for path in migration_files(tmp_path)] == ["zzz", "aaa"]


# --- applying ---------------------------------------------------------------------------------


def test_pending_migrations_are_applied_in_order(tmp_path: Path) -> None:
    _write(tmp_path, "create_thing_20260904_010000", "CREATE TABLE thing (id INTEGER);")
    _write(tmp_path, "add_thing_name_20260904_020000", "ALTER TABLE thing ADD COLUMN name TEXT;")
    db = tmp_path / "t.db"

    applied = apply_pending(db, tmp_path)

    assert applied == ["create_thing_20260904_010000", "add_thing_name_20260904_020000"]
    with sqlite3.connect(db) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(thing)")}
    assert columns == {"id", "name"}


def test_rerunning_applies_nothing(tmp_path: Path) -> None:
    """The ledger is what makes a partially migrated database safe to continue."""
    _write(tmp_path, "create_thing_20260904_010000", "CREATE TABLE thing (id INTEGER);")
    db = tmp_path / "t.db"

    assert len(apply_pending(db, tmp_path)) == 1
    assert apply_pending(db, tmp_path) == []


def test_a_new_migration_after_an_applied_one_is_picked_up(tmp_path: Path) -> None:
    _write(tmp_path, "create_thing_20260904_010000", "CREATE TABLE thing (id INTEGER);")
    db = tmp_path / "t.db"
    apply_pending(db, tmp_path)

    _write(tmp_path, "add_thing_name_20260904_020000", "ALTER TABLE thing ADD COLUMN name TEXT;")

    assert apply_pending(db, tmp_path) == ["add_thing_name_20260904_020000"]


def test_the_ledger_records_what_ran(tmp_path: Path) -> None:
    _write(tmp_path, "create_thing_20260904_010000", "CREATE TABLE thing (id INTEGER);")
    db = tmp_path / "t.db"
    apply_pending(db, tmp_path)

    with sqlite3.connect(db) as connection:
        assert applied_names(connection) == {"create_thing_20260904_010000"}


# --- rolling back -----------------------------------------------------------------------------


def test_rollback_runs_the_matching_file_and_forgets_the_stamp(tmp_path: Path) -> None:
    name = "create_thing_20260904_010000"
    _write(tmp_path, name, "CREATE TABLE thing (id INTEGER);")
    _write(tmp_path / "rollback", name, "DROP TABLE thing;")
    db = tmp_path / "t.db"
    apply_pending(db, tmp_path)

    roll_back(db, name, tmp_path / "rollback")

    with sqlite3.connect(db) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        assert "thing" not in tables
        assert applied_names(connection) == set()

    # Forgetting the stamp is what makes the migration pending again.
    assert apply_pending(db, tmp_path) == [name]


def test_a_missing_rollback_file_stops_rather_than_pretending(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as caught:
        roll_back(tmp_path / "t.db", "never_written_20260904_010000", tmp_path / "rollback")
    assert "no rollback file" in str(caught.value)


# --- the DSN ----------------------------------------------------------------------------------


def test_the_flag_beats_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TALOS_DB_DSN", "postgresql://from-env/talos")
    assert resolve_dsn("postgresql://from-flag/talos") == "postgresql://from-flag/talos"


def test_the_environment_supplies_the_dsn_when_the_flag_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TALOS_DB_DSN", "postgresql://from-env/talos")
    assert resolve_dsn(None) == "postgresql://from-env/talos"


def test_no_dsn_anywhere_names_the_variable_and_the_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TALOS_DB_DSN", raising=False)
    with pytest.raises(SystemExit) as caught:
        resolve_dsn(None)
    assert "TALOS_DB_DSN" in str(caught.value)
    assert ".env" in str(caught.value)
