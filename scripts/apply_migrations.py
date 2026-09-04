"""Apply the forward migrations for one engine, in timestamp order.

The filename stamp is the ordering key -- there is no separate sequence number, because two
ordering keys can disagree and one cannot (standards 4.3). Applied stamps are recorded in a
``schema_migrations`` table, so re-running is a no-op and a partially migrated database
continues where it stopped.

**One set per engine** (standards 4.3). ``db/migrations/*.sql`` is the SQLite set, frozen as the
applied history of any database built from it; ``db/migrations/postgres/`` is what Talos runs on
from P6. The ledger lives in whichever database the set is applied to, so the two never
interleave -- a stamp applied to SQLite says nothing about PostgreSQL.

Usage::

    python scripts/apply_migrations.py                       # postgres, DSN from TALOS_DB_DSN
    python scripts/apply_migrations.py --dsn postgresql://...
    python scripts/apply_migrations.py --list
    python scripts/apply_migrations.py --rollback <migration-stem>
    python scripts/apply_migrations.py --engine sqlite --db talos.db

Rolling back runs the matching file from the set's ``rollback/`` directory and forgets the stamp.
It is a local-development convenience: applied history is forward-only, so a correction that has
left this machine ships as a new migration, never as an edit to an old one (standards 4.4).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "db" / "migrations"
ROLLBACK_DIR = MIGRATIONS_DIR / "rollback"
POSTGRES_DIR = MIGRATIONS_DIR / "postgres"

DEFAULT_ENGINE = "postgres"
ENGINES = ("postgres", "sqlite")

#: Name of the environment variable holding the PostgreSQL DSN. The default matches
#: ``talos.storage.database.dsn_env`` in config/default.yaml; this script does not read the
#: config tree, because a migration runner must work before the application does.
DSN_ENV = "TALOS_DB_DSN"

LEDGER_TABLE = "schema_migrations"

# The one piece of DDL outside db/: the ledger that records which files under db/ ran.
_CREATE_LEDGER_SQLITE = f"""
CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
    name       TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

_CREATE_LEDGER_POSTGRES = f"""
CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
    name       TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def migration_files(directory: Path | None = None) -> list[Path]:
    """Forward migrations, chronologically -- the stamp makes lexical order chronological."""
    return sorted((directory or MIGRATIONS_DIR).glob("*.sql"))


# ---------------------------------------------------------------------------
# SQLite -- the pre-P6 set, kept applicable because its history is forward-only
# ---------------------------------------------------------------------------


def applied_names(connection: sqlite3.Connection) -> set[str]:
    connection.execute(_CREATE_LEDGER_SQLITE)
    return {row[0] for row in connection.execute(f"SELECT name FROM {LEDGER_TABLE}")}


def apply_pending(db_path: Path, directory: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply every SQLite migration not yet recorded. Returns the names applied, in order."""
    applied: list[str] = []
    with sqlite3.connect(db_path) as connection:
        already = applied_names(connection)
        for path in migration_files(directory):
            if path.stem in already:
                continue
            connection.executescript(path.read_text(encoding="utf-8"))
            connection.execute(f"INSERT INTO {LEDGER_TABLE} (name) VALUES (?)", (path.stem,))
            connection.commit()
            applied.append(path.stem)
    return applied


def roll_back(db_path: Path, name: str, rollback_dir: Path = ROLLBACK_DIR) -> None:
    """Run one SQLite rollback file and forget its stamp."""
    path = rollback_dir / f"{name}.sql"
    if not path.is_file():
        raise SystemExit(f"no rollback file at {path}")
    with sqlite3.connect(db_path) as connection:
        applied_names(connection)  # ensure the ledger exists before deleting from it
        connection.executescript(path.read_text(encoding="utf-8"))
        connection.execute(f"DELETE FROM {LEDGER_TABLE} WHERE name = ?", (name,))
        connection.commit()


# ---------------------------------------------------------------------------
# PostgreSQL -- what Talos runs on from P6
# ---------------------------------------------------------------------------


def resolve_dsn(dsn: str | None = None) -> str:
    """The DSN from the flag or the environment, whichever is set."""
    resolved = (dsn or os.environ.get(DSN_ENV, "")).strip()
    if not resolved:
        raise SystemExit(
            f"no DSN: pass --dsn or set {DSN_ENV} (it lives in .env, which is git-ignored)"
        )
    return resolved


async def _connect(dsn: str) -> Any:
    # Imported here so the SQLite path, and --help, work without the driver installed.
    import asyncpg

    return await asyncpg.connect(dsn)


async def applied_names_postgres(connection: Any) -> set[str]:
    await connection.execute(_CREATE_LEDGER_POSTGRES)
    rows = await connection.fetch(f"SELECT name FROM {LEDGER_TABLE}")
    return {row["name"] for row in rows}


async def apply_pending_postgres(dsn: str, directory: Path = POSTGRES_DIR) -> list[str]:
    """Apply every PostgreSQL migration not yet recorded, each in its own transaction.

    Per-migration transactions rather than one for the batch: a failure then leaves every
    earlier migration applied and recorded, so a rerun continues instead of starting over.
    """
    applied: list[str] = []
    connection = await _connect(dsn)
    try:
        already = await applied_names_postgres(connection)
        for path in migration_files(directory):
            if path.stem in already:
                continue
            async with connection.transaction():
                await connection.execute(path.read_text(encoding="utf-8"))
                await connection.execute(
                    f"INSERT INTO {LEDGER_TABLE} (name) VALUES ($1)", path.stem
                )
            applied.append(path.stem)
    finally:
        await connection.close()
    return applied


async def roll_back_postgres(dsn: str, name: str, rollback_dir: Path | None = None) -> None:
    """Run one PostgreSQL rollback file and forget its stamp."""
    path = (rollback_dir or POSTGRES_DIR / "rollback") / f"{name}.sql"
    if not path.is_file():
        raise SystemExit(f"no rollback file at {path}")
    connection = await _connect(dsn)
    try:
        await applied_names_postgres(connection)  # ensure the ledger exists before deleting
        async with connection.transaction():
            await connection.execute(path.read_text(encoding="utf-8"))
            await connection.execute(f"DELETE FROM {LEDGER_TABLE} WHERE name = $1", name)
    finally:
        await connection.close()


async def list_applied_postgres(dsn: str, directory: Path = POSTGRES_DIR) -> list[tuple[str, str]]:
    """``(state, name)`` for every migration in the set."""
    connection = await _connect(dsn)
    try:
        already = await applied_names_postgres(connection)
    finally:
        await connection.close()
    return [
        ("applied" if path.stem in already else "pending", path.stem)
        for path in migration_files(directory)
    ]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _run_sqlite(args: argparse.Namespace) -> int:
    if args.rollback:
        roll_back(args.db, args.rollback)
        print(f"rolled back {args.rollback}")
        return 0

    if args.list:
        with sqlite3.connect(args.db) as connection:
            already = applied_names(connection)
        for path in migration_files():
            print(f"  {'applied' if path.stem in already else 'pending'}  {path.stem}")
        return 0

    applied = apply_pending(args.db)
    for name in applied:
        print(f"applied {name}")
    print(f"{len(applied)} migration(s) applied to {args.db}")
    return 0


def _run_postgres(args: argparse.Namespace) -> int:
    dsn = resolve_dsn(args.dsn)

    if args.rollback:
        asyncio.run(roll_back_postgres(dsn, args.rollback))
        print(f"rolled back {args.rollback}")
        return 0

    if args.list:
        for state, name in asyncio.run(list_applied_postgres(dsn)):
            print(f"  {state}  {name}")
        return 0

    applied = asyncio.run(apply_pending_postgres(dsn))
    for name in applied:
        print(f"applied {name}")
    # The DSN carries a password, so the database is named from the path, never echoed whole.
    print(f"{len(applied)} migration(s) applied to {dsn.rsplit('/', 1)[-1].split('?')[0]}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply Talos database migrations.")
    parser.add_argument(
        "--engine",
        choices=ENGINES,
        default=DEFAULT_ENGINE,
        help=f"which migration set to apply (default: {DEFAULT_ENGINE})",
    )
    parser.add_argument("--dsn", default=None, help=f"PostgreSQL DSN (default: ${DSN_ENV})")
    parser.add_argument("--db", type=Path, default=Path("talos.db"), help="SQLite database path")
    parser.add_argument("--list", action="store_true", help="show applied and pending migrations")
    parser.add_argument("--rollback", metavar="NAME", help="run one rollback file by stem")
    args = parser.parse_args(argv)

    return _run_sqlite(args) if args.engine == "sqlite" else _run_postgres(args)


if __name__ == "__main__":
    sys.exit(main())
