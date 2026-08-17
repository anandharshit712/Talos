"""Apply the forward migrations in ``db/migrations/`` in timestamp order.

The filename stamp is the ordering key -- there is no separate sequence number, because two
ordering keys can disagree and one cannot (standards 4.3). Applied stamps are recorded in a
``schema_migrations`` table, so re-running is a no-op and a partially migrated database
continues where it stopped.

Usage::

    python scripts/apply_migrations.py --db talos.db
    python scripts/apply_migrations.py --db talos.db --list
    python scripts/apply_migrations.py --db talos.db --rollback <migration-stem>

Rolling back runs the matching file from ``db/migrations/rollback/`` and forgets the stamp. It
is a local-development convenience: applied history is forward-only, so a correction that has
left this machine ships as a new migration, never as an edit to an old one (standards 4.4).
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "db" / "migrations"
ROLLBACK_DIR = MIGRATIONS_DIR / "rollback"

LEDGER_TABLE = "schema_migrations"

# The one piece of DDL outside db/: the ledger that records which files under db/ ran.
_CREATE_LEDGER = f"""
CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
    name       TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""


def migration_files(migrations_dir: Path = MIGRATIONS_DIR) -> list[Path]:
    """Forward migrations, chronologically -- the stamp makes lexical order chronological."""
    return sorted(migrations_dir.glob("*.sql"))


def applied_names(connection: sqlite3.Connection) -> set[str]:
    connection.execute(_CREATE_LEDGER)
    return {row[0] for row in connection.execute(f"SELECT name FROM {LEDGER_TABLE}")}


def apply_pending(db_path: Path, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply every migration not yet recorded. Returns the names applied, in order."""
    applied: list[str] = []
    with sqlite3.connect(db_path) as connection:
        already = applied_names(connection)
        for path in migration_files(migrations_dir):
            if path.stem in already:
                continue
            connection.executescript(path.read_text(encoding="utf-8"))
            connection.execute(f"INSERT INTO {LEDGER_TABLE} (name) VALUES (?)", (path.stem,))
            connection.commit()
            applied.append(path.stem)
    return applied


def roll_back(db_path: Path, name: str, rollback_dir: Path = ROLLBACK_DIR) -> None:
    """Run one rollback file and forget its stamp."""
    path = rollback_dir / f"{name}.sql"
    if not path.is_file():
        raise SystemExit(f"no rollback file at {path}")
    with sqlite3.connect(db_path) as connection:
        applied_names(connection)  # ensure the ledger exists before deleting from it
        connection.executescript(path.read_text(encoding="utf-8"))
        connection.execute(f"DELETE FROM {LEDGER_TABLE} WHERE name = ?", (name,))
        connection.commit()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply Talos database migrations.")
    parser.add_argument("--db", type=Path, default=Path("talos.db"), help="SQLite database path")
    parser.add_argument("--list", action="store_true", help="show applied and pending migrations")
    parser.add_argument("--rollback", metavar="NAME", help="run one rollback file by stem")
    args = parser.parse_args(argv)

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


if __name__ == "__main__":
    sys.exit(main())
