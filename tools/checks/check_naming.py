"""Enforce R3 (files named for the work they do) and R4 (date-time stamped SQL).

R3 checks:

R3.1   every module under ``src/talos/`` ends in a role suffix from the closed vocabulary
R3.1   files under ``scripts/`` and ``tools/`` use the ``<verb>_<object>`` script form
R3.2   no banned filename (utils, base, common, manager, ``*_v2``, ``*_final``, ...)
R3.3   every module basename is unique across the whole repository
R3.5   every ``src/talos/`` module has a mirrored test file  (``--strict`` only)
R3.7   prompt templates are named ``<agent>_<purpose>_v<N>.md``
R3.8   no spaces, uppercase extensions, or shell-hostile characters in any filename

R4 checks:

R4.1   every ``.sql`` filename ends in ``_YYYYMMDD_HHMMSS`` and the stamp is a real UTC time
R4.2   the leading action word comes from the closed vocabulary
R4.3   every forward migration has a same-named file under ``db/migrations/rollback/``
R4.4   every migration carries the required header comment block

The R3.5 mirror check is gated behind ``--strict`` on purpose. It belongs to the phase gate
(``run_all_checks.py --strict``, CI), not to pre-commit: blocking a local commit because a
module's test lands in the next commit would make the gate something to work around rather
than something to satisfy.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from violation_types import Violation, build_parser, find_repo_root, iter_files, rel, report

# ---------------------------------------------------------------------------
# R3 vocabularies
# ---------------------------------------------------------------------------

#: Closed role-suffix vocabulary for modules under src/talos/ (standards 3.1).
ROLE_SUFFIXES = (
    "_parser",
    "_orchestrator",
    "_registry",
    "_domain_agent",
    "_type_classifier",
    "_sub_agent",
    "_detector",
    "_engine",
    "_rules",
    "_baseline",
    "_baseliner",
    "_scorer",
    "_store",
    "_client",
    "_router",
    "_server",
    "_routes",
    "_sink",
    "_schema",
    "_mapping",
    "_contract",
    "_contracts",
    "_setup",
    "_types",
    "_cli",
)

#: Single-word foundation modules where the word is simultaneously subject and role
#: (standards 3.1 foundation-module exemption).
FOUNDATION_MODULE_STEMS = frozenset({"settings", "constants"})

#: Dunder and tooling files that carry no role (standards 3.3 exemptions).
NAME_CHECK_EXEMPT = frozenset({"__init__.py", "__main__.py", "py.typed", "conftest.py"})

#: Verbs permitted to open a script filename (standards 3.8).
SCRIPT_VERBS = (
    "check",
    "run",
    "generate",
    "replay",
    "apply",
    "build",
    "export",
    "import",
    "validate",
    "seed",
    "migrate",
    "sync",
    "fetch",
    "render",
    "convert",
    "clean",
    "setup",
    "measure",
)

#: Names that describe a container rather than a job (standards 3.2). Bare stems only.
BANNED_STEMS = frozenset(
    {
        "utils",
        "util",
        "helpers",
        "helper",
        "common",
        "shared",
        "misc",
        "base",
        "core",
        "app",
        "stuff",
        "temp",
        "tmp",
        "data",
        "handler",
        "manager",
        "processor",
        "service",
    }
)

#: Superseded code is deleted, not renamed with a version suffix (standards 3.2).
BANNED_PATTERNS = (
    re.compile(r"^new_"),
    re.compile(r"^old_"),
    re.compile(r"_v\d+$"),
    re.compile(r"_final$"),
    re.compile(r"_copy$"),
    re.compile(r"_backup$"),
    re.compile(r"_bak$"),
    re.compile(r"_test\d+$"),
)

#: Suffixes subject to the banned-name and character rules. Markdown is excluded because
#: prose filenames legitimately carry version suffixes (prompt templates, dated notes).
CODE_SUFFIXES = frozenset({".py", ".sql", ".ts", ".tsx", ".js", ".ps1", ".sh"})

SNAKE_CASE = re.compile(r"^[a-z][a-z0-9_]*$")
PROMPT_NAME = re.compile(r"^[a-z][a-z0-9_]*_v\d+$")
SHELL_HOSTILE = re.compile(r"[ #%&$!'\"`()\[\]{}*?<>|:;]")

# ---------------------------------------------------------------------------
# R4 vocabularies
# ---------------------------------------------------------------------------

SQL_ACTIONS = (
    "create",
    "alter",
    "drop",
    "add",
    "remove",
    "rename",
    "index",
    "backfill",
    "seed",
    "select",
    "snapshot",
)

SQL_NAME = re.compile(r"^(?P<action>[a-z]+)_(?P<subject>[a-z0-9_]+)_(?P<stamp>\d{8}_\d{6})$")

#: Every migration announces its purpose and its reversibility (standards 4.4 rule 4).
MIGRATION_HEADER_KEYS = ("-- Migration:", "-- Created:", "-- Purpose:", "-- Reversible:")


# ---------------------------------------------------------------------------
# R3
# ---------------------------------------------------------------------------


def check_filename_characters(root: Path) -> list[Violation]:
    """R3.8: filenames stay portable and shell-safe."""
    violations: list[Violation] = []
    for path in iter_files(root):
        if SHELL_HOSTILE.search(path.name):
            violations.append(
                Violation(
                    "R3.8",
                    rel(path, root),
                    "filename contains a space or shell-hostile character; use snake_case or "
                    "kebab-case",
                )
            )
        elif path.suffix != path.suffix.lower():
            violations.append(
                Violation("R3.8", rel(path, root), "file extensions are always lowercase")
            )
    return violations


def check_banned_names(root: Path) -> list[Violation]:
    """R3.2: reject names that describe a container instead of a job."""
    violations: list[Violation] = []
    for path in iter_files(root):
        if path.suffix.lower() not in CODE_SUFFIXES or path.name in NAME_CHECK_EXEMPT:
            continue
        stem = path.stem
        relative_path = rel(path, root)
        if stem in BANNED_STEMS:
            violations.append(
                Violation(
                    "R3.2",
                    relative_path,
                    f"'{stem}' names a container, not a job -- say what it does (standards 3.2)",
                )
            )
            continue
        for pattern in BANNED_PATTERNS:
            if pattern.search(stem):
                violations.append(
                    Violation(
                        "R3.2",
                        relative_path,
                        "version and scratch suffixes are banned; superseded code is deleted, "
                        "and git holds the history",
                    )
                )
                break
    return violations


def check_module_roles(root: Path) -> list[Violation]:
    """R3.1: modules under src/talos/ end in a role suffix from the closed vocabulary."""
    violations: list[Violation] = []
    for path in iter_files(root, "src"):
        if path.suffix != ".py" or path.name in NAME_CHECK_EXEMPT:
            continue
        stem = path.stem
        relative_path = rel(path, root)
        if not SNAKE_CASE.match(stem):
            violations.append(
                Violation("R3.1", relative_path, "module names are snake_case, ASCII only")
            )
            continue
        if stem in FOUNDATION_MODULE_STEMS or stem.endswith(ROLE_SUFFIXES):
            continue
        violations.append(
            Violation(
                "R3.1",
                relative_path,
                f"'{stem}' ends in no role suffix from the closed vocabulary -- rename it "
                f"<subject>_<role>.py, or propose a suffix addition in standards 3.1",
            )
        )
    return violations


def check_script_names(root: Path) -> list[Violation]:
    """R3.8: files under scripts/ and tools/ use the <verb>_<object> form.

    A ``tools/`` file may satisfy either form: shared libraries there (``violation_types.py``)
    legitimately carry a role suffix instead of a verb.
    """
    violations: list[Violation] = []
    for tree in ("scripts", "tools"):
        for path in iter_files(root, tree):
            if path.suffix.lower() not in CODE_SUFFIXES or path.name in NAME_CHECK_EXEMPT:
                continue
            stem = path.stem
            relative_path = rel(path, root)
            if not SNAKE_CASE.match(stem):
                violations.append(
                    Violation("R3.8", relative_path, "script names are snake_case, ASCII only")
                )
                continue
            if stem.startswith(SCRIPT_VERBS) and "_" in stem:
                continue
            if tree == "tools" and stem.endswith(ROLE_SUFFIXES):
                continue
            violations.append(
                Violation(
                    "R3.8",
                    relative_path,
                    f"'{stem}' is not <verb>_<object> -- start it with one of: "
                    f"{', '.join(SCRIPT_VERBS[:6])}, ...",
                )
            )
    return violations


def check_basename_uniqueness(root: Path) -> list[Violation]:
    """R3.3: every module basename is unique repo-wide, so tracebacks stay unambiguous."""
    seen: dict[str, list[str]] = {}
    for path in iter_files(root):
        if path.suffix != ".py" or path.name in NAME_CHECK_EXEMPT:
            continue
        seen.setdefault(path.name, []).append(rel(path, root))
    violations: list[Violation] = []
    for name, paths in sorted(seen.items()):
        if len(paths) < 2:
            continue
        others = ", ".join(paths[1:])
        violations.append(
            Violation(
                "R3.3",
                paths[0],
                f"module basename '{name}' also exists at {others} -- qualify each with its "
                f"domain or component so imports and tracebacks are unambiguous",
            )
        )
    return violations


def check_prompt_names(root: Path) -> list[Violation]:
    """R3.7: prompts are versioned artifacts, named <agent>_<purpose>_v<N>.md."""
    prompts_dir = root / "src" / "talos" / "llm" / "prompts"
    if not prompts_dir.is_dir():
        return []
    return [
        Violation(
            "R3.7",
            rel(path, root),
            "prompt templates are named <agent_or_detector>_<purpose>_v<N>.md so behaviour "
            "changes stay traceable",
        )
        for path in sorted(prompts_dir.iterdir())
        # Dotfiles are git plumbing (.gitkeep), not prompt templates.
        if path.is_file()
        and not path.name.startswith(".")
        and (path.suffix != ".md" or not PROMPT_NAME.match(path.stem))
    ]


def check_test_mirror(root: Path) -> list[Violation]:
    """R3.5: tests/unit/ mirrors src/talos/ path-for-path. Strict mode only."""
    package_root = root / "src" / "talos"
    if not package_root.is_dir():
        return []
    violations: list[Violation] = []
    for path in iter_files(root, "src/talos"):
        if path.suffix != ".py" or path.name in NAME_CHECK_EXEMPT:
            continue
        relative_module = path.resolve().relative_to(package_root.resolve())
        expected = root / "tests" / "unit" / relative_module.parent / f"test_{path.name}"
        if not expected.is_file():
            violations.append(
                Violation(
                    "R3.5",
                    rel(path, root),
                    f"no mirrored test at {rel(expected, root)}",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# R4
# ---------------------------------------------------------------------------


def check_sql_names(root: Path) -> list[Violation]:
    """R4.1/R4.2: every .sql filename is <action>_<subject>_<YYYYMMDD_HHMMSS>.sql, UTC."""
    violations: list[Violation] = []
    for path in iter_files(root, "db"):
        if path.suffix.lower() != ".sql":
            continue
        relative_path = rel(path, root)
        match = SQL_NAME.match(path.stem)
        if match is None:
            violations.append(
                Violation(
                    "R4.1",
                    relative_path,
                    "filename must be <action>_<subject>_<YYYYMMDD_HHMMSS>.sql with the UTC "
                    "date-time stamp last -- no .sql file is exempt",
                )
            )
            continue
        if match.group("action") not in SQL_ACTIONS:
            violations.append(
                Violation(
                    "R4.2",
                    relative_path,
                    f"'{match.group('action')}' is not in the action vocabulary: "
                    f"{', '.join(SQL_ACTIONS)}",
                )
            )
        try:
            # Naive parse is correct here: the stamp is UTC by convention, not by offset.
            datetime.strptime(match.group("stamp"), "%Y%m%d_%H%M%S")
        except ValueError:
            violations.append(
                Violation(
                    "R4.1",
                    relative_path,
                    f"'{match.group('stamp')}' is not a real UTC date-time in YYYYMMDD_HHMMSS form",
                )
            )
    return violations


def check_migration_pairs(root: Path) -> list[Violation]:
    """R4.3: every forward migration has a same-named rollback, and vice versa."""
    migrations_dir = root / "db" / "migrations"
    rollback_dir = migrations_dir / "rollback"
    if not migrations_dir.is_dir():
        return []
    forward = {p.name for p in migrations_dir.glob("*.sql")}
    rollback = {p.name for p in rollback_dir.glob("*.sql")} if rollback_dir.is_dir() else set()
    violations: list[Violation] = []
    for name in sorted(forward - rollback):
        violations.append(
            Violation(
                "R4.3",
                f"db/migrations/{name}",
                "no rollback at db/migrations/rollback/ under the identical filename; an "
                "irreversible migration still needs the file, containing only the reason why",
            )
        )
    for name in sorted(rollback - forward):
        violations.append(
            Violation(
                "R4.3",
                f"db/migrations/rollback/{name}",
                "rollback has no forward migration of the same name",
            )
        )
    return violations


def check_migration_headers(root: Path) -> list[Violation]:
    """R4.4 rule 4: every migration carries the required header comment block."""
    migrations_dir = root / "db" / "migrations"
    if not migrations_dir.is_dir():
        return []
    violations: list[Violation] = []
    for path in sorted(migrations_dir.glob("*.sql")):
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
        missing = [key for key in MIGRATION_HEADER_KEYS if key not in head]
        if missing:
            violations.append(
                Violation(
                    "R4.4",
                    rel(path, root),
                    f"header block is missing {', '.join(missing)} (standards 4.4 rule 4)",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def run(root: Path, strict: bool = False) -> list[Violation]:
    """Run every R3/R4 check. ``strict`` adds the R3.5 test-mirror requirement."""
    violations = [
        *check_filename_characters(root),
        *check_banned_names(root),
        *check_module_roles(root),
        *check_script_names(root),
        *check_basename_uniqueness(root),
        *check_prompt_names(root),
        *check_sql_names(root),
        *check_migration_pairs(root),
        *check_migration_headers(root),
    ]
    if strict:
        violations.extend(check_test_mirror(root))
    return violations


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser("Enforce R3 (naming) and R4 (SQL date-time stamps).")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also require a mirrored test for every src/talos module (R3.5)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve() if args.root else find_repo_root()
    return report("check_naming", run(root, strict=args.strict))


if __name__ == "__main__":
    sys.exit(main())
