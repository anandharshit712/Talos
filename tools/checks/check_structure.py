"""Enforce R1 (clean repository root) and R2 (component-based directory taxonomy).

Checks performed:

R1     no file at the repository root outside the standards 1.1 allowlist
R1     no directory at the repository root outside the standards 1.1 allowlist
R1.4   ``src/talos/`` holds only ``__init__.py`` and ``py.typed`` as files
R2     every directory under ``src/`` is an importable package (has ``__init__.py``)
R2     no ``.sql`` file outside ``db/`` -- schema changes never live in application code
R2.4   every directory name is documented in the standards 2.1 tree

The 2.4 check reads the directory names out of the standards document itself rather than
duplicating them here, so adding a folder without documenting it fails, and documenting it is
the fix. The check is name-based, not full-path-based: it catches an undocumented ``utils/``
but not a documented name nested in an unexpected place. That is the intended trade -- a
path-reconstructing parser would be brittle enough to become the thing people work around.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from violation_types import Violation, is_excluded_dir, iter_dirs, iter_files, rel, run_cli

STANDARDS_DOC = "docs/standards/Talos_Engineering_Standards.md"

#: Manifests and configuration only. Standards 1.1, exhaustive.
ROOT_FILE_ALLOWLIST = frozenset(
    {
        "README.md",
        "CLAUDE.md",
        "LICENSE",
        "CHANGELOG.md",
        "pyproject.toml",
        "uv.lock",
        "requirements.lock",
        "Makefile",
        ".env.example",
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".pre-commit-config.yaml",
    }
)

#: Standards 1.1, exhaustive.
ROOT_DIR_ALLOWLIST = frozenset(
    {
        "src",
        "tests",
        "docs",
        "db",
        "config",
        "data",
        "deploy",
        "scripts",
        "tools",
        ".github",
        ".claude",
    }
)

#: Created by the documented setup steps and blocked from commits by .gitignore. Failing a
#: developer's local gate on a file the README tells them to create makes the gate the thing to
#: work around; git is what enforces "never committed", and it already does.
ROOT_LOCAL_ONLY_FILES = frozenset({".env"})

#: Names explicitly forbidden at the root even though their extension looks harmless.
FORBIDDEN_ROOT_STEMS = frozenset(
    {"main", "app", "run", "server", "test", "setup", "orchestrator", "utils", "manage"}
)

#: The only files permitted directly inside the package root (R1.4).
PACKAGE_ROOT_FILES = frozenset({"__init__.py", "py.typed"})

#: Trees whose internal directory layout is owned by a tool or by R5, not by standards 2.1.
UNDOCUMENTED_DIR_EXEMPT_PREFIXES = (
    ".github/",
    ".claude/",
    "docs/features/",
    "db/migrations/rollback",
)

#: Placeholder files that keep an intentionally empty directory in git.
PLACEHOLDER_FILENAMES = frozenset({".gitkeep"})


def documented_dir_names(root: Path) -> set[str]:
    """Directory names appearing in the standards 2.1 tree.

    Returns an empty set when the standards document is missing, which disables the R2.4 check
    rather than failing every directory -- a checker that explodes on an incomplete tree is
    useless inside test fixtures.
    """
    doc = root / STANDARDS_DOC
    if not doc.is_file():
        return set()
    names: set[str] = set()
    inside_tree = False
    seen_heading = False
    for line in doc.read_text(encoding="utf-8").splitlines():
        if line.startswith("### 2.1"):
            seen_heading = True
            continue
        if seen_heading and line.startswith("```"):
            if inside_tree:
                break  # end of the tree block
            inside_tree = True
            continue
        if not inside_tree:
            continue
        # Strip box-drawing prefixes, then take the first whitespace-delimited token.
        stripped = line.replace("│", " ").replace("├──", " ").replace("└──", " ").split()
        token = stripped[0] if stripped else ""
        if token.endswith("/") and len(token) > 1:
            names.add(token.rstrip("/"))
    return names


def check_root(root: Path) -> list[Violation]:
    """R1: the repository root is a manifest and configuration surface only."""
    violations: list[Violation] = []
    for entry in sorted(root.iterdir()):
        if entry.is_dir():
            if is_excluded_dir(entry.name) or entry.name in ROOT_DIR_ALLOWLIST:
                continue
            violations.append(
                Violation(
                    "R1",
                    entry.name + "/",
                    "directory is not in the standards 1.1 root allowlist -- move it under an "
                    "allowed top-level directory or add it to 1.1",
                )
            )
            continue
        if entry.name in ROOT_FILE_ALLOWLIST or entry.name in ROOT_LOCAL_ONLY_FILES:
            continue
        detail = "not in the standards 1.1 root allowlist"
        if entry.suffix == ".py":
            detail = (
                "no importable code at the root -- put modules under src/talos/ and expose "
                "entry points via [project.scripts] (R1.3)"
            )
        elif entry.suffix == ".sql":
            detail = "all SQL lives under db/ (R2)"
        elif entry.stem.lower() in FORBIDDEN_ROOT_STEMS:
            detail = "explicitly forbidden at the root (standards 1.2)"
        violations.append(Violation("R1", entry.name, detail))
    return violations


def check_package_root(root: Path) -> list[Violation]:
    """R1.4: the rule recurses one level -- src/talos/ stays clean."""
    package_root = root / "src" / "talos"
    if not package_root.is_dir():
        return []
    return [
        Violation(
            "R1.4",
            rel(entry, root),
            "the package root holds only __init__.py and py.typed -- move this into a "
            "subpackage (core/, schemas/, knowledge/, ...)",
        )
        for entry in sorted(package_root.iterdir())
        if entry.is_file() and entry.name not in PACKAGE_ROOT_FILES
    ]


def check_packages_importable(root: Path) -> list[Violation]:
    """R2: every code directory under src/ is an importable package.

    Directories holding no Python at any depth are data directories (``llm/prompts/`` holds
    versioned markdown templates) and are not packages. The rule is stated in terms of what a
    directory contains rather than as a list of exceptions, so it needs no maintenance.
    """
    return [
        Violation(
            "R2",
            rel(directory, root),
            "directory under src/ contains Python but has no __init__.py, so it is not an "
            "importable package",
        )
        for directory in iter_dirs(root, "src")
        if any(directory.rglob("*.py")) and not (directory / "__init__.py").is_file()
    ]


def check_sql_location(root: Path) -> list[Violation]:
    """R2: no SQL outside db/. Application code never issues DDL."""
    violations: list[Violation] = []
    for path in iter_files(root):
        if path.suffix.lower() != ".sql":
            continue
        relative_path = rel(path, root)
        if relative_path.startswith("db/"):
            continue
        violations.append(
            Violation(
                "R2",
                relative_path,
                "all SQL lives under db/ (schema/, migrations/, seeds/, queries/); "
                "src/ never contains DDL",
            )
        )
    return violations


def check_documented_dirs(root: Path) -> list[Violation]:
    """R2.4: a new directory requires a purpose entry in the standards 2.1 tree."""
    documented = documented_dir_names(root)
    if not documented:
        return []
    violations: list[Violation] = []
    for directory in iter_dirs(root):
        relative_path = rel(directory, root)
        if relative_path.startswith(UNDOCUMENTED_DIR_EXEMPT_PREFIXES):
            continue
        if directory.name in documented:
            continue
        violations.append(
            Violation(
                "R2.4",
                relative_path,
                f"directory name '{directory.name}' is not documented in the standards 2.1 "
                f"tree -- add a one-line purpose entry there in this same commit",
            )
        )
    return violations


def check_placeholders(root: Path) -> list[Violation]:
    """R2: a placeholder-only directory must actually be empty of real content."""
    violations: list[Violation] = []
    for directory in iter_dirs(root):
        entries = [e for e in directory.iterdir() if e.is_file()]
        placeholders = [e for e in entries if e.name in PLACEHOLDER_FILENAMES]
        if placeholders and len(entries) > len(placeholders):
            violations.append(
                Violation(
                    "R2",
                    rel(placeholders[0], root),
                    "placeholder file left behind in a directory that now has real content "
                    "-- delete it",
                )
            )
    return violations


def run(root: Path) -> list[Violation]:
    """Run every R1/R2 check and return the combined findings."""
    return [
        *check_root(root),
        *check_package_root(root),
        *check_packages_importable(root),
        *check_sql_location(root),
        *check_documented_dirs(root),
        *check_placeholders(root),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    return run_cli(
        "check_structure",
        "Enforce R1 (clean root) and R2 (component-based taxonomy).",
        run,
        argv,
    )


if __name__ == "__main__":
    sys.exit(main())
