"""Shared types, traversal, and reporting for the repository rule checkers.

Every checker in this package exposes ``run(root, ...) -> list[Violation]`` plus a ``main()``
that prints the findings and exits non-zero when any exist. Centralising the plumbing here
means each failure line names the rule ID from
``docs/standards/Talos_Engineering_Standards.md``, so a CI failure points at the rule that was
broken instead of at a bare traceback.

Rule IDs used across the checkers:

==== =========================================================================
R1   no loose code files in the repository root
R2   every file lives in a component-based folder documented in standards 2.1
R3   every file is named for the work it does
R4   all SQL and migration filenames end with a UTC date-time stamp
R5   every feature has its own doc folder under ``docs/features/``
R6   files target <= 1,000 lines, hard cap 1,500 lines
==== =========================================================================
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

#: Directories never walked by any checker: tool caches, environments, and build output.
EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".idea",
        ".vscode",
        ".impeccable",
        "dist",
        "build",
        "htmlcov",
        ".eggs",
    }
)

#: Directory name suffixes never walked (editable-install metadata).
EXCLUDED_DIR_SUFFIXES = (".egg-info",)


@dataclass(frozen=True)
class Violation:
    """A single rule breach, rendered as one line of checker output."""

    rule: str
    """Rule ID, e.g. ``"R6"`` or ``"R3.3"``."""

    path: str
    """Repo-relative POSIX path of the offending file or directory."""

    message: str
    """What is wrong, phrased so the fix is obvious."""

    def __str__(self) -> str:
        return f"[{self.rule}] {self.path}: {self.message}"


def find_repo_root(start: Path | None = None) -> Path:
    """Return the repository root, located by walking up to the directory holding pyproject.toml.

    Falls back to the current working directory when no marker is found, so the checkers stay
    usable from a partially-populated tree (for example inside a test fixture).
    """
    current = (start or Path(__file__).resolve()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return Path.cwd().resolve()


def is_excluded_dir(name: str) -> bool:
    """True when a directory of this name must not be walked."""
    return name in EXCLUDED_DIR_NAMES or name.endswith(EXCLUDED_DIR_SUFFIXES)


def rel(path: Path, root: Path) -> str:
    """Repo-relative POSIX path, used verbatim in violation messages."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(root: Path, under: str | None = None) -> Iterator[Path]:
    """Yield every non-excluded file below ``root`` (optionally below ``root/under``)."""
    base = root if under is None else root / under
    if not base.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not is_excluded_dir(d))
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def iter_dirs(root: Path, under: str | None = None) -> Iterator[Path]:
    """Yield every non-excluded directory below ``root`` (optionally below ``root/under``)."""
    base = root if under is None else root / under
    if not base.is_dir():
        return
    for dirpath, dirnames, _ in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not is_excluded_dir(d))
        for dirname in dirnames:
            yield Path(dirpath) / dirname


def report(check_name: str, violations: Sequence[Violation], notes: Sequence[str] = ()) -> int:
    """Print findings and return the process exit code (0 clean, 1 violations found)."""
    for note in notes:
        print(f"  note: {note}")
    for violation in sorted(violations, key=lambda v: (v.rule, v.path)):
        print(f"  {violation}")
    if violations:
        plural = "" if len(violations) == 1 else "s"
        print(f"FAIL {check_name}: {len(violations)} violation{plural}")
        return 1
    print(f"ok   {check_name}")
    return 0


def build_parser(description: str) -> argparse.ArgumentParser:
    """Standard CLI for a checker: ``--root`` to point at a tree other than this repo."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root to check (default: auto-detected from this file)",
    )
    return parser


def run_cli(
    check_name: str,
    description: str,
    run_fn: Callable[[Path], list[Violation]],
    argv: Sequence[str] | None = None,
) -> int:
    """Parse args, run a single-argument checker, and report. Returns the exit code."""
    args = build_parser(description).parse_args(argv)
    root = args.root.resolve() if args.root else find_repo_root()
    return report(check_name, run_fn(root))
