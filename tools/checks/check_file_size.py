"""Enforce R6: files target <= 1,000 lines, with a hard cap of 1,500 that never yields.

Line count is physical lines -- blank lines, comments, docstrings, and imports all included --
matching ``wc -l`` for newline-terminated files. This is deliberately the dumbest possible
metric: any tool and any reviewer can reproduce it, and there is nothing to argue about.

Do not reimplement this with PowerShell's ``Measure-Object -Line``: it silently skips blank
lines and undercounts by 15-20% on typical source files, so a 1,750-line module can report as
compliant.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from violation_types import Violation, build_parser, find_repo_root, iter_files, rel, report

#: Plan the split now, and say so in the PR.
REVIEW_TRIGGER_LINES = 800

#: No new code goes into a file past this point until it is split.
TARGET_CEILING_LINES = 1_000

#: CI fails. Merge blocked. No exceptions, no waivers.
HARD_CAP_LINES = 1_500

#: Hand-written source and test files. Everything else is out of scope by definition.
CHECKED_SUFFIXES = frozenset({".py", ".sql", ".ts", ".tsx", ".js", ".ps1", ".sh", ".yaml", ".yml"})

#: Non-hand-written or non-source trees (standards 6.4). This list is exhaustive.
EXEMPT_PATH_PREFIXES = ("tests/fixtures/", "data/", "vendor/")

#: Lockfiles are resolver output, not source.
EXEMPT_FILENAMES = frozenset({"uv.lock", "requirements.lock", "package-lock.json"})

#: A generated file must announce itself on its first line to claim the exemption.
GENERATED_MARKERS = ("GENERATED FILE", "DO NOT EDIT", "@GENERATED")


def count_lines(path: Path) -> int:
    """Physical line count, equal to ``wc -l`` for files ending in a newline."""
    data = path.read_bytes()
    if not data:
        return 0
    lines = data.count(b"\n")
    if not data.endswith(b"\n"):
        lines += 1  # trailing content with no final newline still occupies a line
    return lines


def is_generated(path: Path) -> bool:
    """True when the file's first line marks it as generated (standards 6.4)."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            first_line = handle.readline().upper()
    except OSError:
        return False
    return any(marker in first_line for marker in GENERATED_MARKERS)


def is_exempt(relative_path: str, path: Path) -> bool:
    """True when R6 does not apply, per the exhaustive standards 6.4 list."""
    if path.name in EXEMPT_FILENAMES:
        return True
    if relative_path.startswith(EXEMPT_PATH_PREFIXES):
        return True
    return is_generated(path)


def measure(root: Path) -> list[tuple[int, str]]:
    """Return ``(lines, relative_path)`` for every in-scope file, largest first."""
    measured: list[tuple[int, str]] = []
    for path in iter_files(root):
        if path.suffix.lower() not in CHECKED_SUFFIXES:
            continue
        relative_path = rel(path, root)
        if is_exempt(relative_path, path):
            continue
        measured.append((count_lines(path), relative_path))
    measured.sort(reverse=True)
    return measured


def violations_from(measured: Sequence[tuple[int, str]]) -> list[Violation]:
    """Return one violation per measured file over the hard cap."""
    return [
        Violation(
            "R6",
            relative_path,
            f"{lines} lines exceeds the {HARD_CAP_LINES}-line hard cap -- split it "
            f"(standards 6.5); this cap has no exceptions",
        )
        for lines, relative_path in measured
        if lines > HARD_CAP_LINES
    ]


def run(root: Path) -> list[Violation]:
    """Return one violation per file over the hard cap."""
    return violations_from(measure(root))


def advisories(measured: Sequence[tuple[int, str]]) -> list[str]:
    """Non-failing notes for files over the ceiling or past the review trigger.

    These exist so a file's growth is visible long before it reaches the cap, which is the only
    way a cap with no exceptions stays painless.
    """
    notes: list[str] = []
    for lines, relative_path in measured:
        if lines > HARD_CAP_LINES:
            continue  # already reported as a violation
        if lines > TARGET_CEILING_LINES:
            notes.append(
                f"{relative_path} is {lines} lines: over the {TARGET_CEILING_LINES}-line "
                f"ceiling, split before adding code"
            )
        elif lines > REVIEW_TRIGGER_LINES:
            notes.append(f"{relative_path} is {lines} lines: plan the split (standards 6.5)")
    return notes


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser("Enforce R6 file-length limits.").parse_args(argv)
    root = args.root.resolve() if args.root else find_repo_root()
    measured = measure(root)
    return report("check_file_size", violations_from(measured), notes=advisories(measured))


if __name__ == "__main__":
    sys.exit(main())
