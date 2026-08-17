"""Enforce R5: every feature ships with its own documentation folder.

R5 checks:

R5.1   every folder under ``docs/features/`` uses a kebab-case slug
R5.2   every feature folder has README.md, design.md, testing.md, changelog.md, and one of
       detection-logic.md (detection features) or behaviour.md (everything else)
R5.3   README.md declares a **Status:** from the closed vocabulary
R5.4   every attack-type package under ``src/talos/domains/`` is referenced by some feature
       README, so shipped code cannot be undocumented

The last check works by looking for the code path as a substring of a README rather than by
maintaining a code-path-to-slug map here. A map would be a second source of truth that drifts;
the README's own **Code:** line is the one that matters, and this makes it load-bearing.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from pathlib import Path

from violation_types import Violation, rel, run_cli

FEATURES_DIR = "docs/features"

#: Always required in a feature folder (standards 5.2).
REQUIRED_DOCS = ("README.md", "design.md", "testing.md", "changelog.md")

#: Exactly one of these is required: detection features document their logic, everything else
#: documents its behaviour.
REQUIRED_EITHER = ("detection-logic.md", "behaviour.md")

#: Closed status vocabulary (standards 5.3).
VALID_STATUSES = ("planned", "in-progress", "stable", "deprecated")

KEBAB_CASE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
STATUS_LINE = re.compile(r"^\*\*Status:\*\*\s*(?P<status>[a-z-]+)\s*$", re.MULTILINE)

#: Folders inside a feature directory that are structure, not sub-features.
NON_FEATURE_SUBDIRS = frozenset({"assets", "sub-features"})


def feature_dirs(root: Path) -> list[Path]:
    """Every immediate subdirectory of docs/features/."""
    base = root / FEATURES_DIR
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir() if p.is_dir())


def check_slug(root: Path, feature: Path) -> list[Violation]:
    """R5.1: slugs are kebab-case so they map mechanically to code components."""
    if KEBAB_CASE.match(feature.name):
        return []
    return [
        Violation(
            "R5.1",
            rel(feature, root),
            "feature slug must be kebab-case (lowercase words joined by single hyphens)",
        )
    ]


def check_required_docs(root: Path, feature: Path) -> list[Violation]:
    """R5.2: the required file set exists."""
    violations = [
        Violation(
            "R5.2",
            f"{rel(feature, root)}/{name}",
            "required feature document is missing (standards 5.2)",
        )
        for name in REQUIRED_DOCS
        if not (feature / name).is_file()
    ]
    if not any((feature / name).is_file() for name in REQUIRED_EITHER):
        violations.append(
            Violation(
                "R5.2",
                rel(feature, root),
                f"needs one of {' or '.join(REQUIRED_EITHER)}: detection features document "
                f"their logic, other features document their behaviour",
            )
        )
    return violations


def check_status(root: Path, feature: Path) -> list[Violation]:
    """R5.3: README declares a status from the closed vocabulary."""
    readme = feature / "README.md"
    if not readme.is_file():
        return []  # already reported by check_required_docs
    match = STATUS_LINE.search(readme.read_text(encoding="utf-8", errors="replace"))
    if match is None:
        return [
            Violation(
                "R5.3",
                rel(readme, root),
                "no '**Status:** <status>' line; the front block is required (standards 5.3)",
            )
        ]
    status = match.group("status")
    if status not in VALID_STATUSES:
        return [
            Violation(
                "R5.3",
                rel(readme, root),
                f"status '{status}' is not in the closed vocabulary: {', '.join(VALID_STATUSES)}",
            )
        ]
    return []


def check_code_is_documented(root: Path) -> list[Violation]:
    """R5.4: every attack-type package is referenced by some feature README."""
    domains_dir = root / "src" / "talos" / "domains"
    if not domains_dir.is_dir():
        return []
    readme_text = "\n".join(
        (feature / "README.md").read_text(encoding="utf-8", errors="replace")
        for feature in feature_dirs(root)
        if (feature / "README.md").is_file()
    )
    violations: list[Violation] = []
    for domain in sorted(p for p in domains_dir.iterdir() if p.is_dir()):
        for attack_type in sorted(p for p in domain.iterdir() if p.is_dir()):
            if attack_type.name.startswith("__"):
                continue
            # An empty skeleton package is not shipped code yet.
            modules = [
                p for p in attack_type.glob("*.py") if p.name not in {"__init__.py", "py.typed"}
            ]
            if not modules:
                continue
            needle = f"domains/{domain.name}/{attack_type.name}"
            if needle not in readme_text:
                violations.append(
                    Violation(
                        "R5.4",
                        f"src/talos/{needle}",
                        "no docs/features/*/README.md references this code path -- create the "
                        "feature folder (R5.1) and list the path on its **Code:** line",
                    )
                )
    return violations


def check_sub_features(root: Path, feature: Path) -> list[Violation]:
    """R5.1: sub-feature folders follow the same slug rule as features."""
    sub_root = feature / "sub-features"
    if not sub_root.is_dir():
        return []
    return [
        Violation(
            "R5.1",
            rel(sub, root),
            "sub-feature slug must be kebab-case",
        )
        for sub in sorted(p for p in sub_root.iterdir() if p.is_dir())
        if not KEBAB_CASE.match(sub.name)
    ]


def run(root: Path) -> list[Violation]:
    """Run every R5 check and return the combined findings."""
    violations: list[Violation] = []
    for feature in feature_dirs(root):
        if feature.name in NON_FEATURE_SUBDIRS:
            continue
        violations.extend(check_slug(root, feature))
        violations.extend(check_required_docs(root, feature))
        violations.extend(check_status(root, feature))
        violations.extend(check_sub_features(root, feature))
    violations.extend(check_code_is_documented(root))
    return violations


def main(argv: Sequence[str] | None = None) -> int:
    return run_cli(
        "check_feature_docs",
        "Enforce R5 per-feature documentation.",
        run,
        argv,
    )


if __name__ == "__main__":
    sys.exit(main())
