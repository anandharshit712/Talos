"""Run every repository rule checker and aggregate the exit codes.

This is the single entry point used by the Makefile, ``scripts/run_checks.ps1``, pre-commit, and
CI, so all four surfaces enforce exactly the same rules. Every checker runs even when an earlier
one fails: a contributor should see the full list of what to fix, not just the first item.

    python tools/checks/run_all_checks.py            # pre-commit / local
    python tools/checks/run_all_checks.py --strict   # phase gate / CI (adds R3.5 test mirror)
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

import check_feature_docs
import check_file_size
import check_naming
import check_structure
from violation_types import build_parser, find_repo_root


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser("Run every repository rule checker (R1-R6).")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="phase-gate mode: also require a mirrored test for every module (R3.5)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve() if args.root else find_repo_root()

    print(f"checking {root}")
    exit_codes = [
        check_structure.main(["--root", str(root)]),
        check_naming.main(["--root", str(root)] + (["--strict"] if args.strict else [])),
        check_file_size.main(["--root", str(root)]),
        check_feature_docs.main(["--root", str(root)]),
    ]

    failed = sum(1 for code in exit_codes if code != 0)
    if failed:
        plural = "" if failed == 1 else "s"
        print(f"\n{failed} check{plural} failed. See docs/standards/Talos_Engineering_Standards.md")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
