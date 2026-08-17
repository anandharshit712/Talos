"""R6 enforcement: the hard cap must actually block, and the exemptions must actually exempt."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from check_file_size import (
    HARD_CAP_LINES,
    REVIEW_TRIGGER_LINES,
    TARGET_CEILING_LINES,
    advisories,
    count_lines,
    measure,
    run,
)


def make_py(write_file: Callable[..., Path], root: Path, relative: str, lines: int) -> Path:
    """Write a Python file of exactly ``lines`` physical lines."""
    return write_file(root / relative, "".join(f"x = {n}\n" for n in range(lines)))


class TestCountLines:
    def test_counts_blank_lines(self, write_file: Callable[..., Path], tmp_path: Path) -> None:
        # The whole point: PowerShell's Measure-Object -Line would report 2 here.
        path = write_file(tmp_path / "a.py", "x = 1\n\n\n\ny = 2\n")
        assert count_lines(path) == 5

    def test_counts_trailing_content_without_newline(
        self, write_file: Callable[..., Path], tmp_path: Path
    ) -> None:
        assert count_lines(write_file(tmp_path / "a.py", "x = 1\ny = 2")) == 2

    def test_empty_file_is_zero(self, write_file: Callable[..., Path], tmp_path: Path) -> None:
        assert count_lines(write_file(tmp_path / "a.py", "")) == 0


class TestHardCap:
    def test_file_over_hard_cap_is_a_violation(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        make_py(write_file, fake_repo, "src/talos/core/big_store.py", HARD_CAP_LINES + 1)
        violations = run(fake_repo)
        assert [v.rule for v in violations] == ["R6"]
        assert violations[0].path == "src/talos/core/big_store.py"
        assert "no exceptions" in violations[0].message

    def test_file_exactly_at_hard_cap_passes(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        make_py(write_file, fake_repo, "src/talos/core/edge_store.py", HARD_CAP_LINES)
        assert run(fake_repo) == []

    def test_clean_repo_has_no_violations(self, fake_repo: Path) -> None:
        assert run(fake_repo) == []

    def test_sql_is_in_scope(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(
            fake_repo / "db" / "queries" / "select_x_20260817_120000.sql",
            "-- c\n" * (HARD_CAP_LINES + 1),
        )
        assert len(run(fake_repo)) == 1


class TestExemptions:
    def test_test_fixtures_are_exempt(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        make_py(write_file, fake_repo, "tests/fixtures/logs/huge.py", HARD_CAP_LINES + 500)
        assert run(fake_repo) == []

    def test_data_tree_is_exempt(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "data" / "reference" / "big.yaml", "a: 1\n" * (HARD_CAP_LINES + 1))
        assert run(fake_repo) == []

    def test_generated_marker_exempts(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        body = "x = 1\n" * (HARD_CAP_LINES + 1)
        write_file(
            fake_repo / "src" / "talos" / "core" / "wire_types.py",
            "# GENERATED FILE -- DO NOT EDIT (source: schema.json)\n" + body,
        )
        assert run(fake_repo) == []

    def test_markdown_is_out_of_scope(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "docs" / "planning" / "long.md", "line\n" * (HARD_CAP_LINES + 1))
        assert run(fake_repo) == []

    def test_unmarked_file_of_the_same_name_is_not_exempt(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        # The exemption comes from the marker, not from looking generated.
        make_py(write_file, fake_repo, "src/talos/core/wire_types.py", HARD_CAP_LINES + 1)
        assert len(run(fake_repo)) == 1


class TestAdvisories:
    def test_over_ceiling_warns_without_failing(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        make_py(write_file, fake_repo, "src/talos/core/mid_store.py", TARGET_CEILING_LINES + 1)
        assert run(fake_repo) == []
        notes = advisories(measure(fake_repo))
        assert len(notes) == 1
        assert "ceiling" in notes[0]

    def test_review_trigger_warns(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        make_py(write_file, fake_repo, "src/talos/core/warm_store.py", REVIEW_TRIGGER_LINES + 1)
        notes = advisories(measure(fake_repo))
        assert len(notes) == 1
        assert "plan the split" in notes[0]

    def test_small_file_is_silent(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        make_py(write_file, fake_repo, "src/talos/core/small_store.py", 50)
        assert advisories(measure(fake_repo)) == []

    def test_hard_cap_breach_is_not_also_an_advisory(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        make_py(write_file, fake_repo, "src/talos/core/huge_store.py", HARD_CAP_LINES + 1)
        assert advisories(measure(fake_repo)) == []
