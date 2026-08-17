"""Shared checker plumbing: traversal exclusions, root detection, and exit codes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from violation_types import (
    Violation,
    find_repo_root,
    is_excluded_dir,
    iter_dirs,
    iter_files,
    rel,
    report,
)


class TestViolation:
    def test_renders_as_one_line_naming_the_rule(self) -> None:
        violation = Violation("R6", "src/talos/core/big_store.py", "1623 lines")
        assert str(violation) == "[R6] src/talos/core/big_store.py: 1623 lines"

    def test_is_hashable_so_findings_can_be_deduplicated(self) -> None:
        assert len({Violation("R1", "a.py", "m"), Violation("R1", "a.py", "m")}) == 1


class TestExclusions:
    @pytest.mark.parametrize(
        "name", [".git", ".venv", "__pycache__", ".ruff_cache", "node_modules", "dist"]
    )
    def test_known_caches_are_excluded(self, name: str) -> None:
        assert is_excluded_dir(name)

    def test_egg_info_suffix_is_excluded(self) -> None:
        assert is_excluded_dir("talos.egg-info")

    def test_real_directories_are_not_excluded(self) -> None:
        assert not is_excluded_dir("src")
        assert not is_excluded_dir("detection")


class TestTraversal:
    def test_iter_files_skips_excluded_trees(
        self, write_file: Callable[..., Path], tmp_path: Path
    ) -> None:
        write_file(tmp_path / "src" / "a_store.py", "X = 1\n")
        write_file(tmp_path / ".venv" / "lib" / "b_store.py", "X = 1\n")
        write_file(tmp_path / "__pycache__" / "c_store.pyc", "\n")
        assert [p.name for p in iter_files(tmp_path)] == ["a_store.py"]

    def test_iter_files_can_scope_to_a_subtree(
        self, write_file: Callable[..., Path], tmp_path: Path
    ) -> None:
        write_file(tmp_path / "src" / "a_store.py", "X = 1\n")
        write_file(tmp_path / "docs" / "note.md", "text\n")
        assert [p.name for p in iter_files(tmp_path, "src")] == ["a_store.py"]

    def test_iter_files_on_a_missing_subtree_is_empty(self, tmp_path: Path) -> None:
        assert list(iter_files(tmp_path, "nope")) == []

    def test_iter_dirs_yields_nested_directories(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "talos" / "core").mkdir(parents=True)
        (tmp_path / ".venv" / "lib").mkdir(parents=True)
        assert {p.name for p in iter_dirs(tmp_path)} == {"src", "talos", "core"}


class TestPaths:
    def test_rel_returns_posix_paths(self, write_file: Callable[..., Path], tmp_path: Path) -> None:
        path = write_file(tmp_path / "src" / "talos" / "core" / "a_store.py", "X = 1\n")
        assert rel(path, tmp_path) == "src/talos/core/a_store.py"

    def test_find_repo_root_locates_the_pyproject_marker(
        self, write_file: Callable[..., Path], tmp_path: Path
    ) -> None:
        write_file(tmp_path / "pyproject.toml", "[project]\n")
        nested = tmp_path / "src" / "talos" / "core"
        nested.mkdir(parents=True)
        assert find_repo_root(nested / "a_store.py") == tmp_path.resolve()


class TestReport:
    def test_clean_run_returns_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert report("check_x", []) == 0
        assert "ok   check_x" in capsys.readouterr().out

    def test_violations_return_one(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert report("check_x", [Violation("R6", "a.py", "too long")]) == 1
        output = capsys.readouterr().out
        assert "[R6] a.py: too long" in output
        assert "FAIL check_x: 1 violation" in output

    def test_notes_print_without_failing(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert report("check_x", [], notes=["a.py is 900 lines"]) == 0
        assert "note: a.py is 900 lines" in capsys.readouterr().out
