"""R1/R2 enforcement: the root stays clean and every directory is documented."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from check_structure import documented_dir_names, run


def rules(violations: list) -> set[str]:  # type: ignore[type-arg]
    return {v.rule for v in violations}


class TestCleanTree:
    def test_fixture_repo_passes(self, fake_repo: Path) -> None:
        assert run(fake_repo) == []


class TestRootAllowlist:
    def test_loose_python_file_at_root_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "main.py", "print('hi')\n")
        violations = run(fake_repo)
        assert rules(violations) == {"R1"}
        assert "src/talos/" in violations[0].message

    def test_loose_utils_file_at_root_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "utils.py", "\n")
        assert rules(run(fake_repo)) == {"R1"}

    def test_sql_at_root_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "schema.sql", "SELECT 1;\n")
        violations = run(fake_repo)
        assert "R1" in rules(violations)
        assert any("db/" in v.message for v in violations)

    def test_undeclared_root_directory_fails(self, fake_repo: Path) -> None:
        (fake_repo / "lib").mkdir()
        assert "R1" in rules(run(fake_repo))

    def test_allowlisted_root_files_pass(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "Makefile", "help:\n")
        write_file(fake_repo / "CHANGELOG.md", "# Changelog\n")
        write_file(fake_repo / ".env.example", "TALOS_LOG_LEVEL=INFO\n")
        assert run(fake_repo) == []

    def test_excluded_caches_are_ignored(self, fake_repo: Path) -> None:
        (fake_repo / ".venv" / "lib").mkdir(parents=True)
        (fake_repo / "talos.egg-info").mkdir()
        (fake_repo / "__pycache__").mkdir()
        assert run(fake_repo) == []


class TestPackageRoot:
    def test_module_in_package_root_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "settings.py", "X = 1\n")
        violations = run(fake_repo)
        assert "R1.4" in rules(violations)

    def test_init_and_py_typed_are_allowed(self, fake_repo: Path) -> None:
        assert run(fake_repo) == []


class TestPackagesImportable:
    def test_python_directory_without_init_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "schemas" / "event_schema.py", "X = 1\n")
        violations = run(fake_repo)
        assert "R2" in rules(violations)
        assert any("__init__.py" in v.message for v in violations)

    def test_data_only_directory_needs_no_init(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "llm" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "llm" / "prompts" / "a_route_v1.md", "text\n")
        assert run(fake_repo) == []


class TestSqlLocation:
    def test_sql_under_src_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(
            fake_repo / "src" / "talos" / "core" / "create_x_20260817_120000.sql", "SELECT 1;\n"
        )
        violations = run(fake_repo)
        assert "R2" in rules(violations)
        assert any("db/" in v.message for v in violations)

    def test_sql_under_db_passes(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "db" / "schema" / "snapshot_x_20260817_120000.sql", "SELECT 1;\n")
        assert run(fake_repo) == []


class TestDocumentedDirectories:
    def test_tree_is_parsed_from_the_standards_document(self, fake_repo: Path) -> None:
        names = documented_dir_names(fake_repo)
        assert {"src", "talos", "core", "migrations", "rollback", "prompts"} <= names
        # Prose after the closing fence must not leak in as a directory name.
        assert "Trailing" not in names

    def test_undocumented_directory_fails(self, fake_repo: Path) -> None:
        (fake_repo / "src" / "talos" / "utilities").mkdir()
        violations = run(fake_repo)
        assert "R2.4" in rules(violations)
        assert any("standards 2.1" in v.message for v in violations)

    def test_feature_folders_are_exempt(self, fake_repo: Path) -> None:
        (fake_repo / "docs" / "features" / "web-sql-injection-detection" / "assets").mkdir(
            parents=True
        )
        assert run(fake_repo) == []

    def test_missing_standards_document_disables_the_check(self, fake_repo: Path) -> None:
        (fake_repo / "docs" / "standards" / "Talos_Engineering_Standards.md").unlink()
        (fake_repo / "src" / "talos" / "utilities").mkdir()
        assert documented_dir_names(fake_repo) == set()
        assert "R2.4" not in rules(run(fake_repo))


class TestPlaceholders:
    def test_gitkeep_beside_real_content_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "db" / "seeds" / ".gitkeep")
        write_file(fake_repo / "db" / "seeds" / "seed_x_20260817_120000.sql", "SELECT 1;\n")
        violations = run(fake_repo)
        assert "R2" in rules(violations)
        assert any("placeholder" in v.message for v in violations)

    def test_gitkeep_alone_passes(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "db" / "seeds" / ".gitkeep")
        assert run(fake_repo) == []
