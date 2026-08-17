"""R3/R4 enforcement: names describe the work, and every SQL filename is stamped."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from check_naming import (
    check_banned_names,
    check_basename_uniqueness,
    check_migration_headers,
    check_migration_pairs,
    check_module_roles,
    check_prompt_names,
    check_script_names,
    check_sql_names,
    check_test_mirror,
    run,
)

MIGRATION_HEADER = """-- Migration: create_verdict_log_table
-- Created:   2026-08-20 10:15:00 UTC
-- Feature:   docs/features/incident-aggregation/
-- Purpose:   Persistent audit trail of detector verdicts.
-- Reversible: yes
CREATE TABLE verdict_log (verdict_id TEXT PRIMARY KEY);
"""


def rules(violations: list) -> set[str]:  # type: ignore[type-arg]
    return {v.rule for v in violations}


class TestCleanTree:
    def test_fixture_repo_passes(self, fake_repo: Path) -> None:
        assert run(fake_repo) == []


class TestRoleSuffixes:
    def test_module_without_role_suffix_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "things.py", "X = 1\n")
        violations = check_module_roles(fake_repo)
        assert rules(violations) == {"R3.1"}
        assert "closed vocabulary" in violations[0].message

    def test_role_suffix_passes(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "agent_contracts.py", "X = 1\n")
        assert check_module_roles(fake_repo) == []

    def test_foundation_modules_are_exempt(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "settings.py", "X = 1\n")
        write_file(fake_repo / "src" / "talos" / "core" / "constants.py", "X = 1\n")
        assert check_module_roles(fake_repo) == []

    def test_camel_case_module_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "EventStore.py", "X = 1\n")
        assert rules(check_module_roles(fake_repo)) == {"R3.1"}

    def test_dunder_modules_are_exempt(self, fake_repo: Path) -> None:
        assert check_module_roles(fake_repo) == []


class TestBannedNames:
    def test_banned_stem_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "helpers.py", "X = 1\n")
        violations = check_banned_names(fake_repo)
        assert rules(violations) == {"R3.2"}
        assert "container" in violations[0].message

    def test_version_suffix_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "event_store_v2.py", "X = 1\n")
        assert rules(check_banned_names(fake_repo)) == {"R3.2"}

    def test_backup_suffix_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "event_store_backup.py", "X = 1\n")
        assert rules(check_banned_names(fake_repo)) == {"R3.2"}

    def test_markdown_version_suffix_is_allowed(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        # Prompt templates are versioned on purpose (R3.7); the ban is for code.
        write_file(fake_repo / "docs" / "planning" / "notes_v2.md", "text\n")
        assert check_banned_names(fake_repo) == []


class TestBasenameUniqueness:
    def test_duplicate_basename_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "domains" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "core" / "event_store.py", "X = 1\n")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "event_store.py", "X = 1\n")
        violations = check_basename_uniqueness(fake_repo)
        assert rules(violations) == {"R3.3"}
        assert "event_store.py" in violations[0].message

    def test_repeated_init_files_are_exempt(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "schemas" / "__init__.py")
        assert check_basename_uniqueness(fake_repo) == []


class TestScriptNames:
    def test_non_verb_script_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "scripts" / "logs_thing.py", "X = 1\n")
        violations = check_script_names(fake_repo)
        assert rules(violations) == {"R3.8"}

    def test_verb_object_script_passes(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "scripts" / "generate_sample_logs.py", "X = 1\n")
        write_file(fake_repo / "scripts" / "run_checks.ps1", "# ps\n")
        assert check_script_names(fake_repo) == []

    def test_tools_library_may_use_a_role_suffix(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "tools" / "checks" / "violation_types.py", "X = 1\n")
        assert check_script_names(fake_repo) == []


class TestPromptNames:
    def test_unversioned_prompt_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "llm" / "prompts" / "classify.md", "text\n")
        violations = check_prompt_names(fake_repo)
        assert rules(violations) == {"R3.7"}

    def test_versioned_prompt_passes(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(
            fake_repo / "src" / "talos" / "llm" / "prompts" / "web_type_classifier_route_v1.md",
            "text\n",
        )
        assert check_prompt_names(fake_repo) == []


class TestSqlStamps:
    def test_unstamped_sql_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "db" / "queries" / "select_top_ips.sql", "SELECT 1;\n")
        violations = check_sql_names(fake_repo)
        assert rules(violations) == {"R4.1"}
        assert "date-time stamp last" in violations[0].message

    def test_stamp_not_last_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(
            fake_repo / "db" / "queries" / "select_20260817_120000_top_ips.sql", "SELECT 1;\n"
        )
        assert rules(check_sql_names(fake_repo)) == {"R4.1"}

    def test_impossible_date_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "db" / "queries" / "select_x_20260899_120000.sql", "SELECT 1;\n")
        violations = check_sql_names(fake_repo)
        assert rules(violations) == {"R4.1"}
        assert "not a real UTC date-time" in violations[0].message

    def test_unknown_action_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "db" / "queries" / "frobnicate_x_20260817_120000.sql", "SELECT 1;\n")
        assert rules(check_sql_names(fake_repo)) == {"R4.2"}

    def test_well_formed_sql_passes(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(
            fake_repo / "db" / "queries" / "select_top_attacking_ips_20260819_161240.sql",
            "SELECT 1;\n",
        )
        assert check_sql_names(fake_repo) == []


class TestMigrations:
    def test_missing_rollback_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(
            fake_repo / "db" / "migrations" / "create_verdict_log_table_20260820_101500.sql",
            MIGRATION_HEADER,
        )
        violations = check_migration_pairs(fake_repo)
        assert rules(violations) == {"R4.3"}
        assert "rollback" in violations[0].message

    def test_orphan_rollback_fails(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(
            fake_repo
            / "db"
            / "migrations"
            / "rollback"
            / "create_verdict_log_table_20260820_101500.sql",
            "DROP TABLE verdict_log;\n",
        )
        violations = check_migration_pairs(fake_repo)
        assert rules(violations) == {"R4.3"}
        assert "no forward migration" in violations[0].message

    def test_paired_migration_passes(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        name = "create_verdict_log_table_20260820_101500.sql"
        write_file(fake_repo / "db" / "migrations" / name, MIGRATION_HEADER)
        write_file(fake_repo / "db" / "migrations" / "rollback" / name, "DROP TABLE verdict_log;\n")
        assert check_migration_pairs(fake_repo) == []
        assert check_migration_headers(fake_repo) == []

    def test_missing_header_keys_fail(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(
            fake_repo / "db" / "migrations" / "create_verdict_log_table_20260820_101500.sql",
            "CREATE TABLE verdict_log (verdict_id TEXT);\n",
        )
        violations = check_migration_headers(fake_repo)
        assert rules(violations) == {"R4.4"}
        assert "-- Purpose:" in violations[0].message


class TestTestMirror:
    def test_module_without_mirrored_test_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "error_types.py", "X = 1\n")
        violations = check_test_mirror(fake_repo)
        assert rules(violations) == {"R3.5"}
        assert "tests/unit/core/test_error_types.py" in violations[0].message

    def test_mirrored_test_passes(self, write_file: Callable[..., Path], fake_repo: Path) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "error_types.py", "X = 1\n")
        write_file(
            fake_repo / "tests" / "unit" / "core" / "test_error_types.py", "def test(): ...\n"
        )
        assert check_test_mirror(fake_repo) == []

    def test_mirror_check_is_off_by_default(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "core" / "error_types.py", "X = 1\n")
        assert run(fake_repo) == []
        assert rules(run(fake_repo, strict=True)) == {"R3.5"}
