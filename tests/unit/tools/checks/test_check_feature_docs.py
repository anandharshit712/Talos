"""R5 enforcement: a feature without its documentation folder does not merge."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from check_feature_docs import REQUIRED_DOCS, run


def rules(violations: list) -> set[str]:  # type: ignore[type-arg]
    return {v.rule for v in violations}


class TestCleanTree:
    def test_complete_feature_passes(self, feature_dir: Path, fake_repo: Path) -> None:
        assert run(fake_repo) == []

    def test_empty_features_directory_passes(self, fake_repo: Path) -> None:
        assert run(fake_repo) == []


class TestRequiredDocuments:
    def test_each_missing_document_is_reported(self, feature_dir: Path, fake_repo: Path) -> None:
        for name in REQUIRED_DOCS:
            (feature_dir / name).unlink()
        violations = run(fake_repo)
        # A missing README is one finding, not two: the status check stays silent rather than
        # piling an R5.3 on top of the R5.2 that already says the file is absent.
        assert rules(violations) == {"R5.2"}
        reported = {v.path.rsplit("/", 1)[-1] for v in violations}
        assert set(REQUIRED_DOCS) <= reported

    def test_missing_logic_and_behaviour_fails(self, feature_dir: Path, fake_repo: Path) -> None:
        (feature_dir / "detection-logic.md").unlink()
        violations = run(fake_repo)
        assert rules(violations) == {"R5.2"}
        assert "detection-logic.md or behaviour.md" in violations[0].message

    def test_behaviour_satisfies_the_either_requirement(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        (feature_dir / "detection-logic.md").unlink()
        write_file(feature_dir / "behaviour.md", "# behaviour\n")
        assert run(fake_repo) == []


class TestStatus:
    def test_missing_status_line_fails(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        write_file(feature_dir / "README.md", "# Feature\n\nNo status here.\n")
        violations = run(fake_repo)
        assert rules(violations) == {"R5.3"}

    def test_status_outside_the_vocabulary_fails(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        write_file(feature_dir / "README.md", "# Feature\n\n**Status:** nearly-done\n")
        violations = run(fake_repo)
        assert rules(violations) == {"R5.3"}
        assert "closed vocabulary" in violations[0].message

    def test_every_valid_status_is_accepted(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        for status in ("planned", "in-progress", "stable", "deprecated"):
            write_file(feature_dir / "README.md", f"# Feature\n\n**Status:** {status}\n")
            assert run(fake_repo) == [], status


class TestSlugs:
    def test_non_kebab_slug_fails(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        bad = fake_repo / "docs" / "features" / "Web_SQL_Injection"
        write_file(bad / "README.md", "**Status:** planned\n")
        for name in ("design.md", "testing.md", "changelog.md", "behaviour.md"):
            write_file(bad / name, "# x\n")
        violations = run(fake_repo)
        assert rules(violations) == {"R5.1"}

    def test_non_kebab_sub_feature_fails(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        write_file(feature_dir / "sub-features" / "SqlI" / "testing.md", "# x\n")
        violations = run(fake_repo)
        assert rules(violations) == {"R5.1"}


class TestCodeIsDocumented:
    def test_shipped_attack_type_without_a_feature_folder_fails(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "domains" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "injection" / "__init__.py")
        write_file(
            fake_repo
            / "src"
            / "talos"
            / "domains"
            / "web"
            / "injection"
            / "sql_injection_detector.py",
            "X = 1\n",
        )
        violations = run(fake_repo)
        assert rules(violations) == {"R5.4"}
        assert violations[0].path == "src/talos/domains/web/injection"

    def test_referencing_readme_satisfies_the_check(
        self, write_file: Callable[..., Path], feature_dir: Path, fake_repo: Path
    ) -> None:
        # The fixture README's **Code:** line already names this path.
        write_file(fake_repo / "src" / "talos" / "domains" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "injection" / "__init__.py")
        write_file(
            fake_repo
            / "src"
            / "talos"
            / "domains"
            / "web"
            / "injection"
            / "sql_injection_detector.py",
            "X = 1\n",
        )
        assert run(fake_repo) == []

    def test_empty_skeleton_package_is_not_shipped_code(
        self, write_file: Callable[..., Path], fake_repo: Path
    ) -> None:
        write_file(fake_repo / "src" / "talos" / "domains" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "__init__.py")
        write_file(fake_repo / "src" / "talos" / "domains" / "web" / "injection" / "__init__.py")
        assert run(fake_repo) == []
