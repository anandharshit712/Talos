"""The console surface: argument handling, wiring, and operator-facing failure messages.

The verdict log speaks to PostgreSQL from P6, and a CLI test should not need a database running
to prove that ``--pretty`` reaches the sink. The pool and the store are replaced here; the live
storage path is ``tests/integration/test_verdict_log_postgres.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from talos.cli import main_cli
from talos.cli.main_cli import build_sinks, main
from talos.core.error_types import StorageError
from talos.core.settings import TalosSettings

SSH_LOG = (
    Path(__file__).resolve().parents[2] / "fixtures" / "logs" / "network_ssh_brute_force_sshd.log"
)

DSN = "postgresql://talos@localhost:5432/talos"


class FakePool:
    """Stands in for ``PostgresConnectionPool``: records the DSN, opens nothing."""

    last_dsn: str | None = None

    def __init__(self, dsn: str, config: Any) -> None:
        FakePool.last_dsn = dsn

    async def close(self) -> None:
        return None


@pytest.fixture
def scan_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verdict_log: Any) -> Any:
    """A working directory the sinks can write into, and storage that never opens a socket."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TALOS_DB_DSN", DSN)
    monkeypatch.setattr(main_cli, "PostgresConnectionPool", FakePool)
    monkeypatch.setattr(main_cli, "VerdictLogStore", lambda pool: verdict_log)
    return verdict_log


def test_scan_reports_an_incident(scan_env: Any, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["scan", str(SSH_LOG), "--year", "2026"])
    captured = capsys.readouterr()
    assert exit_code == 0
    reports = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
    assert reports, "expected at least one incident on stdout"
    assert reports[0]["category"] == "network_brute_force"
    assert "incident(s)" in captured.err


def test_incidents_reach_the_audit_trail(scan_env: Any) -> None:
    main(["scan", str(SSH_LOG), "--year", "2026"])
    assert scan_env.reports, "a detected incident that is never recorded is not reportable"


def test_reports_are_written_to_the_json_sink(scan_env: Any, tmp_path: Path) -> None:
    main(["scan", str(SSH_LOG), "--year", "2026"])
    written = list((tmp_path / "out" / "reports").glob("*.json"))
    assert written


def test_skipped_lines_are_counted_for_the_operator(
    scan_env: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["scan", str(SSH_LOG), "--year", "2026"])
    assert "line(s) skipped" in capsys.readouterr().err


def test_missing_file_exits_two(scan_env: Any, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "no-such-file.log"]) == 2
    assert "no such log file" in capsys.readouterr().err


def test_the_dsn_comes_from_the_configured_variable(scan_env: Any) -> None:
    main(["scan", str(SSH_LOG), "--year", "2026"])
    assert FakePool.last_dsn == DSN


def test_the_dsn_flag_beats_the_environment(scan_env: Any) -> None:
    override = "postgresql://talos@localhost:5432/other"
    main(["scan", str(SSH_LOG), "--year", "2026", "--dsn", override])
    assert FakePool.last_dsn == override


def test_a_missing_dsn_is_fatal_and_names_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No audit trail, no scan. Detecting into a database that was never reachable is worse."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TALOS_DB_DSN", raising=False)

    assert main(["scan", str(SSH_LOG), "--year", "2026"]) == 1
    assert "TALOS_DB_DSN" in capsys.readouterr().err


def test_unmigrated_database_names_the_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """src/ issues no DDL, so the operator is told to run the migration runner."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TALOS_DB_DSN", DSN)
    monkeypatch.setattr(main_cli, "PostgresConnectionPool", FakePool)

    class _UnmigratedStore:
        async def append(self, report: Any) -> None:
            raise StorageError("table 'verdict_log' does not exist -- apply_migrations")

    monkeypatch.setattr(main_cli, "VerdictLogStore", lambda pool: _UnmigratedStore())

    assert main(["scan", str(SSH_LOG), "--year", "2026"]) == 1
    assert "apply_migrations" in capsys.readouterr().err


def test_unknown_sink_is_skipped_not_fatal(talos_settings: TalosSettings) -> None:
    talos_settings.output.sinks = ["stdout", "api", "carrier_pigeon"]
    assert [sink.name for sink in build_sinks(talos_settings, pretty=False)] == ["stdout"]


def test_pretty_flag_reaches_the_stdout_sink(talos_settings: TalosSettings) -> None:
    talos_settings.output.sinks = ["stdout"]
    sink = build_sinks(talos_settings, pretty=True)[0]
    assert sink._indent == 2


def test_scan_loads_the_env_file_before_building_the_router(
    scan_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider keys live in .env and are not settings fields, so the CLI is what loads them.

    Regression: for three phases the CLI read no .env at all, so a developer with keys on disk
    silently got templated narratives and had no way to tell.
    """
    calls: list[object] = []
    monkeypatch.setattr(main_cli, "load_env_file", lambda *a: calls.append(a) or [])

    main(["scan", str(SSH_LOG), "--year", "2026"])

    assert calls, "the CLI ran without loading .env"
