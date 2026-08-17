"""The console surface: argument handling, wiring, and operator-facing failure messages."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from apply_migrations import apply_pending

from talos.cli.main_cli import build_sinks, main
from talos.core.settings import TalosSettings

SSH_LOG = (
    Path(__file__).resolve().parents[2] / "fixtures" / "logs" / "network_ssh_brute_force_sshd.log"
)


@pytest.fixture
def scan_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A migrated database and a working directory the sinks can write into."""
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / "talos.db"
    apply_pending(db_path)
    return db_path


def test_scan_reports_an_incident(
    scan_env: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    exit_code = main(["scan", str(SSH_LOG), "--db", str(scan_env), "--year", "2026"])
    captured = capsys.readouterr()
    assert exit_code == 0
    reports = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
    assert reports, "expected at least one incident on stdout"
    assert reports[0]["category"] == "network_brute_force"
    assert "incident(s)" in captured.err


def test_reports_are_written_to_the_json_sink(scan_env: Path, tmp_path: Path) -> None:
    main(["scan", str(SSH_LOG), "--db", str(scan_env), "--year", "2026"])
    written = list((tmp_path / "out" / "reports").glob("*.json"))
    assert written


def test_skipped_lines_are_counted_for_the_operator(
    scan_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["scan", str(SSH_LOG), "--db", str(scan_env), "--year", "2026"])
    assert "line(s) skipped" in capsys.readouterr().err


def test_missing_file_exits_two(scan_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "no-such-file.log", "--db", str(scan_env)]) == 2
    assert "no such log file" in capsys.readouterr().err


def test_unmigrated_database_names_the_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """src/ issues no DDL, so the operator is told to run the migration runner."""
    monkeypatch.chdir(tmp_path)
    exit_code = main(["scan", str(SSH_LOG), "--db", str(tmp_path / "fresh.db"), "--year", "2026"])
    assert exit_code == 1
    assert "apply_migrations" in capsys.readouterr().err


def test_unknown_sink_is_skipped_not_fatal(talos_settings: TalosSettings) -> None:
    talos_settings.output.sinks = ["stdout", "api", "carrier_pigeon"]
    assert [sink.name for sink in build_sinks(talos_settings, pretty=False)] == ["stdout"]


def test_pretty_flag_reaches_the_stdout_sink(talos_settings: TalosSettings) -> None:
    talos_settings.output.sinks = ["stdout"]
    sink = build_sinks(talos_settings, pretty=True)[0]
    assert sink._indent == 2
