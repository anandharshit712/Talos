"""The demo trace is what the P9 differentiator rests on, so pin what it records.

Both faces of the demo -- the terminal renderer and the trace visualiser -- read this structure, so
a regression here breaks the reasoning both show. The chains are the real committed demo logs, run
through the real pipeline with the model off.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from talos.core.settings import TalosSettings, repository_root
from talos.ingestion.parsers.network_log_parser import NetworkLogParser
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.output.demo_trace_engine import DEMO_CHAINS, build_trace

SUBMISSION = Path(__file__).resolve().parents[3] / "docs" / "submission"
CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"


class _NoBaseline:
    async def get(self, account: str) -> Any | None:
        return None

    async def put(self, baseline: Any) -> None:
        return None


@pytest.fixture
def settings() -> TalosSettings:
    return TalosSettings.load(config_dir=CONFIG_DIR)


def _trace(name: str, parser: Any, settings: TalosSettings):  # type: ignore[no-untyped-def]
    lines = (SUBMISSION / name).read_text(encoding="utf-8").splitlines()
    return build_trace(name, lines, parser, settings, baseline_store=_NoBaseline())


def test_web_chain_shows_injection_then_brute_force(settings: TalosSettings) -> None:
    trace = _trace("demo_web_chain.log", WebLogParser(), settings)
    assert trace.used_llm is False, "the demo must not depend on a model being reachable"
    categories = {step.incident.category for step in trace.steps if step.incident}
    assert "injection" in categories
    assert "auth_failure" in categories
    techniques = {v.technique for step in trace.steps for v in step.verdicts if v.attack_detected}
    assert {"sql_injection", "brute_force"} <= techniques


def test_network_chain_escalates_on_the_trailing_success(settings: TalosSettings) -> None:
    trace = _trace("demo_network_chain.log", NetworkLogParser(default_year=2026), settings)
    incidents = [step.incident for step in trace.steps if step.incident]
    assert incidents, "the SSH burst produced no incident"
    # The last incident is the one raised when the burst lands: higher severity, succeeded scope.
    assert incidents[-1].severity == "high"
    assert incidents[-1].confidence >= incidents[0].confidence


def test_every_firing_verdict_carries_evidence(settings: TalosSettings) -> None:
    """A verdict with no evidence is exactly what the trace exists to make impossible to ship."""
    for name, parser in (
        ("demo_web_chain.log", WebLogParser()),
        ("demo_network_chain.log", NetworkLogParser(default_year=2026)),
    ):
        trace = _trace(name, parser, settings)
        for step in trace.steps:
            for verdict in step.verdicts:
                if verdict.attack_detected:
                    assert verdict.evidence, f"{verdict.detector} fired with no evidence"
                    assert 0.0 <= verdict.confidence <= 1.0


def test_the_trace_serialises_for_the_ui(settings: TalosSettings) -> None:
    """The visualiser consumes to_dict() as JSON, so it must be a plain nested structure."""
    import json

    trace = _trace("demo_web_chain.log", WebLogParser(), settings)
    payload = json.loads(json.dumps(trace.to_dict(), default=str))
    assert payload["title"] == "demo_web_chain.log"
    assert payload["incidents"] >= 2
    assert isinstance(payload["steps"], list)


def test_the_demo_chains_are_committed_not_just_present() -> None:
    """A chain that exists only on the author's disk is a demo that crashes on a fresh clone.

    `.gitignore` carries a blanket `*.log` for runtime artifacts, with carve-outs for the corpora
    that are source rather than output. `docs/submission/` was not among them, so both prepared
    chains were untracked: every check passed locally and `talos demo` died on a missing file for
    anyone who cloned the repository. Caught by running the README quickstart in a clean clone,
    which is what this test makes cheap to repeat.
    """
    import subprocess

    for chain in DEMO_CHAINS:
        relative = chain.path().relative_to(repository_root())
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(relative).replace("\\", "/")],
            cwd=repository_root(),
            capture_output=True,
        )
        assert tracked.returncode == 0, f"{relative} is not tracked by git"
