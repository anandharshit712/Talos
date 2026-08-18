"""Shared fixtures. A ``fake_repo`` builds a minimal compliant tree that tests then break.

The rule checkers are only worth having if they fail on real violations, so every checker test
follows the same shape: start from a clean tree, plant exactly one violation, assert that the
checker reports it and names the right rule. Asserting a checker passes on a clean tree proves
almost nothing on its own.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.core.settings import TalosSettings
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import Actor, AuthEvent, NormalizedEvent, Target, WebRequest
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict
from talos.storage.event_window_store import EventWindowStore

#: Where a burst of fabricated events starts. Fixed, so window maths in tests is readable.
BURST_START = datetime(2026, 8, 15, 10, 15, 0, tzinfo=UTC)

#: A cut-down standards document. ``check_structure`` reads the documented directory names out of
#: the real document's section 2.1 tree, so the fixture must supply one in the same shape.
STANDARDS_STUB = """# Talos -- Engineering Standards

### 2.1 Full repository tree

```
Talos/
├── config/
├── db/
│   ├── schema/
│   ├── migrations/
│   │   └── rollback/
│   ├── seeds/
│   └── queries/
├── docs/
│   ├── architecture/
│   ├── features/
│   ├── standards/
│   └── planning/
├── scripts/
├── src/
│   └── talos/
│       ├── core/
│       ├── schemas/
│       ├── domains/
│       │   └── web/
│       │       └── injection/
│       └── llm/
│           └── prompts/
├── tests/
│   ├── unit/
│   └── fixtures/
└── tools/
    └── checks/
```

Trailing prose so the block above is unambiguously closed.
"""


def write(path: Path, content: str = "") -> Path:
    """Create ``path`` and any missing parents, then write ``content``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def write_file() -> Callable[..., Path]:
    """Expose :func:`write` as a fixture.

    Tests reach it this way rather than by importing ``conftest``: with no ``__init__.py`` under
    ``tests/``, pytest puts each test file's own directory on ``sys.path``, so a direct
    ``from conftest import write`` would resolve only for tests sitting beside this file.
    """
    return write


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """A minimal tree that passes every checker, ready to have one violation planted in it."""
    write(tmp_path / "pyproject.toml", '[project]\nname = "talos"\n')
    write(tmp_path / "README.md", "# Talos\n")
    write(tmp_path / ".gitignore", "__pycache__/\n")
    write(tmp_path / "docs" / "standards" / "Talos_Engineering_Standards.md", STANDARDS_STUB)
    write(tmp_path / "src" / "talos" / "__init__.py", '"""Talos."""\n')
    write(tmp_path / "src" / "talos" / "py.typed")
    write(tmp_path / "src" / "talos" / "core" / "__init__.py")
    (tmp_path / "docs" / "features").mkdir(parents=True, exist_ok=True)
    (tmp_path / "db" / "migrations" / "rollback").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def sample_event() -> NormalizedEvent:
    """One failed SSH login -- the smallest realistic event the pipeline handles."""
    return NormalizedEvent(
        event_id="11111111-1111-4111-8111-111111111111",
        timestamp=datetime(2026, 8, 19, 10, 15, 0, tzinfo=UTC),
        domain="network",
        telemetry_source="sshd",
        actor=Actor(source_ip="203.0.113.7", account="root"),
        target=Target(host="bastion-01", port=22),
        auth=AuthEvent(protocol="ssh", outcome="failure", reason="invalid_password"),
        raw=(
            "Aug 19 10:15:00 bastion-01 sshd[4242]: Failed password for root "
            "from 203.0.113.7 port 51234 ssh2"
        ),
    )


@pytest.fixture
def sample_verdict(sample_event: NormalizedEvent) -> Verdict:
    """A statistical verdict: no model involved, evidence and confidence both present."""
    return Verdict(
        verdict_id="22222222-2222-4222-8222-222222222222",
        event_ids=[sample_event.event_id],
        detector="ssh_brute_force_detector",
        domain="network",
        category="network_brute_force",
        technique="brute_force",
        attack_detected=True,
        confidence=0.91,
        mitre=mitre_for("brute_force"),
        scope=Scope(
            affected_accounts=["root"],
            affected_hosts=["bastion-01"],
            attempt_count=12,
            source_diversity=1,
            succeeded=False,
            window_start=datetime(2026, 8, 19, 10, 14, 0, tzinfo=UTC),
            window_end=datetime(2026, 8, 19, 10, 15, 0, tzinfo=UTC),
        ),
        evidence=[
            Evidence(
                kind="statistic",
                detail="12 failed ssh logins for root@bastion-01 within 120s (threshold 8)",
                references=[sample_event.event_id],
            )
        ],
        reasoning="Sustained failed-password burst against a single account from one source.",
        model=ModelInfo(
            name="none", route_reason="statistical path, no model needed", used_llm=False
        ),
    )


@pytest.fixture(autouse=True)
def _clean_talos_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """No TALOS_* variable from the developer's shell may change what a test observes."""
    for key in list(os.environ):
        if key.startswith("TALOS_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def talos_settings(tmp_path: Path) -> TalosSettings:
    """Settings on model defaults alone -- no repository YAML, no environment."""
    return TalosSettings.load(config_dir=tmp_path / "absent")


class RecordingVerdictLog:
    """In-memory stand-in for ``VerdictLogStore``."""

    def __init__(self) -> None:
        self.reports: list[IncidentReport] = []

    async def append(self, report: IncidentReport) -> None:
        self.reports.append(report)


class NullBaselineStore:
    """Cold start for every account -- the P6 store is not built yet."""

    async def get(self, account: str) -> Any | None:
        return None

    async def put(self, baseline: Any) -> None:
        return None


@pytest.fixture
def detection_ctx(talos_settings: TalosSettings) -> DetectionContext:
    """A real event window plus in-memory doubles -- no network, no database (LLD 14)."""
    return DetectionContext(
        event_window=EventWindowStore(
            ttl_seconds=talos_settings.storage.event_window_ttl_seconds,
            max_events_per_key=talos_settings.storage.event_window_max_events,
        ),
        baseline_store=NullBaselineStore(),
        # No replies configured: every caller takes its templated path. A test that wants a
        # model answer builds its own StubModelRouter(replies=...).
        model_client=StubModelRouter(),
        settings=talos_settings,
        verdict_log=RecordingVerdictLog(),
    )


def make_ssh_event_impl(
    *,
    account: str = "root",
    host: str = "bastion-01",
    source_ip: str = "203.0.113.7",
    outcome: str = "failure",
    offset_seconds: int = 0,
    start: datetime = BURST_START,
) -> NormalizedEvent:
    """One sshd authentication event, ``offset_seconds`` into the burst."""
    timestamp = start + timedelta(seconds=offset_seconds)
    verb = "Failed" if outcome == "failure" else "Accepted"
    return NormalizedEvent(
        event_id=uuid.uuid4().hex,
        timestamp=timestamp,
        domain="network",
        telemetry_source="sshd",
        actor=Actor(source_ip=source_ip, account=account),
        target=Target(host=host, port=22),
        auth=AuthEvent(
            protocol="ssh",
            outcome=outcome,
            reason="invalid_password" if outcome == "failure" else "accepted",
        ),
        raw=(
            f"{timestamp:%b %d %H:%M:%S} {host} sshd[4242]: {verb} password for {account} "
            f"from {source_ip} port 51234 ssh2"
        ),
    )


def make_web_event_impl(
    *,
    path: str = "/search",
    query: dict[str, str] | None = None,
    body: str | None = None,
    method: str = "GET",
    status: int = 200,
    source_ip: str = "203.0.113.50",
    account: str | None = None,
    host: str = "shop.example.com",
    offset_seconds: int = 0,
    start: datetime = BURST_START,
) -> NormalizedEvent:
    """One HTTP request event, already parsed. The unit of web detection."""
    timestamp = start + timedelta(seconds=offset_seconds)
    params = query or {}
    rendered = "&".join(f"{key}={value}" for key, value in params.items())
    return NormalizedEvent(
        event_id=uuid.uuid4().hex,
        timestamp=timestamp,
        domain="web",
        telemetry_source="app_log",
        actor=Actor(source_ip=source_ip, account=account, user_agent="Mozilla/5.0"),
        target=Target(host=host, endpoint=path),
        request=WebRequest(
            method=method,
            path=path,
            query_params=params,
            body=body,
            headers={},
            status_code=status,
        ),
        raw=f'{source_ip} - - [15/Aug/2026] "{method} {path}?{rendered}" {status} 100',
    )


@pytest.fixture
def make_web_event() -> Callable[..., NormalizedEvent]:
    """Factory for a parsed HTTP request; see :func:`make_web_event_impl` for the knobs."""
    return make_web_event_impl


@pytest.fixture
def make_ssh_event() -> Callable[..., NormalizedEvent]:
    """Expose :func:`make_ssh_event` as a fixture.

    Not imported directly: with no ``__init__.py`` under ``tests/``, ``tests.conftest``
    resolves against whatever else on ``sys.path`` is called ``tests``. Fixtures are the only
    import-safe way to share a helper across suites.
    """
    return make_ssh_event_impl


@pytest.fixture
def ssh_events() -> Callable[..., list[NormalizedEvent]]:
    """Factory for a burst: ``ssh_events(count=12, succeeded=True)``."""

    def build(
        count: int = 12,
        *,
        succeeded: bool = False,
        account: str = "root",
        host: str = "bastion-01",
        source_ip: str = "203.0.113.7",
        spacing_seconds: int = 5,
    ) -> list[NormalizedEvent]:
        events = [
            make_ssh_event_impl(
                account=account,
                host=host,
                source_ip=source_ip,
                offset_seconds=index * spacing_seconds,
            )
            for index in range(count)
        ]
        if succeeded:
            events.append(
                make_ssh_event_impl(
                    account=account,
                    host=host,
                    source_ip=source_ip,
                    outcome="success",
                    offset_seconds=count * spacing_seconds,
                )
            )
        return events

    return build


@pytest.fixture
def feature_dir(fake_repo: Path) -> Path:
    """A complete, compliant feature folder under ``docs/features/``."""
    feature = fake_repo / "docs" / "features" / "web-sql-injection-detection"
    write(
        feature / "README.md",
        "# Feature -- Web SQL Injection Detection\n\n"
        "**Status:** in-progress\n"
        "**Code:** `src/talos/domains/web/injection/sql_injection_detector.py`\n",
    )
    for name in ("design.md", "testing.md", "changelog.md", "detection-logic.md"):
        write(feature / name, f"# {name}\n")
    return feature
