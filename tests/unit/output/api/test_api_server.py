"""The application factory: what it builds, when it opens a socket, and what it prunes.

Nothing here needs a database. The self-provisioning path is checked by what it *asks for* --
the pool it would open and the retention it would apply -- rather than by opening it, because
"does asyncpg connect" is the integration suite's question, not this one.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from talos.core.error_types import StorageError
from talos.core.settings import TalosSettings
from talos.output.api import api_server
from talos.output.api.api_server import create_app
from talos.output.api.report_routes import TalosState


class StubStore:
    def __init__(self, pruned: int = 0, prune_raises: Exception | None = None) -> None:
        self.prune_calls: list[int] = []
        self.pruned = pruned
        self.prune_raises = prune_raises

    async def recent(self, limit: int = 50) -> list[Any]:
        return []

    async def get(self, incident_id: str) -> Any | None:
        return None

    async def prune(self, older_than_days: int) -> int:
        self.prune_calls.append(older_than_days)
        if self.prune_raises is not None:
            raise self.prune_raises
        return self.pruned


class StubOrchestrator:
    async def submit(self, event: Any) -> Any | None:
        return None


def test_construction_opens_no_socket() -> None:
    """Building the app must not touch the network: the pool belongs to uvicorn's loop."""
    create_app(TalosSettings(), orchestrator=StubOrchestrator(), verdict_log=StubStore())


def test_supplied_dependencies_reach_the_routes() -> None:
    orchestrator = StubOrchestrator()
    store = StubStore()
    app = create_app(TalosSettings(), orchestrator=orchestrator, verdict_log=store)

    with TestClient(app):
        state = app.state.talos
        assert isinstance(state, TalosState)
        assert state.orchestrator is orchestrator
        assert state.verdict_log is store


def test_supplied_dependencies_skip_the_retention_prune() -> None:
    """Only the self-provisioning path owns the database, so only it may delete from it."""
    store = StubStore()
    with TestClient(
        create_app(TalosSettings(), orchestrator=StubOrchestrator(), verdict_log=store)
    ):
        pass
    assert store.prune_calls == []


def test_the_app_is_titled_and_versioned() -> None:
    app = create_app(TalosSettings(), orchestrator=StubOrchestrator(), verdict_log=StubStore())
    assert app.title == "Talos"
    assert app.version


# --- retention ------------------------------------------------------------------------------


def test_retention_prunes_at_the_configured_age() -> None:
    settings = TalosSettings()
    settings.storage.database.retention_days = 30
    store = StubStore(pruned=12)

    import asyncio

    asyncio.run(api_server._prune(store, settings))  # type: ignore[arg-type]
    assert store.prune_calls == [30]


def test_retention_of_zero_keeps_everything() -> None:
    """ "No retention policy" is a real answer for anyone who needs the full history."""
    settings = TalosSettings()
    settings.storage.database.retention_days = 0
    store = StubStore()

    import asyncio

    asyncio.run(api_server._prune(store, settings))  # type: ignore[arg-type]
    assert store.prune_calls == []


def test_a_failed_prune_does_not_stop_the_service() -> None:
    """Keeping too much history costs disk; not starting costs every incident from now on."""
    settings = TalosSettings()
    settings.storage.database.retention_days = 30
    store = StubStore(prune_raises=StorageError("permission denied"))

    import asyncio

    asyncio.run(api_server._prune(store, settings))  # type: ignore[arg-type]  # must not raise


# --- the self-provisioning path -------------------------------------------------------------


def test_the_self_provisioning_path_needs_a_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    """No audit trail, no service -- the same rule the scan follows."""
    from talos.core.error_types import ConfigError

    monkeypatch.delenv("TALOS_DB_DSN", raising=False)
    app = create_app(TalosSettings())

    with pytest.raises(ConfigError) as caught, TestClient(app):
        pass
    assert "TALOS_DB_DSN" in str(caught.value)


def test_the_dsn_argument_beats_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """What ``talos serve --dsn`` relies on."""
    opened: list[str] = []

    class FakePool:
        def __init__(self, dsn: str, config: Any) -> None:
            opened.append(dsn)

        async def close(self) -> None:
            return None

    monkeypatch.setattr(api_server, "PostgresConnectionPool", FakePool)
    monkeypatch.setattr(api_server, "VerdictLogStore", lambda pool: StubStore())
    monkeypatch.setenv("TALOS_DB_DSN", "postgresql://from-env/talos")

    settings = TalosSettings()
    settings.storage.database.retention_days = 0
    with TestClient(create_app(settings, dsn="postgresql://from-arg/talos")):
        pass

    assert opened == ["postgresql://from-arg/talos"]
