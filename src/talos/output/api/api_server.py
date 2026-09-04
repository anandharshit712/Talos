"""The FastAPI application factory, and the state its routes read (LLD 2.1, P7).

``create_app`` builds the whole pipeline once, at startup, and hands every request the same
orchestrator. That is deliberate: the event window and the duplicate filter are per-process
state, so a per-request pipeline would forget the burst it is halfway through detecting.

**The pool's lifetime is the application's.** It is opened in the lifespan hook rather than at
import, because an ``asyncpg`` pool belongs to the event loop that created it -- the loop uvicorn
runs, not the one that happened to be current when the module was imported.

**State is a typed object, not string keys on ``app.state``.** ``TalosState`` and ``state_of``
live in ``report_routes`` -- this module imports that one, so the reverse would be a cycle.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from talos.core.error_types import StorageError
from talos.core.settings import TalosSettings
from talos.output.api.report_routes import TalosState, router
from talos.storage.postgres_connection_pool import PostgresConnectionPool
from talos.storage.verdict_log_store import VerdictLogStore

_log = logging.getLogger(__name__)

TITLE = "Talos"
DESCRIPTION = (
    "Multi-agent attack detection, classification and scope analysis. Submit normalised "
    "events; get back scoped incident reports carrying every verdict and its evidence."
)


def create_app(
    settings: TalosSettings | None = None,
    *,
    orchestrator: Any | None = None,
    verdict_log: Any | None = None,
    dsn: str | None = None,
) -> FastAPI:
    """Build the application.

    With no arguments it provisions its own pipeline and PostgreSQL pool -- what ``talos serve``
    does. Passing ``orchestrator`` and ``verdict_log`` supplies them instead, which is how the
    route tests run without a database: the routes are what is under test, not the driver.
    """
    resolved = settings or TalosSettings.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = None
        if orchestrator is None or verdict_log is None:
            # Imported here rather than at module scope: only the self-provisioning path needs
            # the CLI's wiring, and importing it eagerly would make the API depend on the CLI.
            from talos.cli.main_cli import build_orchestrator
            from talos.storage.baseline_store import BaselineStore

            pool = PostgresConnectionPool(
                dsn or resolved.storage.database.resolve_dsn(), resolved.storage.database
            )
            store = VerdictLogStore(pool)
            await _prune(store, resolved)
            app.state.talos = TalosState(
                settings=resolved,
                orchestrator=build_orchestrator(resolved, store, BaselineStore(pool)),
                verdict_log=store,
            )
        else:
            app.state.talos = TalosState(
                settings=resolved, orchestrator=orchestrator, verdict_log=verdict_log
            )
        try:
            yield
        finally:
            if pool is not None:
                await pool.close()

    app = FastAPI(
        title=TITLE,
        description=DESCRIPTION,
        version=_version(),
        lifespan=lifespan,
        # The OpenAPI page is part of the deliverable: it is how a reviewer sees the contract
        # without reading the code.
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.include_router(router)
    return app


async def _prune(store: VerdictLogStore, settings: TalosSettings) -> None:
    """Apply the retention policy once, at startup. Never fatal.

    A pruning failure must not stop the service from detecting: the cost of keeping too much
    history is disk, and the cost of not starting is every incident from now on.
    """
    days = settings.storage.database.retention_days
    if days <= 0:
        return
    try:
        removed = await store.prune(days)
    except StorageError as exc:
        _log.warning("retention prune failed, continuing", extra={"error": str(exc)})
        return
    if removed:
        _log.info("pruned incidents past retention", extra={"removed": removed, "days": days})


def _version() -> str:
    """The installed package version, or a placeholder when running from a source tree."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("talos")
    except PackageNotFoundError:
        return "0.0.0+source"
