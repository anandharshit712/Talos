"""The trace visualiser's endpoints (HLD P9).

The demo's claim is that Talos shows its reasoning rather than a score, so the browser has to be
served the reasoning itself -- every event, what it was routed to, the evidence behind each
verdict, the confidence, and the incident it aggregated into. That structure is
``demo_trace_engine.Trace``, and these routes hand it over unchanged:

- ``GET /trace/chains`` -- the prepared attack chains, each with its log, so the page has
  something to run before anyone has typed anything.
- ``POST /trace`` -- raw log lines for one domain, through the real pipeline, back as a trace.

**Neither route owns any detection logic.** They call the same ``trace_for`` that ``talos demo``
calls, so the terminal and the browser cannot disagree about what the pipeline concluded -- a
difference between them would have to be a rendering difference.

**Submitted logs are attacker-controlled, and bounded here.** ``POST /trace`` accepts text from
whoever can reach the port and runs it through parsers and detectors. Every detector already
treats log content as data rather than instruction (payloads are delimited and length-bounded
before prompting, HLD 11/13), so the new exposure is volume, not handling: the length and line
ceilings are ``output.api.max_trace_log_chars`` and ``max_trace_log_lines``.

**The pipeline runs on a worker thread.** ``build_trace`` owns its event loop -- it calls
``asyncio.run`` -- so calling it directly inside a route would raise, and running it inline would
block every other request for the length of the scan.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from talos.core.error_types import TalosError
from talos.output.api.report_routes import state_of
from talos.output.demo_trace_engine import (
    DEFAULT_SYSLOG_YEAR,
    DEMO_CHAINS,
    Trace,
    chain_for,
    trace_for,
)

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/trace", tags=["trace"])

#: Domains with a parser. A request naming anything else is a 422, not a silent empty trace.
DOMAINS = tuple(chain.domain for chain in DEMO_CHAINS)


class TraceRequest(BaseModel):
    """One log to run, and how to read it."""

    model_config = {"extra": "forbid"}

    domain: str = Field(description="web | network -- which parser reads the lines")
    log: str = Field(description="raw log text, one event per line")
    year: int = Field(
        default=DEFAULT_SYSLOG_YEAR,
        ge=1970,
        le=2100,
        description="year for year-less syslog stamps; ignored for web access logs",
    )


class ChainView(BaseModel):
    """A prepared chain, with the log it runs, ready for the page's picker."""

    domain: str
    title: str
    log: str


@router.get("/chains", summary="The prepared attack chains and their logs")
async def list_chains() -> list[ChainView]:
    """Every chain ``talos demo`` runs, so the page opens with something real to show."""
    return [
        ChainView(domain=chain.domain, title=chain.title, log=chain.path().read_text("utf-8"))
        for chain in DEMO_CHAINS
    ]


@router.post(
    "",
    summary="Run a log through the pipeline and return the annotated trace",
    responses={
        200: {"description": "The trace: every event, its verdicts, evidence and incidents."},
        413: {"description": "The submitted log is past the configured ceiling."},
        422: {"description": "The domain has no parser, or the body is malformed."},
    },
)
async def run_trace(body: TraceRequest, request: Request) -> dict[str, Any]:
    """Run raw log lines through the real pipeline and return what each stage decided."""
    if body.domain not in DOMAINS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unknown domain {body.domain!r}; expected one of {', '.join(DOMAINS)}",
        )

    api = state_of(request).settings.output.api
    lines = body.log.splitlines()
    if len(body.log) > api.max_trace_log_chars or len(lines) > api.max_trace_log_lines:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"log is {len(body.log)} chars over {len(lines)} lines; the ceiling is "
                f"{api.max_trace_log_chars} chars and {api.max_trace_log_lines} lines"
            ),
        )

    settings = state_of(request).settings
    chain = chain_for(body.domain)
    title = chain.title if chain is not None else f"{body.domain} - submitted log"
    try:
        trace: Trace = await asyncio.to_thread(
            trace_for, body.domain, lines, settings, title=title, year=body.year
        )
    except TalosError as exc:
        # A detector that fails must not take the surface down with it: the caller gets a reason
        # rather than a 500 with a traceback, and the process keeps serving.
        _log.warning("trace run failed", extra={"domain": body.domain, "error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return trace.to_dict()
