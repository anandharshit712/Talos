"""The report API's endpoints (LLD 2.1, P7).

Four routes, and the shape of each is chosen so the pipeline trace stays the deliverable:

- ``POST /events`` -- one ``NormalizedEvent`` through the real pipeline. ``200`` with the report,
  ``204`` when nothing fired.
- ``GET /reports`` -- the newest incidents first, bounded by ``recent_limit_max``.
- ``GET /reports/{incident_id}`` -- one recorded incident, ``404`` when it was never written.
- ``GET /healthz`` -- liveness **and** a real database round-trip.

**``204`` rather than an empty report.** Most events are not attacks. A body saying
``attack_detected: false`` would invite a caller to treat absence of evidence as a verdict, and
the orchestrator's own contract is that ``None`` means nothing fired -- not an empty incident.

**Malformed events are pydantic's job.** ``NormalizedEvent`` is ``extra="forbid"`` with bounded
fields, so a bad body is a ``422`` naming the offending field before a line of Talos code runs.
That is the trust boundary: nothing downstream has to re-validate.

**Submitted events are attacker-controlled data.** Everything a detector does with one already
treats it that way (payloads are delimited and length-bounded before prompting, HLD §11/§13);
accepting them over HTTP changes who can supply one, not how it is handled.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from talos.core.error_types import StorageError
from talos.core.settings import TalosSettings
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport

_log = logging.getLogger(__name__)

router = APIRouter()


@dataclass
class TalosState:
    """Everything the routes need, resolved once at startup by the app factory.

    A typed object rather than string keys on ``app.state``: a route reaching for
    ``app.state.orchestrator`` gets ``Any``, so a typo there is a 500 at runtime instead of an
    error from mypy. It lives here rather than beside the factory because the factory imports
    this module, and the reverse would be a cycle.
    """

    settings: TalosSettings
    orchestrator: Any
    verdict_log: Any


def state_of(request: Request) -> TalosState:
    """The application state, typed. Every route reads its dependencies through this."""
    state: TalosState = request.app.state.talos
    return state


@router.get("/healthz", tags=["ops"], summary="Liveness, including the database")
async def healthz(request: Request) -> dict[str, object]:
    """Report readiness, and say which part is unhealthy when one is.

    The database round-trip is the point. A process that answers ``200`` while unable to record
    an incident is exactly the failure this endpoint exists to catch, so a health check that
    only proved the event loop was running would be worse than none.
    """
    store = state_of(request).verdict_log
    try:
        await store.recent(limit=1)
    except StorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "degraded", "storage": str(exc)},
        ) from exc
    return {"status": "ok", "storage": "ok"}


@router.post(
    "/events",
    tags=["ingest"],
    summary="Submit one normalised event",
    response_model=None,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "An incident was raised; the report is the body."},
        204: {"description": "The event was analysed and nothing fired."},
        422: {"description": "The event does not satisfy the NormalizedEvent contract."},
        503: {"description": "The event could not be recorded."},
    },
)
async def submit_event(event: NormalizedEvent, request: Request) -> Response | IncidentReport:
    """Run one event through the whole pipeline and return what it produced."""
    orchestrator = state_of(request).orchestrator
    try:
        report: IncidentReport | None = await orchestrator.submit(event)
    except StorageError as exc:
        # Fail-safe for reporting: an incident that cannot be recorded must not be answered
        # with 200. The caller has to know its event was not accounted for.
        _log.warning("event analysed but not recorded", extra={"event_id": event.event_id})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if report is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return report


@router.get(
    "/reports",
    tags=["reports"],
    summary="Recent incidents, newest first",
    response_model=list[IncidentReport],
)
async def list_reports(
    request: Request, limit: int = Query(default=50, ge=1)
) -> list[IncidentReport]:
    """The newest incidents. ``limit`` is clamped to ``talos.output.api.recent_limit_max``."""
    state = state_of(request)
    ceiling = state.settings.output.api.recent_limit_max
    try:
        reports: list[IncidentReport] = await state.verdict_log.recent(limit=min(limit, ceiling))
        return reports
    except StorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc


@router.get(
    "/reports/{incident_id}",
    tags=["reports"],
    summary="One recorded incident",
    response_model=IncidentReport,
    responses={404: {"description": "No incident was recorded under that id."}},
)
async def get_report(incident_id: str, request: Request) -> IncidentReport:
    """One incident, verbatim as it was recorded -- every verdict and its evidence."""
    store = state_of(request).verdict_log
    try:
        report: IncidentReport | None = await store.get(incident_id)
    except StorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"no incident recorded as {incident_id}"
        )
    return report
