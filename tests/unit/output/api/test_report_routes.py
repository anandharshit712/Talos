"""Every route, through FastAPI's ``TestClient``, with the pipeline and store supplied.

The routes are what is under test. The orchestrator and the store are doubles, so a route test
does not need PostgreSQL running -- and does not silently become a detector test that happens to
go through HTTP.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from talos.core.error_types import StorageError
from talos.core.settings import TalosSettings
from talos.output.api.api_server import create_app
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import Scope, Verdict


class StubOrchestrator:
    """Returns a staged report, or raises what a broken store would."""

    def __init__(self, report: IncidentReport | None = None, raises: Exception | None = None):
        self.report = report
        self.raises = raises
        self.submitted: list[NormalizedEvent] = []

    async def submit(self, event: NormalizedEvent) -> IncidentReport | None:
        self.submitted.append(event)
        if self.raises is not None:
            raise self.raises
        return self.report


class StubStore:
    """An in-memory verdict log with an optional failure mode."""

    def __init__(
        self, reports: list[IncidentReport] | None = None, raises: Exception | None = None
    ):
        self.reports = reports or []
        self.raises = raises
        self.limits: list[int] = []

    async def recent(self, limit: int = 50) -> list[IncidentReport]:
        if self.raises is not None:
            raise self.raises
        self.limits.append(limit)
        return self.reports[:limit]

    async def get(self, incident_id: str) -> IncidentReport | None:
        if self.raises is not None:
            raise self.raises
        return next((r for r in self.reports if r.incident_id == incident_id), None)


def _report(verdict: Verdict, incident_id: str = "incident-1") -> IncidentReport:
    return IncidentReport(
        incident_id=incident_id,
        domain=verdict.domain,
        category=verdict.category,
        summary="12 failed ssh logins for root@bastion-01",
        severity="high",
        confidence=verdict.confidence,
        verdicts=[verdict],
        aggregate_scope=verdict.scope or Scope(),
    )


@pytest.fixture
def client_for() -> Callable[..., Iterator[TestClient]]:
    """Build a client over a given orchestrator and store."""

    def build(orchestrator: Any, store: Any, settings: TalosSettings | None = None) -> TestClient:
        app = create_app(
            settings or TalosSettings(),
            orchestrator=orchestrator,
            verdict_log=store,
        )
        return TestClient(app)

    return build


# --- POST /events ---------------------------------------------------------------------------


def test_an_event_that_fires_returns_the_report(
    client_for: Any, sample_verdict: Verdict, make_ssh_event: Callable[..., NormalizedEvent]
) -> None:
    report = _report(sample_verdict)
    with client_for(StubOrchestrator(report), StubStore()) as client:
        response = client.post("/events", content=make_ssh_event().model_dump_json())

    assert response.status_code == 200
    assert response.json()["incident_id"] == "incident-1"


def test_an_event_that_fires_nothing_is_204_not_an_empty_report(
    client_for: Any, make_ssh_event: Callable[..., NormalizedEvent]
) -> None:
    """A body saying "no attack" invites a caller to read absence of evidence as a verdict."""
    with client_for(StubOrchestrator(None), StubStore()) as client:
        response = client.post("/events", content=make_ssh_event().model_dump_json())

    assert response.status_code == 204
    assert not response.content


def test_the_event_reaches_the_pipeline_intact(
    client_for: Any, make_ssh_event: Callable[..., NormalizedEvent]
) -> None:
    orchestrator = StubOrchestrator(None)
    event = make_ssh_event(account="root", source_ip="203.0.113.7")
    with client_for(orchestrator, StubStore()) as client:
        client.post("/events", content=event.model_dump_json())

    assert len(orchestrator.submitted) == 1
    assert orchestrator.submitted[0].event_id == event.event_id
    assert orchestrator.submitted[0].actor.source_ip == "203.0.113.7"


def test_a_malformed_event_is_422_before_any_talos_code_runs(client_for: Any) -> None:
    """``NormalizedEvent`` is the trust boundary, so nothing downstream re-validates."""
    orchestrator = StubOrchestrator(None)
    with client_for(orchestrator, StubStore()) as client:
        response = client.post("/events", json={"nonsense": True})

    assert response.status_code == 422
    assert orchestrator.submitted == [], "an invalid event must not reach the pipeline"


def test_an_unknown_field_is_rejected_rather_than_ignored(
    client_for: Any, make_ssh_event: Callable[..., NormalizedEvent]
) -> None:
    """``extra="forbid"``: a parser inventing a field is a contract break, not a silent pass."""
    payload = json.loads(make_ssh_event().model_dump_json())
    payload["invented_field"] = "surprise"

    with client_for(StubOrchestrator(None), StubStore()) as client:
        response = client.post("/events", json=payload)

    assert response.status_code == 422


def test_an_unrecordable_incident_is_503_not_200(
    client_for: Any, make_ssh_event: Callable[..., NormalizedEvent]
) -> None:
    """Fail-safe for reporting: the caller has to know its event was not accounted for."""
    orchestrator = StubOrchestrator(raises=StorageError("connection reset"))
    with client_for(orchestrator, StubStore()) as client:
        response = client.post("/events", content=make_ssh_event().model_dump_json())

    assert response.status_code == 503
    assert "connection reset" in response.json()["detail"]


# --- GET /reports ---------------------------------------------------------------------------


def test_recent_reports_are_listed(client_for: Any, sample_verdict: Verdict) -> None:
    store = StubStore([_report(sample_verdict, "a"), _report(sample_verdict, "b")])
    with client_for(StubOrchestrator(), store) as client:
        response = client.get("/reports")

    assert response.status_code == 200
    assert [item["incident_id"] for item in response.json()] == ["a", "b"]


def test_the_limit_is_clamped_to_the_configured_ceiling(
    client_for: Any, sample_verdict: Verdict
) -> None:
    """One request must not be able to ask for the whole table."""
    store = StubStore([_report(sample_verdict)])
    settings = TalosSettings()
    settings.output.api.recent_limit_max = 5

    with client_for(StubOrchestrator(), store, settings) as client:
        client.get("/reports", params={"limit": 10_000})

    assert store.limits == [5]


def test_a_limit_below_one_is_rejected(client_for: Any) -> None:
    with client_for(StubOrchestrator(), StubStore()) as client:
        assert client.get("/reports", params={"limit": 0}).status_code == 422


def test_a_storage_failure_listing_reports_is_503(client_for: Any) -> None:
    store = StubStore(raises=StorageError("no such table"))
    with client_for(StubOrchestrator(), store) as client:
        assert client.get("/reports").status_code == 503


# --- GET /reports/{id} ----------------------------------------------------------------------


def test_one_report_round_trips_with_every_verdict_intact(
    client_for: Any, sample_verdict: Verdict
) -> None:
    """The pipeline trace is the deliverable, so nothing may be summarised away in transit."""
    report = _report(sample_verdict)
    store = StubStore([report])

    with client_for(StubOrchestrator(), store) as client:
        response = client.get("/reports/incident-1")

    assert response.status_code == 200
    assert IncidentReport.model_validate(response.json()) == report
    assert response.json()["verdicts"][0]["evidence"], "evidence must survive the round trip"


def test_an_unknown_incident_is_404_and_names_the_id(client_for: Any) -> None:
    with client_for(StubOrchestrator(), StubStore()) as client:
        response = client.get("/reports/never-written")

    assert response.status_code == 404
    assert "never-written" in response.json()["detail"]


# --- GET /healthz ---------------------------------------------------------------------------


def test_healthz_is_ok_when_the_database_answers(client_for: Any) -> None:
    with client_for(StubOrchestrator(), StubStore()) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "storage": "ok"}


def test_healthz_is_503_when_the_database_does_not(client_for: Any) -> None:
    """A process that answers 200 while unable to record an incident is the failure to catch."""
    store = StubStore(raises=StorageError("connection refused"))
    with client_for(StubOrchestrator(), store) as client:
        response = client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["detail"]["status"] == "degraded"


# --- the contract surface -------------------------------------------------------------------


def test_the_openapi_document_renders_and_names_every_route(client_for: Any) -> None:
    """Part of the deliverable: a reviewer reads the contract without reading the code."""
    with client_for(StubOrchestrator(), StubStore()) as client:
        document = client.get("/openapi.json").json()

    assert set(document["paths"]) == {"/events", "/reports", "/reports/{incident_id}", "/healthz"}
    assert document["info"]["title"] == "Talos"


def test_the_docs_page_is_served(client_for: Any) -> None:
    with client_for(StubOrchestrator(), StubStore()) as client:
        assert client.get("/docs").status_code == 200
