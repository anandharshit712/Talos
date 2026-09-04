"""**The P7 gate.** A posted event goes through the real pipeline into PostgreSQL and comes back.

Skipped unless ``TALOS_TEST_DB_DSN`` names a database the suite may write to; see
``test_verdict_log_postgres.py`` for the setup.

Nothing is doubled here. The app provisions its own pool, the orchestrator is the real one with
every domain agent registered, and the incident is read back out of the database through a second
request -- which is the only way to prove the API and the store agree about what was written.

The model layer is switched off: detection is statistical, and a gate that depends on a hosted
free tier answering is not a gate.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from talos.core.settings import DatabaseSettings, TalosSettings
from talos.output.api.api_server import create_app
from talos.schemas.event_schema import Actor, AuthEvent, NormalizedEvent, Target
from talos.storage.postgres_connection_pool import PostgresConnectionPool

DSN_ENV = "TALOS_TEST_DB_DSN"
DSN = os.environ.get(DSN_ENV, "").strip()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason=f"{DSN_ENV} is not set; see this module's docstring"),
]

#: A burst well past the SSH threshold, on an account nothing else in the suite touches.
ACCOUNT = "gate-root"
HOST = "gate-bastion"
SOURCE_IP = "203.0.113.199"
BURST_START = datetime(2026, 9, 4, 12, 0, 0, tzinfo=UTC)


def _event(offset_seconds: int, *, outcome: str = "failure") -> NormalizedEvent:
    when = BURST_START + timedelta(seconds=offset_seconds)
    verb = "Failed" if outcome == "failure" else "Accepted"
    return NormalizedEvent(
        # Required by the frozen contract: the caller owns event identity, because the caller
        # is the one that can correlate a report back to its own telemetry.
        event_id=uuid.uuid4().hex,
        timestamp=when,
        domain="network",
        telemetry_source="sshd",
        actor=Actor(source_ip=SOURCE_IP, account=ACCOUNT),
        target=Target(host=HOST, port=22),
        auth=AuthEvent(protocol="ssh", outcome=outcome, reason="invalid_password"),
        raw=(
            f"{when:%b %d %H:%M:%S} {HOST} sshd[4242]: {verb} password for {ACCOUNT} "
            f"from {SOURCE_IP} port 51234 ssh2"
        ),
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A live app on the test database, with the rows it wrote removed afterwards.

    Cleanup opens its own short-lived pool: the app closes its own on shutdown, and reusing a
    closed pool is exactly the cross-loop mistake the pool now refuses.
    """
    settings = TalosSettings.load()
    settings.llm.enabled = False
    # Retention must never delete from an operator's history during a test run.
    settings.storage.database.retention_days = 0

    try:
        with TestClient(create_app(settings, dsn=DSN)) as test_client:
            yield test_client
    finally:

        async def cleanup() -> None:
            pool = PostgresConnectionPool(DSN, DatabaseSettings())
            try:
                async with pool.acquire() as connection:
                    await connection.execute(
                        "DELETE FROM verdict_log WHERE report_json->>'summary' LIKE $1",
                        f"%{HOST}%",
                    )
            finally:
                await pool.close()

        asyncio.run(cleanup())


def test_a_posted_burst_returns_a_report(client: TestClient) -> None:
    """**The gate.** `talos serve` accepts a posted event and returns a report."""
    reports = []
    for offset in range(12):
        response = client.post("/events", json=_event(offset * 4).model_dump(mode="json"))
        assert response.status_code in (200, 204), response.text
        if response.status_code == 200:
            reports.append(response.json())

    assert reports, "twelve failures past the threshold must produce an incident"
    final = reports[-1]
    assert final["category"] == "network_brute_force"
    assert final["aggregate_scope"]["affected_accounts"] == [ACCOUNT]
    assert final["verdicts"], "the pipeline trace is the deliverable"
    assert final["verdicts"][0]["model"]["used_llm"] is False


def test_the_reported_incident_is_readable_back_from_the_database(client: TestClient) -> None:
    """Two requests, one row: this is what proves the API and the store agree."""
    incident_id = None
    for offset in range(12):
        response = client.post("/events", json=_event(offset * 4).model_dump(mode="json"))
        if response.status_code == 200:
            incident_id = response.json()["incident_id"]
    assert incident_id is not None

    fetched = client.get(f"/reports/{incident_id}")
    assert fetched.status_code == 200
    assert fetched.json()["incident_id"] == incident_id
    assert fetched.json()["verdicts"][0]["evidence"], "evidence must survive the round trip"


def test_the_incident_appears_in_the_recent_listing(client: TestClient) -> None:
    for offset in range(12):
        client.post("/events", json=_event(offset * 4).model_dump(mode="json"))

    listed = client.get("/reports", params={"limit": 50})
    assert listed.status_code == 200
    assert any(HOST in report["summary"] for report in listed.json())


def test_healthz_reports_a_working_database(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "storage": "ok"}


def test_the_openapi_document_renders(client: TestClient) -> None:
    document = client.get("/openapi.json").json()
    assert set(document["paths"]) == {"/events", "/reports", "/reports/{incident_id}", "/healthz"}
