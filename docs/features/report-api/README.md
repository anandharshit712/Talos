# Feature — Report API

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/output/api/api_server.py`, `src/talos/output/api/report_routes.py`, `src/talos/cli/main_cli.py`
**Config:** `config/default.yaml` → `talos.output.api`, `talos.storage.database.retention_days`
**Tests:** `tests/unit/output/api/test_report_routes.py`, `tests/unit/output/api/test_api_server.py`, `tests/unit/cli/test_main_cli.py`, `tests/integration/test_report_api_postgres.py`

The HTTP surface: submit a normalised event, get back a scoped `IncidentReport`, and read
recorded incidents afterwards. Four routes, no more — `POST /events`, `GET /reports`,
`GET /reports/{incident_id}`, `GET /healthz`.

**The pipeline is the same one `talos scan` runs.** The API is a way in, not a second
implementation: one orchestrator, built at startup, shared by every request. That sharing is
required rather than convenient — the event window and the duplicate filter are per-process
state, so a per-request pipeline would forget the burst it is halfway through detecting.

**`talos serve` binds loopback by default.** Talos has no authentication, so any other bind
address publishes an unauthenticated incident feed onto the network. `--host 0.0.0.0` works and
logs a warning; putting it behind something that authenticates is the operator's job, and P7
does not pretend otherwise.

| Document | Contents |
|---|---|
| [design.md](design.md) | why one shared pipeline, why `204`, what is deliberately absent |
| [behaviour.md](behaviour.md) | every route, its statuses, error handling and edge cases |
| [testing.md](testing.md) | cases covered, and the live gate |
| [changelog.md](changelog.md) | dated entries |

**Gate passed 2026-09-04:** a posted burst returns an incident, the incident reads back out of
PostgreSQL through a second request with its evidence intact, and the OpenAPI document renders
with all four routes.
