# Testing — Report API

Two layers. The routes are tested through FastAPI's `TestClient` with the pipeline and store
supplied, so a route test needs no database and cannot quietly become a detector test that
happens to go through HTTP. The live gate runs the real thing against PostgreSQL.

## Routes (`tests/unit/output/api/test_report_routes.py`, 16 cases)

**`POST /events`**

- an event that fires returns `200` and the report
- an event that fires nothing returns `204` with an empty body, not a report saying "no attack"
- the event reaches the pipeline intact — same `event_id`, same source address
- a malformed body is `422` **and never reaches the pipeline**: the contract is the trust boundary
- an unknown field is `422` rather than ignored (`extra="forbid"`)
- a storage failure is `503`, not `200` — the caller has to know its event was not recorded

**`GET /reports`**

- newest first
- `limit` is clamped to `recent_limit_max`, asserted by what the store was asked for
- `limit=0` is `422`
- a storage failure is `503`

**`GET /reports/{incident_id}`**

- the report round-trips and revalidates as an identical `IncidentReport`, evidence included
- an unknown id is `404` and the message names the id

**`GET /healthz`**

- `200` with `{"status": "ok", "storage": "ok"}` when the database answers
- `503` with `degraded` when it does not — the failure this endpoint exists to catch

**The contract surface**

- `/openapi.json` names exactly the four routes
- `/docs` renders

## The factory (`tests/unit/output/api/test_api_server.py`, 9 cases)

- construction opens no socket; the pool belongs to uvicorn's loop
- supplied dependencies reach the routes as a typed `TalosState`
- supplied dependencies **skip the retention prune** — only the self-provisioning path owns the
  database, so only it may delete from it
- retention prunes at the configured age; `0` keeps everything; a failed prune does not stop the
  service
- the self-provisioning path raises `ConfigError` naming `TALOS_DB_DSN` when it is unset
- `--dsn` beats the environment

## CLI (`tests/unit/cli/test_main_cli.py`)

- `serve` uses the configured host and port; flags beat configuration
- binding a non-loopback address logs the missing-authentication warning
- `replay` posts every parsed event to `<url>/events`, counts the incidents, prints them
- a `422` on one line is reported and the rest of the file continues
- replaying a missing file exits 2
- **the model layer is off in every CLI test**, with a guard test that fails if that is removed

## The P7 gate (`tests/integration/test_report_api_postgres.py`) — **passed 2026-09-04**

Skipped unless `TALOS_TEST_DB_DSN` is set. Nothing doubled: the app provisions its own pool, the
orchestrator is the real one with both domain agents registered, and the model layer is switched
off because a gate that depends on a hosted free tier answering is not a gate.

- **a posted burst returns a report** — twelve SSH failures through `POST /events`, the incident
  comes back as `network_brute_force` scoped to the account, `used_llm=false`
- **the incident reads back out of the database** through `GET /reports/{id}` with its evidence
  intact. Two requests, one row: this is what proves the API and the store agree about what was
  written
- the incident appears in `GET /reports`
- `/healthz` reports a working database
- the OpenAPI document renders with all four routes

Rows written by the gate are deleted afterwards, through a fresh pool — the app closes its own on
shutdown, and reusing a closed one is the cross-loop mistake the pool now refuses.

## Not covered

- **Concurrency under load.** The routes are `async` and the pool is shared, and the baseline's
  per-account lock has its own concurrency test (P6.1), but nothing here drives the API with
  parallel clients. Throughput measurement is P8.
- **Multi-process deployment.** It does not work, by design — the event window is per-process.
  Documented in [design.md](design.md) rather than tested.
- **A restart mid-burst.** The window is RAM-only; the limitation is documented in
  [behaviour.md](behaviour.md) and carried in the tracker's open items.
