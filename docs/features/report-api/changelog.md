# Changelog — Report API

## 2026-09-04 — the HTTP surface (P7)

- Added `create_app`, the FastAPI factory. It builds the pipeline once at startup and shares it,
  because the event window and the duplicate filter are per-process state — a per-request
  pipeline would forget the burst it is halfway through detecting. Dependencies can be supplied
  instead of provisioned, which is how the route tests run with no database.
- Added the four routes: `POST /events`, `GET /reports`, `GET /reports/{incident_id}`,
  `GET /healthz`. `204` rather than a report saying "no attack"; `503` rather than `200` when an
  incident could not be recorded; `422` from the contract before any Talos code runs.
- `/healthz` does a real database round-trip. A process that answers `200` while unable to record
  an incident is exactly the failure it exists to catch.
- Added `talos serve` and `talos replay`. `serve` binds **loopback by default** and warns on any
  other address, because Talos has no authentication and anything else publishes an
  unauthenticated incident feed. `replay` streams a log file into a running server one event at
  a time — synchronous on purpose, because sending concurrently reorders events and the windowed
  detectors read order.
- Added `scripts/generate_sample_logs.py`: eight reproducible corpora, **each attack paired with
  the benign traffic it must be told apart from**. Fixed timestamps and addresses, no randomness
  — a corpus that changes between runs cannot compare two versions of a detector.
- **`scripts/replay_log_file.py` is cut.** The plan listed it alongside `talos replay`; building
  both is two implementations of one job, which R3 exists to prevent, and standards §1.3 makes
  the subcommand the entry point.
- Added config: `talos.output.api` (`host`, `port`, `recent_limit_max`),
  `talos.storage.database.retention_days`, and `talos.aggregation.suppression_ttl_seconds` /
  `max_tracked_incidents`.
- **Closed two open items carried since P2:**
  - **The duplicate filter cleared itself when full.** `MAX_TRACKED_INCIDENTS` was a hard cap on
    a plain dict, and hitting it wiped every remembered signature — so on a long-running server
    a burst of unrelated incidents would erase the memory of an attack still in progress, and
    every one of those attacks would then re-alert. It is now a TTL map in **event** time
    (matching the event window, so a replay behaves like a live stream), ordered so eviction
    takes the oldest rather than everything.
  - **No retention policy on `verdict_log`.** `VerdictLogStore.prune()` plus a dated delete at
    server startup. `0` keeps everything. A failed prune is logged and the service starts anyway.
    A scan never prunes — deleting history as a side effect of reading a log file would be
    indefensible.
- **Gate passed:** a posted burst returns an incident; the incident reads back out of PostgreSQL
  through a second request with its evidence intact; the OpenAPI document renders.
- **Known limitations, all deliberate:** no authentication, rate limiting or TLS; single-process
  only, because the event window is per-process and two workers would each see half a burst; the
  window is RAM-only, so a restart mid-burst restarts its count. Each is recorded with the
  trigger that would change it, in [design.md](design.md) and [behaviour.md](behaviour.md).
