# Behaviour — Report API

## `POST /events`

Submit one `NormalizedEvent`. It goes through the real pipeline: window, domain agent,
classifier, sub-agent, detectors, aggregator, verdict log.

| Status | When | Body |
|---|---|---|
| `200` | an incident was raised | the `IncidentReport`, every verdict and its evidence |
| `204` | the event was analysed and nothing fired | empty |
| `422` | the body is not a valid `NormalizedEvent` | pydantic's field-level errors |
| `503` | the incident could not be recorded | the storage error |

**`204`, not a report saying "no attack".** Most events are not attacks. A body carrying
`attack_detected: false` invites a caller to read absence of evidence as a verdict, and the
orchestrator's own contract is that `None` means nothing fired — not an empty incident.

**`event_id` is required.** The caller owns event identity, because the caller is the only party
that can correlate a report back to its own telemetry. `NormalizedEvent` is frozen (P1), so this
is the contract rather than a choice made here.

**`503` rather than `200` on a storage failure.** Fail-safe for reporting: an event that was
analysed but not recorded has not been accounted for, and the caller has to know that. The
detection result is discarded with it — resubmitting is the correct response.

**Submitted events are attacker-controlled data.** Every detector already treats them that way:
payloads are delimited and length-bounded before they reach a prompt (HLD §11/§13). Accepting
events over HTTP changes *who can supply one*, not how one is handled.

## `GET /reports?limit=`

The newest incidents first. `limit` defaults to 50, must be ≥ 1, and is clamped to
`talos.output.api.recent_limit_max` (200) so one request cannot ask for the whole table.

| Status | When |
|---|---|
| `200` | a list, newest first — possibly empty |
| `422` | `limit` below 1 |
| `503` | the store could not be read |

An empty list is a `200`. Nothing recorded is a fact, not an error.

## `GET /reports/{incident_id}`

One incident, verbatim as it was recorded — every verdict, every piece of evidence, the MITRE
mappings and the recommended actions.

| Status | When |
|---|---|
| `200` | the incident |
| `404` | no incident was recorded under that id; the message names the id |
| `503` | the store could not be read |

**Nothing is summarised away.** The pipeline trace is the deliverable, so the response is the
stored report rather than a projection of it.

## `GET /healthz`

Liveness **and** a database round-trip.

| Status | Body |
|---|---|
| `200` | `{"status": "ok", "storage": "ok"}` |
| `503` | `{"status": "degraded", "storage": "<error>"}` |

The round-trip is the point. A process that answers `200` while unable to record an incident is
exactly the failure this endpoint exists to catch, so a check that only proved the event loop was
running would be worse than none.

## `GET /docs`, `GET /openapi.json`

The generated contract. Part of the deliverable: a reviewer reads what the service accepts and
returns without reading the code.

## Startup and shutdown

- The PostgreSQL pool opens in the lifespan hook, not at import — an `asyncpg` pool belongs to
  the event loop that created it, which is uvicorn's.
- The retention policy is applied once, at startup: incidents older than
  `talos.storage.database.retention_days` (90) are deleted. `0` keeps everything. A failed prune
  is logged and the service starts anyway — keeping too much history costs disk, and not
  starting costs every incident from now on.
- The pool closes on shutdown.

## Edge cases and limitations

| Case | Behaviour |
|---|---|
| Two events with the same `event_id` | both are analysed; the window holds both. Deduplication is by incident signature, not event id |
| An ongoing attack posted event by event | one incident at the crossing, then again only on escalation (`talos.aggregation.suppress_duplicates`) |
| Suppression memory | a TTL map in **event** time, `suppression_ttl_seconds` (3600), capped at `max_tracked_incidents` (2048), evicting oldest-first |
| **A restart mid-burst** | the event window is RAM-only, so in-flight windows are lost and a burst in progress restarts its count. Deliberately not fixed in P7 — see below |
| No authentication, no rate limiting, no TLS | absent by design at this stage. Loopback by default, and a warning on any other bind address |
| Concurrent requests | the pipeline is `async` and the pool is shared; the baseline's per-account lock is what makes concurrent object accesses safe (P6.1) |

**The RAM-only event window is a known, deliberate limitation.** Fixing it means either
persisting every event on the hot path or replaying recent history at startup, and both are
larger than the surface they would protect: a restart is rare, and the cost is that one burst
resumes counting from zero rather than a wrong verdict. The trigger for revisiting it is P8
measurement showing restarts materially affect recall, or a deployment where restarts are
routine. Recorded in the build tracker's open items rather than silently carried.
