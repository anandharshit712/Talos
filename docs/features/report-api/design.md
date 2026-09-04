# Design — Report API

## One pipeline, built once

`create_app` builds the orchestrator at startup and hands every request the same one. That is a
correctness requirement, not a performance one: the event window and the duplicate filter are
per-process state, so a per-request pipeline would forget the burst it is halfway through
detecting and would re-alert on every event of it.

The consequence is that the API is single-process. Two workers behind a load balancer would each
hold half the events, so a burst split between them might trip neither threshold. That is a real
constraint on how this can be deployed, and it belongs in the open items rather than in a
docstring nobody reads: the fix is a shared window (Redis, or the database), and the trigger is
needing more than one process.

## `create_app` takes its dependencies, or provisions them

With no arguments it opens its own pool and builds the real pipeline — what `talos serve` does.
Passing `orchestrator` and `verdict_log` supplies them instead, which is how the route tests run
with no database.

That is not a test hook bolted on. It is the same separation the stores already have: the routes
depend on the `VerdictRecorder`/orchestrator behaviour, never on asyncpg, so the thing under test
in a route test is the route.

## Typed state, not string keys

`app.state.orchestrator` returns `Any`, so a typo in a route is a 500 at runtime. `TalosState` is
a dataclass and `state_of(request)` returns it typed, so mypy catches the typo instead.

It lives in `report_routes` rather than beside the factory because the factory imports the
routes; the reverse would be a cycle. A third module for two declarations would be worse than
either.

## Why the pool is opened in the lifespan hook

An `asyncpg` pool belongs to the event loop that created it. Opening one at import time binds it
to whichever loop happened to be current, and uvicorn then runs a different one — which fails
deep in the driver as "another operation is in progress". The pool refuses that explicitly now
(LLD §16.12), and the lifespan hook is where a pool can be opened on the right loop.

## Retention at startup, not on a timer

One dated delete when the service starts. A timer would mean a background task, a schedule to
configure, and a failure mode that only shows up at 3am; a delete-on-start is enough at this
size and has an obvious trigger. The upgrade path when the table outgrows it is partitioning by
month, which PostgreSQL does natively and SQLite could not have.

A scan never prunes. Deleting an operator's history as a side effect of reading a log file would
be indefensible.

## `talos replay` rather than a second script

The plan listed both a `replay` subcommand and `scripts/replay_log_file.py`. Building both means
two implementations of the same job, which R3 exists to prevent — and standards §1.3 says the
entry point is a console subcommand. `replay` is the subcommand; the script is cut.

`scripts/generate_sample_logs.py` stays, because synthesising a corpus is a different job from
replaying one. Every generator in it comes in a pair — an attack and the benign traffic it must
be told apart from — because a corpus of attacks alone measures recall, and recall alone is what
a detector that fires on everything scores perfectly.

Replay is synchronous, one request at a time. Sending concurrently would reorder events, and the
windowed detectors read order; it would also make the trace unreadable, which is the thing the
demo is for.

## What is deliberately absent

| Absent | Why, and what would bring it in |
|---|---|
| Authentication | Nothing here is multi-tenant, and a token check that is not enforced anywhere else is theatre. Loopback by default, warned on any other bind. Needed the moment this is deployed off a workstation |
| Rate limiting | The only client is a replay tool or a collector. Needed when an untrusted party can post |
| TLS | Terminated upstream in any real deployment |
| Pagination cursors | `limit` on a newest-first list answers "what just happened", which is the question the API exists for. A cursor is P8+ if the listing is used for export |
| Bulk `POST /events` | Would help throughput and hurt the trace: a rejected event in a batch of 500 is much harder to point at. Revisit only if measurement shows per-request overhead dominating |
| Websocket / streaming | A demo wants a readable trace, not a firehose |
