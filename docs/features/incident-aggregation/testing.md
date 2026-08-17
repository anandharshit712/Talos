# Testing — Incident Aggregation and Output

## How to run

```bash
python -m pytest tests/unit/orchestrator tests/unit/output tests/unit/storage tests/unit/cli
python -m pytest tests/e2e/test_ssh_brute_force_pipeline.py
```

The storage, CLI, and e2e suites apply the real migration to a temporary database first, so the
migration runner is exercised on every run rather than assumed.

## Cases covered

**Aggregator** (`test_verdict_aggregator.py`)

- one verdict becomes one incident, carrying its verdict verbatim
- all-inconclusive input returns `None` — never an empty report
- duplicate verdicts collapse, keeping the confident one
- scopes union across verdicts and `succeeded` wins when any verdict says so
- two independent detectors raise aggregate confidence by exactly one boost
- severity rises on success, falls on low confidence
- actions name the real source address and account; success adds containment actions
- the summary reads as one triage line

**Orchestrator** (`test_event_orchestrator.py`)

- a quiet stream produces nothing
- the incident appears on the event that crosses the threshold, not the one after
- incidents reach the audit trail
- an event from an unregistered domain is a logged miss, not a crash
- an ongoing burst is reported once, not once per event past the threshold
- suppression yields to escalation: a trailing success and a doubled attempt count both re-report
- a different account is a different incident
- suppression can be switched off in config
- every verdict in every report has `used_llm=false` in this phase

**Registry** (`test_agent_registry.py`) — lookup, unknown domain is `None`, double registration
is a `ConfigError`.

**Sinks** (`test_stdout_sink.py`, `test_json_file_sink.py`)

- one parseable JSON object per line; two reports stay on two lines; `--pretty` indents
- a report round-trips back into `IncidentReport` from what the sink wrote
- one file per incident, directory created on demand
- an unwritable destination raises `StorageError` instead of dropping the report

**Audit trail** (`test_verdict_log_store.py`)

- reports round-trip through SQLite unchanged; unknown ids return `None`
- `recent()` is newest-first; re-appending an incident replaces it
- a database without migrations raises `StorageError` naming the fix
- the migration creates `verdict_log` and the `schema_migrations` ledger

**CLI** (`test_main_cli.py`)

- scanning the fixture prints an incident on stdout and a summary on stderr
- reports land in the JSON sink directory
- missing file exits 2; unmigrated database exits 1 naming `apply_migrations`
- an unknown sink in config is skipped, not fatal

## Latest observed results

2026-08-18 — 45 tests across aggregator, orchestrator, registry, sinks, store, and CLI, all
passing. End to end on `network_ssh_brute_force_sshd.log`: 15 events, 5 lines skipped,
**2 incidents** — the threshold crossing (`medium`, 0.70) and the escalation once the burst
succeeded (`high`, 0.90) — each written to stdout, the JSON sink, and the audit trail.
Without duplicate suppression the same burst emits 6.
