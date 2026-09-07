# Feature — Incident Aggregation and Output

**Status:** stable
**Owner:** Harshit Anand
**Code:** `src/talos/storage/postgres_connection_pool.py`, `src/talos/orchestrator/event_orchestrator.py`, `src/talos/orchestrator/agent_registry.py`, `src/talos/orchestrator/verdict_aggregator.py`, `src/talos/output/sinks/stdout_sink.py`, `src/talos/output/sinks/json_file_sink.py`, `src/talos/storage/verdict_log_store.py`, `src/talos/cli/main_cli.py`
**Config:** `config/default.yaml` → `talos.aggregation`, `talos.output`, `talos.storage`
**Tests:** `tests/unit/orchestrator/`, `tests/unit/output/sinks/`, `tests/unit/storage/test_verdict_log_store.py`, `tests/unit/storage/test_postgres_connection_pool.py`, `tests/unit/cli/test_main_cli.py`, `tests/integration/test_verdict_log_postgres.py`, `tests/e2e/test_ssh_brute_force_pipeline.py`
**Migrations:** `db/migrations/postgres/create_verdict_log_table_20260904_091113.sql` (+ rollback).
The SQLite set `db/migrations/create_verdict_log_table_20260817_120000.sql` is the pre-P6
history and stays forward-only (standards 4.3).

Turns the verdicts raised for one event into a single `IncidentReport`: deduped, scope-merged,
severity-scored, action-annotated — then writes it to the configured sinks and the audit trail.

Every contributing verdict travels into the report verbatim. The pipeline trace is the
deliverable, so nothing that produced the conclusion is summarised away.

| Document | Contents |
|---|---|
| [design.md](design.md) | routing, the five aggregation steps, the emit-or-`None` rule |
| [behaviour.md](behaviour.md) | inputs, outputs, severity table, actions, error handling, edge cases |
| [testing.md](testing.md) | cases covered, fixtures, results |
| [changelog.md](changelog.md) | dated entries |

**Scope for the hackathon slice:** stdout and JSON-file sinks plus the PostgreSQL audit trail
(SQLite through P5; the engine changed in P6.0 — HLD §7.1). The HTTP surface is P7.
