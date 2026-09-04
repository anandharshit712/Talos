# Changelog — Incident Aggregation and Output

## 2026-09-04 — the audit trail moves to PostgreSQL (P6.0)

- `VerdictLogStore` now speaks `asyncpg`. `INSERT OR REPLACE` became
  `ON CONFLICT (incident_id) DO UPDATE`, `created_at` became `timestamptz` instead of ISO text
  (so ordering no longer depends on lexical date sorting), and `report_json` became `jsonb` with
  a GIN index. The `VerdictRecorder` Protocol is untouched: **no agent, detector, orchestrator,
  or aggregator file changed in this port** — which is what making the store contracts `async`
  in P1 was for (LLD §16.6).
- Added `PostgresConnectionPool`: one pool per process, borrowed by every store, opened on first
  use. This closes the P2 limitation that the store held a single connection from `__init__` and
  never recovered if it dropped — asyncpg replaces a dead connection on the next acquire, so the
  fix is a dependency rather than a reconnect layer of our own.
- Added the PostgreSQL migration set `db/migrations/postgres/`, with its own `rollback/`. The
  SQLite set is untouched and stays forward-only (standards §4.3).
- `scripts/apply_migrations.py` takes `--engine {postgres,sqlite}`, defaulting to postgres. The
  `schema_migrations` ledger lives in whichever database the set is applied to, so a stamp
  applied to SQLite says nothing about PostgreSQL. Each PostgreSQL migration runs in its own
  transaction, so a failure part-way leaves the earlier ones applied and a rerun continues.
- Config: `talos.storage.database` (`dsn_env`, pool bounds, timeouts). The DSN itself never
  enters the YAML tree — only the *name* of the variable holding it, exactly as provider keys
  work. `TalosSettings.db_path` and `talos scan --db` are gone; `--dsn` replaces the flag.
- An unset `TALOS_DB_DSN` is fatal at startup rather than at the first incident. A pipeline that
  cannot record what it concludes should not run.
- **Known limitations:** there is still no retention policy on `verdict_log` — it grows without
  bound, and deciding the window is a P7 item. The e2e pipeline tests now use an in-memory
  recorder for the audit trail; the live round-trip moved to `tests/integration/`, which skips
  unless `TALOS_TEST_DB_DSN` is set.

## 2026-08-18 — the walking skeleton's output half (P2)

- Added `EventOrchestrator`: window, route by domain, aggregate, persist. It knows domains only —
  no technique appears anywhere in it.
- Added `AgentRegistry`: domain-agent registration, `None` for an unknown domain, `ConfigError`
  on a double registration.
- Added `VerdictAggregator`: dedupe, scope merge, severity scoring, corroboration-boosted
  confidence, and category-driven recommended actions. Returns `None` when nothing fired.
- Added `VerdictLogStore` (SQLite audit trail) with the first migration,
  `create_verdict_log_table_20260817_120000.sql`, and its rollback. The store never issues DDL;
  a missing table names `scripts/apply_migrations.py`.
- Added `scripts/apply_migrations.py`: timestamp-ordered forward migrations recorded in a
  `schema_migrations` ledger, plus `--list` and a local-development `--rollback`.
- Added `StdoutSink` (JSON Lines) and `JsonFileSink` (one file per incident).
- Added the `talos scan <file>` CLI, wiring every layer end to end with no LLM involved.
- Added `talos.aggregation.corroboration_boost` and `talos.storage.*` to `config/default.yaml`.
- Added duplicate suppression in the orchestrator: an ongoing attack is reported when first
  seen and again only when it escalates (it succeeded, or its attempt count grew by
  `aggregation.escalation_attempt_factor`). The fixture burst went from 6 near-identical
  incidents to 2 — the crossing and the escalation. Set `aggregation.suppress_duplicates: false`
  to see every firing.
- **Known limitations:** the HTTP surface is P7. Suppression state is per-process and capped at
  2048 signatures; a long-running service wants a TTL map instead, marked with a `ponytail:`
  comment in `event_orchestrator.py`.
