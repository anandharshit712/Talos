# Changelog — Incident Aggregation and Output

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
