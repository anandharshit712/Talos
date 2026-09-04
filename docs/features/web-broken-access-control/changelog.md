# Changelog — Web Broken Access Control (IDOR)

## 2026-09-04 — the baseline and its store (P6.1)

- Added `AccessBaseline` and its online update rule in
  `src/talos/detection/baseline/access_baseline.py`. `observe()` is pure and takes its bounds as
  arguments, so the whole learning rule is tested against a list of accesses with no server.
- Added `BaselineStore` in `src/talos/storage/baseline_store.py`, with `record_access()`:
  `pg_advisory_xact_lock(hashtext(account))`, read, fold, write, in one transaction. **This is
  the operation the storage engine changed for** — `get` then `put` from a caller is the
  lost-update race, and on SQLite a per-account lock is unachievable because the write lock is
  database-wide (HLD §7.1).
- Added `db/migrations/postgres/create_access_baseline_table_20260904_105455.sql` + rollback.
  One row per account, so the primary key is the lookup index; **no separate index on `account`
  was created**, because the primary key already provides one (the plan listed one; it would
  have been a duplicate). The only non-key query is staleness, which `idx_access_baseline_updated_at`
  serves.
- Added `talos.detection.idor.max_seen_object_ids` (500) and `max_endpoints` (50). Bounds, not
  tuning knobs: the row is read and rewritten on every object access.
- **Two deltas from the LLD's sketch** (§7.4), recorded in LLD §16.11:
  - `seen_object_ids` is an ordered list, not a set. Eviction needs an order, or it eventually
    forgets yesterday's id while keeping last month's — and `jsonb` has no set, so a set
    round-trips as a list anyway.
  - `observations` is a field of its own. Maturity cannot be derived from the bounded
    collections: summing them undercounts a busy account back below its threshold, and the
    baseline would oscillate between mature and immature.
- **One bug caught while writing the tests:** the endpoint eviction rule dropped the endpoint it
  had just counted. On a full baseline that endpoint is the least-used by definition, so a novel
  endpoint would never have been learned — and endpoint novelty is one of the four deviation
  features. The rule now excludes the endpoint just counted; the test that pins it is
  `test_a_novel_endpoint_survives_its_own_arrival_on_a_full_baseline`.
- **Known limitations:** a baseline never decays, so an account that legitimately changes role
  keeps its old pattern indefinitely — the trigger for adding a half-life is P8 precision
  measurement. The detector, the baseliner that drives this store from live events, and the
  deviation scorer are all P6.2; nothing here produces a `Verdict` yet.
