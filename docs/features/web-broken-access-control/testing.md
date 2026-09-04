# Testing — Web Broken Access Control (IDOR)

Three layers, the same shape as the verdict log: a pure update rule tested with no I/O, a store
tested through a fake connection for its statement sequence, and a live suite for the behaviour
only a real server has.

## Baseline model (`tests/unit/detection/baseline/test_access_baseline.py`, 27 cases)

- a new baseline is immature; maturity is reached **at** the threshold, not after it
- only plain integers parse as numeric ids — `order-1002`, `1002a`, a UUID and `1_002` do not
- the range widens to cover every numeric id seen; non-numeric ids leave it alone
- ids inside the range, and the boundaries themselves, are not deviations
- an unanswerable range question is not evidence: no numeric history, or a non-numeric id
- **eviction never narrows the range** — an id evicted from the list is still inside the range
- object ids are capped, oldest evicted first; re-accessing an id refreshes rather than duplicates
- every access counts toward maturity, including a repeat of an id already known
- endpoints are capped, least-used evicted first
- **a novel endpoint survives its own arrival on a full baseline** — it is the least-used by
  definition, so the naive rule would drop it and endpoint novelty could never be learned
- `observe` does not mutate its input: the store folds inside a transaction that may roll back
- the model round-trips through JSON, because it is persisted as `jsonb`

## Store statements (`tests/unit/storage/test_baseline_store.py`, no server needed)

- an unseen account reads as `None`; a stored row becomes a baseline with its collections parsed
- **reads are not locked** — scoring must not serialise behind learning
- `record_access` locks **before** reading: the statement order is lock, read, write
- lock, read and write share one transaction, so the `xact` lock is released rather than held
  for the life of a pooled connection
- the lock is keyed on the account
- a first access creates the baseline; a later one folds into what was stored
- the write upserts; the collections are serialised as JSON text
- a missing table raises `StorageError` naming the migration runner

## Live server (`tests/integration/test_baseline_store_postgres.py`)

Skipped unless `TALOS_TEST_DB_DSN` is set.

- a baseline round-trips through PostgreSQL unchanged
- `record_access` accumulates across calls, in order
- **twenty simultaneous accesses to one account produce twenty observations.** This is the P6
  storage gate. Without the per-account lock the count comes back below twenty and *nothing
  raises* — the failure mode is a baseline that silently never matures under load
- ten accounts updating at once each end with their own count, so the lock key is provably the
  account and not something global that would pass the test above anyway
- the bounds hold in the stored row, and eviction does not narrow the numeric range

## Not yet covered

The detector itself is P6.2. Its gate — enumeration detected with correct object-level scope and
zero false positives on the benign corpus — is measured there, and the numbers land in this file
when they exist. Nothing above is a detection result; it is all machinery.
