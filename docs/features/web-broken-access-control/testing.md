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

## The detector (`tests/unit/domains/web/broken_access_control/`, 51 cases)

**Discriminator, both directions.** A twelve-id walk fires; a legitimate user opening one new
record does not. Each threshold has a case at its exact edge and one below it.

- an event naming no object, or naming one with no account, is never scored
- cold start returns a verdict with `attack_detected=False`, and the **aggregator drops it**, so
  an unfamiliar account produces no incident while the record still shows Talos looked
- an immature baseline says how far off it is ("10 of 50 observations")
- maturity is reached *at* the threshold, not after it
- a walk of `sequential_run_len - 1` fires nothing; the threshold itself fires
- three adjacent ids the account owns — paging a list — stays silent
- one genuinely new id stays silent; a novel endpoint alone stays silent
- ids from another account do not build a run: the window is keyed per account
- opaque (non-numeric) ids produce no run and no finding, so UUID-keyed applications are not
  flagged wholesale
- scope lists exactly the run, and a gap breaks it so unrelated accesses are not scoped in
- a `403` is still reported, with `succeeded=False` — the control held, the attempt happened
- the endpoint template drops the object id (six cases), and two accesses to different objects
  on one endpoint count as one endpoint twice
- **score-then-learn**, and **flagged traffic is never learned from** — the baseline-poisoning
  guard, each with a trace assertion that fails if the order is swapped
- a scorer that raises does not take the pipeline with it, and the access is still learned from
- with a model: an agreeing judge moves the confidence and is credited; a disagreeing one caps
  the finding at the floor rather than vetoing it; a malformed reply leaves the score standing

## The P6 gate (`tests/e2e/test_web_idor_pipeline.py`) — **passed 2026-09-04**

Two corpora, one pipeline, one settings object. Every layer real; the baseline is in memory
(running the real `observe`) because the locked store has its own live suite.

**Recall** — `web_idor_enumeration_combined.log`, 71 lines: 55 scattered legitimate accesses
mature `mallory`'s baseline, then thirty minutes later the same account walks `8001…8012`.

- the incident fires, `critical`, confidence **0.767**, `used_llm=false`
- scope names `8001…8010` and nothing else; MITRE leads `T1083` then `T1530`
- `bob`'s own order, timed inside the run, is not scoped in and does not appear in the accounts
- **two incidents, not twelve** — the crossing at five ids, the escalation at ten. `8011` and
  `8012` double nothing so no report names them. Pinned by its own test, because the cost of
  per-escalation reporting should be visible rather than discovered in a demo

**Precision** — `web_idor_benign_access_combined.log`, 65 lines, the same warm-up then the three
cases most likely to be mistaken for IDOR: paging three adjacent owned ids, opening an endpoint
never used before, and one genuinely new object id outside everything the account has touched.

- **zero incidents.** Recall without precision is not a result
- and the baseline still matured to ≥50 observations, so the silence is the detector deciding,
  not the pipeline never reaching it

**Read the numbers honestly.** Two hand-built corpora of 71 and 65 lines are a functional gate,
not a measurement: they say the detector fires on the shape it was built for and stays quiet on
the shapes it was built to tolerate. Precision and recall against a real capture is P8.

The thinnest margin found while building: one brand-new object id outside the learned range
scores **0.333** against a floor of 0.35. That is a 0.017 margin, and it is the first thing P8
calibration should measure — a slightly wider learned range, or one extra access in the window,
would push an ordinary user over.
