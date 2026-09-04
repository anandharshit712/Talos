# Design — Web Broken Access Control (IDOR)

## Why this category is different

Every other detector in Talos matches something. SQL injection has payload shapes; brute force
has a rate. IDOR has neither: the request that steals someone else's invoice is identical to the
request that reads your own. What separates them is *who is asking*, and the only evidence
available in a log is whether this account has ever plausibly asked for that object before.

So the detector needs state — and not global state, per-account state. That single requirement is
what shaped everything below.

## Three parts, deliberately separate

| Part | Module | Knows about |
|---|---|---|
| The model and update rule | `detection/baseline/access_baseline.py` | nothing external — no config, no database |
| Persistence and locking | `storage/baseline_store.py` | PostgreSQL |
| Scoring and the verdict (P6.2) | `domains/web/broken_access_control/` | the pipeline |

The update rule is a pure function taking its bounds as arguments, so it is tested against a list
of accesses with no server and no fixtures. The store folds one access inside a transaction and
decides when the result is written. Nothing in the model knows what a `Verdict` is.

## Why the store owns a `record_access`, not just `get`/`put`

The `BaselineReader` Protocol names `get` and `put`, and both exist. But a caller doing
`get` → modify → `put` has a read-modify-write with no lock between the halves: two accesses for
one account both read the old baseline and the second write discards the first observation. That
does not raise, does not fail a unit test, and quietly stops a busy account's baseline from
maturing.

`record_access` closes it: `pg_advisory_xact_lock(hashtext(account))`, read, fold, write, in one
transaction. The lock is released by the transaction ending, including on rollback. `hashtext`
can collide, which costs two accounts a shared lock and occasional contention — never
correctness.

**This is the operation the engine changed for.** SQLite's write lock is database-wide, so a
"per-account" lock there would serialise the whole pipeline, verdict appends included, on the
per-event hot path (HLD §7.1).

`put` stays a last-writer-wins overwrite for seeding and restoring a baseline. It is documented
as such so it is not reached for by mistake.

## Why the baseline is bounded, and what the bounds cost

The row is read and rewritten on every object access. An unbounded row means the hot path grows
without limit for exactly the accounts that use the system most.

Two collections are capped (`talos.detection.idor.max_seen_object_ids`, `max_endpoints`), and
each eviction rule is a decision about what to forget:

- **Object ids evict oldest-first.** Recency is what matters for "has this account touched this
  object", so an ordered list replaced the set the LLD sketched.
- **Endpoints evict least-used first** — except the endpoint just counted, which on a full
  baseline is the least-used by definition. Evicting it would mean a novel endpoint could never
  be learned, and endpoint novelty is one of the deviation features.
- **The numeric range is never narrowed by eviction.** `numeric_min`/`numeric_max` are separate
  columns precisely so forgetting an id's entry cannot turn that id into an outlier tomorrow.
- **`observations` is counted separately** from both collections. Deriving maturity by summing a
  bounded collection would push a busy account back below its own threshold and make the
  baseline oscillate between mature and immature.

## Deferred, with the trigger named

| Deferred | Trigger |
|---|---|
| Baseline decay — an account that changes role keeps its old pattern forever | P8 measurement: if precision suffers on a long corpus, add a half-life on `updated_at` |
| Sequential-run detection across the event window | P6.2, where the scorer is built |
| Sharing one baseline across a user's sessions or devices | not planned; the account is the unit of access control |
