# Changelog — Web Broken Access Control (IDOR)

## 2026-09-04 — the detector, and the P6 gate (P6.2)

- Added `DeviationScorer`: four weighted features into a deterministic score, the `heavy`-tier
  judge above the floor, and `Scope.affected_objects` naming exactly the ids walked outside the
  learned pattern. A disagreeing judge **caps** the finding at the floor rather than vetoing it —
  the deterministic layer decides, the model adjusts how loudly.
- Added `AccessBaseliner` and `BrokenAccessControlSubAgent`. The sub-agent is an *ordering*, not
  a fan-out: score first (learning first puts the current id inside the learned range, so the
  detector could never fire on the tripping event), and learn only from traffic that scored
  clean (an enumeration run is exactly what would teach the baseline that walking the id space
  is normal for this account). Cold-start accesses *are* learned from.
- Added `llm/prompts/deviation_scorer_judge_v1.md`. Access history is delimited and
  length-bounded as data; the prompt states that a first visit is not a breach, and that
  sequence length matters more than novelty.
- Registered the sub-agent on `WebDomainAgent`. The classifier already routed
  `broken_access_control`, so nothing in it changed.
- Added the `talos.detection.idor` scorer keys: `window_seconds`, `access_rate_saturation`,
  `weights`, `low_score_floor`, `judge_weight`, `immature_confidence`.
- Added the corpus: `web_idor_enumeration_combined.log` (71 lines) and its **benign counterpart**
  `web_idor_benign_access_combined.log` (65 lines), plus `tests/support/memory_baseline_store.py`
  so the pipeline test needs no server.
- **Gate passed:** the walk is detected with correct object-level scope; the benign corpus
  produces nothing. Numbers in [testing.md](testing.md).
- **Three defects found while building:**
  - **The endpoint compared was the raw path, which carries the object id.** Every access
    therefore read as a novel endpoint forever, `novel_endpoint` was a constant, and the bounded
    `endpoints` map would have grown one entry per object until it evicted the real endpoints.
    Found by the discriminator test firing on a legitimate user opening one new record — the
    case that exists to catch exactly this.
  - **The CLI unit tests were making live inference calls.** `main()` loads `.env`, which is its
    job, so on a machine with provider keys six tests took 108–175s each, burned free-tier quota
    on every run, and made the suite's result depend on someone else's rate limiter. The suite
    went from 922s to 15s with `TALOS_LLM__ENABLED=false` in the fixture; a guard test now fails
    if that line is removed.
  - **Three routed models were dead** — two end-of-life (HTTP 410) and one outside the
    subscription tier (403). Re-probed and repaired before the gate: the `nano` tier's primary
    moved to Groq, because NVIDIA serves this account nothing at that size any more. 7/7 answer.
- **Known limitations:** a baseline never decays, so an account that changes role keeps its old
  pattern; the last ids of a run reach no report, because suppression is per escalation rather
  than per campaign; and the benign corpus's thinnest margin is 0.017, which P8 calibration
  should measure first.

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
