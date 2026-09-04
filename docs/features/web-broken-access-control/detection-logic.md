# Detection logic — Web Broken Access Control (IDOR)

**Built so far: the baseline.** The deviation features are specified here because the baseline's
shape is chosen to serve them, but the scorer that computes them is P6.2.

## The baseline

`AccessBaseline`, one row per account in `access_baseline`:

| Field | Type | Purpose |
|---|---|---|
| `account` | `TEXT` primary key | the unit of access control, and the lock key |
| `seen_object_ids` | `jsonb` list, oldest first | has this account touched this object before |
| `numeric_min` / `numeric_max` | `BIGINT` | the observed id range, never narrowed |
| `endpoints` | `jsonb` object, endpoint → count | is this endpoint novel for this account |
| `observations` | `INTEGER` | what maturity is measured against |
| `updated_at` | `TIMESTAMPTZ` | staleness, and the only non-key query |

### Maturity

`is_mature(baseline, min_observations)` — `observations >= talos.detection.idor.min_baseline_observations`
(default 50). Below it the scorer returns a **low-confidence `baseline immature` verdict**, never
a confident finding and never silence: the operator should be able to see that Talos looked and
did not yet know enough.

### What counts as a numeric id

`numeric_id()` accepts a plain integer, optionally signed and surrounded by whitespace, and
nothing else. `1002` is enumerable; `order-1002` and a UUID are not.

The strictness is the point. A loose parse that dug digits out of any string would invent a
numeric range for opaque identifiers, and then report every one of them as outside it — a false
positive on every account whose ids happen to be UUIDs.

### The bounds

| Bound | Default | Eviction |
|---|---|---|
| `max_seen_object_ids` | 500 | oldest first; re-access moves an id to newest |
| `max_endpoints` | 50 | least-used first, never the endpoint just counted |

`observations` and the numeric range are outside both caps, so neither eviction can make an
account look less experienced or its historical range look smaller than it was.

## The deviation features

Four features, weighted into a deterministic `stat_score` in `[0, 1]`, normalised by the total
weight so the result is bounded whatever the weights are:

| Feature | Weight | Source | Reads |
|---|---|---|---|
| `sequential_run` | 0.40 | the event window | consecutive ids in one window, length ≥ `sequential_run_len` (default 5) |
| `outside_range` | 0.30 | `outside_numeric_range()` | the baseline's `numeric_min`/`numeric_max` |
| `access_rate` | 0.20 | the event window | accesses in the window ÷ `access_rate_saturation` (30) |
| `novel_endpoint` | 0.10 | the baseline's `endpoints` | endpoint template absent from the account's history |

`sequential_run` leads because it is the only one of the four that is hard to produce by
accident, and it reads the **window** rather than the baseline: once a walk begins, each id
widens the learned range, so `outside_range` catches the initial jump and the run carries the
rest. `novel_endpoint` is lightest because a legitimate user reaching a new part of the
application looks exactly like it.

**The endpoint compared is the template, not the path.** `/api/orders/1002` reduces to
`/api/orders`. Comparing the raw path makes every object access a novel endpoint forever — the
feature becomes a constant, and the bounded `endpoints` map grows one entry per object until it
evicts the real endpoints. Caught by the discriminator test, not by inspection.

`outside_numeric_range` returns `False` — not `True` — for a non-numeric id and for a baseline
that has seen no numeric ids. An unanswerable question is not evidence.

Below `low_score_floor` (0.35) the scorer returns `None` — no verdict at all, not a
low-confidence one. Above it, the `heavy`-tier reasoning model weighs the access history and
`blend()` combines the two at `judge_weight` (0.40). With no model reachable the statistical
score stands alone and the verdict carries `used_llm=false`; that path is supported, not
degraded.

**A disagreeing judge caps rather than vetoes.** If the model answers `is_idor: false`, the
deterministic score is not discarded — it is capped at the floor, which turns a finding into a
lead. The deterministic layer decides; the model adjusts how loudly.

## Ordering: score first, and learn only from clean traffic

Two rules in the sub-agent, both load-bearing, each with a test that fails if it is swapped:

1. **Score before learning.** Folding the access in first puts its id inside the learned range,
   so `outside_range` is false by construction and the detector can never fire on the event that
   should trip it.
2. **Learn only from traffic that scored clean.** An enumeration run is precisely the traffic
   that would teach the baseline that walking the id space is normal for this account.

A cold-start access *is* learned from — that is how a baseline matures at all.

## Scoping

`Scope.affected_objects` lists **exactly** the object ids accessed outside the learned pattern —
for a sequential walk `1001, 1002, 1003, …`, those ids and no others. The account goes in
`affected_accounts`. Object-level scope is the deliverable for this category: "someone read
things they should not have" is not actionable, "these eleven order ids were read by this
account" is.
