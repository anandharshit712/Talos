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

## The deviation features (P6.2)

Four features, weighted into a deterministic `stat_score` in `[0, 1]`:

| Feature | Source | Reads |
|---|---|---|
| `outside_range` | `outside_numeric_range()` | the baseline's `numeric_min`/`numeric_max` |
| `sequential_run` | the event window | consecutive ids in one window, length ≥ `sequential_run_len` (default 5) |
| `novel_endpoint` | the baseline's `endpoints` | endpoint absent from the account's history |
| `rate` | the event window | object accesses per window |

`outside_numeric_range` returns `False` — not `True` — for a non-numeric id and for a baseline
that has seen no numeric ids. An unanswerable question is not evidence.

Below the low threshold the scorer returns `None`. Above it, a reasoning model weighs the access
history for borderline cases and `blend()` combines the two; with no model reachable the
statistical score stands alone and the verdict carries `used_llm=false`. That path is supported,
not degraded.

## Scoping

`Scope.affected_objects` lists **exactly** the object ids accessed outside the learned pattern —
for a sequential walk `1001, 1002, 1003, …`, those ids and no others. The account goes in
`affected_accounts`. Object-level scope is the deliverable for this category: "someone read
things they should not have" is not actionable, "these eleven order ids were read by this
account" is.
