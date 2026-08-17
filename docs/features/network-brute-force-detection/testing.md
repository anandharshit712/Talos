# Testing — Network Brute Force Detection

## How to run

```bash
python -m pytest tests/unit/detection/rate tests/unit/domains/network
python -m pytest tests/e2e/test_ssh_brute_force_pipeline.py
```

## Fixtures

| Fixture | Contents |
|---|---|
| `tests/fixtures/logs/network_ssh_brute_force_sshd.log` | 12 failures for `root@bastion-01` in 52s, a trailing success, one unrelated failure from another source, and non-auth noise |
| `tests/fixtures/expected/network_ssh_brute_force_report.json` | the stable fields the e2e test asserts (ids and timestamps are generated per run) |
| `ssh_events` fixture (`tests/conftest.py`) | fabricates bursts of arbitrary size, spacing, account, source, and trailing success |

## Cases covered

**Rate engine** (`test_rate_engine.py`) — the edges the whole rate family shares

- fires at exactly the threshold; silent one below it
- eight failures spread over an hour do not fire (window, not total)
- a success after the burst is reported and is not counted as a failure
- a success *before* the burst is not credited to it
- signal carries accounts, hosts, distinct sources, event ids, and sample lines
- non-auth events and unkeyable events are ignored

**Event window** (`test_event_window_store.py`)

- an event is indexed under account, source IP, and host+account
- namespaced keys — a username shaped like an IP cannot collide with one
- the query window is relative to the newest event (replay behaves like a live stream)
- TTL eviction and the per-key count bound both hold

**Detector** (`test_ssh_brute_force_detector.py`)

- a burst produces a fully scoped verdict: T1110, attempt count, accounts, hosts, diversity
- `used_llm=false`, `model.name="none"`, and the stub model client records **zero** prompts
- evidence contains both the statistic and quoted log lines
- confidence grows with the burst, caps at 0.95, and floors at 0.90 on a trailing success
- below threshold → `None`; RDP traffic → `None` (P5 owns it)
- thresholds are read from settings, not from literals

**Sub-agent and domain agent**

- category equals the package name equals the classifier's output
- a detector that raises does not silence its siblings (fail-open)
- a sub-agent that raises is contained by the domain agent
- unclassified events route nowhere; an unregistered category is a logged miss, not a crash

**Classifier** (`test_network_type_classifier.py`)

- ssh and rdp auth route to `network_brute_force`; flow-only telemetry is `unclassified`
- the confidence floor demotes a weak route
- no model is called

## Latest observed results

2026-08-18 — 46 tests across the rate engine, window, detector, sub-agent, agent, and classifier;
all passing. End to end against the fixture: **2 incidents** — the threshold crossing
(`medium`, confidence 0.70, `attempt_count=8`) and the escalation once the burst succeeded
(`high`, confidence 0.90, `attempt_count=12`, `succeeded=true`). MITRE `T1110` and
`used_llm=false` on every verdict.

Measured precision/recall against a labelled corpus is P8 work; the numbers above are behavioural,
not statistical.
