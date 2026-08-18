# Testing — Web SQL Injection Detection

## How to run

```bash
python -m pytest tests/unit/detection/patterns tests/unit/domains/web
python -m pytest tests/e2e/test_web_injection_precision.py    # the P4 gate
```

## Cases covered

**Pattern table** (`test_sql_injection_pattern_rules.py`)

- one positive per class: tautology (three shapes), union (three), stacked (two), blind (two)
- decisive payloads are certain without a model
- mixed case and comment padding do not evade
- **17 benign lookalikes stay silent**: `O'Brien`, `d'Artagnan`, `select a plan`,
  `union square hotel`, `SELECT`, `3 or 4 items`, `drop me a line`, `insert coin`,
  `price < 100 and rating > 4`, `user@example.com`, `1=1 is a tautology, discuss`,
  `I need help -- urgent`, `#hashtag`, `cafe`, `shoes`, `1042`
- a lone comment marker is recorded but never actionable
- two actionable families together are decisive; corroboration-only hits do not count
- the named table is read from the payload, not the matched fragment

**Detector** (`test_sql_injection_detector.py`)

- a decisive payload produces a scoped verdict with the table in `affected_objects`
- a decisive payload makes **zero** model calls
- evidence names every rule and quotes the raw line
- benign content is cleared with no model call
- a borderline payload reaches the judge, and the judge can **veto**
- no model reachable turns a borderline payload into a lead (confidence < 0.5), not a finding
- a fallback judgement costs 0.85x confidence
- **the model cannot invent scope**: a reply claiming other endpoints is ignored
- `succeeded` from status: 200/201/500 true, 403/400/429 false, 304 unknown
- body payloads detected; non-web events ignored

## Measured results

2026-08-18, on the labelled corpus, **with the model stubbed out**:

| Metric | Value |
|---|---|
| True positives | 8 / 8 |
| False negatives | 0 |
| False positives (14 benign lines) | 0 |
| **Precision** | **1.00** (gate: 0.90) |
| **Recall** | **1.00** (gate: 0.85) |
| F1 | 1.00 |
| Model calls | 0 |

**Read that honestly.** A perfect score on an 8-attack, 14-benign corpus is a statement about the
corpus size, not proof of perfect accuracy. The benign half is adversarially chosen, which makes
it meaningful; it is still small. P8 measures against Juice Shop, DVWA, and PortSwigger captures,
and those numbers are the ones that count.
