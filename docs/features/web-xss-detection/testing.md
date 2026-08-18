# Testing — Web XSS Detection

## How to run

```bash
python -m pytest tests/unit/detection/patterns/test_xss_pattern_rules.py \
                 tests/unit/domains/web/injection/test_xss_detector.py
python -m pytest tests/e2e/test_web_injection_precision.py    # the P4 gate
```

## Cases covered

**Pattern table**

- one positive per class: script element, remote `src`, SVG vector, handler assignment, handler
  wired to a function, `javascript:`, `data:text/html`, encoded tag, attribute breakout
- decisive payloads are certain without a model; whitespace padding does not evade
- **13 benign lookalikes stay silent**: `<b>bold</b>`, `<p>hello world</p>`, `<i>`/`<u>` markup,
  `C++ <iostream>`, `onerror` in prose, bare `onerror`, `5 > 3 and 2 < 4`, `script kiddie`, a URL,
  an email address, a base64 image URI, `shoes`, `<3`
- inert markup is recorded for corroboration but never actionable
- a handler needs an assignment to count
- an unrecognised handler is actionable but judged — the test that keeps the judge path reachable
- the payload signature is stable across endpoints and differs across payloads

**Detector**

- a script payload produces a scoped verdict at 0.93 with no model call
- benign markup is cleared with zero model calls
- an obfuscated payload reaches the judge; the judge can veto
- **stored detection**: the same payload at a second endpoint floors confidence at 0.9, lists both
  endpoints in scope, and says so in the reasoning
- the same payload at the *same* endpoint stays reflected — a user retrying a URL is not evidence
  of persistence
- a different payload elsewhere does not make it stored
- reflection read from status: 200/302 true, 403/500 false

## Measured results

2026-08-18, on the labelled corpus, **with the model stubbed out**:

| Metric | Value |
|---|---|
| True positives | 6 / 6 |
| False negatives | 0 |
| False positives (14 benign lines) | 0 |
| **Precision** | **1.00** (gate: 0.90) |
| **Recall** | **1.00** (gate: 0.85) |
| Model calls | 0 |

As with SQL injection: a perfect score on a 6-attack corpus measures the corpus, not the detector.
The benign half is adversarially chosen, which makes it worth something; it is still 14 lines.
P8 replaces these with measurements against real captures.
