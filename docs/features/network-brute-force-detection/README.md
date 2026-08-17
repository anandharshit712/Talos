# Feature — Network Brute Force Detection

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/domains/network/brute_force/ssh_brute_force_detector.py`, `src/talos/domains/network/brute_force/network_brute_force_sub_agent.py`, `src/talos/domains/network/network_type_classifier.py`, `src/talos/domains/network/network_domain_agent.py`, `src/talos/detection/rate/rate_engine.py`, `src/talos/storage/event_window_store.py`
**Config:** `config/thresholds.yaml` → `talos.detection.ssh_brute_force`, `talos.detection.rate_confidence`
**Tests:** `tests/unit/domains/network/`, `tests/unit/detection/rate/test_rate_engine.py`, `tests/e2e/test_ssh_brute_force_pipeline.py`
**MITRE:** T1110 (Brute Force) · **OWASP:** A07:2021 Identification and Authentication Failures

Detects sustained failed-authentication bursts against a single account on a single host, scopes
them, and reports whether the burst was followed by a successful login — the signal that
separates internet background noise from an initial-access event.

Runs entirely on statistics. No model is called, `used_llm` is false, and the verdict carries a
templated narrative. P3 adds a model-written narrative on top of a path that already works.

| Document | Contents |
|---|---|
| [design.md](design.md) | the agent chain, shared rate engine, why the window is keyed this way |
| [detection-logic.md](detection-logic.md) | signals, thresholds, confidence maths, MITRE/OWASP mapping, FP/FN modes |
| [testing.md](testing.md) | cases covered, fixtures, results |
| [changelog.md](changelog.md) | dated entries |

**Scope for the hackathon slice:** SSH (P2). RDP is the same engine with a protocol filter and
arrives in P5 — it is the first item in the plan's cut order, and cutting it costs one detector,
not the category.
