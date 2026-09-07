# Feature — Network Brute Force Detection

**Status:** stable
**Owner:** Harshit Anand
**Code:** `src/talos/domains/network/brute_force/ssh_brute_force_detector.py`, `src/talos/domains/network/brute_force/rdp_brute_force_detector.py`, `src/talos/domains/network/brute_force/network_brute_force_sub_agent.py`, `src/talos/domains/network/network_type_classifier.py`, `src/talos/domains/network/network_domain_agent.py`, `src/talos/detection/rate/rate_engine.py`, `src/talos/detection/rate/rate_verdict_engine.py`, `src/talos/storage/event_window_store.py`
**Config:** `config/thresholds.yaml` → `talos.detection.ssh_brute_force`, `talos.detection.rdp_brute_force`, `talos.detection.rate_confidence`
**Tests:** `tests/unit/domains/network/`, `tests/unit/detection/rate/`, `tests/e2e/test_ssh_brute_force_pipeline.py`, `tests/e2e/test_rdp_brute_force_pipeline.py`
**MITRE:** T1110 (Brute Force) · **OWASP:** A07:2021 Identification and Authentication Failures

Detects sustained failed-authentication bursts against a single account on a single host, scopes
them, and reports whether the burst was followed by a successful login — the signal that
separates internet background noise from an initial-access event. **SSH (P2) and RDP (P5)**, one
detector each, sharing everything but the protocol filter and their thresholds.

Runs entirely on statistics. The narrative model, when reachable, only words the finding; with no
model in play `used_llm` is false and a templated narrative ships instead — a supported path, not
a degraded one.

| Document | Contents |
|---|---|
| [design.md](design.md) | the agent chain, shared rate engine, why the window is keyed this way |
| [detection-logic.md](detection-logic.md) | signals, thresholds, confidence maths, MITRE/OWASP mapping, FP/FN modes |
| [testing.md](testing.md) | cases covered, fixtures, results |
| [changelog.md](changelog.md) | dated entries |

**Scope for the hackathon slice:** SSH (P2) and RDP (P5), both delivered. Port scanning and
DDoS remain reserved: the network classifier returns `unclassified` for flow-only telemetry, so
adding them is a classifier route plus a sub-agent, not a change to this feature.
