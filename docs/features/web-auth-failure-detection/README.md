# Feature — Web Auth Failure Detection

**Status:** stable
**Owner:** Harshit Anand
**Code:** `src/talos/domains/web/auth_failure/auth_failure_sub_agent.py`, `src/talos/domains/web/auth_failure/brute_force_detector.py`, `src/talos/domains/web/auth_failure/credential_stuffing_detector.py`, `src/talos/detection/rate/rate_verdict_engine.py`, `src/talos/detection/rate/rate_engine.py`, `src/talos/ingestion/parsers/web_log_parser.py`
**Config:** `config/thresholds.yaml` → `talos.detection.brute_force`, `talos.detection.credential_stuffing`, `talos.detection.rate_confidence`
**Tests:** `tests/unit/domains/web/auth_failure/`, `tests/unit/detection/rate/`, `tests/unit/ingestion/parsers/test_web_log_parser.py`, `tests/e2e/test_web_credential_stuffing_pipeline.py`
**MITRE:** T1110 (Brute Force), T1110.004 (Credential Stuffing) · **OWASP:** A07:2021 Identification and Authentication Failures

Two detectors over the same failed HTTP logins, answering two different questions:

| Sub-feature | Question | Key | MITRE |
|---|---|---|---|
| [brute force](sub-features/brute-force/README.md) | is one account being ground? | account | T1110 |
| [credential stuffing](sub-features/credential-stuffing/README.md) | is a leaked dump being replayed? | source IP | T1110.004 |

**Depth versus breadth is the whole feature.** A stuffing run sits below every brute-force
threshold on every account it touches, so counting failures harder never finds it; a password
grind satisfies "many failures from one source", so breadth alone would mislabel it. Each
detector therefore asserts its own shape *and* the absence of the other's, in both directions —
`tests/unit/domains/web/auth_failure/test_auth_failure_discrimination.py` is the P5 gate.

Both run on statistics alone. `used_llm` is false with a templated narrative when no model is
reachable, and nothing a model returns can change `attack_detected`, a count, or a scope.

| Document | Contents |
|---|---|
| [design.md](design.md) | the chain, where HTTP auth events come from, why each key was chosen |
| [detection-logic.md](detection-logic.md) | thresholds, confidence maths, evidence, FP/FN modes and limits |
| [testing.md](testing.md) | cases covered, fixtures, results |
| [changelog.md](changelog.md) | dated entries |

**Scope for the hackathon slice:** single-source and small-source-set stuffing. A run rotated
across many addresses with few accounts each is a documented false negative — see
[detection-logic.md](detection-logic.md#known-limits).
