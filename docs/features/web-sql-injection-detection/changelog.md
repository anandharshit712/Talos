# Changelog — Web SQL Injection Detection

## 2026-08-18 — the flagship detector (P4)

- Added `pattern_engine`: shared extraction, matching, evidence, and the three signal grades used
  by both injection detectors.
- Added `sql_injection_pattern_rules`: five classes, every rule written against the benign
  lookalike that would otherwise defeat it.
- Added `SqlInjectionDetector`: decisive patterns produce a verdict with no model call, borderline
  payloads go to a code-aware judge that may veto, and corroboration-grade noise is cleared
  without either.
- Added `InjectionSubAgent`, `WebTypeClassifier`, and `WebDomainAgent`; the classifier checks
  injection markers **before** the auth-endpoint check, so a payload aimed at `/login` is routed
  as injection rather than to a failure counter.
- Added `sql_injection_detector_judge_v1.md`, written so that "no" is an expected answer.
- **Fixed during development:** `infer_target_table` searched the matched fragment, which by
  construction cannot contain the table name that follows `UNION SELECT`. It reads the payload now.
- **Fixed during development:** the corroboration threshold was 3, but only two families can fire
  ambiguously -- the branch was unreachable. Lowered to 2, and corroboration-only hits are
  excluded from the count so noise cannot manufacture certainty.
- **Known limitations:** headers are not scanned; second-order injection is out of slice; a
  developer pasting real SQL into a form would be reported.
