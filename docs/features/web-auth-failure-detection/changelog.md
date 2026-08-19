# Changelog — Web Auth Failure Detection

## 2026-08-19 — Brute force and credential stuffing, end to end (P5)

- Added `BruteForceDetector` — T1110, keyed per account, depth over `talos.detection.brute_force`.
- Added `CredentialStuffingDetector` — T1110.004, keyed per source, requiring both breadth
  (`distinct_accounts`) and shallowness (`fails_per_account_max`).
- Added `AuthFailureSubAgent`, registered in `WebDomainAgent`; a raising detector is contained at
  both levels.
- Added `RateVerdictEngine` (`detection/rate/rate_verdict_engine.py`): the confidence curve, the
  narration call, `Scope`, `ModelInfo`, and `Verdict` assembly, shared by all four rate detectors.
  `SshBruteForceDetector` was refactored onto it and lost 100 lines.
- `RateSignal` gained `endpoints`, `succeeded_accounts`, and `fails_per_account`. The last replaces
  LLD §7.3's `distributed: bool` mode flag — the engine reports the tally, the detector decides
  (LLD rev 1.9).
- **The web parser now derives HTTP auth events.** Until now `WebLogParser` set `auth=None` on
  every line, so both detectors would have been dead on arrival; `derive_http_auth` reads
  `401`/`403` as a failure and a credential-carrying `2xx`/`3xx` as a success, on login paths only,
  and pulls the submitted username out of the query or body with exactly one decode.
- `WebTypeClassifier` now routes on `event.auth` and shares the parser's `LOGIN_ENDPOINT` pattern
  instead of keeping a second copy. Registration and password-reset paths no longer route to this
  category — they carry no authentication outcome.
- Prompt `rate_detector_narrate_v1` → `v2`: adds the distinct-account fact and tells the model to
  read the threshold against the matching dimension, so a stuffing narrative does not describe a
  breadth finding as a failure count. All four detectors use it.
- **Defect found while building:** `VerdictAggregator` sorted MITRE ids, which reversed the
  primary-first order `mitre_all` promises. Credential stuffing is the first technique with two
  mappings, so its incidents led with T1110 instead of T1110.004. Now insertion-ordered.
- **Known limitations:** a stuffing run rotated across many sources is not detected (see
  [detection-logic.md](detection-logic.md#known-limits)); an application that answers a failed
  login `200` is unreadable from an access log; a login naming no account produces no
  brute-force key.
