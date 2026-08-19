# Changelog — Network Brute Force Detection

## 2026-08-19 — RDP brute force (P5)

- Added `RdpBruteForceDetector` — T1110, `auth.protocol == "rdp"`, keyed on `(host, account)`,
  thresholds in `talos.detection.rdp_brute_force`. Registered in `NetworkBruteForceSubAgent`.
- `NetworkLogParser` now reads exported Windows Security events (JSON per line): 4625/4624 with
  `LogonType` 10, `SubStatus` mapped to a named reason, port 3389, `telemetry_source="rdp"`.
  Events with no usable source or no account are skipped, not keyed on a placeholder.
- `SshBruteForceDetector` refactored onto the new shared `RateVerdictEngine` and lost 100 lines;
  its behaviour, evidence wording, and thresholds are unchanged.
- Narrative prompt moved from `rate_detector_narrate_v1` to `v2` (distinct-account fact added for
  credential stuffing; both network detectors use the same template).
- **The two-day reuse claim, measured:** RDP cost one detector file (94 lines), one parser branch,
  and one list entry. No change to the engine, the window, the classifier, or the aggregator.

## 2026-08-17 — SSH brute force, end to end (P2)

- Added `RateEngine` (`detection/rate/rate_engine.py`), the shared statistical core for every
  rate-based detector: window, threshold, distinct sources, and success-after-burst.
- Added `EventWindowStore` (`storage/event_window_store.py`): keyed, TTL-bounded, count-bounded.
  Keys are derived by the store and namespaced; TTL is measured in **event time** so replay
  behaves like a live stream.
- Added `SshBruteForceDetector` — T1110, keyed on `(host, account)`, statistical only
  (`used_llm=false`) with a templated narrative.
- Added `NetworkBruteForceSubAgent`, `NetworkTypeClassifier` (static path only), and
  `NetworkDomainAgent`, with detector failures contained at both levels.
- Added `talos.detection.rate_confidence` to `config/thresholds.yaml` — the shared confidence
  curve, and the first thing P8 calibration will move.
- **Known limitations:** RDP is not detected yet (P5). A slow grind under the window threshold
  and a broad low-volume spray are documented false negatives; the spray is what P5's credential
  stuffing detector answers.
