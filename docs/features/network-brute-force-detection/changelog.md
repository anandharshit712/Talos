# Changelog — Network Brute Force Detection

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
