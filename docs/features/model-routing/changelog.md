# Changelog — Model Routing

## 2026-08-18 — the LLM layer (P3)

- Added `OpenAiCompatibleClient` (`llm/model_client.py`): one client for NIM, Groq, and Mistral,
  with retry on timeout/5xx/429 only, a single stricter re-ask on unparseable JSON, and reply
  extraction that reads `reasoning_content` when `content` is null.
- Added `ModelRouter` (`llm/model_router.py`): per-agent route resolution, cross-provider
  fallback, the 0.85 confidence penalty recorded in `ModelInfo.route_reason`, and `None` when no
  model is reachable.
- Added `seal_payload` and file-based prompt rendering; prompts live in `llm/prompts/` as
  `<agent>_<purpose>_v1.md` (R3.7).
- Added `rate_detector_narrate_v1.md` and `network_type_classifier_route_v1.md`.
- `SshBruteForceDetector` now asks the routed model to word its finding, applies the fallback
  penalty, and falls back to its template on any failure including an empty narrative.
- `NetworkTypeClassifier` now refines **only** events its static pass could not place, and
  discards any category outside the closed list.
- `DetectionContext.model_client` moved from a raw `complete(...)` to the routed
  `complete_for(component, ...)` returning `ModelOutcome | None` — a P1-frozen contract change,
  recorded in LLD 16.4.
- Added `tests/support/stub_model_client.py`, the shared router double, and put `tests/support`
  on the pytest path so every suite can import it.
- Added the prompt-injection hardening suite. It found a real defect during development: account
  and host names are attacker-chosen and were being rendered into the prompt's *trusted facts*
  block. Identifiers are now sealed with the raw line.
- **Known limitations:** the `payload_guard` route is configured and probed but not yet called by
  any detector — it belongs with the P4 injection judges. Web-tier prompts (`sql_injection`,
  `xss`, `deviation_scorer`) arrive with their detectors.
