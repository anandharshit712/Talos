# Changelog — Model Routing

## 2026-08-18 — an off switch for the model layer

- Added `talos.llm.enabled` (default `true`). `false` makes `build_router` skip every provider
  even when keys are present, so every `complete_for` returns `None` and the pipeline runs the
  statistical path it already had. Previously the only way to reach that path was deleting the
  API keys — an irreversible, invisible way to change behaviour.
- `.env.example` rewritten as a reference: every environment variable, its permitted values, and
  its default, including the `TALOS_<SECTION>__<KEY>` nesting that already reached the whole
  config tree but was documented nowhere.
- A test walks `.env.example` and asserts every documented variable resolves to a real settings
  field holding the stated default, so the reference cannot drift from the code.
- **Fixed: `.env` was never loaded.** Provider keys are not settings fields, by design, so
  pydantic's `env_file` never read them and no entry point read the file either. `talos scan` had
  been running with three keys on disk and zero providers since P3, reporting `used_llm=false`
  with no indication anything was wrong — the P3 live gate passed only because the keys were
  exported into that shell. `load_env_file()` now runs in `main()`, real environment variables
  still win, and a test asserts the call site exists. Verified live: providers
  `["groq", "mistral", "nim"]`, narratives model-written.
- `check_model_availability.py`'s private copy of the loader deleted in favour of the shared one.
- `route_reason` for the no-model path reads "no model used" rather than "no model reachable",
  which was false whenever the model was switched off deliberately.

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
