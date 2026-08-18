# Feature — Web XSS Detection

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/domains/web/injection/xss_detector.py`, `src/talos/detection/patterns/xss_pattern_rules.py`, `src/talos/detection/patterns/pattern_engine.py`
**Config:** `config/model_routing.yaml` → `routing.xss_detector`
**Prompt:** `src/talos/llm/prompts/xss_detector_judge_v1.md`
**Tests:** `tests/unit/domains/web/injection/test_xss_detector.py`, `tests/unit/detection/patterns/test_xss_pattern_rules.py`, `tests/e2e/test_web_injection_precision.py`
**MITRE:** T1059.007 (Command and Scripting Interpreter: JavaScript) · **OWASP:** A03:2021 Injection

Detects cross-site scripting payloads in query parameters, bodies, and paths, and — the part that
changes who is affected — distinguishes **reflected** from **stored** by consulting the event
window for the same payload signature at a different endpoint.

Same discipline as the SQL detector: patterns decide, a model judges only the obfuscated middle,
and inert markup is cleared without either. `<b>bold</b>` in a comment field is the most common
benign lookalike in the corpus, and it must never cost a model call.

| Document | Contents |
|---|---|
| [design.md](design.md) | reflected vs stored, why the signature is path-independent |
| [detection-logic.md](detection-logic.md) | pattern classes, confidence, scope, FP/FN modes |
| [testing.md](testing.md) | cases covered, measured results |
| [changelog.md](changelog.md) | dated entries |
