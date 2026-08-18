# Feature — Web SQL Injection Detection

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/domains/web/injection/sql_injection_detector.py`, `src/talos/detection/patterns/sql_injection_pattern_rules.py`, `src/talos/detection/patterns/pattern_engine.py`, `src/talos/domains/web/injection/injection_sub_agent.py`, `src/talos/domains/web/web_type_classifier.py`, `src/talos/domains/web/web_domain_agent.py`
**Config:** `config/model_routing.yaml` → `routing.sql_injection_detector`
**Prompt:** `src/talos/llm/prompts/sql_injection_detector_judge_v1.md`
**Tests:** `tests/unit/domains/web/injection/test_sql_injection_detector.py`, `tests/unit/detection/patterns/test_sql_injection_pattern_rules.py`, `tests/e2e/test_web_injection_precision.py`
**MITRE:** T1190 (Exploit Public-Facing Application) · **OWASP:** A03:2021 Injection

Detects SQL injection attempts in query parameters, request bodies, and path segments, scopes
them to the endpoint and — where the payload names one — the target table, and reports whether
the request reached the application or was blocked.

**The deterministic layer is the detector.** Five pattern classes decide; a code-aware model
judges only genuinely borderline payloads, and content whose only signal is corroboration-grade
noise is cleared without either. The P4 gate is measured with the model stubbed out, so the
pattern layer carries the numbers alone.

| Document | Contents |
|---|---|
| [design.md](design.md) | the three-way decision, why patterns before models |
| [detection-logic.md](detection-logic.md) | pattern classes, thresholds, confidence, FP/FN modes |
| [testing.md](testing.md) | per-class cases, the benign corpus, measured results |
| [changelog.md](changelog.md) | dated entries |
