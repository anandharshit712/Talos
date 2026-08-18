# Feature — Model Routing

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/llm/model_client.py`, `src/talos/llm/model_router.py`, `src/talos/llm/prompts/`
**Config:** `config/model_routing.yaml` (providers + per-agent routes), `config/default.yaml` → `talos.llm`
**Tests:** `tests/unit/llm/`, `tests/integration/test_prompt_injection_hardening.py`
**Verification:** `python scripts/check_model_availability.py`

Gives every agent its own model without giving any agent knowledge of providers. A detector names
itself; the router resolves the route, tries the primary, falls back across providers, applies the
confidence penalty, and reports which model answered.

**The model is never load-bearing for detection.** Detection is statistical or pattern-based; a
model narrates a finding, refines a routing guess, or judges a borderline payload. With no key
configured the pipeline runs exactly as before with `used_llm=false` — a supported mode, exercised
on every test run.

| Document | Contents |
|---|---|
| [design.md](design.md) | the three-state router, why one client class, provider profiles |
| [behaviour.md](behaviour.md) | resolution order, retries, penalties, reply parsing, failure table |
| [testing.md](testing.md) | cases covered, the injection gate, live results |
| [changelog.md](changelog.md) | dated entries |

**Providers:** NVIDIA NIM (primary for most tiers), Groq and Mistral (cross-provider fallbacks).
Model choices and the evidence behind them are in
[../../research/Talos_Model_Selection_Research.md](../../research/Talos_Model_Selection_Research.md).
