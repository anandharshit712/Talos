# Feature — Web Broken Access Control (IDOR)

**Status:** stable
**Owner:** Harshit Anand
**Code:** `src/talos/domains/web/broken_access_control/deviation_scorer.py`, `src/talos/domains/web/broken_access_control/access_baseliner.py`, `src/talos/domains/web/broken_access_control/broken_access_control_sub_agent.py`, `src/talos/detection/baseline/access_baseline.py`, `src/talos/storage/baseline_store.py`, `src/talos/domains/web/web_type_classifier.py`, `src/talos/domains/web/web_domain_agent.py`
**Config:** `config/thresholds.yaml` → `talos.detection.idor` · `config/model_routing.yaml` → `routing.deviation_scorer`
**Prompt:** `src/talos/llm/prompts/deviation_scorer_judge_v1.md`
**Tests:** `tests/unit/domains/web/broken_access_control/test_deviation_scorer.py`, `tests/unit/domains/web/broken_access_control/test_access_baseliner.py`, `tests/unit/domains/web/broken_access_control/test_broken_access_control_sub_agent.py`, `tests/unit/detection/baseline/test_access_baseline.py`, `tests/unit/storage/test_baseline_store.py`, `tests/integration/test_baseline_store_postgres.py`, `tests/e2e/test_web_idor_pipeline.py`
**Migrations:** `db/migrations/postgres/create_access_baseline_table_20260904_105455.sql` (+ rollback)
**MITRE:** T1083 (File and Directory Discovery) · T1530 (Data from Cloud Storage) · **OWASP:** A01:2021 Broken Access Control

Detects insecure direct object references — an authenticated account reading objects that are not
its own — and scopes the finding to **exactly which object ids** were touched outside that
account's learned pattern.

**This is the category with no payload.** `GET /api/orders/1002` is byte-identical whether the
caller owns order 1002 or is walking the id space, so there is nothing to match. The only signal
is deviation from what *this account* has done before, which means the detector needs a memory:
a per-account baseline, learned online and persisted across runs.

**Cold start is a supported state, not a gap.** An account below its observation threshold yields
a low-confidence `baseline immature` verdict. An account Talos has never seen is not a suspicious
account, and a detector that treats unfamiliarity as guilt is a false-positive generator.

| Document | Contents |
|---|---|
| [design.md](design.md) | why a baseline, why per-account locking, what is deliberately deferred |
| [detection-logic.md](detection-logic.md) | the baseline model, its bounds, and the deviation features |
| [testing.md](testing.md) | cases covered, and the lost-update test that is the storage gate |
| [changelog.md](changelog.md) | dated entries |

**Measured on 2026-09-04**, statistical path only, no model reachable: the enumeration corpus
produces the incident with the walked object ids in scope; the paired benign corpus produces
**nothing**. Numbers and the corpus's honest size are in [testing.md](testing.md).
