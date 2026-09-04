# Feature — Web Broken Access Control (IDOR)

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/detection/baseline/access_baseline.py`, `src/talos/storage/baseline_store.py`
**Config:** `config/thresholds.yaml` → `talos.detection.idor`
**Tests:** `tests/unit/detection/baseline/test_access_baseline.py`, `tests/unit/storage/test_baseline_store.py`, `tests/integration/test_baseline_store_postgres.py`
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

**What is built so far (P6.1):** the baseline model and its update rule, and the store that
persists it with per-account locking. **What is not:** the sub-agent, the baseliner that drives
the store from live events, and the deviation scorer that turns a baseline into a `Verdict` —
all P6.2.
