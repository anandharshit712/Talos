# Sub-feature — Credential Stuffing

**Status:** in-progress
**Code:** `src/talos/domains/web/auth_failure/credential_stuffing_detector.py`
**Config:** `talos.detection.credential_stuffing` — `window_seconds: 300`,
`distinct_accounts: 15`, `fails_per_account_max: 3`
**MITRE:** T1110.004, then T1110

Breadth from one source: a leaked dump replayed two or three tries per account across many
accounts — *below* every brute-force threshold on every account it touches. Counting failures
harder never finds it; the shape is the signal.

Two conditions must hold together:

| Condition | Setting | Without it |
|---|---|---|
| many distinct accounts | `distinct_accounts` | ordinary login noise fires |
| few attempts per account | `fails_per_account_max` | a password grind is mislabelled as stuffing |

Confidence is read from the **account** count, not the failure total: a run over 400 accounts is
worse than one over 20 even when the second retried more. A success after the run begins names the
compromised accounts in the evidence — the most useful line in the report.

**Not detected yet:** a run rotated across many source addresses, since the window is keyed per
source. The trigger and the phase that decides it are recorded in
[../../detection-logic.md](../../detection-logic.md#known-limits) and in the build tracker's
deferred items.
