# Testing — Web Auth Failure Detection

## Where the tests live

| File | Covers |
|---|---|
| `tests/unit/domains/web/auth_failure/test_auth_failure_discrimination.py` | the P5 gate: depth against breadth, both directions |
| `tests/unit/domains/web/auth_failure/test_brute_force_detector.py` | verdict shape, threshold edge, trailing success, protocol filter, model path |
| `tests/unit/domains/web/auth_failure/test_credential_stuffing_detector.py` | both breadth conditions and their edges, evidence wording, confidence basis |
| `tests/unit/domains/web/auth_failure/test_auth_failure_sub_agent.py` | both children registered, a raising detector contained |
| `tests/unit/detection/rate/test_rate_verdict_engine.py` | confidence curve, fallbacks, prompt sealing |
| `tests/unit/ingestion/parsers/test_web_log_parser.py` | HTTP auth derivation, including what it refuses to read |
| `tests/e2e/test_web_credential_stuffing_pipeline.py` | log file → `IncidentReport`, every layer real |

## The gate, in both directions

| Corpus | Must fire | Must stay silent |
|---|---|---|
| 1 account × 40 failures | `brute_force`, `attempt_count=40`, T1110 | `credential_stuffing` |
| 30 accounts × 2 failures | `credential_stuffing`, 30 accounts, T1110.004 | `brute_force` |
| 20 accounts × 2 **plus** one account × 12, one source | `brute_force` | `credential_stuffing` — the per-account ceiling is what rejects it |
| stuffing from one source **and** a grind from another | both, one verdict each | — |
| 3 accounts × 2 failures | — | both |

Asserting only that each detector fires on its own corpus would pass with two detectors that fire
on everything, so every row asserts the negative as well.

## Threshold reachability

`test_the_account_threshold_is_reachable_exactly` runs a corpus of exactly 15 accounts with one
failure each. P4 shipped two unreachable branches (a corroboration threshold set above the number
of families that could reach it, and a judge tier with no rule to trigger it), and both were found
only when a test was written to sit exactly on the boundary. Every threshold in this feature now
has a test at its edge and one below it.

## Parser cases

Covered explicitly: a rejected login with a form body; a `302` after a `POST` with a JSON body; a
rendered form (`GET … 200`) recording no outcome; a posted `200`; `POST /register 201` recording
no outcome; a `403` on a non-login path recording no outcome; the collector's `remote_user`
winning over a submitted username; single-decode of `%2527` in a submitted username; a `401` on
`/oauth/token` with no body at all.

## Fixtures

`tests/fixtures/logs/web_credential_stuffing_access.log` — 48 lines: 20 accounts × 2 rejected
logins from `203.0.113.66` at 4-second spacing, one working credential (`user013`) at the end, a
follow-on request, three benign lines (a rendered form, a clean sign-in, ordinary browsing), a
genuine typo-then-success for a second user, and one unreadable line so the skip counter is
exercised. `tests/fixtures/expected/web_credential_stuffing_report.json` holds the stable fields
only — ids and timestamps are generated per run.

## Results

588 tests pass repository-wide (`ruff`, `mypy --strict`, and `run_all_checks.py --strict` clean).
No model is reachable in any test, so every verdict asserted here is statistical with
`used_llm=false`.

**What the numbers do and do not show.** The corpora above are hand-built to isolate one shape
each, which is what makes the discrimination claim meaningful and is *not* a precision figure. No
precision or recall is claimed for this feature yet; P8 measures both against real captures, and
the rotated-source false negative in [detection-logic.md](detection-logic.md#known-limits) will
show up there rather than here.
