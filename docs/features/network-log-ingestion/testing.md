# Testing — Network Log Ingestion

## How to run

```bash
python -m pytest tests/unit/ingestion
python -m pytest tests/e2e/test_ssh_brute_force_pipeline.py    # ingestion in the full pipeline
```

## Fixtures

| Fixture | Contents |
|---|---|
| `tests/fixtures/logs/network_ssh_brute_force_sshd.log` | 12 failed logins for `root@bastion-01` inside 60s, one failed login for a different account, a trailing successful login, plus noise: a CRON line, a `Server listening` line, a disconnect line, a truncated line, and a second host |

The noise is deliberate. A fixture containing only attack lines proves a parser reads what it was
written for; it proves nothing about what it does with everything else in a real log.

## Cases covered

**`test_parser_contract.py`** — the contract, independent of any format

- unparseable lines are counted, not raised
- blank lines are neither events nor errors
- `parse_stream` yields lazily (a live tail must not wait for EOF)
- `BaseParser` cannot be instantiated

**`test_network_log_parser.py`** — the sshd format

- every field of a `Failed password` line maps correctly, including `raw` verbatim
- `invalid user` is distinguished from a wrong password (`unknown_user` vs `invalid_password`)
- standalone `Invalid user` lines are failures
- `Accepted password` is a success
- non-auth sshd lines, other daemons, truncated lines, and non-syslog text are all skipped
- the skip counter matches the number of unreadable lines
- a stamp more than a day in the future is read as last year's
- an impossible date (`Feb 30`) is skipped rather than crashing

## Latest observed results

2026-08-18 — 15 ingestion tests, all passing. Against the fixture above: 15 events parsed,
5 lines skipped, 0 exceptions. Measured precision/recall belongs to P8; ingestion has no
detection numbers of its own.
