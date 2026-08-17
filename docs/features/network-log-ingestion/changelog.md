# Changelog — Network Log Ingestion

## 2026-08-17 — sshd syslog ingestion (P2)

- Added `BaseParser` (`ingestion/parser_contract.py`): `parse_line` / `parse_stream` and the
  `parse_errors` counter. Unparseable input is skipped and counted, never raised.
- Added `NetworkLogParser` (`ingestion/parsers/network_log_parser.py`) for `sshd` syslog:
  failed password, failed password for an invalid user, standalone invalid user, and accepted
  password, for both `password` and `publickey`.
- Year-less syslog stamps are reconstructed against `default_year` and stepped back a year when
  the result would be in the future.
- Added the labelled fixture `tests/fixtures/logs/network_ssh_brute_force_sshd.log`, including
  deliberate noise: another daemon, non-auth sshd lines, a truncated line, and a second host.
- **Known limitation:** RDP event logs are not parsed yet (P5). Netflow records are out of scope
  for the slice.
