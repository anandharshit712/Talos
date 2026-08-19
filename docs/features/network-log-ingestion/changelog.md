# Changelog — Network Log Ingestion

## 2026-08-19 — RDP event logs (P5)

- `NetworkLogParser` reads exported Windows Security events alongside `sshd` syslog, chosen
  per line by whether it starts with `{`. One file may interleave both, and the e2e fixture
  does.
- Accepted: `EventID` 4625/4624 with `LogonType` 10 (RemoteInteractive). Types 3 and 7 share
  those ids and are skipped — counting them as RDP would inflate a burst with unrelated
  failures.
- Field aliases cover both `wevtutil` (Windows names) and Winlogbeat (lower-cased) exports;
  ids and logon types are accepted as numbers or strings, because real captures contain both.
- `SubStatus` mapped to a named reason for the six codes worth naming, generic otherwise, with
  the raw code kept in `meta` either way.
- **EVTX is not parsed.** Reading the exporter's JSON avoids a third-party library and a
  Windows-only binary format; the collector that ships these logs has already converted them.
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
