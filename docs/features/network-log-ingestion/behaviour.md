# Behaviour — Network Log Ingestion

## Accepted input

Syslog envelope: `<Mon> <day> <HH:MM:SS> <host> <daemon>[<pid>]: <message>`. Only `sshd` messages
are read; any other daemon on the same channel is skipped.

| Message shape | `auth.outcome` | `auth.reason` |
|---|---|---|
| `Failed password for <user> from <ip> port <n>` | `failure` | `invalid_password` |
| `Failed password for invalid user <user> from <ip> port <n>` | `failure` | `unknown_user` |
| `Invalid user <user> from <ip>` | `failure` | `unknown_user` |
| `Accepted password for <user> from <ip> port <n>` | `success` | `accepted` |

`publickey` is accepted wherever `password` is.

## Field mapping

| Source | `NormalizedEvent` field |
|---|---|
| syslog month/day/time + `default_year` | `timestamp` (UTC) |
| syslog host | `target.host` |
| — (fixed for sshd) | `target.port = 22` |
| message `from <ip>` | `actor.source_ip` |
| message `for <user>` | `actor.account` |
| message verb | `auth.outcome`, `auth.reason` |
| `sshd` | `telemetry_source`, and `auth.protocol = "ssh"` |
| the whole line, verbatim | `raw` |
| syslog pid | `meta.daemon_pid` |

`event_id` is a fresh UUID per event, assigned here.

## Edge cases

| Input | Behaviour |
|---|---|
| Blank or whitespace-only line | Ignored; **not** counted as an error |
| Non-sshd daemon (`CRON`, `systemd`) | Skipped, counted |
| sshd line with no auth outcome (`Server listening`, `Received disconnect`) | Skipped, counted |
| Truncated line (`sshd[4260] Failed password for`) | Skipped, counted |
| Impossible date (`Feb 30`) | Skipped, counted |
| Unknown month name | Skipped, counted |
| Date more than one day ahead of now | Read as the same date one year earlier |
| Invalid UTF-8 byte | Replaced (`errors="replace"` at the CLI's file open), line still parsed |

## Error handling

`parse_line` never raises. `parse_errors` accumulates skipped lines and the CLI reports the
total: `scanned <file>: 15 event(s), 5 line(s) skipped, 2 incident(s)`.

A silently-zero event count with a high skip count is the signal that the log format is not one
this parser knows — which is a real answer, not a crash.

## RDP event logs (P5)

A line starting with `{` is read as one exported Windows Security event; anything else goes to the
`sshd` syslog path. One file may hold both.

| Field (aliases) | Mapped to |
|---|---|
| `EventID` / `event_id` / `EventCode` | 4625 → `outcome="failure"`, 4624 → `"success"`, else skipped |
| `LogonType` / `logon_type` | must be 10 (RemoteInteractive); 3 and 7 share the ids and are skipped |
| `TargetUserName` / `target_user_name` / `user` | `actor.account` |
| `IpAddress` / `ip_address` / `SourceNetworkAddress` | `actor.source_ip` |
| `Computer` / `computer_name` / `Hostname` | `target.host`, with `port=3389` |
| `TimeCreated` / `@timestamp` / `EventTime` | `timestamp` (ISO-8601, `Z` accepted) |
| `SubStatus` / `Status` | `auth.reason`, named for six codes, generic otherwise; raw code kept in `meta` |
| `WorkstationName` | `meta.workstation` |

Ids and logon types are accepted as numbers or as strings, because real exports contain both.
An event is skipped when the source is `-`, `127.0.0.1`, or `::1`, when no account is named, or
when the timestamp is unreadable — a placeholder key would merge unrelated events into one window.

**EVTX itself is not parsed.** That would need a third-party library and a Windows-only binary
file; the collector shipping these logs has already converted them, and the JSON export is what
`wevtutil`, Winlogbeat, and every EVTX-to-JSON tool emit.
