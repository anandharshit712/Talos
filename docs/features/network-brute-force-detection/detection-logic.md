# Detection Logic — SSH and RDP Brute Force

**Technique:** `brute_force` · **MITRE:** T1110 (Brute Force, Credential Access) ·
**OWASP:** A07:2021 Identification and Authentication Failures

## Signals

| Signal | Source | Used for |
|---|---|---|
| Failed authentications for `(host, account)` inside the window | `EventWindowStore` | the firing decision |
| A successful authentication at or after the first failure in that window | same window | `scope.succeeded`, confidence floor, severity |
| Distinct source IPs behind the failures | the same events | `scope.source_diversity` |
| The raw log lines | `NormalizedEvent.raw` | evidence an analyst can verify by eye |

## Thresholds — all in `config/thresholds.yaml`

```yaml
talos:
  detection:
    ssh_brute_force: { window_seconds: 120, fail_threshold: 8 }
    rdp_brute_force: { window_seconds: 120, fail_threshold: 8 }
    rate_confidence: { base: 0.70, per_extra_attempt: 0.02, cap: 0.95, success_floor: 0.90 }
```

Nothing above appears as a literal in the detector; tuning is a config change (standards §2.3).

## Algorithm

1. Ignore the event unless `auth.protocol` is this detector's protocol — `ssh` or `rdp`. The
   two detectors share the key function, so the filter is the only thing keeping each out of
   the other's window.
2. Key it as `host_account:<host>|<account>`; an event missing either is unkeyable and ignored.
3. Read every event for that key within `window_seconds` of the newest one.
4. Count failures. Below `fail_threshold` → return `None` (not a verdict of "benign", an
   absence of one).
5. Look for a success at or after the first failure in the window → `succeeded`.
6. Score, scope, evidence, narrate.

## Confidence

```
score = min(cap, base + per_extra_attempt × (failures − threshold))
if succeeded: score = max(score, success_floor)
```

At the threshold exactly: **0.70**. Twenty failures: 0.94. Capped at **0.95** — a threshold
count is strong evidence of a pattern, never proof of intent, so the curve never reaches 1.0. A
trailing success floors it at **0.90** regardless of count: an attempt that worked matters even
if it took few tries.

These numbers are the first thing P8 calibration will move, which is why they are one shared
config block rather than four per-detector ones.

## Scope

| Field | Filled with |
|---|---|
| `affected_accounts` | accounts named in the failures (one, given the key) |
| `affected_hosts` | hosts named in the failures |
| `attempt_count` | failures inside the window |
| `source_diversity` | distinct source IPs |
| `succeeded` | trailing success present |
| `window_start` / `window_end` | first and last contributing event |

## Evidence

Always at least one `statistic` (`"12 failed ssh authentications for bastion-01|root within 120s
(threshold 8), from 1 source IP(s)"`), up to three `log_line` items quoted verbatim, and a second
`statistic` when a success followed. Never empty — the contract makes an unevidenced verdict
unconstructible.

## Known false-positive modes

| Mode | Effect | Mitigation |
|---|---|---|
| Misconfigured service or cron job retrying a stale password | Fires; looks identical to an attack from the log alone | Analyst-visible: `source_diversity == 1` from an internal address. Allowlisting is a P8 calibration input, not a code change. |
| Password rotation across a fleet | Several accounts fire at once | Each is a separate key, so scope stays accurate; severity stays `medium` without a success |
| Deliberately noisy honeypot | Fires constantly, correctly | `succeeded` separates real access from noise; that is the field to triage on |

## Known false-negative modes

| Mode | Effect | Planned answer |
|---|---|---|
| Slow grind — 5 attempts/hour | Never crosses the window | Longer-window profile, post-slice |
| Spray across many accounts, few tries each | Below threshold on every key | **Credential stuffing (P5, delivered)** — the breadth view over the same window, for HTTP logins |
| Rotating source IPs against one account | Still fires: the key is `(host, account)`, not the IP | Already covered |
| Success with no preceding failures | Not brute force by definition | Anomalous-login detection, out of slice |
| Logs the parser cannot read | Silent | Skip counter is printed on every scan |

## RDP specifics (P5)

Same algorithm, same curve, same key. What differs:

| Aspect | SSH | RDP |
|---|---|---|
| Telemetry | `sshd` syslog lines | exported Windows Security events, JSON per line |
| Accepted | `Failed`/`Accepted password`, `Invalid user` | `EventID` 4625/4624 with `LogonType` 10 |
| Failure reason | `invalid_password`, `unknown_user` | mapped from `SubStatus` — `unknown_user`, `invalid_password`, `account_disabled`, `account_locked`, `account_expired`, `workstation_restriction`, else `logon_failed` |
| Port recorded | 22 | 3389 |
| On success | probable initial access | probable initial access, and called out as a leading ransomware entry point in the narrative |

**A locked account is named rather than folded into a generic failure.** `0xC0000234` after a
burst is the sequence an analyst most wants to see, because it tells them the lockout policy
worked and roughly when the attempt stopped.

### RDP false-negative modes

| Mode | Effect |
|---|---|
| RDP behind a gateway that rewrites the source | Every failure shares the gateway's address; still fires on `(host, account)`, but `source_diversity` is 1 and misleading |
| `LogonType` 7 (unlock) brute force | Skipped by design — not a remote session; would need its own route |
| An export that omits `IpAddress` | Skipped rather than keyed on a placeholder, so the burst is invisible |
| NLA rejecting before Windows logs a 4625 | No event to count; a network-level detector's job, out of slice |
