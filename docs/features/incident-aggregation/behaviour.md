# Behaviour — Incident Aggregation and Output

## Inputs and outputs

| Input | Output |
|---|---|
| One `NormalizedEvent` and the verdicts its domain agent produced | One `IncidentReport`, or `None` when no verdict claims an attack |

## The five aggregation steps

1. **Dedupe** on `(technique, sorted(event_ids))`; the most confident duplicate survives.
2. **Merge scope** — union of accounts, endpoints, objects, hosts; `max` of attempt count and
   source diversity; widest window; `succeeded` is true if any verdict says so.
3. **Score severity** — see the table below.
4. **Combine confidence** — highest verdict, plus `corroboration_boost` per additional distinct
   detector, capped at 1.0.
5. **Recommend actions** — category templates filled from the merged scope, plus containment
   actions when the attack succeeded.

## Severity

| Category | Floor |
|---|---|
| `injection`, `broken_access_control` | high |
| `auth_failure`, `network_brute_force` | medium |
| anything unregistered | medium |

Then: `succeeded` → one step up · confidence < 0.5 → one step down · clamped to
`info … critical`.

## Recommended actions

| Category | Templates |
|---|---|
| `network_brute_force` | block the source IP at the perimeter; review authentication history for the accounts on the hosts |
| `auth_failure` | block or rate-limit the source; force a password reset |
| `injection` | block the source; review and patch input handling on the endpoints |
| `broken_access_control` | revoke the session; audit access to the listed objects |
| *any, when `succeeded`* | rotate credentials; hunt for follow-on activity on the target |

Source addresses are named from the triggering event — `Scope` counts distinct sources but does
not carry their addresses.

## Duplicate suppression

A windowed detector fires again on every event past its threshold, so one 40-attempt burst would
otherwise become 32 identical incidents. The orchestrator reports an incident when its signature
— domain, category, techniques, accounts, hosts, endpoints — is first seen, and stays quiet until
it escalates:

| Change | Re-reported? |
|---|---|
| Another failure in the same burst | no |
| The attack succeeded (`succeeded` flips true) | **yes** |
| Attempt count reaches `escalation_attempt_factor` × the last reported count | **yes** |
| A different account, host, or endpoint | **yes** — different signature |

Nothing is lost: every event stays in the window and every verdict stays in the next report.
What is suppressed is the repeated *alert*. `aggregation.suppress_duplicates: false` disables it.

## Persistence and sinks

| Destination | Behaviour |
|---|---|
| `VerdictLogStore` (SQLite) | one row per incident, full report stored as JSON; re-appending the same `incident_id` replaces it |
| `StdoutSink` | one JSON object per line on stdout (`--pretty` indents for a demo) |
| `JsonFileSink` | `<talos.output.report_dir>/<incident_id>.json`, directory created on demand |

## Error handling

| Failure | Behaviour |
|---|---|
| No domain agent registered for the event's domain | Logged warning, event not analysed, `None` returned — the stream continues |
| Domain agent or sub-agent raises | Contained below this layer; the orchestrator sees an empty verdict list |
| `verdict_log` table missing | `StorageError` naming `scripts/apply_migrations.py`; the CLI prints it and exits 1 |
| Report directory cannot be created | `StorageError` — a report that cannot be written must be heard about, not dropped |
| Log file does not exist | CLI prints the path and exits 2 |

## Edge cases

- Every verdict inconclusive (`attack_detected=false`) → `None`, no report, nothing persisted.
- Two detectors, same technique, same events → one verdict in the report, the confident one.
- Two detectors, same technique, different event sets → both kept; scope is the union.
- A verdict whose category has no action template → report still emitted, `recommended_actions`
  empty rather than invented.
- Unknown sink name in config (`api` before P7) → logged and skipped, scan proceeds.
