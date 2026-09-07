# Behaviour — Pipeline-Trace Demo

## `talos demo [--chain web|network|all] [--json] [--file LOG]`

Runs the prepared chains (or a custom `--file`) and prints the trace. Exit 0 always; this is a
presentation path, not a gate.

## The web chain

`docs/submission/demo_web_chain.log`: four SQL injection payloads (tautology, union, error-based,
stacked — one per pattern class), then twelve `POST /login` failures against `admin` from the same
source, then a `302` success. Produces three incidents: an `injection`/critical, then an
`auth_failure` that rises from medium to high when the burst lands. The classifier routes the first
four events to the SQL injection detector and the rest to the brute-force detector — the routing is
visible in the trace.

## The network chain

`docs/submission/demo_network_chain.log`: twelve failed SSH logins for `root`, then an accepted one.
The brute-force detector fires at the eighth failure (medium/0.70) and re-reports at high/0.90 when
the trailing success arrives — the escalation an analyst most needs to see.

## The trace structure (what the UI consumes)

`Trace{ title, events, incidents, used_llm, steps[] }`, each `TraceStep{ index, summary, source,
verdicts[], incident? }`. A verdict carries its detector, technique, confidence, and evidence; an
incident carries category, severity, MITRE ids, scope, and recommended actions.
