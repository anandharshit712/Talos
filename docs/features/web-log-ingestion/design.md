# Design — Web Log Ingestion

## Position in the pipeline

```
combined | nginx-JSON | WAF-JSON  ->  WebLogParser  ->  NormalizedEvent  ->  EventOrchestrator
```

## Contracts

| Direction | Contract |
|---|---|
| Consumes | lines of text, three formats, mixed freely within one file |
| Emits | `NormalizedEvent` with `domain="web"`, `telemetry_source` of `app_log` or `waf` |

## Decisions

**Format is detected per line, not per file.** A real collector interleaves sources, and a parser
that must be told which format it is reading is a parser somebody configures wrongly. A leading
`{` means JSON; anything else is tried as combined.

**WAF records are labelled, and their verdict is kept.** A record carrying `rule_id`, `blocked`,
or `anomaly_score` becomes `telemetry_source="waf"`, and those fields survive into `meta`. What
the WAF already decided is evidence, not noise.

**Decoding is exactly one layer, and the boundary has its own test.** `parse_qsl` performs that
layer; nothing decodes again afterwards. This was wrong in the first implementation — an extra
pass turned `%2527` into `'` — and the test caught it before any detector was written.

**`raw` keeps the original encoding.** Evidence must quote what was on the wire, not the parser's
interpretation of it.

**Key aliases rather than a normaliser per collector.** Collectors disagree on names:
`remote_addr`, `client_ip`, `src_ip`. A per-field alias list covers the same ground in a fraction
of the lines.

**A numeric trailing path segment becomes `target.resource_id`.** That is the raw material for
IDOR reasoning in P6, extracted here because the parser is the only layer that sees the path
structurally.

## Alternatives considered

| Option | Why not |
|---|---|
| A format flag per run | Fails on a mixed file, which is the normal case for a collector. |
| Decode until the string stops changing | The evasion this rule exists to prevent: the attacker picks the number of layers. |
| Scan headers for payloads | Attacker-controlled, but the false-positive rate from scanners and referrers would swamp the corpus. A documented gap, not an oversight. |
| A regex per collector | The alias table is shorter and adding a collector becomes a list entry. |
