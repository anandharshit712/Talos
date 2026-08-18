# Changelog — Web Log Ingestion

## 2026-08-18 — HTTP, nginx-JSON, and WAF-JSON ingestion (P4)

- Added `WebLogParser`: three formats autodetected per line, because a collector interleaves them.
- WAF records are labelled `telemetry_source="waf"` and keep `rule_id`, `blocked`, and anomaly
  fields in `meta` — the WAF's own verdict is evidence, not noise.
- Field aliases per logical field (`remote_addr` / `client_ip` / `src_ip`, and so on), so a new
  collector is a list entry rather than a new parser.
- Trailing numeric path segments become `target.resource_id`, the raw material for P6's IDOR
  reasoning.
- Added three labelled fixtures: SQL injection, XSS, and a benign corpus of deliberate lookalikes.
- **Fixed during development:** query values were decoded twice, because `parse_qsl` already
  decodes once — `%2527` became `'` instead of `%27`, the exact double-decode evasion LLD 5.2
  exists to prevent. A test now pins the boundary.
- **Known limitations:** headers are not scanned for payloads (the false-positive rate from
  scanners and referrers would swamp the corpus); response bodies are absent from these formats,
  so reflection is inferred from status codes rather than observed.
