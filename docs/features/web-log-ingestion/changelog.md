# Changelog — Web Log Ingestion

## 2026-08-19 — HTTP authentication outcomes (P5)

- **Defect found: `auth` was never populated.** `WebLogParser` set it to `None` on every
  line, so any web auth detector would have been dead on arrival. `derive_http_auth` now
  reads an outcome off the request: `401`/`403` on a login path is a failure, a
  credential-carrying `2xx`/`3xx` is a success, and anything else stays `None` rather than
  being guessed.
- The submitted username is read from the query string or the body (form-encoded or JSON)
  when the collector did not already resolve one, with **exactly one decode** — the same
  boundary the payload path holds to, and asserted by a `%2527` test. Only the account field
  is read; the password beside it is never copied into an event.
- `LOGIN_ENDPOINT` lives here and is imported by `WebTypeClassifier`, which dropped its own
  copy. Registration and password-reset paths are deliberately outside the pattern: a `201`
  from `POST /register` is a new account, not a login, and would otherwise read as a trailing
  success on somebody else's burst.
- **Known limit:** an application that answers a failed login with `200` and a re-rendered
  form is unreadable from an access log alone. Recorded as a success, and documented rather
  than guessed at.
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
