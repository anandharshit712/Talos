# Feature — Web Log Ingestion

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/ingestion/parsers/web_log_parser.py`
**Config:** `config/default.yaml` → `talos.ingestion.web.formats`
**Tests:** `tests/unit/ingestion/parsers/test_web_log_parser.py`
**Fixtures:** `tests/fixtures/logs/web_sql_injection_mixed_waf.log`, `web_xss_mixed_combined.log`, `web_benign_traffic_combined.log`

Turns Apache/nginx combined lines, nginx-JSON records, and WAF-JSON records into
`NormalizedEvent`, autodetected per line. Everything a web detector reasons about — path, query
parameters, body, headers, status, actor — is extracted here so no detector parses a string.

**Decoding happens exactly once.** `%2527` becomes `%27`, never `'`. Decoding until the string
stops changing lets the attacker choose how many layers the parser unwraps, and what it lands on
is then not what the application received.

| Document | Contents |
|---|---|
| [design.md](design.md) | format autodetection, the decode boundary, alternatives rejected |
| [behaviour.md](behaviour.md) | accepted formats, field mapping, edge cases, error handling |
| [testing.md](testing.md) | cases covered, fixtures, results |
| [changelog.md](changelog.md) | dated entries |
