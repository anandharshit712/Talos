# Testing — Web Log Ingestion

## How to run

```bash
python -m pytest tests/unit/ingestion/parsers/test_web_log_parser.py
python -m pytest tests/e2e/test_web_injection_precision.py    # ingestion inside the P4 gate
```

## Fixtures

| Fixture | Contents |
|---|---|
| `web_sql_injection_mixed_waf.log` | 8 WAF-JSON records: tautology, UNION, comment terminator, stacked DDL, time delay, comment-obfuscated UNION, schema enumeration |
| `web_xss_mixed_combined.log` | 6 combined lines: script element, event handler, `javascript:` URI, double-encoded script, SVG vector, attribute breakout |
| `web_benign_traffic_combined.log` | 14 lookalikes: `O'Brien`, `select a plan`, `union square hotel`, `<b>bold</b>`, `onerror` in prose, `5 > 3`, a hyphenated sentence, a base64 image URI, a static asset |

## Cases covered

- every field of a combined line, including `raw` verbatim
- nginx JSON read as `app_log`; WAF JSON labelled `waf`, with its rule id and verdict kept
- `-` is not a username
- **query decoded exactly once**: `%2527` becomes `%27`, not `'`
- `raw` keeps the original encoding, so evidence quotes the wire
- numeric path tail becomes `resource_id`; a slug does not
- ISO-8601 and epoch timestamps both accepted
- blank lines, malformed JSON, missing targets, bad timestamps, and non-log text are skipped
- the skip counter matches the number of unreadable lines

## Latest observed results

2026-08-18 — 16 parser tests passing. Across the three fixtures: 28 events parsed, 0 skipped,
0 exceptions.

**One defect found by these tests during development.** `parse_qsl` already performs one
percent-decode, and the parser applied a second — so `%2527` decoded to `'` instead of `%27`.
That is exactly the double-decode evasion LLD 5.2 forbids, and it was live in the first
implementation. The boundary now has a test of its own.
