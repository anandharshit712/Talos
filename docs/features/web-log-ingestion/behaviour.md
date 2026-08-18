# Behaviour — Web Log Ingestion

## Accepted formats

| Format | Detected by |
|---|---|
| Combined / common | anything not starting with `{` |
| nginx JSON | leading `{`, no WAF marker |
| WAF JSON | leading `{` plus one of `rule_id`, `waf`, `attack_type`, `anomaly_score`, `blocked`, `action` |

## Field mapping

| Source | `NormalizedEvent` field |
|---|---|
| `remote_addr` / `client_ip` / `src_ip` | `actor.source_ip` |
| `remote_user` / `user` (never `-`) | `actor.account` |
| `http_user_agent`, or the `User-Agent` header | `actor.user_agent` |
| `X-Session-Id` header | `actor.session_id` |
| request line or `request_uri` | `request.method`, `request.path`, `request.query_params` |
| `request_body` / `body` / `post_data` | `request.body` |
| `status` / `status_code` | `request.status_code` |
| `host` / `http_host` / `server_name` | `target.host` |
| trailing numeric path segment | `target.resource_id` |
| WAF fields | `meta` |
| the whole line, verbatim | `raw` |

Timestamps are accepted as ISO-8601, epoch seconds, or the CLF bracket format, and normalised to
UTC by the contract.

## Decoding

Query values are decoded **once**, by `parse_qsl`. Bodies are decoded once, explicitly. Nothing
decodes twice:

| Input | `query_params` value |
|---|---|
| `id=1%27` | `1'` |
| `id=1%2527` | `1%27` |
| `q=a+b` | `a b` |

## Edge cases

| Input | Behaviour |
|---|---|
| Blank line | Ignored; **not** counted as an error |
| `-` in the user field | `actor.account` is `None`, not the string `-` |
| Malformed JSON | Skipped, counted |
| JSON with no request target | Skipped, counted |
| Unparseable timestamp | Skipped, counted |
| Non-combined, non-JSON text | Skipped, counted |
| Slug path (`/about/company`) | No `resource_id` — only numeric tails qualify |

## Error handling

`parse_line` never raises. Unreadable lines increment `parse_errors`, which the CLI reports on
every scan: `scanned <file>: 28 event(s), 3 line(s) skipped, 2 incident(s)`.
