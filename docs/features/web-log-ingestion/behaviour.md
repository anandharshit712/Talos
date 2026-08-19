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

## HTTP authentication outcomes (P5)

`derive_http_auth(path, method, status)` maps a request line onto `AuthEvent(protocol="http")`.
Login paths only — `login`, `signin`, `sign-in`, `auth`, `authenticate`, `session`, `token`,
`oauth`.

| Observed | Recorded | Why |
|---|---|---|
| `401` or `403`, any method | `failure` | a rejected credential, form or Basic/Bearer alike |
| `POST`/`PUT`/`PATCH` → `2xx`/`3xx` | `success` | `302` back into the app is what a real login looks like |
| `GET /login` → `200` | `None` | the form rendering; not an attempt |
| `POST /login` → `200` | `success` | ambiguous in an access log — see below |
| `POST /register` → `201` | `None` | a new account, not a login |
| `403` on a non-login path | `None` | authorisation, not authentication (P6's territory) |

**The account.** When the collector already resolved a user (`remote_user`, `user`, `username`),
that name wins. Otherwise the submitted one is read from the query string or the body — form-encoded
or JSON — through `parse_qsl`/`json.loads`, which each decode exactly once. `%2527` stays `%27`, as
everywhere else in this parser. Only the account field is read; the password beside it is never
copied into an event.

**The one ambiguity, stated plainly.** Applications that answer a failed login with `200` and a
re-rendered form are indistinguishable from a successful one in an access log. Reading `200` as a
failure would invent an attack out of every sign-in on such an application, so it is read as a
success; the cost is a missed burst there, and it needs response bodies or application logs to fix.
