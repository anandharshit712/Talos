# Design — Web Auth Failure Detection

## The chain

```
access log line
  → WebLogParser              status code + login path → AuthEvent(protocol="http")
                              submitted username       → actor.account
  → WebDomainAgent            routes within the domain, knows categories only
     → WebTypeClassifier      injection markers first, then event.auth → "auth_failure"
     → AuthFailureSubAgent    runs both detectors concurrently, isolates their failures
        → BruteForceDetector          keyed per account   → depth
        → CredentialStuffingDetector  keyed per source IP → breadth
           → RateEngine               counts failures per key inside a window
              → RateVerdictEngine     curve, narration, Scope, ModelInfo, Verdict
```

## Contracts

| Direction | Contract |
|---|---|
| Consumes | `NormalizedEvent` with `auth.protocol == "http"`, plus `DetectionContext` |
| Emits | `Verdict` — `category="auth_failure"`, `technique ∈ {brute_force, credential_stuffing}` |

## Decisions

**HTTP auth events are derived in the parser, not in the detectors.** `sshd` states an outcome in
words; an access log states it as a status code against a path. That translation had to live
somewhere, and putting it in the parser means the web detectors read exactly the `event.auth`
shape the network ones read — which is what makes "the same engine, a different key" true rather
than aspirational. It also let the classifier drop its private copy of the login-endpoint regex
and route on the parser's answer instead, so routing and parsing cannot disagree about what a
login is.

The mapping is deliberately narrow (`web_log_parser.derive_http_auth`):

| Observed | Recorded |
|---|---|
| `401`/`403` on a login path, any method | `outcome="failure"` |
| `POST`/`PUT`/`PATCH` on a login path answered `2xx`/`3xx` | `outcome="success"` |
| anything else | `auth = None` |

`GET /login → 200` is the form rendering, not an attempt, and is recorded as neither. A `200` on
a posted login is genuinely ambiguous in an access log; recording it as a failure would invent
attacks out of every successful sign-in on applications that answer `200`, so it is read as a
success and the ambiguity is documented instead of guessed. Registration and password-reset paths
are excluded from the pattern outright: a `201` from `POST /register` is a new account, and
letting it count as a trailing success would raise the confidence of a burst it has nothing to do
with.

**Brute force is keyed on the account, not the host+account pair.** SSH grinds an account on a
box; a web login is served by whichever app server the load balancer picked, so `(host, account)`
would split one attack across three verdicts. LLD §7.3.1 permits keying on the source IP instead,
and that was rejected: it would fire this detector on precisely the window credential stuffing
owns, and one attack would be reported twice under two techniques.

**Credential stuffing is keyed on the source, and needs both halves of the shape.** Many distinct
accounts *and* few attempts per account. The second condition is what makes the verdict a claim
rather than a coincidence — without it, one account ground 200 times from one address satisfies
"many failures from one source" and would be reported as stuffing.

**The two keys are what keep the detectors from colliding.** Both children may answer on the same
event and that is intended: two genuine attacks from two sources are two verdicts, not a choice
between them. What must not happen is one attack arriving twice, and per-account depth against
per-source breadth is the mechanism that prevents it.

**Verdict assembly is shared, and lives in `detection/rate/rate_verdict_engine.py`.** Four rate
detectors differ in three things: the telemetry they accept, what they call the statistic they
fired on, and how they word the fallback narrative. Everything else — the confidence curve, the
narration call, `Scope`, `ModelInfo` — was identical in each, so it now exists once. A change to
the curve cannot land in three detectors and miss the fourth.

**Confidence for stuffing is read from the account count, not the failure total.** A run over 400
accounts is worse than one over 20 even when the second retried more, and a total that grows with
either dimension cannot express that. `RateVerdictSpec.score_count` carries whichever number the
technique is defined by.

## Interaction with injection

The classifier tests injection markers *before* auth routing, unchanged from P4: a SQLi payload
posted to `/login` is an attack on the login form, and handing it to a failure counter would both
miss the injection and pollute a window. A payload-bearing login therefore never reaches this
feature.

## Data flow into the report

`Scope.affected_accounts` carries every account in the window — one for a grind, dozens for a
stuffing run. `Scope.succeeded` and the evidence line name the accounts that authenticated after
the burst began, which is the single most useful sentence in the report: it says who was taken
over rather than that somebody was. The aggregator's `auth_failure` actions (rate-limit the
source, force a reset, and on success rotate credentials) were already in place from P1.
