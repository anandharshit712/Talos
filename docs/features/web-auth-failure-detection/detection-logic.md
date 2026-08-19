# Detection Logic — Web Auth Failure Detection

## Signals

Both detectors read one signal only: `NormalizedEvent.auth.outcome == "failure"` with
`auth.protocol == "http"`, counted inside a rolling window by `RateEngine`. No payload
inspection, no model, no heuristic on user agents.

## Thresholds

All of them live in `config/thresholds.yaml` under `talos.detection`; none is a literal in code.

| Setting | Default | Meaning |
|---|---|---|
| `brute_force.window_seconds` | 120 | window for the depth question |
| `brute_force.fail_threshold` | 10 | failures against one account before it fires |
| `credential_stuffing.window_seconds` | 300 | window for the breadth question |
| `credential_stuffing.distinct_accounts` | 15 | accounts one source must touch |
| `credential_stuffing.fails_per_account_max` | 3 | attempts against any one account, at most |
| `rate_confidence.base` | 0.70 | confidence exactly at threshold |
| `rate_confidence.per_extra_attempt` | 0.02 | added per unit above threshold |
| `rate_confidence.cap` | 0.95 | ceiling however large the burst |
| `rate_confidence.success_floor` | 0.90 | floor once a login succeeded |

The stuffing window is longer than the brute-force one on purpose: a dump replay paces itself to
stay under per-account limits, so it is a slower event by nature.

## The two decisions

**Brute force** fires when one account accumulates `fail_threshold` failures inside
`window_seconds`, from any number of sources. Confidence scales on the failure count.

**Credential stuffing** fires when one source, inside `window_seconds`, reaches
`distinct_accounts` distinct accounts **and** no single account exceeds `fails_per_account_max`.
Confidence scales on the *account* count. The account threshold doubles as the engine's failure
pre-filter, since reaching N distinct accounts takes at least N failures.

`RateSignal.fails_per_account` is what makes the second condition computable. LLD §7.3's original
sketch had a `distributed: bool` on `RateConfig` instead; a mode flag would have made the engine
decide something, and the engine's job is to count. Reporting the per-account tally leaves the
decision in the detector, where the technique is known.

## Confidence

```
score = min(cap, base + per_extra_attempt × (score_count − threshold))
if a login succeeded after the burst began: score = max(score, success_floor)
```

`score_count` is the failure count for brute force and the distinct-account count for stuffing.
A model narrative, when one is produced, multiplies the score by the route's
`confidence_multiplier` — a fallback provider's answer is worth less than the first choice's — and
can never raise it above what the statistics produced.

## Evidence

Every verdict carries, in order:

1. one `statistic` line stating the count, the window, the threshold that fired, and — for
   stuffing — the distinct-account count and the deepest per-account attempt count;
2. up to three `log_line` items quoting raw lines verbatim;
3. for a burst followed by a success, one `statistic` line naming the accounts that got in.

## MITRE and OWASP

| Technique | ATT&CK | OWASP |
|---|---|---|
| `brute_force` | T1110 | A07:2021 |
| `credential_stuffing` | T1110.004, then T1110 | A07:2021 |

Ids come from `knowledge/mitre_mapping.py`; the report lists a technique's mappings
most-specific-first, so a stuffing incident leads with T1110.004 rather than its parent.

## False positives

| Shape | Why it fires | Mitigation |
|---|---|---|
| A monitoring bot with a stale password | genuine repeated failures against one account | allowlist by source is P8; today it is a true positive by the definition used |
| A shared NAT egress for a large office | many accounts failing from one address | `fails_per_account_max` keeps ordinary typos out; a busy enough gateway can still cross 15 accounts in 300s |
| A password rotation deployment | many accounts, few failures each | same shape as stuffing; indistinguishable from an access log alone |

## False negatives, and the known limits {#known-limits}

| Shape | Why it is missed |
|---|---|
| **A rotated stuffing run** — 50 proxies, 3 accounts each | The window is keyed per source. Catching this needs a window keyed on nothing at all, and a global window fires on fifteen unrelated people mistyping passwords unless a source-set heuristic sits beside it. Deferred with the trigger named in the build tracker; P8 decides it against a real capture. |
| **An application that answers a failed login `200`** | The access log states no outcome, and the parser records `None` rather than guessing. Fixable only with response bodies or application logs. |
| **A login that names no account** — no form body, no `remote_user` | No account, no key for the depth detector. Stuffing is unaffected, since it keys on the source. |
| **A grind slower than the window** — 9 failures every 2 minutes | Under threshold by construction. A long-window low-rate detector is a separate technique, not a threshold tweak. |
| **Distributed depth** — one account, 40 sources, 1 try each | Brute force sees 40 failures on the account and *does* fire; it is the stuffing detector that stays quiet, correctly. |

## What cannot happen

- No verdict without evidence and a float confidence.
- No model call can change `attack_detected`, a count, a scope, or a MITRE id.
- A detector that raises is logged and skipped; the other still reports (fail-open detection).
- Log content — usernames, hosts, raw lines — reaches a model sealed as data, never as
  instructions, and is length-bounded first.
