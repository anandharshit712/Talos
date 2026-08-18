# Detection Logic — SQL Injection

**Technique:** `sql_injection` · **MITRE:** T1190 (Initial Access) · **OWASP:** A03:2021 Injection

## Signals

Every attacker-controlled string on the request: the path, each query parameter value, and the
body. Headers are deliberately excluded — see the false-positive table.

## Pattern classes

| Class | Rules | Decisive? |
|---|---|---|
| `tautology` | quoted boolean equality (`' OR '1'='1`), numeric always-true (`OR 1=1`), quote-terminated comment (`admin'--`) | yes |
| `union` | `UNION SELECT`, comment-padded `UNION/**/SELECT`, `FROM information_schema.*` | yes |
| `stacked` | `; DROP|INSERT|UPDATE...`, `EXEC xp_*` | yes |
| `blind` | time delay (`SLEEP(`, `WAITFOR DELAY`) — decisive; boolean probe (`AND 1=2`), conditional substring — judged | mixed |
| `evasion` | inline comment inside a keyword (`SEL/**/ECT`) — decisive; double-encoded quote — judged; long hex, bare comment marker — corroboration only | mixed |

Three grades, and the middle one is the whole design:

- **decisive** — a verdict with no model call
- **actionable but ambiguous** — put to the judge model
- **corroboration-only** — never acts alone; supports another class, nothing more

A bare `--` in prose and `<b>bold</b>` in a comment field are corroboration-only. Without that
grade every hyphenated sentence would spend a model call from a 40-per-minute budget, and invite
a model to agree that punctuation is an attack.

## The decision

```
payloads = path + query values + body          (decoded once by the parser)
hits     = every rule that matched
if nothing actionable fired            -> None            (cleared, no model)
elif a decisive rule fired             -> confidence 0.95, used_llm=false
elif >= 2 actionable families fired    -> confidence 0.95, used_llm=false   (corroboration)
else                                   -> judge model; it may veto
     no model reachable                -> confidence 0.45, reported as a lead
```

Corroboration counts **actionable** families only. Two noise-grade signals must never manufacture
certainty.

## Confidence

| Situation | Confidence |
|---|---|
| Decisive pattern, or two actionable families | 0.95 |
| Judge model says yes | its number, clamped to `[0, 1]` |
| Judge answered via a fallback provider | its number × 0.85 |
| Borderline with no model reachable | 0.45 — a lead, not a finding |

Never 1.0: a rule match is strong evidence of an *attempt*, never proof of intent, and P8
calibration needs headroom.

## Scope

| Field | Filled with |
|---|---|
| `affected_endpoints` | the endpoint the payload was aimed at |
| `affected_objects` | the table named in the payload, when it names one |
| `affected_accounts` | the authenticated account, when the log carries one |
| `succeeded` | from the response status, never from the payload |

`succeeded` mapping: 200/201/202 → true; 5xx → true (the payload reached the database and broke
the query); 400/401/403/406/429/501 → false; anything else → `None`. Guessing here would put a
fabricated `succeeded` in a report, and that is the field an analyst acts on first.

## Known false-positive modes

| Mode | Mitigation |
|---|---|
| A search box receiving SQL words (`select a plan`, `union square hotel`) | Rules demand syntax — quote break plus operator plus comparison — not vocabulary. In the benign corpus. |
| Surnames with apostrophes (`O'Brien`, `d'Artagnan`) | The tautology rule needs an operator after the quote. In the benign corpus. |
| Hyphenated prose (`help -- urgent`) | Comment markers are corroboration-only. |
| Long hex tokens and hashes | Corroboration-only. |
| A developer pasting real SQL into a form | Would fire, correctly by the rules, wrongly by intent. Unresolved; the judge model sees these only if no decisive rule fires. |

## Known false-negative modes

| Mode | Planned answer |
|---|---|
| Payload in a header (`X-Forwarded-For`, cookies) | Documented gap — header scanning's false-positive rate would swamp the corpus |
| Second-order injection (stored now, executed later) | Out of slice; needs response-body correlation |
| Heavy obfuscation with no recognised keyword | The judge tier exists for this, but only if some rule fires first |
| A payload split across two parameters | Each field is matched independently |
| WAF already blocked and did not log the payload | Nothing to detect; the WAF verdict is kept in `meta` |
