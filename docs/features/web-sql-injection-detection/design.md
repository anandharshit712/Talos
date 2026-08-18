# Design — Web SQL Injection Detection

## Position in the pipeline

```
NormalizedEvent(domain="web")
  -> WebDomainAgent          routes within the domain
     -> WebTypeClassifier    injection markers first, then endpoint shape
     -> InjectionSubAgent    SQLi and XSS concurrently
        -> SqlInjectionDetector
           -> pattern_engine + sql_injection_pattern_rules   (deterministic)
           -> model judge, only for borderline payloads
```

## Contracts

| Direction | Contract |
|---|---|
| Consumes | `NormalizedEvent` with a `request`, plus `DetectionContext` |
| Emits | `Verdict` -- `technique="sql_injection"`, `category="injection"`, MITRE T1190 |

## Decisions

**Patterns decide, the model judges the middle.** A decisive payload produces a verdict with no
model call; a request whose only signal is noise-grade is cleared without one. Only the genuinely
ambiguous middle reaches a model. This is what makes the precision number a property of the
detector rather than of a provider's uptime -- the P4 gate is measured with the model stubbed.

**Three grades of signal, not two.** `unambiguous` alone would force every ambiguous hit to a
model, and the most common ambiguous hits are punctuation. The third grade,
`corroborating_only`, lets a signal count toward a finding without ever starting one.

**The judge can veto.** A borderline payload the model clears produces no verdict at all. A judge
that can only agree is not a judge, and the veto is what lets the ambiguous rules stay loose
enough to catch obfuscation.

**The pattern engine is shared with XSS.** Extraction, matching, evidence, and the three grades
are identical; only the tables differ. That is what makes a new family a table rather than a
module.

**`succeeded` comes from the response.** A blocked 403 and a 200 that returned rows are the same
attack and a completely different incident.

## Alternatives considered

| Option | Why not |
|---|---|
| Model-first classification | Slower, unmeasurable, and rate-limited to 40 requests a minute -- below the speed of reading the log. |
| Score every request and threshold | Harder to explain in a report; an analyst can re-check a named rule, not a weight vector. |
| Only decisive rules, no model tier | Gives up on obfuscation, which is exactly where a code-aware model earns its cost. |
| Escalate every ambiguous hit | The common ambiguous hits are punctuation and markup; this spends the request budget on prose. |
