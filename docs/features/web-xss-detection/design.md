# Design — Web XSS Detection

## Position in the pipeline

Identical to the SQL detector, sharing `pattern_engine` and running beside it inside
`InjectionSubAgent`. One request can be both attacks, and both verdicts are produced.

## Contracts

| Direction | Contract |
|---|---|
| Consumes | `NormalizedEvent` with a `request`, plus `DetectionContext` (for the event window) |
| Emits | `Verdict` — `technique="xss"`, `category="injection"`, MITRE T1059.007 |

## Decisions

**Rules require an executable construct, not angle brackets.** A script element, a handler bound
to a value, a scheme that executes. Users legitimately post markup, write `onerror` in bug
reports, and type `5 > 3`; a rule that fires on those trades precision for nothing.

**Reflected versus stored is scope, not prose.** Reflected affects the person who clicked. Stored
affects every later visitor to the endpoints that render it. The detector consults the event
window for the same payload signature at a *different* endpoint; when it finds one, both
endpoints enter `affected_endpoints` and confidence floors at 0.9.

**The signature is built from matched fragments, not from the request.** The same payload arrives
at one endpoint and renders at another, so anything path-dependent could never match twice.

**Stored detection is best-effort, and says so.** It sees the second sighting only if both
requests are still inside the event window. A payload planted on Monday and rendered on Friday
reads as reflected — a documented limitation, not an implied capability.

**One actionable-ambiguous rule exists on purpose.** `unlisted_handler_in_tag` catches an
attribute shaped like an event handler whose name is not on the known list — `onpointerdown`
today, something else tomorrow. Without it, every XSS rule would be either decisive or noise, and
the judge tier would be unreachable code.

## Alternatives considered

| Option | Why not |
|---|---|
| Flag any HTML in user input | Every CMS, comment field, and bug tracker becomes an incident. |
| Decide stored vs reflected from the status code | A 200 means the request succeeded, not that the payload persisted. |
| Key the signature on endpoint plus payload | Stored detection depends on matching *across* endpoints; that key could never match twice. |
| Skip stored detection in this slice | It is the difference between one victim and every visitor — exactly the scope answer the project exists to give. |
