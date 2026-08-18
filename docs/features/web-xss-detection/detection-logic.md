# Detection Logic — Cross-Site Scripting

**Technique:** `xss` · **MITRE:** T1059.007 (Execution) · **OWASP:** A03:2021 Injection

## Pattern classes

| Class | Rules | Grade |
|---|---|---|
| `script_tag` | `<script`, `<script src=`, `<svg\|iframe\|embed\|object\|math ... on*=` | decisive |
| `event_handler` | known handler bound to a value; handler wired to `alert`/`eval`/`fetch`/`document.cookie` | decisive |
| `event_handler` | handler-shaped attribute in a tag whose name is not on the known list | **judged** |
| `uri_scheme` | `javascript:` (whitespace tolerated), `data:text/html` | decisive |
| `encoded` | `%3Cscript`, `&lt;script`, `<script`, `&#60;script` | decisive |
| `encoded` | entity-encoded handler prefix, base64 payload | corroboration only |
| `breakout` | `'><tag`, `> <tag on*=` | decisive |
| `breakout` | any HTML-looking fragment | corroboration only |

The parser decodes exactly once, so an encoded tag that survives it was encoded twice — that is
intent, not markup.

## The decision

Identical in shape to the SQL detector: nothing actionable → cleared; decisive, or two actionable
families → verdict with no model; otherwise the judge, which may veto; no model reachable → a lead
at 0.42 confidence. The variant check then runs, and a stored payload floors confidence at 0.9.

## Reflected versus stored

```
signature = sorted matched fragments, lowercased      (path-independent by construction)
recent    = event window for this source IP, last 900s
if an earlier event at a DIFFERENT endpoint carries the same signature  -> stored
else                                                                    -> reflected
```

| Variant | Scope | Confidence |
|---|---|---|
| Reflected | the endpoint that received it | 0.93 static, or the judge's number |
| Stored | that endpoint **plus** every endpoint the signature already appeared at | floored at 0.9 |

`succeeded` is read from the status: 200/201/202/302 mean the payload came back.

## Known false-positive modes

| Mode | Mitigation |
|---|---|
| Markup in a comment field (`<b>bold</b>`, `<p>hello</p>`) | Corroboration-only; never acts alone. In the benign corpus. |
| The word `onerror` in prose | Handler rules require an assignment. In the benign corpus. |
| Comparisons (`5 > 3 and 2 < 4`) | No tag structure. In the benign corpus. |
| `C++ <iostream>` | Corroboration-only fragment. In the benign corpus. |
| base64 image URIs | Corroboration-only. In the benign corpus. |
| A security team pasting a payload into a bug tracker | Would fire — correct by the rules, wrong by intent. Unresolved. |

## Known false-negative modes

| Mode | Planned answer |
|---|---|
| Stored payload rendered after the event window expires | Documented limitation; needs a persistent payload registry |
| DOM-based XSS with no server-side trace | Invisible in server logs by definition |
| Payload in a header or cookie | Header scanning is out of scope |
| Mutation XSS relying on parser quirks | The judge tier is the only path, and only if some rule fires first |
