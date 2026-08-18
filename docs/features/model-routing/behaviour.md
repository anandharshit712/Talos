# Behaviour — Model Routing

## Resolution order

1. Look up `talos.routing.<component>`. No entry → `None`.
2. Try the primary provider's model. Answer → `ModelOutcome`, multiplier `1.0`.
3. No fallback configured → `None`.
4. Try the fallback provider's model. Answer → `ModelOutcome`, multiplier =
   `talos.llm.fallback_confidence_penalty` (0.85), with the failed provider named in
   `route_reason`.
5. Both failed → `None`, logged at warning level.

A provider whose key variable is unset has no client, so step 2 or 4 is skipped rather than
attempted. One key configured is a supported setup, not a broken one.

## Per-request settings

| Setting | Default | Effect |
|---|---|---|
| `talos.llm.request_timeout_seconds` | 20.0 | Per HTTP attempt |
| `talos.llm.max_retries` | 1 | Retries on timeout, 5xx, and 429 only |
| `talos.llm.max_payload_chars` | 2000 | Attacker-controlled text is truncated to this before prompting |
| `talos.llm.fallback_confidence_penalty` | 0.85 | Multiplier applied when a fallback answered |

Requests use `temperature: 0`. Retry backoff is `0.5s x attempt`, jittered, so concurrent
detectors do not resynchronise onto the same retry instant.

## Reply parsing

1. Read `choices[0].message.content`; if null or blank, read `reasoning_content`. Several models
   answer only there — `openai/gpt-oss-*`, `nvidia/nvidia-nemotron-nano-9b-v2`.
2. Extract the first balanced JSON object, ignoring code fences, prose, and `<think>` blocks.
   Braces inside strings do not terminate the object.
3. If that fails, re-ask once with an explicit "one JSON object, nothing else" instruction.
4. Check the keys named in the schema's `required`. Missing → `ModelError`, which the router turns
   into a fallback attempt.

## Prompt hardening

Everything derived from the log is attacker-chosen — not only the raw line, but the account name,
the host name, and the source address. All of it is sealed:

```
<<<UNTRUSTED_LOG_DATA
accounts: root | hosts: bastion-01 | sources: 203.0.113.7 | Aug 15 10:15:00 ... Failed password ...
UNTRUSTED_LOG_DATA>>>
```

Newlines are flattened so an injected line cannot fake the closing delimiter, and content is
truncated to `max_payload_chars` with the original length reported. The prompt's trusted-facts
section carries only values Talos computed: counts, window length, threshold, outcome.

## Failure table

| Failure | Behaviour |
|---|---|
| No provider key set | Router has no clients; every call returns `None`; templated narrative, `used_llm=false` |
| Component has no route | `None` |
| Timeout or 5xx | One retry, then the fallback provider |
| 429 | Retried — a rate limit is temporary |
| 404 / 401 | Not retried; straight to the fallback |
| Reply is not JSON | One stricter re-ask, then the fallback |
| Reply missing a required key | Treated as a failed call → fallback |
| Reply present but empty (`narrative: "  "`) | Caller falls back to its template, `used_llm=false` |
| Model proposes a category outside the closed list | Discarded; the static route stands |
| Both providers fail | `None`; the verdict still ships, statistically |

## What a model can and cannot change

| Can | Cannot |
|---|---|
| The wording of `Verdict.reasoning` | `attack_detected` |
| A routing category, when it is on the closed list and the static pass was unsure | `scope.attempt_count`, `scope.succeeded`, or any measured field |
| Its own reported confidence for a routing decision | A detector's statistical confidence, except by the fallback penalty |

## Rate limits shape the design

The primary provider allows roughly 40 requests per minute. A model call per event would cap the
pipeline below the speed of reading the log file, so the classifier calls a model only for events
its static pass could not place, and rate detectors call one only after a threshold has already
fired. Throughput stays a property of the parser rather than of a provider.
