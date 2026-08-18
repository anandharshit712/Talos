# Design — Model Routing

## Position in the pipeline

```
Detector / Classifier
    |  complete_for("ssh_brute_force_detector", prompt=..., schema=...)
    v
ModelRouter -- route lookup --> primary provider --> OpenAiCompatibleClient --> HTTPS
    |                                | fails
    |                                v
    |                          fallback provider (different provider, penalised confidence)
    v
ModelOutcome | None
```

## Contracts

| Direction | Contract |
|---|---|
| Consumes | a component name, a rendered prompt, a schema fragment naming required keys |
| Emits | `ModelOutcome(data, model, route_reason, confidence_multiplier)`, or `None` |

`ModelCaller` in `core/agent_contracts.py` is what `DetectionContext.model_client` is typed as, so
any detector can be exercised against `StubModelRouter` with no network and no key.

## Decisions

**Three states, and the third is ordinary.** Primary answers, full confidence. Fallback answers,
`confidence_multiplier` below 1.0 and a `route_reason` naming the provider that failed. Nothing
answers, `None`, and the caller uses its templated path. A fresh clone with no keys has to detect,
so "no model" cannot be an error path.

**Detectors do not know about providers.** They name themselves and get an answer. Provider
selection, retries, fallback, and the penalty live in one place; a detector that knew about them
would need editing every time a provider changed — which, on free tiers, is often.

**One client class.** NIM, Groq, and Mistral all speak the OpenAI chat-completions dialect, and
local inference is out of scope, so `NimClient` / `VllmClient` / `OllamaClient` collapse into
`OpenAiCompatibleClient`. A provider is a base URL plus the *name* of the environment variable
holding its key; adding one is a config entry (LLD 16.4).

**Fallbacks cross provider boundaries.** A fallback on the same provider does not survive that
provider being down, rate-limited, or having de-provisioned the account's models — all three
observed during selection. A test asserts the property over the real routing table rather than
trusting review to catch it.

**Keys live in the environment, named by config.** `api_key_env: TALOS_NIM_API_KEY`, never the key
itself. A provider whose variable is unset is simply absent from the router.

**Prompts are files, not literals.** `llm/prompts/<agent>_<purpose>_v<N>.md` (R3.7), rendered with
`str.format`. A behaviour change becomes a version bump and a diff a reviewer can read.

**Trusted facts and untrusted data are separated in the prompt itself.** Counts, windows, and
thresholds are computed by Talos and presented as facts. Everything sourced from the log —
including the account and host names, not just the raw line — is sealed in a delimited block the
prompt describes as data.

## Alternatives considered

| Option | Why not |
|---|---|
| One model for everything | Free tiers cap *requests*, not only tokens. One bucket empties mid-demo, and a 120B model answering "write one sentence" is waste. |
| Detector calls the client directly with a model id | Puts fallback and penalty logic in every detector, or nowhere. |
| Raise on model failure | Turns a provider outage into a pipeline outage. The statistical path exists precisely so that cannot happen. |
| `response_format: json_object` | Not supported uniformly across the three providers; the balanced-object parser handles every observed shape instead. |
| Retry on any error | A 404 for a de-provisioned model will not fix itself, and retrying burns request budget. Only timeouts, 5xx, and 429 are retried. |
| Identifiers as trusted prompt facts | An attacker chooses the username. Putting it in the trusted block is an injection vector — caught by a test, then fixed by sealing identifiers with the raw line. |
