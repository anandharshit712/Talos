# Talos — LLM Model Selection Research

**Project:** Talos — Open-Source Multi-Agent System for Attack Detection, Classification, and Scope Analysis
**Document type:** Research / decision input for P3 (LLM layer)
**Created:** 2026-08-18
**Verified:** 2026-08-18 — catalogues surveyed, then **every routed model probed with a live
completion** using real keys. Section 6 records what answered. Free-tier terms move without
notice; re-run `python scripts/check_model_availability.py` before P8.
**Companion documents:** [../architecture/Talos_LLD.md](../architecture/Talos_LLD.md) §8,
[../architecture/Talos_HLD.md](../architecture/Talos_HLD.md) §8,
[../planning/Talos_Implementation_Plan.md](../planning/Talos_Implementation_Plan.md) P3,
[../planning/Talos_Build_Tracker.md](../planning/Talos_Build_Tracker.md)

**Method.** NVIDIA's catalogue was read from the live `GET https://integrate.api.nvidia.com/v1/models`
endpoint, so those IDs are what the API actually serves. Groq's and Google's limits come from their
own documentation. OpenRouter's free list came from its public models API. The remaining figures
come from secondary sources and are marked as such — treat them as a starting point for a smoke
test, not as a contract.

**Constraint from the brief:** hosted inference only. No local models, so vLLM and Ollama are out of
scope for the slice and every candidate below is a hosted free tier.

---

## 1. Decisions this document asks for

| ID | Decision | Recommendation |
|----|---|---|
| **D1** | Single central model, or per-agent models? | **Per-agent routing keys resolved through five tiers** (§2) |
| **D2** | Primary provider | **NVIDIA NIM** — matches the HLD, 106 models live, no card (§3) |
| **D3** | Fallback provider | **Groq** — no card, 200K tokens/day per model, no training clause (§3, §7) |
| **D4** | Google Gemini as a third fallback? | **No** — free-tier prompts train Google's models outside the EU/UK/EEA, and our prompts are verbatim customer log lines (§7) |
| **D5** | Prompt-injection screening model | **Yes** — `meta-llama/llama-prompt-guard-2-86m` (Groq) or `nvidia/llama-3.1-nemotron-safety-guard-8b-v3` (NIM) (§6) |
| **D6** | Client architecture | **One `OpenAiCompatibleClient` + provider profiles**, replacing the LLD's three-client split (§7) |

Nothing here is load-bearing for detection. Every detector already produces a verdict with
`used_llm=false`; the model layer is an enhancement to working code, and that ordering is what makes
a provider outage a cosmetic problem rather than a demo-ending one.

---

## 2. D1 — Per-agent, resolved through tiers

```
detector_name  ->  tier  ->  (provider, model, fallback)
```

**Per-agent keys** because the contract already requires them (`routing.<detector_name>`, LLD §8.2),
and because the load profile differs by two orders of magnitude: a type classifier sees every event,
an IDOR judge fires a handful of times per run. Pointing both at one model wastes a large model on
routing decisions and starves the judgement calls that need one.

**Only five tier values**, so each phase verifies five model IDs rather than ten. Ten bespoke
choices is ten things to re-check every time a provider prunes its catalogue.

**A single central model is the wrong shape here for one hard reason:** free tiers cap *requests*,
not only tokens. NIM allows ~40 RPM; Groq allows 1,000 requests/day per model. One model for
everything is one bucket to exhaust, and it empties in the middle of a demo. Spreading across tiers
and two providers multiplies the ceiling at no cost.

| Tier | Used by | Why this size |
|---|---|---|
| `nano` | rate detectors' narrative, network classifier | Renders a computed `RateSignal` into a sentence. No judgement required. |
| `small` | web type classifier | Routing decision on ambiguous events only; cheapest tier that reads a payload |
| `code` | SQL injection, XSS judges | Reads adversarial code-shaped payloads; the one place a code-tuned model earns its cost |
| `long_context` | access baseliner | Weighs a whole access history in one call |
| `heavy` | deviation scorer (IDOR) | The hardest judgement in the system, called least often |

---

## 3. Free tiers that actually exist (2026-08-18)

| Provider | Free allowance | Card | Catch |
|---|---|---|---|
| **NVIDIA NIM** | ~40 RPM (200 RPM on request); 1,000 signup credits, +4,000 with a business email; 106 models on `/v1/models` | No | Free models can be withdrawn at short notice. Credits-vs-unlimited is documented inconsistently across NVIDIA's own pages — assume credits and verify in the console. |
| **Groq** | Per model: 30 RPM · 1K RPD · 8K TPM · **200K TPD** (`gpt-oss-120b`, `gpt-oss-20b`, `gpt-oss-safeguard-20b`, `qwen3.6-27b`). Prompt-guard models: 30 RPM · **14.4K RPD** · 15K TPM · 500K TPD | No | Catalogue has shrunk — the Llama instruct family is no longer on the free table |
| **Google AI Studio** | Entire Flash family free of charge (2.0/2.5/3.x Flash and Flash-Lite, Gemini 2.5 Pro); ~15 RPM, few hundred to 1,500 RPD depending on model and account | No | **Prompts are used for training** outside the EU/UK/EEA. Disqualifying for log content — see §7. |
| **Mistral La Plateforme** | "Experiment" tier, ~1B tokens/month, all models including Codestral | No | Requires opting in to data training; exact limits are console-only now |
| **OpenRouter** | 20 RPM / 50 RPD, rising to 1,000 RPD after a one-off $10 top-up | No | Only four genuinely free IDs remain (below) |
| **Cloudflare Workers AI** | 10,000 neurons/day ≈ 550K output tokens on a 1B model, ≈ 49K on a 70B | No | Small context windows; neuron accounting is per-model |
| **GitHub Models** | 10–15 RPM, 50–150 RPD, 8K in / 4K out per request, concurrency 2 | No | The per-request cap is too small for a long payload plus instructions |
| **Cerebras** | 5 RPM · 30K TPM · 1M TPD (`gpt-oss-120b`, `gemma-4-31b`) | **Yes** | $5 in credits expiring 30 days after issue — **disqualified**, the brief asks for durable free tiers |
| **Hugging Face** | ~$0.10/month in Inference Provider credits | No | Not viable. PRO at $9/month buys 2M credits; that is a subscription, not a free tier. |

**OpenRouter's remaining free IDs:** `nvidia/nemotron-3.5-lightning:free` (1M context),
`dots-studio/dots-3-note-preview:free` (512K), `poolside/laguna-s-2.1:free` and
`poolside/laguna-xs-2.1:free` (262K each).

---

## 4. NVIDIA NIM catalogue extract — verbatim IDs

Read from the live endpoint. These are the ones relevant to Talos; the catalogue holds 106.

**Small instruct**

```
meta/llama-3.2-1b-instruct
meta/llama-3.2-3b-instruct
meta/llama-3.1-8b-instruct
mistralai/mistral-7b-instruct-v0.3
ibm/granite-3.0-8b-instruct
google/gemma-3-4b-it
google/gemma-3-12b-it
google/gemma-4-31b-it
nvidia/nemotron-mini-4b-instruct
nvidia/nvidia-nemotron-nano-9b-v2
nvidia/mistral-nemo-minitron-8b-8k-instruct
openai/gpt-oss-20b
```

**Code**

```
mistralai/codestral-22b-instruct-v0.1
meta/codellama-70b
deepseek-ai/deepseek-coder-6.7b-instruct
google/codegemma-7b
google/codegemma-1.1-7b
ibm/granite-8b-code-instruct
ibm/granite-34b-code-instruct
bigcode/starcoder2-15b
```

**Larger / reasoning / long context**

```
meta/llama-3.3-70b-instruct
meta/llama-3.1-70b-instruct
nvidia/nemotron-3-nano-30b-a3b
nvidia/nemotron-3.5-lightning-30b-a3b
nvidia/nemotron-3-super-120b-a12b
nvidia/nemotron-3-ultra-550b-a55b
nvidia/llama-3.3-nemotron-super-49b-v1.5
nvidia/llama-3.1-nemotron-ultra-253b-v1
deepseek-ai/deepseek-v4-flash-0731
moonshotai/kimi-k2.6
mistralai/mistral-large-2-instruct
openai/gpt-oss-120b
```

**Safety / guard**

```
nvidia/llama-3.1-nemotron-safety-guard-8b-v3
nvidia/nemotron-3.5-content-safety
```

---

## 5. The current config is partly dead

`config/model_routing.yaml` was written from the LLD's placeholder table. Three entries do not
resolve against the live catalogue:

| Placeholder in config | Status | Replacement |
|---|---|---|
| `meta/codellama-13b-instruct` | **absent** | `mistralai/codestral-22b-instruct-v0.1` |
| `mistralai/mixtral-8x7b-instruct` | **absent** (catalogue has `mixtral-8x22b-v0.1`, a base model) | `nvidia/nemotron-3.5-lightning-30b-a3b` |
| `meta/llama-3.1-70b-instruct` | present but superseded | `meta/llama-3.3-70b-instruct` |
| `meta/llama-3.1-8b-instruct` | live | keep |
| `meta/llama-3.2-3b-instruct` | live | keep |

This is exactly the failure the plan predicted ("a deprecated model ID discovered in P8 is a
schedule-breaking discovery"). Two of the ten routing entries would have 404'd on first contact.

---

## 6. Routing table — as probed, 2026-08-18

Every entry below returned a live completion. Latencies are a single cold-ish call, not a
benchmark.

| Agent | Tier | Primary | ms | Fallback | ms |
|---|---|---|---|---|---|
| `network_type_classifier` | nano | NIM `meta/llama-3.1-8b-instruct` | 735 | Groq `openai/gpt-oss-20b` | 796 |
| `ssh_brute_force_detector` | nano | NIM `meta/llama-3.1-8b-instruct` | 735 | Groq `openai/gpt-oss-20b` | 796 |
| `rdp_brute_force_detector` | nano | NIM `meta/llama-3.1-8b-instruct` | 735 | Groq `openai/gpt-oss-20b` | 796 |
| `brute_force_detector` | nano | NIM `meta/llama-3.1-8b-instruct` | 735 | Groq `openai/gpt-oss-20b` | 796 |
| `credential_stuffing_detector` | nano | NIM `meta/llama-3.1-8b-instruct` | 735 | Groq `openai/gpt-oss-20b` | 796 |
| `web_type_classifier` | small | NIM `nvidia/nemotron-3-nano-30b-a3b` | 1,782 | Groq `openai/gpt-oss-20b` | 796 |
| `sql_injection_detector` | code | **Mistral** `codestral-2508` | 875 | Groq `openai/gpt-oss-120b` | 1,342 |
| `xss_detector` | code | **Mistral** `codestral-2508` | 875 | Groq `openai/gpt-oss-120b` | 1,342 |
| `access_baseliner` | long_context | NIM `nvidia/nemotron-3.5-lightning-30b-a3b` | 5,045 | Mistral `mistral-large-2512` | 1,233 |
| `deviation_scorer` | heavy | NIM `nvidia/nemotron-3-super-120b-a12b` | 967 | Mistral `mistral-large-2512` | 1,233 |
| `payload_guard` | guard | Groq `meta-llama/llama-prompt-guard-2-86m` | 594 | NIM `nvidia/llama-3.1-nemotron-safety-guard-8b-v3` | 984 |

### What probing changed from the paper recommendation

**A published NIM catalogue entry is not an entitlement.** `GET /v1/models` lists 106 models;
this account is served far fewer. These return `404 Function ... Not found for account`:

```
mistralai/codestral-22b-instruct-v0.1     meta/codellama-70b
deepseek-ai/deepseek-coder-6.7b-instruct  google/codegemma-7b
ibm/granite-8b-code-instruct              bigcode/starcoder2-15b
mistralai/mistral-7b-instruct-v0.3        moonshotai/kimi-k2.6
```

And these accept the request but never respond, timing out at 120s:

```
meta/llama-3.2-3b-instruct    meta/llama-3.3-70b-instruct
google/gemma-4-31b-it         deepseek-ai/deepseek-v4-flash-0731
```

Three consequences:

1. **The nano tier moved to `meta/llama-3.1-8b-instruct`** (735 ms). `llama-3.2-3b-instruct` was
   the paper pick and times out on this account — three attempts, up to 120s.
2. **The code tier is led by Mistral, not NIM.** NVIDIA serves this account no code specialist at
   all, so `codestral-2508` on Mistral's own platform is the primary and Groq's 120B generalist is
   the fallback. This is the one tier where NIM is not in the path.
3. **The long-context fallback is `mistral-large-2512`, not `zai-glm-5-2`.** GLM answers HTTP 429
   on the free Mistral tier every time. The fallback is therefore 128K against a 1M primary: a
   very long access history truncates when the fallback fires, which is documented rather than
   hidden.

### Models confirmed working but not routed

Useful spares, all probed green: NIM `nvidia/nvidia-nemotron-nano-9b-v2` (1,063 ms),
`nvidia/llama-3.3-nemotron-super-49b-v1.5` (2,000 ms), `nvidia/nemotron-mini-4b-instruct`
(750 ms), `openai/gpt-oss-20b` (764 ms); Groq `qwen/qwen3.6-27b` (765 ms); Mistral
`mistral-small-2603` (1,407 ms), `ministral-8b-2512` (1,047 ms), `ministral-3b-2512` (9,093 ms
cold).

### Integration note the probe surfaced

Several models return `message.content = null` and put the answer in `message.reasoning_content`
— observed on `openai/gpt-oss-20b` and `openai/gpt-oss-120b` (both providers) and
`nvidia/nvidia-nemotron-nano-9b-v2`. The P3 client must read `content`, fall back to
`reasoning_content`, and treat an empty string as a parse failure rather than as an empty verdict.
The guard models return their own shapes: Groq's prompt-guard returns a bare probability
(`0.00036…`), NVIDIA's safety guard returns `{"User Safety": "safe"}`.

## 7. Consequences worth deciding before code is written

**The classifier cannot call a model per event.** At ~40 RPM, per-event LLM classification caps the
whole pipeline at 40 events/minute — slower than reading the log file. The static short-circuit
built in P2 must remain the primary path, with the model reserved for genuinely ambiguous events.
This is already the LLD's design; the rate limit turns it from an optimisation into a requirement,
and it should be stated that way in the P3 feature docs.

**Gemini is the largest free tier surveyed and the wrong one for this project.** Free-tier prompts
train Google's models outside the EU/UK/EEA. Talos prompts contain verbatim log lines: usernames,
source addresses, request paths, and payloads — that is customer telemetry, and a security tool
that quietly forwards it into a training corpus has a defect no benchmark will show. Groq is the
fallback instead: no training clause on the free tier, no card, and 200K tokens/day per model.

Mistral's free tier carries the same objection in weaker form (it requires opting in to data
training), which is why it is listed as overflow capacity rather than a routed provider.

**One client class, not three.** NIM, Groq, Mistral, OpenRouter and even Gemini all expose
OpenAI-compatible chat-completions endpoints. With local inference out of scope, the LLD's
`NimClient` / `VllmClient` / `OllamaClient` split has no second consumer: it should collapse to a
single `OpenAiCompatibleClient` plus provider profiles in config (base URL, env var holding the
key, default headers). Fewer classes, and adding a provider becomes a config entry rather than a
module. This is an LLD §8.1 deviation and needs a §16 revision entry when P3 lands.

---

## 8. Does the free capacity actually cover the work?

| Workload | Estimated LLM calls | Estimated tokens |
|---|---|---|
| One demo run (fixture, ~20 lines) | 2–5 | < 10K |
| One full P8 evaluation pass (labelled corpus, all detectors) | 200–500 | 0.5–1M |
| A day of P4–P6 development | 300–1,000 | 1–2M |

Against NIM at 40 RPM plus Groq at 200K tokens/day/model plus Mistral's ~1B tokens/month of
overflow, the free allowance is comfortable — provided the static-first principle holds. It stops
being comfortable the moment a detector calls a model on every event, which is the same conclusion
§7 reaches from the latency side.

---

## 9. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A routed model is withdrawn or de-provisioned mid-project | **high** — already observed: eight catalogue models 404 for this account | medium | Availability smoke test in CI; every route has a fallback; `used_llm=false` always works |
| NIM free credits exhaust rather than being unlimited | medium | medium | Sign up with a business email for 5,000 credits; Groq absorbs overflow |
| Free-tier terms change during the project | medium | low | This document carries a verification date; re-check at P8 |
| Fallback provider drifts in output format | medium | low | Schema-validated parse with one retry already required by the LLD; the fallback penalty is recorded in `ModelInfo.route_reason` |
| Secondary sources in §3 are wrong | medium | low | Every number gets a smoke test before it is relied on; only §4 is first-party verified |

---

## 10. Action checklist before P3 code

- [ ] Approve D1–D6
- [ ] NVIDIA account, signed up with a **business email** for the full 5,000 credits → `TALOS_NIM_API_KEY`
- [ ] Groq account → `TALOS_GROQ_API_KEY`, `TALOS_GROQ_BASE_URL=https://api.groq.com/openai/v1`
- [ ] Optional: Mistral account for overflow → `TALOS_MISTRAL_API_KEY`
- [ ] Rewrite `config/model_routing.yaml` from §6, adding a `providers:` block
- [ ] Extend `.env.example` with the new variables
- [ ] `scripts/check_model_availability.py` — ping every routed ID, fail loudly on a 404, run it in CI
- [ ] Record the single-client deviation in LLD §16

---

## 11. Sources

First-party, read directly:

- [NVIDIA NIM live model catalogue](https://integrate.api.nvidia.com/v1/models)
- [Groq rate limits](https://console.groq.com/docs/rate-limits)
- [Google Gemini pricing](https://ai.google.dev/pricing) · [Gemini rate limits](https://ai.google.dev/gemini-api/docs/rate-limits)
- [OpenRouter models API](https://openrouter.ai/api/v1/models)
- [Cerebras rate limits](https://inference-docs.cerebras.ai/support/rate-limits)
- [Cloudflare Workers AI pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/)
- [Hugging Face inference pricing](https://huggingface.co/docs/api-inference/en/pricing)

Secondary, used for figures not published first-party:

- [NVIDIA Build free-tier terms](https://yangmao.ai/en/providers/nvidia-build/free-tier/)
- [OpenRouter's free-LLM provider comparison](https://openrouter.ai/blog/tutorials/free-llm-apis-compared/)
- [Mistral free tier](https://pricepertoken.com/endpoints/mistral/free)
- [GitHub Models limits](https://free-llm.com/provider/github-models)

---

**Document control**

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-08-18 | Initial survey: nine hosted free tiers compared, NIM catalogue verified against the live endpoint, three dead placeholders identified, per-agent routing table proposed, six decisions raised for approval |
| 1.1 | 2026-08-18 | Every routed model probed with a live completion against real keys. Eight NIM catalogue models turned out to be 404 for this account and four more time out, so the nano tier moved to llama-3.1-8b and the code tier moved to Mistral. Recorded the reasoning_content quirk and the working-but-unrouted spares. |
