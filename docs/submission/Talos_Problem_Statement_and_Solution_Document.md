# TALOS
### An Open-Source Multi-Agent System for Attack Detection, Classification, and Scope Analysis
**Problem Statement and Detailed Solution Document**
*Hackathon Prototype Scope: Web Application and Network Domains*

**Companion documents:** `Talos_HLD.md`, `Talos_LLD.md`, `Talos_DFD.md`, `Talos_Architecture_Diagram.svg`
*(Markdown edition of `Talos_Problem_Statement_and_Solution_Document.docx`.)*

---

## Table of Contents
1. [Problem Statement](#1-problem-statement)
2. [Solution Overview](#2-solution-overview)
3. [Agent Architecture in Detail](#3-agent-architecture-in-detail)
4. [Agent Responsibility Matrix](#4-agent-responsibility-matrix)
5. [Testing and Validation Strategy](#5-testing-and-validation-strategy)
6. [Specialized Models Per Agent](#6-specialized-models-per-agent)
7. [Roadmap Beyond the Hackathon](#7-roadmap-beyond-the-hackathon)

---

## 1. Problem Statement

### 1.1 Context and Background
Security Operations Center (SOC) teams are structurally overwhelmed. A mid-sized organization's firewalls, web application firewalls, application logs, and network sensors routinely generate thousands of alerts per day. Each alert requires a human analyst to answer three questions before any action can be taken: **what is this, is it real, and how far has it spread.** Today that process is manual, slow, and inconsistent, and it does not scale with the growth of both traffic volume and attacker automation.

A new category of tooling, commonly called **AI SOC agents** or **Agentic SOC** platforms, has emerged to address this gap. Gartner places this category at only **one to five percent market penetration** as of its 2025 Hype Cycle for Security Operations, meaning the problem is real and largely unsolved rather than a saturated market.

### 1.2 The Core Problem
Existing detection tooling — whether a WAF, an IDS, or a SIEM correlation rule — is good at flagging that something *looks* suspicious. It is much weaker at three things that actually determine an analyst's next action:

- **Classification:** precisely identifying which attack category and technique produced the alert, rather than a generic severity score.
- **Scoping:** determining how far an attack has spread, which accounts, endpoints, or objects were actually affected, and whether it succeeded.
- **Transparency:** showing the reasoning behind a verdict, rather than emitting a single opaque confidence number from a black-box model.

The AI SOC agent platforms that do attempt to close this gap are, almost without exception, **closed source, enterprise-priced, and opaque** about how a verdict was reached. This leaves a wide gap for smaller organizations, student teams, security researchers, and open-source-minded engineers who want real incident triage automation without a six-figure platform license or a black box they cannot audit.

### 1.3 Who Is Affected
- Analysts inside small-to-mid-sized security teams who are drowning in alert volume without automation budget.
- Students, researchers, and independent security engineers who want to study, extend, or trust the detection logic rather than accept a vendor's word for it.
- Organizations without an enterprise SOC budget who are currently priced out of AI-assisted detection entirely.

### 1.4 Why Existing Solutions Fall Short

| Existing Approach | Limitation | What Talos Does Differently |
|---|---|---|
| Signature- or rule-based SIEM correlation | High false-positive rate, no automatic scoping, brittle against novel payload variants | Specialized sub-agents per attack type combine pattern detection with contextual, learned baselines |
| Closed, proprietary AI SOC platforms | Opaque verdicts, cannot be audited, enterprise pricing excludes smaller teams | Fully open source; every reasoning step from every agent is inspectable |
| Single end-to-end LLM triage | One model reasoning over every attack type is shallow on all of them and cannot be improved incrementally | Domain- and attack-type-specific sub-agents, each independently improvable and independently model-matched |
| Tier-1-triage-only platforms | Good at flagging, weak at determining actual blast radius or confirming success | Dedicated scoping logic per attack type, e.g. baseline deviation for IDOR, success confirmation for brute force |

### 1.5 Opportunity Statement
There is a genuine opening for an open-source, multi-agent system that treats **detection, classification, and scoping** as three distinct, chainable problems, and that is transparent enough for a security professional to **trust, audit, and extend** — rather than simply consume as a black-box verdict.

---

## 2. Solution Overview

### 2.1 Vision
Talos is an open-source, multi-agent AI system designed to detect, classify, and scope the large majority of present-day attack categories, across whatever domain they occur in: web application, network, and eventually cloud, endpoint, and Active Directory. The orchestrator, classifier, and sub-agent pattern is **domain-agnostic and attack-type-extensible by design**, so long-term coverage is meant to grow through community contribution rather than being fixed to what a single team can build in one sprint.

### 2.2 Hackathon Scope vs. the Long-Term Product
- **Long-term product:** a community-extensible platform aiming to cover most present-day attack categories across many telemetry domains.
- **Hackathon prototype:** a fully working, tested **vertical slice** covering two domains — web application and network — proving that the architecture genuinely generalizes rather than being a diagram that only works for one case.

This distinction matters for how the project is presented: the hackathon build is **evidence of the architecture, not the finished product.** The honest answer to how far this eventually goes is "as far as the open-source community takes it."

### 2.3 High-Level Architecture
Telemetry flows through five conceptual layers:

1. **Ingestion:** domain-specific parsers normalize raw telemetry (WAF or application logs for web; auth logs and flow data for network) into a common event schema.
2. **Orchestrator:** receives normalized events and routes each to the correct domain agent.
3. **Domain Agent:** owns a domain (web application or network) and forwards events to that domain's type classifier.
4. **Type Classifier Sub-Agent:** determines the likely attack category for the event within its domain.
5. **Specialized Attack-Type Sub-Agent:** confirms the classification and performs scoping, delegating to its own child sub-agents where a category has multiple distinct attack techniques underneath it.

A **Reporting Layer** sits across the output: every sub-agent emits a structured, machine-readable verdict that the orchestrator aggregates into a final incident report.

---

## 3. Agent Architecture in Detail

### 3.1 Orchestrator (Top Level)
The Orchestrator is the single entry point for all telemetry. It does not perform any attack-specific reasoning itself. Its responsibilities are:

- Accept normalized events from ingestion pipelines.
- Route each event to the correct Domain Agent based on telemetry source.
- Track an event through the full pipeline and assemble the final structured incident report once all relevant sub-agents have responded.
- Expose the system's output over a documented API and as SIEM- or SOAR-compatible JSON.

### 3.2 Domain Agents
A Domain Agent owns everything specific to one telemetry domain: how its logs are shaped, what a normal baseline looks like, and which type classifier and attack-type sub-agents apply. Two domain agents are built for the hackathon.

- **Web Application Domain Agent:** consumes HTTP access logs, WAF logs, and application logs. Normalizes requests, responses, headers, and payloads into a common schema before handing off to its type classifier.
- **Network Domain Agent:** consumes authentication logs (SSH, RDP) and flow-level data. Normalizes connection attempts, source/destination pairs, and timing into a common schema before handing off to its type classifier.

### 3.3 Web Application Domain — Type Classifier and Sub-Agents
The **Web Application Type Classifier Sub-Agent** inspects a normalized web event and outputs a likely category — **Injection**, **Authentication Failure**, or **Broken Access Control** — along with a confidence score. That category determines which specialized sub-agent is invoked next.

#### 3.3.1 Injection Sub-Agent
**Specialization:** confirms and scopes injection-style attacks. Delegates to two child sub-agents, since SQL Injection and Cross-Site Scripting require different payload grammars and different evidence of impact.

- **SQL Injection Detector (child):** analyzes query parameters and request bodies for tautology patterns, UNION-based patterns, comment-based evasion, and time- or boolean-blind indicators. Scopes the finding by identifying which endpoint and, where inferable, which backend table or field was targeted, and whether the payload pattern matches a known successful exploitation technique versus a blocked or malformed attempt.
- **XSS Detector (child):** analyzes inputs and stored fields for script-tag, event-handler, and encoded payload patterns. Distinguishes reflected from stored XSS based on where the payload reappears, and scopes the finding by identifying which endpoint accepted the payload and which downstream pages or sessions could render it.

#### 3.3.2 Authentication Failure Sub-Agent
**Specialization:** confirms and scopes credential-based attacks using rate and frequency analysis rather than payload pattern matching. Delegates to two child sub-agents.

- **Brute Force Detector (child):** flags a high volume of failed login attempts against a single account or from a single source within a short time window, and scopes the finding by reporting attempt count, source diversity, targeted account, and whether any attempt in the sequence ultimately succeeded.
- **Credential Stuffing Detector (child):** flags distributed failed-login patterns consistent with a leaked credential list being tested across many accounts from a rotating set of sources, and scopes the finding by reporting how many distinct accounts were targeted and which, if any, had a successful login immediately following a failed attempt from the same batch.

#### 3.3.3 Broken Access Control (IDOR) Sub-Agent
**Specialization:** this is the hardest and most differentiated category, because there is no fixed payload to pattern-match against. It requires learning what normal access looks like for a given user before a deviation is meaningful. Delegates to two child sub-agents.

- **Access Pattern Baseliner (child):** builds a per-user baseline of which object identifiers, resource paths, and record ranges a user has legitimately accessed over time.
- **Deviation Scorer (child):** compares a new request's target object against that user's baseline, flags statistically significant deviations such as sequential ID enumeration or access to identifiers outside the user's normal range, and scopes the finding by identifying exactly which objects were accessed outside the expected pattern.

### 3.4 Network Domain — Type Classifier and Sub-Agent
The **Network Type Classifier Sub-Agent** inspects normalized authentication and flow events and currently routes to a single fully built category for the hackathon: **Network Brute Force**. Port scanning and DDoS are designed for in the architecture and shown on the roadmap, but are not built out for the hackathon demo.

#### 3.4.1 Network Brute Force Sub-Agent
**Specialization:** intentionally shares its statistical core with the web Authentication Failure Sub-Agent, since both are rate-based credential-attack detection, but is pointed at network authentication telemetry instead of HTTP logs. Delegates to two child sub-agents.

- **SSH Brute Force Detector (child):** flags high-volume failed SSH authentication attempts against a host or account, scoping by source IP, targeted account, and whether a successful authentication followed the failed sequence — which is the highest-value signal for a real analyst, since it distinguishes noise from a genuine initial-access event.
- **RDP Brute Force Detector (child):** the same statistical approach applied to RDP authentication telemetry, reflecting that RDP brute force is one of the most common real-world initial-access vectors feeding into ransomware intrusions.

### 3.5 Reporting and Output Layer
Every leaf-level sub-agent — not just the top-level Orchestrator — emits a structured verdict containing:

- A **MITRE ATT&CK technique identifier**, for example `T1110` for brute force or `T1190` for exploitation of a public-facing application.
- A **confidence score** rather than a binary flag, since real detections are probabilistic and a tool that always claims certainty gets distrusted by experienced analysts.
- A **scope object** describing exactly which accounts, endpoints, objects, or hosts were affected.
- **Supporting evidence** — the specific request, log lines, or statistical deviation that produced the verdict — so a human can verify the reasoning rather than simply trust it.

The Orchestrator aggregates these into a single incident report in **structured JSON**, designed to be directly consumable by a SIEM or SOAR pipeline rather than requiring a human to re-read a chat-style explanation.

---

## 4. Agent Responsibility Matrix

| Agent / Sub-Agent | Domain | Specialization / What It Does | Detection Technique | Output |
|---|---|---|---|---|
| Orchestrator | Both | Routes telemetry, aggregates final report | Routing logic, no detection | Aggregated incident report |
| Web App Domain Agent | Web | Normalizes HTTP/WAF/app logs | Schema normalization | Normalized event stream |
| Web Type Classifier | Web | Identifies likely category | Lightweight classification model | Category + confidence |
| SQL Injection Detector | Web | Confirms and scopes SQLi | Payload/pattern analysis | Verdict, endpoint, technique |
| XSS Detector | Web | Confirms and scopes XSS | Payload/pattern analysis | Verdict, reflected/stored, scope |
| Brute Force Detector (web) | Web | Confirms and scopes credential brute force | Rate/frequency analysis | Verdict, account, success flag |
| Credential Stuffing Detector | Web | Confirms and scopes stuffing attacks | Distributed rate analysis | Verdict, accounts targeted |
| Access Pattern Baseliner | Web | Learns per-user normal object access | Behavioral baselining | User access baseline |
| Deviation Scorer (IDOR) | Web | Flags and scopes access deviations | Statistical deviation scoring | Verdict, objects accessed |
| Network Domain Agent | Network | Normalizes auth/flow logs | Schema normalization | Normalized event stream |
| Network Type Classifier | Network | Identifies likely category | Lightweight classification model | Category + confidence |
| SSH Brute Force Detector | Network | Confirms and scopes SSH brute force | Rate/frequency analysis | Verdict, source, success flag |
| RDP Brute Force Detector | Network | Confirms and scopes RDP brute force | Rate/frequency analysis | Verdict, source, success flag |

---

## 5. Testing and Validation Strategy

### 5.1 Attack Traffic and Datasets

| Category | Attack Traffic Source | Benign Baseline Source | Key Metrics |
|---|---|---|---|
| SQLi / XSS | OWASP Juice Shop and PortSwigger Web Security Academy labs, run with known attack scripts | Normal Juice Shop browsing and API traffic captured separately | Precision, recall, F1 |
| Auth Failures (web) | Scripted brute force and credential stuffing runs against a test login endpoint using public breached-credential sample lists | Normal login traffic with occasional genuine typos | Detection latency, false positive rate |
| IDOR | Scripted sequential and out-of-range object-ID requests against Juice Shop or a purpose-built test API | Normal per-user object access over a simulated multi-day session history | Baseline accuracy, deviation precision |
| Network Brute Force | Public SSH/RDP honeypot-style datasets (e.g. Cowrie honeypot logs) plus scripted local brute force runs | Normal administrative SSH/RDP session logs | Precision, recall, success-detection accuracy |

### 5.2 False-Positive Testing Against Benign Traffic
Every sub-agent is tested against **clean, attack-free traffic** from its own domain, not only against attack traffic. A tool that only reports catch rate against known attacks and never states its false-positive rate is not credible to a working analyst. Each sub-agent's benign test pass produces a reported **precision** figure alongside its **recall** figure.

### 5.3 Metrics Tracked Per Sub-Agent
- **Precision:** of everything flagged, what fraction was a real attack.
- **Recall:** of everything that was actually an attack, what fraction was caught.
- **F1 score:** the balance of the two above.
- **Confidence calibration:** whether a 90%-confidence verdict is actually correct roughly 90% of the time when checked against labeled test data.
- **Detection latency:** time from event ingestion to verdict.

### 5.4 Validation Process
- **Unit level:** each leaf sub-agent (e.g. SQL Injection Detector) is tested in isolation against its own labeled attack and benign dataset as soon as it is built, not deferred to the end.
- **Integration level:** the full chain from ingestion → orchestrator → classifier → sub-agent is tested end-to-end per domain.
- **System level:** the final three days of the build are reserved for full-pipeline rehearsal and demo scripting using a mixed, realistic traffic sample — not first-time testing of any individual component.

---

## 6. Specialized Models Per Agent

### 6.1 Is Per-Agent Model Specialization Feasible?
Yes. Because the Orchestrator already routes each event to a specific sub-agent by category, that same routing layer can just as easily route to a **different underlying model per sub-agent** rather than forcing every sub-agent to share one large general-purpose model. This is a better architecture, not just a possible one, for three reasons:

- **Task fit:** rate-based detection (brute force) is a fundamentally different reasoning task than contextual baseline deviation (IDOR), and a model well-matched to one is not necessarily well-matched to the other.
- **Cost and latency:** routing simple, high-frequency classification tasks to a small fast model and reserving a larger model for genuinely hard contextual reasoning keeps overall inference cost and response latency down.
- **Independent improvement:** a specific sub-agent's model can be swapped or fine-tuned later without touching the rest of the system, which matters directly for the open-source, community-extensible goal.

### 6.2 How Model Selection Was Approached
Sub-agents were grouped into task profiles rather than judged one by one, since several share the same underlying reasoning shape:

- **Pattern- and signature-heavy tasks (SQLi, XSS):** benefit most from a model with strong code and structured-text understanding, layered *on top of* — not instead of — a deterministic regex or static-rule pre-filter. The LLM's job here is **edge-case judgment** on payloads a static filter is unsure about, not first-line detection.
- **Statistical and rate-based tasks (Auth Failures, Network Brute Force):** the actual detection is a **statistical threshold, not an LLM decision.** A small model is only needed to turn a statistical verdict into a clear, human-readable scoping narrative, so this is the cheapest slot in the system by design.
- **Contextual and behavioral reasoning (IDOR, and the Type Classifiers):** classification benefits from a fast, cheap model since it runs on every single event. IDOR's deviation scoring benefits from a stronger reasoning model since it runs far less often per event but needs to weigh a full access history, not just one request.

### 6.3 Recommended Models Per Agent
The table below reflects model families available as of this document's writing. Model catalogs — especially hosted ones like NVIDIA NIM — change frequently, so the NIM availability column should be **verified directly at `build.nvidia.com`** before locking in a final choice, since this document is not the result of a live catalog lookup.

| Agent | Task Profile | Recommended Model(s) | Size | On NVIDIA NIM* |
|---|---|---|---|---|
| Type Classifiers (web + network) | High-frequency, low-complexity classification | Llama 3.1 8B Instruct, or Mistral 7B Instruct, or Nemotron Mini 4B Instruct | 4B–8B | Yes, typically available |
| SQL Injection Detector | Structured payload reasoning, code-aware | CodeLlama 13B Instruct, or StarCoder2 15B, or Llama 3.1 8B as a fallback | 8B–15B | Partial, verify per model |
| XSS Detector | Structured payload reasoning, HTML/JS-aware | Llama 3.1 8B Instruct, or CodeLlama 13B Instruct | 8B–13B | Yes, typically available |
| Brute Force / Credential Stuffing Detectors (web) | Statistical result → narrative, low reasoning load | Llama 3.2 3B Instruct, or Phi-3 Mini | 3B–4B | Yes, typically available |
| Network Brute Force Detectors (SSH/RDP) | Statistical result → narrative, low reasoning load | Llama 3.2 3B Instruct, or Phi-3 Mini | 3B–4B | Yes, typically available |
| Access Pattern Baseliner | Long-context behavioral summarization | Mixtral 8x7B Instruct, or Llama 3.1 70B Instruct | 8x7B / 70B | Yes, typically available |
| Deviation Scorer (IDOR) | Nuanced contextual judgment, fewer calls per event | Llama 3.1 70B Instruct, or Nemotron 4 340B Instruct for highest accuracy | 70B–340B | Yes, typically available |

> **\* NVIDIA NIM** (accessed via `build.nvidia.com`) hosts many of these open-weight model families as ready-to-call API endpoints, including free, rate-limited API access intended for prototyping and evaluation. This matters directly for a hackathon timeline because it removes the need to provision GPU infrastructure to get a working demo, while the same open-weight models remain self-hostable later via tools like **vLLM** or **Ollama** for a fully open-source, infrastructure-independent long-term deployment.

### 6.4 Deployment Approach
- **Hackathon demo:** call NVIDIA NIM's free-tier hosted API endpoints directly from each sub-agent, since this gets a working multi-model pipeline running fastest with zero GPU provisioning.
- **Long-term open-source product:** since every model recommended above is open-weight, an adopter with no NVIDIA account or budget can self-host the same models via vLLM or Ollama, so the project never depends on one vendor's hosted availability to function.
- **Verification step before committing:** confirm current model availability and free-tier limits directly at `build.nvidia.com`, since hosted catalogs and free-usage terms change over time and are not something this document can guarantee as current.

---

## 7. Roadmap Beyond the Hackathon
- Complete remaining OWASP-aligned web categories where a genuine runtime signature exists — for example, **SSRF**.
- Expand network coverage to **port scanning** and **DDoS**, both already designed for in the classifier but not built for the hackathon.
- Add new domains: **cloud** (e.g. IAM misuse, storage exposure), **endpoint** (EDR telemetry), and **Active Directory** (lateral movement, credential dumping).
- Publish a documented sub-agent interface so a community contributor can add a new attack-type sub-agent **without modifying the orchestrator**.
- Explore fine-tuning smaller open-weight models on Talos's own labeled detection data as the project accumulates real usage.

---
*End of document.*
