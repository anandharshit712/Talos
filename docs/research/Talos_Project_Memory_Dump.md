# Talos — Full Project Memory Dump
*Compiled from two conversations: "Cybersecurity basics for hackathon project" and the follow-up planning/document session. Use this to resume work on a different system or in a fresh chat.*

---

## 1. Who You Are / Starting Point

- Solid web and application development background, **no prior cybersecurity background** going in — cybersecurity knowledge was built up through this project's research and planning conversations.
- Competing in a **multi-week hackathon**. Idea submission phase is complete. **Final prototype submission deadline: September 4.**
- Received an automated idea profiling result: **"Low-risk enhancements with tangible benefits"** — explained as boilerplate/templated per-dimension text, not custom feedback, but still a positive signal for surviving an elimination round.

---

## 2. The Project: Talos

**What it is:** An open source, multi-agent AI system that automates the **detection, classification, and scoping** of security incidents from live runtime telemetry.

**Long-term vision (beyond the hackathon):** A community-extensible open source product aiming to eventually cover most present-day attack categories across many domains — web application, network, cloud, endpoint, and Active Directory. Coverage is meant to grow through community contribution, not be fixed to what one team builds in one sprint.

**Hackathon scope:** A working proof-of-concept **vertical slice** covering only the web application and network domains — presented to judges as evidence the architecture generalizes, not as the finished product.

**Naming journey:**
- **Triagent** — rejected, name implies a fixed set of exactly three agents.
- **SentinelSwarm** — considered; "swarm" signals many coordinated autonomous agents without a fixed count.
- **Talos** (final choice) — mythological "vigilant guardian" connotation, doesn't imply any fixed agent count. Locked in.

---

## 3. Key Foundational Corrections Made Along the Way

1. **CI/CD is the wrong integration point.** CI/CD (SAST/SCA/secret scanning/DAST) catches vulnerabilities *before* shipping — a build-time problem. Live attack detection is a fundamentally different, runtime problem. Talos must plug into **live telemetry** (WAF/app logs, network flow, EDR data, cloud/AD audit logs), not a build pipeline.
2. **Scoping, not classification, is the real bottleneck.** In a real incident response lifecycle (Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned), classification is fast once a pattern is recognized — figuring out **how far an attack spread** is the slow part, and often runs in parallel with containment rather than finishing before it. This is why Talos treats scoping as a first-class, dedicated step per attack type, not an afterthought.
3. **"Full coverage of every attack type" is the wrong differentiator.** Incumbent platforms (see competitive research below) have years of engineering behind their breadth — a hackathon team can't out-cover them, and claiming shallow breadth invites judges to poke exactly at the weak spot. The winning differentiator is **depth and transparency** of multi-agent reasoning on a focused set of categories, not raw category count.
4. **Not every OWASP Top 10 category is runtime-detectable.** Some are pre-deployment/process concerns with no traffic signature at all (see Section 6 — Explicitly Out of Scope). Building fake detection logic for these would weaken credibility, not help it.

---

## 4. Competitive Landscape (Research Findings)

The space is called **"AI SOC agents"** or **"Agentic SOC"** — genuinely early stage, per Gartner's 2025 Hype Cycle for Security Operations sitting at only **1–5% market penetration** ("Innovation Trigger" phase). Real room to build something meaningful; not a solved problem, but not empty either.

Three categories of existing players:
- **AI-native investigation platforms:** Dropzone AI (markets itself as "first AI SOC analyst," fast API deployment, Tier-1 triage focus), Intezer (forensic-depth investigation — code analysis, memory forensics, sandboxing), Conifers.ai (claims multi-tier Tier-1/2/3 coverage, "mesh agentic" architecture).
- **SIEM-embedded copilots:** Microsoft Security Copilot, CrowdStrike, Palo Alto Cortex XSIAM, IBM QRadar.
- **Hyperautomation platforms:** Torq HyperSOC, Splunk SOAR.

**Common weak spots across all of them** (this is where Talos's differentiation story lives):
- Most only do **Tier-1 triage well** — shallow, not deep investigation.
- Most are **enterprise-priced, closed black boxes**.
- **Institutional/environment-specific learning** is immature everywhere.

*Note: this research came from a vendor-written source (conifers.ai blog), so competitor names/categories were treated as reliable but comparative rankings/scores were treated skeptically.*

**Talos's positioning against this landscape:**
- Open source and transparent — every verdict's reasoning is inspectable, not a single opaque score.
- Depth over breadth — real working detection on a focused, OWASP-anchored set of categories, not shallow fake coverage of everything.
- Domain-agnostic core — same orchestrator pattern works across domains by swapping telemetry parsers + sub-agents.
- Built for teams without enterprise SOC budgets — students, small orgs, researchers.

---

## 5. Architecture

```
Telemetry (WAF/app logs, later network flow/auth logs)
   → Orchestrator (routes by domain)
   → Domain Agent (Web App / Network)
   → Type Classifier sub-agent (identifies likely attack category)
   → Specialized Attack-Type sub-agent (confirms + scopes)
       → further child sub-agents per specific technique, where a category
         has more than one distinct attack shape underneath it
   → Structured JSON report (aggregated by Orchestrator)
```

### Agent hierarchy in full

**Orchestrator (top level)** — no attack-specific reasoning itself; accepts normalized events, routes by domain, aggregates the final structured incident report, exposes SIEM/SOAR-compatible JSON output.

**Web Application Domain Agent** — normalizes HTTP/WAF/app logs → hands off to Web Type Classifier.
- **Web Type Classifier** — outputs likely category (Injection / Auth Failure / Broken Access Control) + confidence.
  - **Injection Sub-Agent**
    - SQL Injection Detector (child) — tautology/UNION/comment-based/blind-injection pattern analysis; scopes by endpoint + likely backend target + exploitation vs. blocked attempt.
    - XSS Detector (child) — script-tag/event-handler/encoded payload analysis; distinguishes reflected vs. stored; scopes by endpoint + affected pages/sessions.
  - **Authentication Failure Sub-Agent**
    - Brute Force Detector (child) — rate/frequency analysis on failed logins per account/source; scopes by attempt count, source diversity, targeted account, success/failure of the sequence.
    - Credential Stuffing Detector (child) — distributed failed-login pattern analysis across many accounts; scopes by accounts targeted + any successful login following a failed batch attempt.
  - **Broken Access Control (IDOR) Sub-Agent** — hardest category, no fixed payload to match; requires learned baselines.
    - Access Pattern Baseliner (child) — builds per-user baseline of normally-accessed object IDs/paths/ranges.
    - Deviation Scorer (child) — flags statistically significant deviations (e.g. sequential ID enumeration); scopes by exactly which objects were accessed outside the expected pattern.

**Network Domain Agent** — normalizes SSH/RDP auth logs + flow data → hands off to Network Type Classifier.
- **Network Type Classifier** — routes to the one fully-built category for the hackathon: Network Brute Force. (Port scan and DDoS are designed-for but not built for the hackathon.)
  - **Network Brute Force Sub-Agent** — intentionally shares its statistical core with the web Auth Failure Sub-Agent (same rate-based logic, different telemetry source).
    - SSH Brute Force Detector (child).
    - RDP Brute Force Detector (child) — RDP brute force flagged as one of the most common real-world initial-access vectors feeding ransomware intrusions, which is why it's worth building fully rather than stubbing.

**Reporting/Output layer** — every leaf sub-agent (not just the Orchestrator) emits: a MITRE ATT&CK technique ID, a confidence score (not a binary flag), a scope object (exact accounts/endpoints/objects/hosts affected), and supporting evidence (the actual request/log lines/statistical deviation behind the verdict).

---

## 6. Category Decisions

### Web/App domain — 3 fully functional categories
1. **Injection** (SQLi + XSS) — built first, easiest fast win; plenty of public attack traffic (OWASP Juice Shop, PortSwigger labs), most recognizable to judges.
2. **Authentication Failures** (brute force, credential stuffing) — second; rate/frequency-based, demos well visually (spike graph of failed attempts).
3. **Broken Access Control (IDOR)** — built last, on purpose; hardest to build (needs learned per-user baselines, not payload matching) but the **strongest differentiator** — exactly the contextual, environment-learning detection that incumbents are weak at.

### Network domain — narrower, but one category fully functional (not just stubbed)
- **Network Brute Force (SSH/RDP)** — chosen over port scan or DDoS specifically because it reuses the same rate-based statistical core being built for web Auth Failures (just pointed at a different telemetry source), making it the fastest path to *genuinely* full-functional rather than stretched thin. Also higher expert-credibility value: it's a top real-world initial-access vector feeding ransomware chains, and "did any attempt succeed" is a high-value scoping question.
- Port scan — lower value alone (recon, not compromise); kept as roadmap/stretch, not built.
- DDoS — hardest to make genuinely robust in the timeframe (needs proper multi-vector traffic baselining); kept as roadmap, not built.

### Explicitly out of scope for runtime detection (roadmap-labeled, not "gaps")
Not runtime-detectable regardless of time available — these are pre-deployment/process concerns, framed to judges as "a different tool's job, like a CI/CD security gate, not an incident detection agent":
- **A02 Cryptographic Failures** — mostly a config/implementation weakness, rarely a distinct traffic-level "attack."
- **A04 Insecure Design** — an architecture review finding, not an attack event.
- **A06 Vulnerable and Outdated Components** — dependency/CVE scanning (SCA), a pre-deployment problem.
- **A09 Security Logging and Monitoring Failures** — literally about the *absence* of logs; can't detect via the thing that's missing.
- (SSRF was floated as a possible 4th/5th web category earlier but was not included in the final 3 chosen for the hackathon build — it remains a roadmap item.)

### Reference framework
- **OWASP Top 10** used as the grounding taxonomy for web categories (deliberately fixed at 10 curated risk categories — there is no official "Top 15/20"; the real extension-of-granularity reference if a bigger roadmap number is wanted is **MITRE's CWE Top 25 Most Dangerous Software Weaknesses**).
- **MITRE ATT&CK** technique mapping required on every verdict (e.g. T1110 for brute force, T1190 for exploitation of a public-facing app).

---

## 7. Build Timeline (23 days: 20 build + 3 test/polish)

| Phase | Days | Deliverable |
|---|---|---|
| 1 | 1–4 | Orchestrator + ingestion pipeline (web log parser **and** network/auth log parser skeleton) + classifier skeleton |
| 2 | 5–9 | Injection sub-agent (SQLi + XSS) — fully working, tested against real attack traffic |
| 3 | 10–15 | Authentication Failures (web) **+** Network Brute Force (SSH/RDP) built together, sharing the statistical detection core — extended 1–2 days over the original web-only estimate to cover the second telemetry source and network-specific scoping |
| 4 | 16–20 | Broken Access Control (IDOR) sub-agent |
| 5 | 21–23 | Integration testing, demo rehearsal, README/docs polish |

**Practical rule established:** test each category as it's finished, not all at the end. The final 3 days are for end-to-end integration testing and demo rehearsal, not first-time testing of individual pieces — "we tested continuously and used the buffer to polish," not "we ran out of time to test."

Also decided: since this is meant to be a real open-source product, design the sub-agent interface to be clean/documented enough that a community contributor could add a new attack-type sub-agent without touching the orchestrator — worth building in now while it's cheap, and a good thing to show judges as an open-source signal.

---

## 8. Product Quality Bar ("cybersecurity-expert-would-actually-use-this" bar)

Established as required across **all** built categories, not optional polish:
- **MITRE ATT&CK technique mapping** on every verdict.
- **Confidence scores, not binary flags** — real detections are probabilistic; a tool claiming certainty on everything gets distrusted fast by experienced analysts.
- **False-positive testing against benign traffic**, not just attack traffic — report precision, not just catch rate.
- **Structured JSON output** for SIEM/SOAR integration, not a chat-style explanation.

---

## 9. Testing & Validation Plan

| Category | Attack Traffic Source | Benign Baseline Source | Key Metrics |
|---|---|---|---|
| SQLi / XSS | OWASP Juice Shop + PortSwigger Web Security Academy labs, run with known attack scripts | Normal Juice Shop browsing/API traffic captured separately | Precision, recall, F1 |
| Auth Failures (web) | Scripted brute force + credential stuffing runs using public breached-credential sample lists | Normal login traffic with occasional genuine typos | Detection latency, false positive rate |
| IDOR | Scripted sequential/out-of-range object ID requests against Juice Shop or a purpose-built test API | Normal per-user object access over simulated multi-day session history | Baseline accuracy, deviation precision |
| Network Brute Force | Public SSH/RDP honeypot datasets (e.g. Cowrie honeypot logs) + scripted local brute force runs | Normal administrative SSH/RDP session logs | Precision, recall, success-detection accuracy |

**Validation process:** unit-test each leaf sub-agent in isolation as soon as it's built → integration-test the full chain per domain → reserve the final 3 days for full-pipeline rehearsal with mixed, realistic traffic (not first-time testing).

**Demo data sources called out specifically:** OWASP Juice Shop and DVWA (Damn Vulnerable Web App) — open-source apps deliberately built with OWASP-style vulnerabilities, good for generating realistic attack traffic to feed the pipeline as if it were live telemetry (since there's no real production traffic to plug into for a hackathon demo).

---

## 10. Specialized Models Per Sub-Agent

**Feasibility: confirmed yes**, and treated as architecturally preferable, not just possible — since the Orchestrator already routes by category, it can just as easily route to a different underlying model per sub-agent. Reasons: (1) task fit — rate-based detection and contextual baseline deviation are fundamentally different reasoning shapes; (2) cost/latency — small fast models for high-frequency simple tasks, larger models reserved for genuinely hard reasoning; (3) independent improvability per sub-agent, which matters for the open-source/community-extensible goal.

**Task-profile grouping used for model selection:**
- **Pattern/signature-heavy (SQLi, XSS):** code-aware models layered on top of a deterministic regex/static-rule pre-filter — the LLM's job is edge-case judgment, not first-line detection.
- **Statistical/rate-based (Auth Failures, Network Brute Force):** detection itself is a statistical threshold, not an LLM decision — a small model is only needed to turn the statistical verdict into a readable scoping narrative. Cheapest slot in the system by design.
- **Contextual/behavioral (IDOR, and both Type Classifiers):** classifiers need to be fast/cheap since they run on every event; IDOR's deviation scorer can afford a stronger/larger model since it runs less often per event but needs to weigh a fuller access history.

**Recommended models (per this document's writing — verify current availability directly at build.nvidia.com before committing, since Claude does not have live web/browser access to NVIDIA's catalog and this is not the result of a live lookup):**

| Agent | Task Profile | Recommended Model(s) | Size | On NVIDIA NIM* |
|---|---|---|---|---|
| Type Classifiers (web + network) | High-frequency, low-complexity classification | Llama 3.1 8B Instruct, or Mistral 7B Instruct, or Nemotron Mini 4B Instruct | 4B–8B | Yes, typically available |
| SQL Injection Detector | Structured payload reasoning, code-aware | CodeLlama 13B Instruct, or StarCoder2 15B, or Llama 3.1 8B as fallback | 8B–15B | Partial, verify per model |
| XSS Detector | Structured payload reasoning, HTML/JS-aware | Llama 3.1 8B Instruct, or CodeLlama 13B Instruct | 8B–13B | Yes, typically available |
| Brute Force / Credential Stuffing Detectors (web) | Statistical result → narrative, low reasoning load | Llama 3.2 3B Instruct, or Phi-3 Mini | 3B–4B | Yes, typically available |
| Network Brute Force Detectors (SSH/RDP) | Statistical result → narrative, low reasoning load | Llama 3.2 3B Instruct, or Phi-3 Mini | 3B–4B | Yes, typically available |
| Access Pattern Baseliner | Long-context behavioral summarization | Mixtral 8x7B Instruct, or Llama 3.1 70B Instruct | 8x7B / 70B | Yes, typically available |
| Deviation Scorer (IDOR) | Nuanced contextual judgment, fewer calls per event | Llama 3.1 70B Instruct, or Nemotron 4 340B Instruct for highest accuracy | 70B–340B | Yes, typically available |

**Deployment approach:**
- **Hackathon demo:** call **NVIDIA NIM's free, rate-limited hosted API** (build.nvidia.com) directly from each sub-agent — fastest path to a working multi-model pipeline with zero GPU provisioning.
- **Long-term open-source product:** every recommended model is open-weight, so an adopter with no NVIDIA account/budget can self-host the same models via **vLLM or Ollama** — the project never depends on one vendor's hosted availability to function.
- **Action item before locking anything in:** verify current model availability and free-tier limits live at build.nvidia.com — hosted catalogs and free-usage terms change over time.

---

## 11. Hackathon Submission Materials (already completed)

- **Idea Title field:** "Talos, an open source multi agent system for automated attack classification and scope finding"
- **Post an Idea field:** "Talos is an open source multi agent system that classifies and scopes web and network attacks using specialized sub agents, giving smaller teams transparent, extensible incident response automation."
- All submission text fields written to comply with the platform's character limits and allowed-character set (`A-Za-z0-9,.?!'()` only — no hyphens, colons, ampersands, slashes, or quotation marks).
- Attachment constraints noted: <25 MB, formats doc/docx/xls/xlsx/msg/txt/pdf/jpeg/jpg/png/ppt/pptx, filenames limited to plain letters/numbers/underscores/spaces, ≤96 characters, no reused filenames, no special characters (`* | , \ : < > [ ] ( ) & $ # % ~ + -` all blocked).
- **Two PDFs produced** using `reportlab`:
  1. A standalone detailed **architecture diagram** (canvas-based).
  2. A two-page **one-pager** (SimpleDocTemplate/Platypus) covering problem, architecture, OWASP-aligned scope, and differentiation.
- **reportlab quirks hit and solved** (useful if regenerating or editing these PDFs):
  - `drawCentredString` does not handle literal `\n` — renders a black artifact instead of a line break. Multi-line box titles require separate `drawCentredString` calls at different y-offsets.
  - Text overflow in boxes isn't automatic — needed a `fit_font` helper using `stringWidth` from `reportlab.pdfbase.pdfmetrics` to shrink font size iteratively until text fits within box width minus padding.
  - Row centering for clustered sub-agent boxes must account for total cluster width — two independently centered clusters sharing a canvas need enough separation between center points or their boxes overlap and obscure each other's text. Fixed by widening `PAGE_W` to 1600 and increasing the gap parameter in the domain agent row to 380.

---

## 12. Documents Already Produced in This Second Chat

1. **`Talos_Problem_Statement_and_Solution_Document.docx`** — a 13-page detailed problem statement + solution document covering: problem statement (context, core problem, who's affected, why existing solutions fall short, opportunity statement), solution overview (vision, hackathon-vs-long-term scope, high-level architecture), full agent architecture breakdown (every agent/sub-agent/child-detector and what it does), an agent responsibility matrix table, the testing/validation strategy, the specialized-models-per-agent section (including the NIM table above), and a roadmap section.
2. **This memory dump** (`Talos_Project_Memory_Dump.md`) — the current file.

Claude's own persistent memory (for this project) has also been updated with the condensed version of all key decisions in Sections 5–8 above, so a fresh chat within the same project should already have baseline context even without re-uploading this file.

---

## 13. Post-Hackathon Roadmap (consolidated)

Everything below is *after* the hackathon submission — none of it is required for the September 4 prototype, but it's the agreed direction once that's done:

- **Complete remaining OWASP-aligned web categories that have a genuine runtime signature** — SSRF was the one specifically floated as the next candidate, since it was considered for the hackathon build but ultimately left out of the final 3.
- **Expand network coverage** to port scanning and DDoS — both already designed for in the network classifier's structure, just not built for the hackathon.
- **Add new domains**: cloud (e.g. IAM misuse, storage exposure), endpoint (EDR telemetry), and Active Directory (lateral movement, credential dumping) — this is the core of the long-term vision from Section 1, extending the same orchestrator/classifier/sub-agent pattern to domains beyond web and network.
- **Publish a documented sub-agent interface** so a community contributor can add a new attack-type sub-agent without modifying the orchestrator — this is the concrete mechanism behind "community-extensible," not just a slogan.
- **Explore fine-tuning smaller open-weight models on Talos's own labeled detection data** once the project has accumulated real usage, rather than relying solely on the general-purpose hosted models listed in Section 10.
- Keep growing community extensibility generally — the explicit long-term aim is that coverage expands through outside contributions, not a fixed roadmap owned by one team.

---

## 14. Where This Leaves Off / Natural Next Steps

Nothing is currently blocking — the scope, architecture, timeline, testing plan, and model plan are all locked in. The natural next steps (not yet started as of this dump):
- Start building **Phase 1**: the Orchestrator + ingestion pipeline + classifier skeleton (Days 1–4).
- Design the actual **Injection sub-agent detection logic** in detail (SQLi pattern set, XSS pattern set, the static-filter-plus-LLM-edge-case-judgment split described in Section 10).
- Set up the NVIDIA NIM API access and confirm current model availability against the table in Section 10.
- Set up or script the OWASP Juice Shop / DVWA test environment for generating labeled attack + benign traffic.

---

*End of dump. Upload this file in a new chat (or on a different system) and reference it directly to continue exactly where this left off.*
