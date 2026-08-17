# Talos — Low-Level Design (LLD)

**Project:** Talos — Open-Source Multi-Agent System for Attack Detection, Classification, and Scope Analysis
**Document type:** Low-Level Design
**Revision:** 1.3 (2026-08-18) — see §16
**Companion documents:** `Talos_HLD.md`, `Talos_DFD.md`, `Talos_Architecture_Diagram.svg`, `../standards/Talos_Engineering_Standards.md`
**Scope:** Component internals, data contracts, interfaces, per-detector algorithms, configuration, and error handling for the hackathon slice (Web + Network). Language/idioms shown in Python 3.11+ with Pydantic-style models; they are illustrative contracts, not final code.

**Structural conformance:** all paths, module names, and class names in this document conform to
`../standards/Talos_Engineering_Standards.md` (rules R1–R6). Where this document and the standards
disagree on *structure, naming, or file size*, the standards win; this document remains authoritative on
design, contracts, and algorithms. **Revision 1.1** realigned every path and identifier to those rules —
see §16 for the change record.

---

## 1. Module and Package Structure

`src/` layout: no importable code sits at the repository root (R1), and the package root `src/talos/`
holds only `__init__.py` and `py.typed` (R1.4). Every module basename is unique repo-wide (R3.3) and
carries a role suffix from the closed vocabulary in the standards §3.1.

```
src/talos/
├── __init__.py
├── py.typed
├── core/                              # cross-cutting foundations
│   ├── settings.py                    # TalosSettings: config load + validation (Pydantic Settings)
│   ├── agent_contracts.py             # DomainAgent, TypeClassifier, AttackTypeSubAgent, Detector ABCs
│   │                                  #   + DetectionContext
│   ├── error_types.py                 # TalosError hierarchy
│   ├── logging_setup.py               # structured logging config
│   └── constants.py                   # non-domain constants
├── schemas/                           # Pydantic data contracts (§2)
│   ├── event_schema.py                # NormalizedEvent + Actor/Target/WebRequest/AuthEvent
│   ├── verdict_schema.py              # Verdict + Evidence + MitreMapping + Scope + ModelInfo
│   └── report_schema.py               # IncidentReport
├── ingestion/
│   ├── parser_contract.py             # BaseParser ABC
│   └── parsers/
│       ├── web_log_parser.py          # HTTP/WAF/app logs -> NormalizedEvent(domain="web")
│       └── network_log_parser.py      # SSH/RDP/flow -> NormalizedEvent(domain="network")
├── orchestrator/
│   ├── event_orchestrator.py          # EventOrchestrator: entry point, routing, pipeline tracking
│   ├── agent_registry.py              # AgentRegistry: domain-agent registry (extensibility)
│   └── verdict_aggregator.py          # VerdictAggregator: Verdict -> IncidentReport
├── domains/
│   ├── web/
│   │   ├── web_domain_agent.py
│   │   ├── web_type_classifier.py
│   │   ├── injection/
│   │   │   ├── injection_sub_agent.py
│   │   │   ├── sql_injection_detector.py
│   │   │   └── xss_detector.py
│   │   ├── auth_failure/
│   │   │   ├── auth_failure_sub_agent.py
│   │   │   ├── brute_force_detector.py
│   │   │   └── credential_stuffing_detector.py
│   │   └── broken_access_control/     # category emitted by the web classifier
│   │       ├── broken_access_control_sub_agent.py
│   │       ├── access_baseliner.py
│   │       └── deviation_scorer.py    # technique = "idor"
│   └── network/
│       ├── network_domain_agent.py
│       ├── network_type_classifier.py
│       └── brute_force/
│           ├── network_brute_force_sub_agent.py
│           ├── ssh_brute_force_detector.py
│           └── rdp_brute_force_detector.py
├── detection/                         # shared, domain-agnostic detection cores
│   ├── rate/
│   │   └── rate_engine.py             # shared statistical core (web auth + network brute force)
│   ├── patterns/
│   │   ├── sql_injection_pattern_rules.py
│   │   └── xss_pattern_rules.py
│   └── baseline/
│       └── access_baseline.py         # AccessBaseline model + per-account update logic
├── llm/
│   ├── model_client.py                # ModelClient ABC + NimClient / VllmClient / OllamaClient
│   ├── model_router.py                # agent -> model resolution + fallback
│   └── prompts/                       # versioned prompt templates (R3.7)
│       ├── web_type_classifier_route_v1.md
│       ├── network_type_classifier_route_v1.md
│       ├── sql_injection_detector_judge_v1.md
│       ├── xss_detector_judge_v1.md
│       ├── rate_detector_narrate_v1.md
│       └── deviation_scorer_judge_v1.md
├── knowledge/
│   ├── mitre_mapping.py               # technique-id constants + tactic mapping
│   └── owasp_mapping.py               # OWASP Top 10 category mapping
├── storage/
│   ├── event_window_store.py          # EventWindowStore: rolling TTL buffer for rate detectors
│   ├── baseline_store.py              # BaselineStore: persistent per-account access baselines
│   └── verdict_log_store.py           # VerdictLogStore: audit trail of verdicts/incidents
├── output/
│   ├── api/
│   │   ├── api_server.py              # FastAPI app factory
│   │   └── report_routes.py           # submit events, fetch reports
│   └── sinks/
│       ├── json_file_sink.py
│       └── stdout_sink.py
└── cli/
    └── main_cli.py                    # `talos` console entry point
```

**Supporting trees** (outside the package, per standards §2.1): `config/` holds `default.yaml`,
`model_routing.yaml`, and `thresholds.yaml` (§10); `db/` holds all SQL and migrations for
`BaselineStore`/`VerdictLogStore` (§4.4 of the standards); `tests/unit/` mirrors this tree path-for-path.

---

## 2. Core Data Contracts

All contracts are Pydantic models; validation is enforced at every layer boundary. Field names below are canonical and shared verbatim with the DFD data dictionary. The contracts are split across three modules under `src/talos/schemas/` — one per contract group, keeping each well inside the R6 line budget.

### 2.1 `NormalizedEvent` — `schemas/event_schema.py`
The single contract produced by ingestion and consumed by every agent.

```python
class Actor(BaseModel):
    source_ip: str
    account: str | None = None       # username / login target if present
    session_id: str | None = None
    user_agent: str | None = None

class Target(BaseModel):
    host: str | None = None          # network host or web host
    endpoint: str | None = None      # web route/path
    resource_id: str | None = None   # object id for IDOR reasoning
    port: int | None = None

class WebRequest(BaseModel):
    method: str | None = None        # GET/POST/...
    path: str | None = None
    query_params: dict[str, str] = {}
    body: str | None = None
    headers: dict[str, str] = {}
    status_code: int | None = None

class AuthEvent(BaseModel):
    protocol: str | None = None      # "ssh" | "rdp" | "http"
    outcome: str | None = None       # "success" | "failure"
    reason: str | None = None        # e.g. "invalid_password", "unknown_user"

class NormalizedEvent(BaseModel):
    event_id: str                    # uuid, assigned by parser
    timestamp: datetime              # event time (source clock, UTC-normalized)
    domain: Literal["web", "network"]
    telemetry_source: str            # "waf" | "app_log" | "sshd" | "rdp" | "netflow"
    actor: Actor
    target: Target
    request: WebRequest | None = None   # populated for domain == "web"
    auth: AuthEvent | None = None       # populated for auth-bearing events
    raw: str                            # original log line, verbatim (evidence)
    meta: dict[str, Any] = {}           # parser-specific extras
```

### 2.2 `Verdict` — `schemas/verdict_schema.py`
Emitted by every **leaf detector**. This is the transparency contract.

```python
class MitreMapping(BaseModel):
    technique_id: str                # e.g. "T1110"
    technique_name: str              # e.g. "Brute Force"
    tactic: str                      # e.g. "Credential Access"

class Evidence(BaseModel):
    kind: Literal["log_line", "matched_pattern", "statistic", "baseline_deviation"]
    detail: str                      # the concrete artifact (raw line, regex hit, z-score...)
    references: list[str] = []       # event_ids / object_ids backing this evidence

class Scope(BaseModel):
    affected_accounts: list[str] = []
    affected_endpoints: list[str] = []
    affected_objects: list[str] = []
    affected_hosts: list[str] = []
    attempt_count: int | None = None
    source_diversity: int | None = None      # distinct source IPs
    succeeded: bool | None = None             # did the attack succeed? (key scoping signal)
    window_start: datetime | None = None
    window_end: datetime | None = None

class ModelInfo(BaseModel):
    name: str                        # resolved model id
    route_reason: str                # why this model was chosen
    used_llm: bool                   # false when a pure statistical/static verdict

class Verdict(BaseModel):
    verdict_id: str
    event_ids: list[str]             # one or many (windowed detectors span events)
    detector: str                    # "sql_injection_detector", ...
    domain: str
    category: str                    # "injection" | "auth_failure" | ...
    technique: str                   # "sql_injection" | "brute_force" | ...
    attack_detected: bool
    confidence: float                # 0.0-1.0, calibrated
    mitre: MitreMapping
    scope: Scope
    evidence: list[Evidence]
    reasoning: str                   # human-readable, model- or rule-generated
    model: ModelInfo
    created_at: datetime
```

### 2.3 `IncidentReport` — `schemas/report_schema.py`
Produced by `VerdictAggregator`; the SIEM/SOAR-consumable output.

```python
class IncidentReport(BaseModel):
    incident_id: str
    created_at: datetime
    domain: str
    category: str
    summary: str                     # one-line human summary
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float                # aggregate confidence
    verdicts: list[Verdict]          # every contributing verdict, verbatim
    aggregate_scope: Scope           # merged scope across verdicts
    mitre_techniques: list[MitreMapping]
    recommended_actions: list[str]   # e.g. "block source IP", "force password reset"
```

---

## 3. Base Interfaces (Abstract Classes) — `core/agent_contracts.py`

These are the extension contracts. Adding a sub-agent means implementing `AttackTypeSubAgent` + one or more `Detector`s — **without touching the Orchestrator** (HLD P7/NFR-4).

All four ABCs plus `DetectionContext` live in one module: they are a single cohesive contract surface, they
change together, and splitting them would force circular imports. Estimated ~120 LOC.

Every method is `async`: each one may sit in front of a model call, and §4.2/§12 award the
pipeline concurrency across detectors of the same sub-agent. Statistical detectors simply never
await (rev 1.2, §16.2).

```python
class TypeClassifier(ABC):
    domain: ClassVar[str]
    @abstractmethod
    async def classify(self, event: NormalizedEvent, ctx: "DetectionContext") -> tuple[str, float]:
        """Return (category, confidence)."""

class Detector(ABC):
    detector_name: ClassVar[str]
    technique: ClassVar[str]
    mitre: ClassVar[MitreMapping]
    @abstractmethod
    async def evaluate(self, event: NormalizedEvent, ctx: "DetectionContext") -> Verdict | None:
        """Confirm + scope one technique. None = not applicable."""

class AttackTypeSubAgent(ABC):
    category: ClassVar[str]          # category emitted by the classifier
    detectors: list[Detector]
    @abstractmethod
    async def handle(self, event: NormalizedEvent, ctx: "DetectionContext") -> list[Verdict]:
        """Dispatch to child detectors, collect verdicts."""

class DomainAgent(ABC):
    domain: ClassVar[str]
    classifier: TypeClassifier
    sub_agents: dict[str, AttackTypeSubAgent]   # category -> sub-agent
    @abstractmethod
    async def process(self, event: NormalizedEvent, ctx: "DetectionContext") -> list[Verdict]:
        ...
```

`DetectionContext` carries shared services into detectors so they stay stateless themselves. The
service fields are typed as `Protocol`s (`EventWindow`, `BaselineReader`, `ModelCaller`,
`VerdictRecorder`) declared alongside the ABCs: the context is frozen in P1 while the concrete
stores arrive in P2/P3/P6, and structural typing lets the real classes — and the in-memory doubles
of §14 — satisfy it without an import in either direction.

```python
@dataclass
class DetectionContext:
    event_window: EventWindow         # rolling TTL buffer for rate detectors  (EventWindowStore)
    baseline_store: BaselineReader    # per-account access baselines, IDOR     (BaselineStore)
    model_client: ModelCaller         # LLM access, routed per detector        (ModelClient)
    settings: TalosSettings           # loaded config (core/settings.py)
    verdict_log: VerdictRecorder      # audit trail                            (VerdictLogStore)
```

---

## 4. Orchestrator Internals

### 4.1 `AgentRegistry` (extensibility mechanism) — `orchestrator/agent_registry.py`
```python
class AgentRegistry:
    def __init__(self):
        self._domain_agents: dict[str, DomainAgent] = {}
    def register_domain_agent(self, agent: DomainAgent): ...
    def get(self, domain: str) -> DomainAgent: ...
```
Domain agents self-register at startup; each domain agent holds its `category -> sub-agent` map. The Orchestrator only knows domains, never techniques.

### 4.2 Processing algorithm — `orchestrator/event_orchestrator.py`
```python
class EventOrchestrator:
    def __init__(self, registry, aggregator, ctx):
        self.registry, self.aggregator, self.ctx = registry, aggregator, ctx

    async def submit(self, event: NormalizedEvent) -> IncidentReport | None:
        self.ctx.event_window.add(event)            # feed windowed detectors
        agent = self.registry.get(event.domain)     # route by domain ONLY
        verdicts = await agent.process(event, self.ctx)
        verdicts = [v for v in verdicts if v is not None]
        if not verdicts:
            return None                              # nothing fired
        report = self.aggregator.aggregate(event, verdicts)
        self.ctx.verdict_log.append(report)
        return report
```

### 4.3 Aggregation — `orchestrator/verdict_aggregator.py`
`VerdictAggregator.aggregate(event, verdicts)`:
1. Dedupe verdicts by `(technique, sorted(event_ids))`.
2. Merge `Scope` objects (union of accounts/endpoints/objects/hosts; `succeeded = any(v.scope.succeeded)`).
3. Severity = function of `max(confidence)`, `succeeded`, and category weight (e.g. successful brute force → `high`; blocked SQLi attempt → `medium`).
4. Aggregate confidence = calibrated combination (default: max, with a small boost when independent detectors corroborate).
5. `recommended_actions` derived from a category→action table.

---

## 5. Ingestion Parsers

### 5.1 `BaseParser` — `ingestion/parser_contract.py`
```python
class BaseParser(ABC):
    domain: str
    @abstractmethod
    def parse_line(self, raw: str) -> NormalizedEvent | None: ...
    def parse_stream(self, lines: Iterable[str]) -> Iterator[NormalizedEvent]:
        for ln in lines:
            ev = self.parse_line(ln)
            if ev: yield ev
```

### 5.2 Web Log Parser — `ingestion/parsers/web_log_parser.py`
- Supports combined/common Apache/Nginx log format and JSON app logs (format autodetected per line).
- Field mapping: `remote_addr→actor.source_ip`, `request_line→request.method/path/query_params`, `status→request.status_code`, `http_user_agent→actor.user_agent`, body/headers when present (WAF JSON).
- URL-decodes `query_params` and `body` **once** and preserves the raw form in `raw` (double-decode is an evasion vector — the detector, not the parser, decides how many layers to normalize).

### 5.3 Network/Auth Log Parser — `ingestion/parsers/network_log_parser.py`
- Parses `sshd` syslog lines and RDP event logs.
- Maps: source IP → `actor.source_ip`; targeted user → `actor.account`; `protocol ∈ {ssh, rdp}` → `auth.protocol`; "Accepted/Failed password" → `auth.outcome`; host/port → `target.host/port`.
- Flow records populate `target` + `meta` for future port-scan/DDoS branches (not consumed by the built detector).

---

## 6. Type Classifiers

`domains/web/web_type_classifier.py`, `domains/network/network_type_classifier.py`.

Classifiers run on **every event** → cheapest model tier, and use a static short-circuit before any LLM call.

```python
class WebTypeClassifier(TypeClassifier):
    domain = "web"
    async def classify(self, event, ctx):
        # 1. cheap static signals first
        if self._looks_like_auth_endpoint(event): base = ("auth_failure", 0.6)
        elif self._has_injection_markers(event):  base = ("injection", 0.6)
        elif self._is_object_access(event):        base = ("broken_access_control", 0.5)
        else:                                       base = ("unclassified", 0.3)
        # 2. small LLM refines category + confidence (bounded prompt)
        return await self._model_refine(event, base, ctx)
```

- **Output parsing:** the LLM is asked for strict JSON `{category, confidence, rationale}`; a schema-validated parse with one retry, else fall back to the static `base`.
- **Network classifier:** routes auth events to `network_brute_force`; flow-only events return `unclassified` for the slice (port-scan/DDoS reserved).
- **Category strings are a hard contract.** The value a classifier emits must equal (a) the
  `AttackTypeSubAgent.category` registered for it and (b) the sub-agent's package name under
  `domains/<domain>/`. Emitted categories for the slice: `injection`, `auth_failure`,
  `broken_access_control`, `network_brute_force`, `unclassified`. Prompt templates live in
  `llm/prompts/*_route_v1.md`, never inline (R2.3).

---

## 7. Detection Logic (per detector)

> **Pattern principle (SQLi/XSS):** a deterministic regex/static pre-filter is the *first line*; the LLM is invoked **only** for payloads the static layer is unsure about — its job is edge-case judgment, not primary detection.
> **Statistical principle (auth/network brute force):** detection is a threshold over a window; the LLM only renders the verdict into a readable scope narrative.

### 7.1 SQL Injection Detector — `technique="sql_injection"`, MITRE `T1190`
`domains/web/injection/sql_injection_detector.py` (class `SqlInjectionDetector`, `detector_name="sql_injection_detector"`); pattern tables in `detection/patterns/sql_injection_pattern_rules.py`.

**Pre-filter pattern classes** (over decoded `query_params` + `body`):
| Class | Example signal |
|---|---|
| Tautology | `' OR '1'='1`, `OR 1=1--` |
| UNION-based | `UNION SELECT`, `UNION ALL SELECT` |
| Comment/evasion | `--`, `#`, `/**/`, mixed-case `UnIoN` |
| Stacked queries | `; DROP`, `; INSERT` |
| Blind (boolean/time) | `AND SLEEP(`, `WAITFOR DELAY`, `AND 1=1`/`AND 1=2` pairs |

**Algorithm**
```python
def evaluate(self, event, ctx):
    payloads = extract_web_payloads(event)          # params + body, decoded once
    hits = pattern_match(payloads, SQL_INJECTION_PATTERNS)   # deterministic
    if not hits:
        return None                                 # static layer clears it
    if is_unambiguous(hits):                        # e.g. explicit UNION SELECT
        confidence, reasoning = 0.95, rule_reasoning(hits)
        used_llm = False
    else:                                           # borderline -> LLM edge-case judgment
        j = ctx.model_client.judge_sql_injection(payloads, hits)   # code-aware model
        confidence, reasoning, used_llm = j.confidence, j.reasoning, True
    succeeded = infer_success(event)                # 500 vs 200 + response length delta if available
    scope = Scope(affected_endpoints=[event.target.endpoint],
                  succeeded=succeeded)
    return build_verdict(self, event, confidence, scope, hits, reasoning, used_llm)
```
**Scoping:** endpoint targeted, inferred backend table/field when derivable from the payload, and exploitation-vs-blocked (`succeeded`) from status code / response anomaly.

### 7.2 XSS Detector — `technique="xss"`, MITRE `T1059.007`
`domains/web/injection/xss_detector.py` (class `XssDetector`); pattern tables in `detection/patterns/xss_pattern_rules.py`.

**Pre-filter pattern classes:** `<script>`, event handlers (`onerror=`, `onload=`), `javascript:` URIs, encoded variants (`%3Cscript%3E`, HTML entities), attribute-breakouts.
**Reflected vs stored:** the detector consults `ctx.event_window` — if the same payload signature later reappears in a *response body / different endpoint render*, it is classified **stored**; if it echoes in the immediate response, **reflected**.
**Scoping:** endpoint that accepted the payload + downstream pages/sessions that could render it. LLM invoked only for obfuscated/borderline payloads.

### 7.3 Shared Rate Engine — `detection/rate/rate_engine.py`
Backs **Brute Force**, **Credential Stuffing**, **SSH**, and **RDP** detectors — same math, different key function and telemetry.

```python
@dataclass
class RateConfig:
    window_seconds: int
    fail_threshold: int          # failures within window to fire
    key_fn: Callable             # what defines "one target" (account / host / ip)
    distributed: bool = False    # credential-stuffing mode

class RateEngine:
    def evaluate(self, event, window: EventWindowStore, cfg: RateConfig):
        if event.auth is None: return None
        key = cfg.key_fn(event)
        recent = window.query(key=key, within=cfg.window_seconds)
        fails = [e for e in recent if e.auth and e.auth.outcome == "failure"]
        if len(fails) < cfg.fail_threshold: return None
        success_after = any(e.auth.outcome == "success" for e in recent
                            if e.timestamp >= min(f.timestamp for f in fails))
        return RateSignal(count=len(fails),
                          sources={e.actor.source_ip for e in fails},
                          succeeded=success_after,
                          window=(recent[0].timestamp, recent[-1].timestamp))
```

#### 7.3.1 Brute Force Detector (web) — `T1110` — `domains/web/auth_failure/brute_force_detector.py`
`key_fn = (account)` OR `(source_ip)`; fires on high failures against a single account/source; scope reports `attempt_count`, `source_diversity`, targeted `account`, and `succeeded`. Confidence scales with count above threshold; a trailing success → confidence ≥ 0.9 and severity `high`.

#### 7.3.2 Credential Stuffing Detector — `T1110.004` — `domains/web/auth_failure/credential_stuffing_detector.py`
`distributed=True`: fires on **low failures per account but across many accounts** from a rotating source set within the window. Scope reports distinct accounts targeted and any account with a success immediately following a failed batch attempt. Distinguished from brute force by breadth (many accounts, few tries each) vs depth (one account, many tries).

#### 7.3.3 SSH / RDP Brute Force Detectors — `T1110` — `domains/network/brute_force/{ssh,rdp}_brute_force_detector.py`
Same engine, `auth.protocol` filter (`ssh`/`rdp`), `key_fn=(target.host, account)`. `succeeded` (a successful auth following the failed burst) is the highest-value analyst signal — it separates honeypot noise from a genuine initial-access event. RDP is called out as a top ransomware initial-access vector.

For all rate detectors, the small "narrative" model turns the `RateSignal` into `reasoning` (prompt: `llm/prompts/rate_detector_narrate_v1.md`); if the model is unavailable, a templated narrative is used and `used_llm=False`.

### 7.4 IDOR — `category="broken_access_control"`, `technique="idor"`, MITRE `T1083`/`T1530`
`domains/web/broken_access_control/` — sub-agent plus two cooperating children (`access_baseliner.py`, `deviation_scorer.py`); no fixed payload, so it needs learned baselines.

**Access Pattern Baseliner** — `detection/baseline/access_baseline.py` (model + update logic), driven by `domains/web/broken_access_control/access_baseliner.py`
```python
class AccessBaseline(BaseModel):
    account: str
    seen_object_ids: set[str]            # sampled/bounded
    numeric_min: int | None              # observed id range
    numeric_max: int | None
    endpoints: dict[str, int]            # endpoint -> access count
    updated_at: datetime
```
Updated online per event; persisted in `BaselineStore`. Cold-start → conservative (low-confidence) verdicts until the baseline matures (configurable min observations).

**Deviation Scorer** — `domains/web/broken_access_control/deviation_scorer.py`
```python
def evaluate(self, event, ctx):
    if not is_object_access(event): return None
    base = ctx.baseline_store.get(event.actor.account)
    if base is None or immature(base):
        return low_confidence_verdict(event, reason="baseline immature")
    features = {
      "outside_range": outside_numeric_range(event, base),
      "sequential_run": sequential_enumeration(event, ctx.event_window, base),
      "novel_endpoint": event.target.endpoint not in base.endpoints,
      "rate": access_rate(event, ctx.event_window),
    }
    stat_score = weighted_score(features)            # deterministic 0..1
    if stat_score < LOW: return None
    # stronger reasoning model weighs the full access history for borderline cases
    j = ctx.model_client.judge_idor(event, base, features)   # large model, fewer calls
    confidence = blend(stat_score, j.confidence)
    scope = Scope(affected_objects=objects_outside_pattern(event, ctx.event_window, base),
                  affected_accounts=[event.actor.account])
    return build_verdict(self, event, confidence, scope,
                         evidence=deviation_evidence(features), reasoning=j.reasoning,
                         used_llm=True)
```
**Scoping:** exactly which object IDs were accessed outside the learned pattern (e.g. a sequential enumeration run `1001,1002,1003,...`).

---

## 8. LLM Access and Routing

### 8.1 `ModelClient` — `llm/model_client.py`
```python
class ModelClient(ABC):
    @abstractmethod
    async def complete(self, *, model: str, prompt: str, schema: dict,
                       max_tokens: int, timeout_s: float) -> dict: ...
```
Concrete impls: `NimClient` (NVIDIA NIM REST), `VllmClient`, `OllamaClient`. Selected by config; the rest of the system is impl-agnostic.

### 8.2 Routing — `llm/model_router.py`, config in `config/model_routing.yaml`
```yaml
# per-agent model routing (config-driven, HLD §8)
routing:
  web_type_classifier:      { model: "meta/llama-3.1-8b-instruct", tier: small }
  network_type_classifier:  { model: "meta/llama-3.1-8b-instruct", tier: small }
  sql_injection_detector:   { model: "meta/codellama-13b-instruct", tier: code, fallback: "meta/llama-3.1-8b-instruct" }
  xss_detector:             { model: "meta/llama-3.1-8b-instruct", tier: code }
  brute_force_detector:     { model: "meta/llama-3.2-3b-instruct", tier: nano }
  credential_stuffing_detector: { model: "meta/llama-3.2-3b-instruct", tier: nano }
  ssh_brute_force_detector: { model: "meta/llama-3.2-3b-instruct", tier: nano }
  rdp_brute_force_detector: { model: "meta/llama-3.2-3b-instruct", tier: nano }
  access_baseliner:         { model: "mistralai/mixtral-8x7b-instruct", tier: long_context }
  deviation_scorer:         { model: "meta/llama-3.1-70b-instruct", tier: heavy, fallback: "meta/llama-3.1-8b-instruct" }
```
Routing keys are exactly the `detector_name` / classifier module names above, so a key can never drift from the component it routes.

> Model IDs are placeholders — verify current availability/free-tier at `build.nvidia.com` before locking in (this is not a live catalog lookup).

### 8.3 Resilience
- **Timeout + retry:** one retry on timeout/5xx with jittered backoff.
- **Fallback:** on persistent failure, route to the configured smaller `fallback` model and set `confidence *= penalty` (default 0.85), noting it in `ModelInfo.route_reason`.
- **Prompt hardening:** attacker-controlled telemetry is embedded as clearly delimited *data*, never as instructions; payloads are length-bounded before prompting (prompt-injection mitigation, HLD §11/§13).

---

## 9. Confidence Scoring and Calibration

- Every detector emits a `float` confidence, never a boolean flag.
- **Static-certain** verdicts (unambiguous UNION SELECT) get high fixed confidence without an LLM call.
- **Blended** verdicts combine a deterministic sub-score with an LLM judgment (`blend()` = weighted mean, weights in config).
- **Calibration methodology:** on the labeled test set, bucket verdicts by predicted confidence (deciles) and compare to observed accuracy; adjust a per-detector calibration curve (isotonic/Platt-style) so a 90%-confidence verdict is right ~90% of the time (NFR-3). Calibration curves are stored per detector in config and applied post-hoc.

---

## 10. Configuration — loader `core/settings.py`, files under `config/`

A single declarative config governs thresholds, windows, enabled sub-agents, routing, and calibration — no code change to tune (HLD §11). `TalosSettings` (Pydantic Settings) loads and validates it; detectors read values from `ctx.settings`, never from module-level literals (R2.3).

| File | Contents |
|---|---|
| `config/default.yaml` | the tree below, minus routing |
| `config/model_routing.yaml` | §8.2 routing table |
| `config/thresholds.yaml` | the `detection:` block, split out because it is the most-tuned surface |
| `config/local.yaml.example` | developer override template; real `local.yaml` is git-ignored |

Secrets (NIM API key) come from environment variables only — documented in `.env.example`, never committed in YAML.

```yaml
talos:
  enabled_domains: [web, network]
  ingestion:
    web: { formats: [combined, nginx_json, waf_json] }
    network: { formats: [sshd_syslog, rdp_evtx] }
  detection:
    brute_force:        { window_seconds: 120, fail_threshold: 10 }
    credential_stuffing:{ window_seconds: 300, distinct_accounts: 15, fails_per_account_max: 3 }
    ssh_brute_force:    { window_seconds: 120, fail_threshold: 8 }
    rdp_brute_force:    { window_seconds: 120, fail_threshold: 8 }
    idor:               { min_baseline_observations: 50, sequential_run_len: 5 }
  classifier:
    min_confidence_floor: 0.35
  llm:                      # resilience + prompt hardening (§8.3)
    request_timeout_seconds: 20.0
    max_retries: 1
    fallback_confidence_penalty: 0.85
    max_payload_chars: 2000 # attacker-controlled text is truncated before prompting
  routing: { ... }          # see §8.2
  calibration: { ... }      # per-detector curves: detector -> {parameter: float}
  output:
    sinks: [json_file, api]
    report_dir: out/reports
```

Every file is rooted at a single `talos:` key, which `TalosSettings.load()` strips; a stray
top-level key is an error rather than a silently ignored setting. Precedence, lowest first:
model defaults < `default.yaml` < `thresholds.yaml` < `model_routing.yaml` < `local.yaml` <
`TALOS_*` environment variables. Invalid values raise `ConfigError` at load — a process whose
thresholds did not load must not start and quietly detect nothing.

---

## 11. Error Handling and Resilience

| Failure | Behavior |
|---|---|
| Parser cannot parse a line | skip line, increment a `parse_error` metric, continue (never crash the stream) |
| Sub-agent/detector raises | caught by domain agent → emit an `inconclusive` low-confidence verdict, log the traceback |
| Model timeout/unavailable | retry once → fallback model → templated narrative; confidence penalized |
| Malformed model JSON | one re-ask with a stricter instruction → else fall back to static score |
| Baseline missing (cold start) | conservative low-confidence verdict, flagged `baseline immature` |
| Aggregator gets zero verdicts | Orchestrator returns `None` (no incident), not an empty report |

Principle: **fail-open for detection** (a broken detector must not silence the pipeline) but **fail-safe for reporting** (never emit a verdict without evidence + a confidence figure).

---

## 12. State, Concurrency, and Performance

- **EventWindowStore** is an in-memory, TTL-bounded ring buffer keyed for O(1) recent-lookups by `(account)`, `(source_ip)`, `(host,account)`; evicts on TTL to bound memory (NFR-7).
- **BaselineStore** is read-mostly, write-on-event; a per-account lock guards baseline updates.
- Orchestrator is `asyncio`-based; classifier/LLM calls are `await`ed concurrently across detectors of the same sub-agent.
- Statistical detectors are pure/fast (sub-second); LLM narrative is generated lazily and can be deferred without blocking the verdict's detection decision.

---

## 13. Extensibility — Adding a New Sub-Agent (worked skeleton)

To add, e.g., an **SSRF** sub-agent (roadmap), with **no Orchestrator edits**:

```python
# src/talos/domains/web/ssrf/ssrf_detector.py
class SsrfDetector(Detector):
    detector_name = "ssrf_detector"
    technique = "ssrf"
    mitre = MitreMapping("T1190", "Exploit Public-Facing Application", "Initial Access")
    def evaluate(self, event, ctx): ...   # pattern/behavioral logic

# src/talos/domains/web/ssrf/ssrf_sub_agent.py
class SsrfSubAgent(AttackTypeSubAgent):
    category = "ssrf"                     # == package name, == classifier output (§6)
    detectors = [SsrfDetector()]
    def handle(self, event, ctx):
        return [v for d in self.detectors if (v := d.evaluate(event, ctx))]
```
Then: (1) register the sub-agent on the Web Domain Agent's `category→sub-agent` map; (2) allow the Web Type Classifier to emit `"ssrf"`; (3) add a `routing.ssrf_detector` entry to `config/model_routing.yaml`; (4) add `llm/prompts/ssrf_detector_judge_v1.md`; (5) create `docs/features/web-ssrf-detection/` per R5; (6) ship a labeled attack/benign test set under `tests/fixtures/`. The registry + config wiring is the entire code integration surface; steps 5–6 are the standards' merge gate.

---

## 14. Testing Hooks

- Each `Detector` is unit-testable in isolation via a fabricated `DetectionContext` with in-memory stores and a stub `ModelClient` (records prompts, returns canned JSON) — no network needed. Shared fabricators live in `tests/conftest.py`.
- `tests/unit/` mirrors `src/talos/` path-for-path; `test_<module_basename>.py` (R3.5). Example: `src/talos/domains/web/injection/sql_injection_detector.py` → `tests/unit/domains/web/injection/test_sql_injection_detector.py`.
- Golden fixtures: labeled attack + benign traces per category (Juice Shop/DVWA/PortSwigger/Cowrie exports) under `tests/fixtures/logs/`, named `<domain>_<scenario>_<source>.log` (R3.6); expected outputs under `tests/fixtures/expected/`.
- Metrics harness (`tests/e2e/`) computes precision/recall/F1, confidence-calibration buckets, and detection latency per detector (maps to `Talos_DFD.md` §metrics and HLD NFR-2/3).

---

## 15. Traceability

| LLD element | HLD ref |
|---|---|
| `NormalizedEvent` / `Verdict` / `IncidentReport` (§2) | HLD §7 data architecture |
| `AgentRegistry` + attack-agnostic Orchestrator (§4, §13) | HLD P7, §14, NFR-4 |
| Shared rate engine (§7.3) | HLD §5.5 deliberate reuse |
| Per-agent routing + fallback (§8) | HLD §8 model strategy |
| Calibration (§9) | HLD NFR-3 |
| Fail-open/fail-safe (§11) | HLD §11 error handling |
| Module layout + naming (§1) | `../standards/Talos_Engineering_Standards.md` R1–R3 |

---

## 16. Revision Record

### 16.1 Revision 1.1 — structural realignment (2026-08-17)

Rev 1.0's layout predated the engineering standards. Content and algorithms are unchanged; paths and identifiers were realigned as follows.

| Rev 1.0 | Rev 1.1 | Rule |
|---|---|---|
| `talos/` (root package) | `src/talos/` | R1 |
| `talos/config.py` → class `TalosConfig` | `core/settings.py` → `TalosSettings` | R1.4, R3.4 |
| `talos/models_schema.py` | `schemas/event_schema.py`, `verdict_schema.py`, `report_schema.py` | R1.4, R6 |
| `talos/mitre.py` | `knowledge/mitre_mapping.py` (+ new `owasp_mapping.py`) | R1.4, R3.1 |
| `domains/base.py` | `core/agent_contracts.py` | R3.2 (`base.py` banned + non-unique) |
| `ingestion/base_parser.py` | `ingestion/parser_contract.py` | R3.1 |
| `ingestion/web_log_parser.py` | `ingestion/parsers/web_log_parser.py` | R2 |
| `orchestrator/orchestrator.py` → `Orchestrator` | `orchestrator/event_orchestrator.py` → `EventOrchestrator` | R3.3 |
| `orchestrator/registry.py` → `Registry` | `orchestrator/agent_registry.py` → `AgentRegistry` | R3.1, R3.4 |
| `orchestrator/aggregator.py` | `orchestrator/verdict_aggregator.py` → `VerdictAggregator` | R3.1 |
| `detection/rate_engine.py` | `detection/rate/rate_engine.py` | R2 |
| `detection/baseline.py` | `detection/baseline/access_baseline.py` | R3.1 |
| `llm/routing.py` | `llm/model_router.py` | R3.1 |
| `storage/event_window.py` → `EventWindow` | `storage/event_window_store.py` → `EventWindowStore` | R3.1, R3.4 |
| `storage/verdict_log.py` → `VerdictLog` | `storage/verdict_log_store.py` → `VerdictLogStore` | R3.1, R3.4 |
| `output/api.py` | `output/api/api_server.py` + `report_routes.py` | R2, R6 |
| `output/sinks.py` | `output/sinks/json_file_sink.py`, `stdout_sink.py` | R3.1 |
| *(no CLI module)* | `cli/main_cli.py` | R1.3 — no root launcher |
| *(inline prompt strings)* | `llm/prompts/*_v<N>.md` | R2.3, R3.7 |

**Two consistency fixes made while realigning** — these were genuine internal contradictions in Rev 1.0, not just renames:

1. **`sqli_detector` → `sql_injection_detector`.** Rev 1.0's §7.1 set `detector: "sql_injection_detector"` and §8.2 keyed routing on `sql_injection_detector`, while §1 named the file `sqli_detector.py`. The long form is now used for the module, the class (`SqlInjectionDetector`), the `detector_name`, the routing key, and the pattern module — one string, greppable everywhere.
2. **`idor/` → `broken_access_control/`.** Rev 1.0's §6 classifier emitted category `broken_access_control` but §1 named the package `idor/`, so the sub-agent's `category` could not equal both. The package and `category` are now `broken_access_control`; `technique` stays `"idor"`. §6 now states the classifier-output ↔ category ↔ package-name equality as an explicit contract.

Also renamed: routing key `access_pattern_baseliner` → `access_baseliner` (matches its module).

### 16.2 Revision 1.2 — contracts made executable, P1 (2026-08-17)

Rev 1.1's contracts were illustrative. P1 turned §2, §3, and §10 into shipped code
(`schemas/`, `core/`, `knowledge/`, `config/`); the deltas below are what the implementation
learned, recorded here so the code and this document do not drift.

| Change | Where | Why |
|---|---|---|
| The four agent methods are `async def` | §3 | §4.2 already wrote `await agent.process(...)` and §12 requires detector calls to be awaited concurrently, while §3 showed plain `def`. An internal contradiction, resolved toward the concurrent form: statistical detectors just never await. |
| `TypeClassifier.classify` takes `ctx` | §3, §6 | §6's `self._model_refine` implied a privately held model client, bypassing the context every other component receives. The classifier needs `ctx.model_client` and `ctx.settings.classifier.min_confidence_floor`; one delivery mechanism, not two. |
| `DetectionContext` services typed as `Protocol`s | §3 | Contracts freeze in P1, but `EventWindowStore` (P2), `ModelClient` (P3), and `BaselineStore` (P6) do not exist yet. `EventWindow`/`BaselineReader`/`ModelCaller`/`VerdictRecorder` are satisfied structurally by the concrete stores and by the in-memory doubles of §14. |
| `EventWindow.query(key: str, within: int)` | §3, §7.3 | §12 lists three key shapes — `(account)`, `(source_ip)`, `(host, account)`. The store takes one composed string key; `RateConfig.key_fn` owns the composition, so the store stays one lookup table rather than three. |
| Contract invariants enforced by the models | §2.2, §2.3 | `Verdict.evidence` and `Verdict.event_ids` are non-empty, `confidence` is bounded `[0, 1]`, `IncidentReport.verdicts` is non-empty. "Fail-safe for reporting" (§11) is a property of the type, not detector discipline; an empty report is unrepresentable, so "nothing fired" can only be expressed as the orchestrator's `None`. |
| Timestamps normalised to UTC in the schema | §2.1 | Sources report naive, local, and offset times in one corpus. Rate detectors compare across them, so normalisation happens once at the contract boundary rather than in every detector. |
| One technique may carry several ATT&CK ids | §2.2, §7.4 | §7.4 maps IDOR to both `T1083` and `T1530`. `knowledge/mitre_mapping.py` maps a technique to an ordered tuple: `Verdict.mitre` carries the primary, `IncidentReport.mitre_techniques` carries all. `credential_stuffing` likewise carries `T1110.004` then `T1110`. |
| `talos.llm` config block; `output.report_dir` | §8.3, §10 | §8.3 specified timeout, retry, fallback penalty, and payload bounding as behaviour but gave them no configuration home, which would have forced module-level literals (standards 2.3). |
| `calibration` shape fixed as `detector -> {parameter: float}` | §9, §10 | §9 left the curve representation open; a concrete shape is needed before P8 can write measured curves into config. |

### 16.3 Revision 1.3 — the walking skeleton, P2 (2026-08-18)

P2 built the thinnest complete path through every layer: parser → window → orchestrator → domain
agent → classifier → sub-agent → detector → aggregator → sinks → CLI, with no LLM anywhere. What
the implementation settled that this document left open:

| Change | Where | Why |
|---|---|---|
| The event window derives its own keys | §12, §7.3 | The orchestrator adds an event before knowing which detector will want it, so the store indexes each event under account, source IP, and host+account, and a detector asks for the slice it reasons about. Keys are namespaced (`account:root`, `ip:…`, `host_account:host\|account`) so a username shaped like an address cannot collide with one. |
| Window TTL is measured in **event time** | §12 | A wall-clock TTL evicts every event of a replayed log on arrival, so replay would detect nothing. The reference point is the newest event held for that key — replay and live tail then behave identically, which the P8 evaluation depends on. |
| The window is bounded per key, not globally | §12 | One noisy source must not be able to evict every other key's history (NFR-7). `storage.event_window_max_events` is per key. |
| `RateConfig.distributed` not implemented | §7.3 | Credential stuffing (P5) is the only consumer; the flag arrives with the detector that reads it rather than sitting unused. |
| Detector failures are contained at **two** levels | §11 | §11 says the domain agent catches a raising detector. The sub-agent now catches per detector as well, so one broken detector does not take its siblings with it; the domain agent's guard remains for a sub-agent that breaks before reaching a detector. |
| The aggregator emits `None` unless some verdict has `attack_detected` | §4.3, §11 | Inconclusive verdicts ride along inside a report another verdict created, but must not create one — otherwise "we looked and found nothing" becomes an incident. |
| **Duplicate suppression in the orchestrator** | §4.2 (new) | A windowed detector re-fires on every event past its threshold, so a 40-attempt burst produced 32 identical incidents. The orchestrator reports an incident when its signature is first seen and again only on escalation — the attack succeeded, or its attempt count grew by `aggregation.escalation_attempt_factor`. Time-based cooldowns were rejected: they behave differently under replay. |
| Severity: category floor, ±1 step | §4.3 | §4.3 called for "a function of max confidence, succeeded, and category weight" without fixing one. Implemented as a per-category floor, one step up on success, one step down below 0.5 confidence. |
| Aggregate confidence = max + boost per extra detector | §4.3 | Averaging punishes corroboration, which is the opposite of what independent agreement means. |
| New config blocks: `detection.rate_confidence`, `aggregation`, `storage` | §10 | The confidence curve, corroboration boost, suppression policy, and window bounds are all tunables; none may sit in code (standards §2.3). |
| `scripts/apply_migrations.py` owns the `schema_migrations` ledger | §5 (plan) | Stores never issue DDL; a missing table raises `StorageError` naming the runner. The ledger table is the one `CREATE` outside `db/`, and it exists to record what ran from `db/`. |

---
*End of LLD.*
