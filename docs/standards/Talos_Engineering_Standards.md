# Talos — Engineering Standards

**Project:** Talos — Open-Source Multi-Agent System for Attack Detection, Classification, and Scope Analysis
**Document type:** Engineering Standards (repository structure, naming, documentation, file size)
**Status:** Authoritative — binding on all code, docs, and data committed to this repository
**Companion documents:** `Talos_HLD.md`, `Talos_LLD.md`, `Talos_DFD.md`
**Applies from:** first commit of implementation code

---

## 0. Scope and Authority

This document defines **six binding rules** (R1–R6) plus their enforcement. Every rule has a stable ID so
review comments, CI failures, and commit messages can cite it directly (e.g. "blocked by R6").

| ID | Rule | Hard failure condition |
|----|------|------------------------|
| **R1** | No loose code files in the repository root | any source file at root |
| **R2** | Every file lives in a component-based folder | file in a directory not defined in §2 |
| **R3** | Every file is named for the work it does | vague or duplicate module name |
| **R4** | All SQL and migration filenames end with a date-time stamp | missing/malformed stamp |
| **R5** | Every feature has its own doc folder under `docs/features/` | feature merged without doc folder |
| **R6** | Files target ≤ 1,000 LOC, hard cap 1,500 LOC | any file > 1,500 lines |

**Precedence:** where this document and the LLD disagree, this document wins on *structure, naming, and
file size*; the LLD wins on *design, contracts, and algorithms*. §8 lists the LLD paths that must be
adjusted to comply.

**"No exceptions" means no exceptions.** R6's hard cap is not waivable by review, deadline, or
convenience. The only files outside its reach are the explicitly non-hand-written categories in §6.4.

---

## 1. Rule R1 — No Loose Code Files in the Root

The repository root is a **manifest and configuration surface only**. It contains no importable code, no
scripts, and no data.

### 1.1 Root allowlist (exhaustive)

Nothing may exist at the repository root unless it appears below.

**Files**
```
README.md                  project entry point, points into docs/
CLAUDE.md                  agent-facing operating rules (cites this document)
LICENSE                    open-source license
CHANGELOG.md               release-level changes
pyproject.toml             package metadata, deps, tool config, console entry points
uv.lock                    resolved dependency lock (or requirements.lock)
Makefile                   task entry points (make setup / test / check / run)
.env.example               documented env var template — never a real .env
.gitignore  .gitattributes  .dockerignore
.pre-commit-config.yaml    hook wiring for the §7 checks
```

**Directories**
```
src/        all first-party importable code
tests/      all test code, fixtures, and expected outputs
docs/       all documentation
db/         all SQL: schema, migrations, seeds, queries
config/     runtime configuration files (YAML), non-secret
data/       sample and reference data (committed, small, non-secret)
deploy/      containerization and deployment manifests
scripts/     operator-facing runnable scripts
tools/       repo tooling (the R1–R6 checkers live here)
.github/     CI workflows
.claude/     agent settings for this workspace
```

### 1.2 Explicitly forbidden at root

`main.py`, `app.py`, `run.py`, `server.py`, `test.py`, `utils.py`, `setup.py`, `orchestrator.py`,
any `*.sql`, any `*.log`, any `*.json` data file, any notebook, any scratch or temp file.

### 1.3 Where the entry point goes instead

Talos is invoked through a console script declared in `pyproject.toml`, backed by code under
`src/talos/cli/`. There is never a root-level launcher.

```toml
[project.scripts]
talos = "talos.cli.main_cli:main"          # src/talos/cli/main_cli.py
talos-api = "talos.output.api.api_server:run"
```

### 1.4 The rule recurses one level

The package root `src/talos/` is also kept clean: it holds **only** `__init__.py` (and `py.typed`).
Configuration, schemas, constants, and base classes go into subpackages — see §2.2 and §8.

---

## 2. Rule R2 — Component-Based Directory Taxonomy

Folders are organised by **the component or concern the code serves**, mirroring the HLD/LLD architecture
(Orchestrator → Domain Agents → Type Classifiers → Attack-Type Sub-Agents → Child Detectors). Folders are
never organised by file type (no `classes/`, `functions/`, `interfaces/`) and never by author or date.

### 2.1 Full repository tree

```
Talos/
├── README.md
├── CLAUDE.md
├── pyproject.toml
├── Makefile
├── .env.example
│
├── config/
│   ├── default.yaml                  base runtime config
│   ├── local.yaml.example            developer overrides template
│   ├── model_routing.yaml            agent -> model map (see LLD §llm/routing)
│   └── thresholds.yaml               detector thresholds, externalised from code
│
├── data/
│   ├── samples/                      small sample logs for demos
│   └── reference/                    MITRE/OWASP reference tables (CSV/JSON)
│
├── db/
│   ├── schema/                       current-state schema snapshots
│   ├── migrations/                   forward migrations (see R4)
│   │   └── rollback/                 matching down-migrations
│   ├── seeds/                        seed data scripts
│   └── queries/                      reusable / ad-hoc analysis queries
│
├── deploy/
│   ├── docker/                       Dockerfiles
│   └── compose/                      docker-compose stacks
│
├── docs/
│   ├── architecture/                 HLD, LLD, DFD, diagrams
│   ├── features/                     one subfolder per feature (see R5)
│   ├── standards/                    this document and other conventions
│   ├── planning/                     build plans, phase breakdowns, milestone tracking
│   ├── operations/                   run, deploy, configure, troubleshoot
│   ├── research/                     competitive/threat research, sources
│   └── submission/                   hackathon deliverables
│
├── scripts/
│   ├── generate_sample_logs.py
│   ├── replay_log_file.py
│   └── run_local_stack.ps1
│
├── src/
│   └── talos/
│       ├── __init__.py
│       ├── py.typed
│       ├── core/                     cross-cutting foundations
│       │   ├── settings.py           Pydantic Settings loader + validation
│       │   ├── agent_contracts.py    DomainAgent / TypeClassifier / SubAgent / Detector ABCs
│       │   ├── error_types.py        exception hierarchy
│       │   ├── logging_setup.py      structured logging config
│       │   └── constants.py          non-domain constants only
│       ├── schemas/                  Pydantic data contracts, one group per file
│       │   ├── event_schema.py       NormalizedEvent + Actor/Target/WebRequest/AuthEvent
│       │   ├── verdict_schema.py     Verdict + Evidence + MitreMapping
│       │   └── report_schema.py      IncidentReport + scope/pipeline subtypes
│       ├── ingestion/
│       │   ├── parser_contract.py    BaseParser ABC
│       │   └── parsers/
│       │       ├── web_log_parser.py
│       │       └── network_log_parser.py
│       ├── orchestrator/
│       │   ├── event_orchestrator.py routing + pipeline tracking
│       │   ├── agent_registry.py     domain-agent / sub-agent registry
│       │   └── verdict_aggregator.py Verdict -> IncidentReport
│       ├── domains/
│       │   ├── web/
│       │   │   ├── web_domain_agent.py
│       │   │   ├── web_type_classifier.py
│       │   │   ├── injection/
│       │   │   │   ├── injection_sub_agent.py
│       │   │   │   ├── sql_injection_detector.py
│       │   │   │   └── xss_detector.py
│       │   │   ├── auth_failure/
│       │   │   │   ├── auth_failure_sub_agent.py
│       │   │   │   ├── brute_force_detector.py
│       │   │   │   └── credential_stuffing_detector.py
│       │   │   └── broken_access_control/
│       │   │       ├── broken_access_control_sub_agent.py
│       │   │       ├── access_baseliner.py
│       │   │       └── deviation_scorer.py
│       │   └── network/
│       │       ├── network_domain_agent.py
│       │       ├── network_type_classifier.py
│       │       └── brute_force/
│       │           ├── network_brute_force_sub_agent.py
│       │           ├── ssh_brute_force_detector.py
│       │           └── rdp_brute_force_detector.py
│       ├── detection/                shared, domain-agnostic detection cores
│       │   ├── rate/
│       │   │   └── rate_engine.py
│       │   ├── patterns/
│       │   │   ├── sql_injection_pattern_rules.py
│       │   │   └── xss_pattern_rules.py
│       │   └── baseline/
│       │       └── access_baseline.py
│       ├── llm/
│       │   ├── model_client.py       NIM / vLLM / Ollama abstraction
│       │   ├── model_router.py       agent -> model resolution
│       │   └── prompts/              versioned prompt templates
│       ├── knowledge/
│       │   ├── mitre_mapping.py      technique ids + tactic mapping
│       │   └── owasp_mapping.py
│       ├── storage/
│       │   ├── event_window_store.py rolling TTL buffer
│       │   ├── baseline_store.py     persistent per-user baselines
│       │   └── verdict_log_store.py  audit trail
│       ├── output/
│       │   ├── api/
│       │   │   ├── api_server.py     FastAPI app factory
│       │   │   └── report_routes.py  submit events / fetch reports
│       │   └── sinks/
│       │       ├── json_file_sink.py
│       │       └── stdout_sink.py
│       └── cli/
│           └── main_cli.py
│
├── tests/
│   ├── unit/                         mirrors src/talos/ tree exactly
│   ├── integration/                  multi-component, real wiring
│   ├── e2e/                          log file in -> IncidentReport out
│   ├── support/                      test doubles shared across suites (stub ModelClient)
│   └── fixtures/
│       ├── logs/                     input log samples
│       └── expected/                 expected JSON outputs
│
├── tools/
│   └── checks/
│       ├── violation_types.py        shared Violation type, traversal, reporting
│       ├── check_structure.py        enforces R1 + R2
│       ├── check_naming.py           enforces R3 + R4
│       ├── check_file_size.py        enforces R6
│       ├── check_feature_docs.py     enforces R5
│       └── run_all_checks.py         single entry point for make / pre-commit / CI
│
├── .github/
│   └── workflows/                    CI: runs the checkers, lint, types, tests
│
└── .claude/                          agent settings for this workspace
```

### 2.2 Placement decision order

When adding a file, walk this list top-down and stop at the first match:

1. **Is it a data contract?** → `src/talos/schemas/`
2. **Is it a cross-cutting foundation** (settings, ABCs, errors, logging)? → `src/talos/core/`
3. **Does it belong to exactly one attack type?** → `src/talos/domains/<domain>/<attack_type>/`
4. **Does it belong to exactly one domain but span its attack types?** → `src/talos/domains/<domain>/`
5. **Is the logic shared across domains?** → `src/talos/detection/<concern>/`
6. **Is it infrastructure** (LLM, storage, output, ingestion)? → the matching top-level subpackage
7. **Is it security-framework reference data?** → `src/talos/knowledge/`
8. Otherwise it is not code — see §2.3.

### 2.3 Non-code placement

| Content | Location |
|---|---|
| Tunable numbers (thresholds, windows, limits) | `config/thresholds.yaml` — **not** hardcoded in detectors |
| Prompt text | `src/talos/llm/prompts/` — never inline string literals over 10 lines |
| Sample logs for demo | `data/samples/` |
| Sample logs for tests | `tests/fixtures/logs/` |
| MITRE/OWASP lookup tables | `data/reference/` (data) + `src/talos/knowledge/` (accessors) |
| Any SQL | `db/` only — never inside `src/` |

### 2.4 Adding a new subfolder

A new directory requires: (a) a one-line purpose entry added to §2.1 of this document in the same
commit, and (b) an `__init__.py` if it sits under `src/`. Undocumented directories fail R2.

---

## 3. Rule R3 — File Naming

**Principle:** a filename states *what work the file does*, readable without opening it and without its
parent path for context.

### 3.1 Python modules

Format: `snake_case`, ASCII, `<subject>_<role>.py`

The `<role>` suffix comes from this **closed vocabulary**, matching the architecture's roles:

| Suffix | Responsibility |
|---|---|
| `_parser` | raw telemetry → `NormalizedEvent` |
| `_orchestrator` | routing and pipeline control |
| `_registry` | component discovery / registration |
| `_domain_agent` | domain-level agent |
| `_type_classifier` | attack-type routing within a domain |
| `_sub_agent` | attack-type sub-agent |
| `_detector` | leaf detector emitting a `Verdict` |
| `_engine` | reusable computational core |
| `_rules` | pattern / rule tables |
| `_baseliner`, `_scorer` | baseline construction, deviation scoring |
| `_store` | persistence |
| `_client` | outbound integration |
| `_router` | resolution/dispatch (e.g. model routing) |
| `_server`, `_routes` | HTTP app factory, endpoint groups |
| `_sink` | output destination |
| `_schema` | Pydantic contract group |
| `_mapping` | framework/reference mapping |
| `_contract`, `_contracts` | abstract base classes / protocols |
| `_setup`, `_types`, `_cli` | wiring, type declarations, CLI surface |

A file whose work fits no suffix above is a signal the work isn't yet understood — name it after the
concrete noun+verb of what it does, and propose a suffix addition in the same PR.

### 3.2 Banned filenames

These are rejected anywhere in the repo, in any language:

```
utils.py  util.py  helpers.py  helper.py  common.py  shared.py  misc.py
base.py   core.py  main.py (outside cli/)   app.py    stuff.py   temp.py
data.py   handler.py  manager.py  processor.py  service.py (bare)
new_*.py  old_*.py  *_v2.py  *_final.py  *_copy.py  *_backup.py  *_test2.py
```

Rationale: each names a *container*, not a *job*. `manager`/`handler`/`processor` describe no boundary —
say what is managed and how (`event_window_store`, `report_routes`). Superseded code is deleted, not
renamed with a version suffix; git holds the history.

### 3.3 Uniqueness

**Every module basename is unique across the whole repository.** No two `base.py`, no two
`detector.py`. This keeps tracebacks, import lines, and grep results unambiguous. Where a name would
collide, the domain or component qualifies it — `web_domain_agent.py` vs `network_domain_agent.py`,
`ssh_brute_force_detector.py` vs `rdp_brute_force_detector.py`.

Exempt from uniqueness: `__init__.py`, `__main__.py`, `py.typed`, `conftest.py`, `README.md`.

### 3.4 In-file identifiers

| Kind | Convention | Example |
|---|---|---|
| Class | `PascalCase`, matches file's subject+role | `SqlInjectionDetector` in `sql_injection_detector.py` |
| Function / method | `snake_case`, verb-first | `detect_injection()`, `build_verdict()` |
| Constant | `UPPER_SNAKE_CASE` | `DEFAULT_WINDOW_SECONDS` |
| Private | leading underscore | `_normalise_path()` |
| Pydantic model | `PascalCase` noun, no `Model` suffix | `NormalizedEvent`, not `EventModel` |

One primary public class per module. A module exporting three unrelated classes is a §6.5 split candidate.

**Exception for `_contract`/`_contracts` modules.** These hold abstract base classes, whose established
names are role words without the file's subject (`BaseParser` in `parser_contract.py`; `Detector`,
`DomainAgent`, `TypeClassifier`, `AttackTypeSubAgent` in `agent_contracts.py`). The subject+role match is
waived for ABCs — mangling them into `ParserContract` would obscure the contract, not clarify it.
Concrete implementations still follow the rule strictly (`WebLogParser` in `web_log_parser.py`).

### 3.5 Tests

`tests/unit/` mirrors `src/talos/` path-for-path; the test file is `test_<module_basename>.py`.

```
src/talos/domains/web/injection/sql_injection_detector.py
tests/unit/domains/web/injection/test_sql_injection_detector.py
```

Integration and e2e tests are named for the scenario, not the module:
`test_web_sql_injection_end_to_end.py`, `test_ssh_brute_force_pipeline.py`.

### 3.6 Fixtures and sample data

Format: `<domain>_<scenario>_<source>.<ext>`

```
tests/fixtures/logs/web_sql_injection_union_select_waf.log
tests/fixtures/logs/network_ssh_brute_force_sshd.log
tests/fixtures/expected/web_sql_injection_union_select_report.json
```

### 3.7 Prompts

Prompts are versioned artifacts — behaviour changes must be traceable.

Format: `<agent_or_detector>_<purpose>_v<N>.md`

```
src/talos/llm/prompts/web_type_classifier_route_v1.md
src/talos/llm/prompts/deviation_scorer_judge_v2.md
```

Bump `v<N>` on any semantic change; keep the prior version until nothing references it.

### 3.8 Configuration, scripts, docs, diagrams

| Kind | Format | Example |
|---|---|---|
| Config | `<environment-or-purpose>.yaml` | `default.yaml`, `model_routing.yaml` |
| Script | `<verb>_<object>.<ext>` | `generate_sample_logs.py`, `run_local_stack.ps1` |
| Doc (architecture/standards/ops) | `Talos_<Subject_In_Title_Case>.md` | `Talos_Engineering_Standards.md` |
| Doc (inside a feature folder) | fixed kebab-case names per §5.2 | `detection-logic.md` |
| Diagram | `Talos_<Subject>_Diagram.<svg\|png>` | `Talos_Architecture_Diagram.svg` |

Spaces, `#`, `%`, `&`, and uppercase file extensions are never used in filenames — they break shell
pipelines, URLs, and Windows/Linux portability.

---

## 4. Rule R4 — SQL and Migration Naming

**Every `.sql` file in this repository ends with a date-time stamp, immediately before the extension.
No `.sql` file is exempt.**

### 4.1 Stamp format

```
YYYYMMDD_HHMMSS        UTC, 24-hour, zero-padded
```

Example: `20260817_143052` = 2026-08-17 14:30:52 UTC.

UTC removes ambiguity across machines. The `_` separator and absence of `:` keep the name valid on
Windows and safe in URLs. The format sorts lexicographically in true chronological order.

### 4.2 General SQL filename format

```
<action>_<subject>_<YYYYMMDD_HHMMSS>.sql
```

`<action>` comes from a closed vocabulary: `create`, `alter`, `drop`, `add`, `remove`, `rename`,
`index`, `backfill`, `seed`, `select`, `snapshot`.

```
db/schema/snapshot_full_schema_20260817_143052.sql
db/seeds/seed_mitre_techniques_20260818_090500.sql
db/queries/select_top_attacking_ips_20260819_161240.sql
```

### 4.3 Migrations

Migrations live in `db/migrations/` and use the same format. **The timestamp is the ordering key** —
there is no separate numeric sequence prefix, because two ordering keys can disagree and one cannot.

```
db/migrations/create_verdict_log_table_20260818_101500.sql
db/migrations/add_baseline_confidence_column_20260819_093015.sql
db/migrations/index_verdict_log_by_source_ip_20260820_154500.sql
```

**Rollbacks** live in `db/migrations/rollback/` under the **identical filename** as the forward
migration. This keeps the date-time last (R4) while making the pair unmistakable.

```
db/migrations/create_verdict_log_table_20260818_101500.sql
db/migrations/rollback/create_verdict_log_table_20260818_101500.sql
```

A migration with no safe rollback still requires the rollback file, containing only a comment stating
why it is irreversible.

### 4.4 Migration rules

1. **Forward-only history.** An applied migration is never edited or renamed. Corrections ship as a new
   migration with a new timestamp.
2. **Timestamp = authoring time**, generated at creation. On collision, increment by one second.
3. **One logical change per migration.** Table creation and a backfill are two files.
4. **Required header block** at the top of every migration:

```sql
-- Migration: create_verdict_log_table
-- Created:   2026-08-18 10:15:00 UTC
-- Feature:   docs/features/verdict-audit-trail/
-- Purpose:   Persistent audit trail of detector verdicts for report replay.
-- Reversible: yes -> db/migrations/rollback/create_verdict_log_table_20260818_101500.sql
```

5. **No DDL in application code.** `src/` never issues `CREATE`/`ALTER`; schema changes only via `db/`.
6. **No secrets or environment-specific literals** in any `.sql` file.

---

## 5. Rule R5 — Per-Feature Documentation

**Every feature ships with its own documentation folder. A feature without its doc folder is
incomplete and is not merged.** "Feature" = any user-visible or architecturally distinct capability:
a detector, a sub-agent, a parser, an output sink, the API surface, the CLI.

### 5.1 Location and slug

```
docs/features/<feature-slug>/
```

`<feature-slug>` is kebab-case and matches the code component it documents, so the mapping is
mechanical:

| Code | Feature folder |
|---|---|
| `domains/web/injection/sql_injection_detector.py` | `docs/features/web-sql-injection-detection/` |
| `domains/web/broken_access_control/` | `docs/features/web-broken-access-control/` |
| `domains/network/brute_force/` | `docs/features/network-brute-force-detection/` |
| `ingestion/parsers/web_log_parser.py` | `docs/features/web-log-ingestion/` |
| `output/api/` | `docs/features/report-api/` |

Nested subfolders are used when a feature has distinct sub-capabilities:

```
docs/features/web-injection-detection/
├── README.md
├── design.md
├── detection-logic.md
├── testing.md
├── changelog.md
├── assets/
│   └── injection-flow-diagram.svg
└── sub-features/
    ├── sql-injection/
    │   ├── detection-logic.md
    │   └── testing.md
    └── xss/
        ├── detection-logic.md
        └── testing.md
```

### 5.2 Required files

| File | Contents |
|---|---|
| `README.md` | one-paragraph summary; **status**; owner; code paths; links to the other files |
| `design.md` | approach, data contracts consumed/emitted, agent/detector position in the pipeline, alternatives considered and rejected |
| `detection-logic.md` | *(detection features)* signals used, thresholds and where they are configured, scoring/confidence maths, MITRE technique + OWASP category mapping, known false-positive and false-negative modes |
| `testing.md` | fixtures used, cases covered, how to run them, latest observed results |
| `changelog.md` | reverse-chronological dated entries: `## 2026-08-18 — <what changed and why>` |
| `assets/` | *(optional)* diagrams and screenshots referenced by the above |

Non-detection features (parsers, sinks, API, CLI) replace `detection-logic.md` with `behaviour.md`
documenting inputs, outputs, error handling, and edge cases.

### 5.3 Required `README.md` front block

```markdown
# Feature — Web SQL Injection Detection

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/domains/web/injection/sql_injection_detector.py`, `src/talos/detection/patterns/sql_injection_pattern_rules.py`
**Config:** `config/thresholds.yaml` → `web.injection.sql_injection`
**Tests:** `tests/unit/domains/web/injection/test_sql_injection_detector.py`
**MITRE:** T1190 (Exploit Public-Facing Application) · **OWASP:** A03:2021 Injection
```

**Status vocabulary (closed):** `planned` → `in-progress` → `stable` → `deprecated`.

### 5.4 Lifecycle obligations

- The doc folder is created **in the same commit** that creates the feature's first code file, at
  minimum with `README.md` at status `planned`.
- Status advances to `stable` only when tests pass and `testing.md` records the results.
- Any behaviour change adds a `changelog.md` entry in the same commit.
- Deleting a feature sets status `deprecated` and keeps the folder — the reasoning stays discoverable.
- Cross-feature and system-wide documentation stays in `docs/architecture/`; `docs/features/` never
  duplicates the HLD/LLD, it links to them.

---

## 6. Rule R6 — File Length Limits

| Threshold | Lines | Meaning |
|---|---|---|
| Review trigger | **800** | plan the split now; note it in the PR |
| Target ceiling | **1,000** | no new code added to this file until it is split |
| **Hard cap** | **1,500** | **CI fails. Merge blocked. No exceptions, no waivers.** |

### 6.1 Measurement

LOC = **physical lines in the file**, exactly what `wc -l` reports — blank lines, comments, docstrings,
and imports all included. A single unambiguous number that any tool and any reviewer can reproduce.

### 6.2 Checking

```powershell
# Files over the 1,000-line target, worst first
Get-ChildItem -Recurse -Include *.py,*.sql,*.ts,*.tsx,*.js,*.ps1,*.yaml |
  ForEach-Object { [pscustomobject]@{ Lines = @(Get-Content $_.FullName).Count; File = $_.FullName } } |
  Where-Object { $_.Lines -gt 1000 } | Sort-Object Lines -Descending
```

> **Do not use `Measure-Object -Line` for this.** It silently skips blank lines and undercounts by 15–20%
> on typical source files — a 1,700-line file can report as compliant. `@(Get-Content $path).Count` and
> `wc -l` agree; `Measure-Object -Line` does not.

```bash
# equivalent, and the CI gate
make check-size
```

### 6.3 In scope

All hand-written source and test files: `.py`, `.sql`, `.ts`, `.tsx`, `.js`, `.ps1`, `.sh`, and
hand-maintained `.yaml`/`.json` configuration.

### 6.4 Out of scope

Only files that are **not hand-written source**:

- Generated code — must carry a first-line marker: `# GENERATED FILE — DO NOT EDIT (source: <path>)`
- Lockfiles (`uv.lock`, `package-lock.json`)
- Vendored third-party code (isolated under a `vendor/` directory)
- Test data fixtures and reference data (`tests/fixtures/`, `data/`)
- Markdown documentation — uncapped, though ≤ 1,000 lines is the strong recommendation; past that,
  split into a folder with a `README.md` index

This list is exhaustive. "It's cohesive", "it's one big table", "it's temporary", and "the deadline is
close" are not exemptions.

### 6.5 How to split — in preference order

1. **Extract by responsibility.** Pull a coherent job into a new module with the right §3.1 role suffix.
   `web_domain_agent.py` too long → move classification out to `web_type_classifier.py`.
2. **Promote a module to a package.** `xss_detector.py` → `xss/` containing
   `xss_detector.py` + `xss_context_analyzer.py` + `xss_confidence_scorer.py`, with `__init__.py`
   re-exporting the public name so imports elsewhere don't change.
3. **Externalise data.** Pattern tables, thresholds, and mappings move to `config/` or `data/` and are
   loaded — long literal tables are configuration wearing a `.py` extension.
4. **Externalise prompts.** Any prompt over ~10 lines moves to `src/talos/llm/prompts/` (§3.7).
5. **Split the test file to mirror the split source**, preserving the §3.5 mirror rule.

Splitting is never done by cutting a file at line 750 into `x_part1.py`/`x_part2.py`. A split that
doesn't produce independently nameable responsibilities means the boundary is wrong — find the real one.

### 6.6 Advisory sub-limits (not CI-enforced)

Guidance, not gates — a file passing R6 while violating these is a design smell worth a review comment:
functions ≤ 60 lines · classes ≤ 300 lines · function parameters ≤ 5 (use a Pydantic model beyond that)
· nesting depth ≤ 4.

---

## 7. Enforcement

Rules that aren't mechanically checked decay. All six are checkable.

### 7.1 Checkers

`tools/checks/` holds one script per concern, each exiting non-zero with the violating paths and the
rule ID:

| Script | Enforces | Checks |
|---|---|---|
| `check_structure.py` | R1, R2 | root allowlist; every path under a §2.1 directory; `src/talos/` holds only `__init__.py`/`py.typed`; no `.sql` under `src/` |
| `check_naming.py` | R3, R4 | snake_case; role-suffix vocabulary; banned-name list; basename uniqueness; test-mirror correspondence; SQL date-time stamp format and position; rollback pairing |
| `check_file_size.py` | R6 | warn > 800, fail > 1,500, report the > 1,000 list |
| `check_feature_docs.py` | R5 | every `docs/features/*/` has the §5.2 required files and a valid status; every new `domains/*/<attack_type>/` has a matching feature folder |

### 7.2 Wiring

```makefile
check: check-structure check-naming check-size check-docs lint test
```

- **pre-commit** runs `check_structure`, `check_naming`, `check_file_size` on staged files.
- **CI** (`.github/workflows/`) runs the full `make check` on every push and PR. R6's hard cap and R4's
  stamp check are **blocking**; nothing merges past them.

### 7.3 PR checklist

Every PR description confirms:

- [ ] No new files at the repository root (R1)
- [ ] Every new file sits in a §2.1 directory, added to §2.1 if the directory is new (R2)
- [ ] Filenames use the role-suffix vocabulary; no banned names; basenames unique (R3)
- [ ] Every new `.sql` ends with `_YYYYMMDD_HHMMSS`; migrations have headers + rollback pairs (R4)
- [ ] Feature doc folder created/updated, including a `changelog.md` entry (R5)
- [ ] No file exceeds 1,000 lines; nothing anywhere near 1,500 (R6)

---

## 8. Required Adjustments to the Current Repository and LLD

The LLD's §1 module layout predated these rules. **Status: applied.** `Talos_LLD.md` revision 1.1
(2026-08-17) adopts every path and identifier below — see its §16 revision record — and the `docs/`
reorganisation in the last three rows is complete. The table is retained as the rationale trail; the
code-side rows describe the layout the implementation now starts from, not pending work.

| LLD / current path | Compliant path | Rule |
|---|---|---|
| `talos/` (repo root package) | `src/talos/` | R1 — src layout keeps code out of root |
| `talos/config.py` | `src/talos/core/settings.py` | R1.4 — package root stays clean |
| `talos/models_schema.py` | `src/talos/schemas/event_schema.py`, `verdict_schema.py`, `report_schema.py` | R1.4, R3.1, R6 — three contract groups, three files |
| `talos/mitre.py` | `src/talos/knowledge/mitre_mapping.py` | R1.4, R3.1 |
| `talos/domains/base.py` | `src/talos/core/agent_contracts.py` | R3.2 — `base.py` is banned and non-unique |
| `talos/ingestion/base_parser.py` | `src/talos/ingestion/parser_contract.py` | R3.1 |
| `talos/orchestrator/orchestrator.py` | `src/talos/orchestrator/event_orchestrator.py` | R3.3 — basename must differ from its package |
| `talos/orchestrator/aggregator.py` | `src/talos/orchestrator/verdict_aggregator.py` | R3.1 |
| `talos/orchestrator/registry.py` | `src/talos/orchestrator/agent_registry.py` | R3.1 |
| `talos/detection/baseline.py` | `src/talos/detection/baseline/access_baseline.py` | R3.1 |
| `talos/llm/routing.py` | `src/talos/llm/model_router.py` | R3.1 |
| `talos/output/api.py` | `src/talos/output/api/api_server.py` + `report_routes.py` | R2, R6 |
| `talos/output/sinks.py` | `src/talos/output/sinks/json_file_sink.py`, `stdout_sink.py` | R3.1 — one sink per file |
| `docs/Talos_HLD.md`, `Talos_LLD.md`, `Talos_DFD.md`, `Talos_Architecture_Diagram.svg`, `Talos_Detailed_Architecture.pdf`, `Talos_Idea_OnePager.pdf` | `docs/architecture/` | R2 |
| `docs/Talos_Problem_Statement_and_Solution_Document.md` | `docs/submission/` | R2 |
| `docs/Talos_Project_Memory_Dump.md` | `docs/research/` | R2 |

Detector, sub-agent, classifier, and store filenames from the LLD already comply and are unchanged.

---

## 9. Quick Reference

```
ROOT           manifests + config only. No code. No SQL. No data.
CODE           src/talos/<component>/...  — grouped by architectural role
NAME           <subject>_<role>.py  — role from the §3.1 closed vocabulary
               unique basename repo-wide; no utils/base/common/helpers/v2/final
SQL            <action>_<subject>_<YYYYMMDD_HHMMSS>.sql   — stamp always last, UTC
MIGRATION      db/migrations/<same format>  + identical filename under rollback/
               forward-only; never edit an applied migration
TESTS          tests/unit/ mirrors src/talos/ ; test_<module>.py
DOCS           docs/features/<feature-slug>/{README,design,detection-logic,testing,changelog}.md
SIZE           800 = plan the split · 1,000 = target ceiling · 1,500 = hard fail, no exceptions
CONFIG         thresholds and prompts live outside code — config/ and llm/prompts/
```

---

**Document control**

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-08-17 | Initial standards: R1 root cleanliness, R2 component taxonomy, R3 naming, R4 SQL/migration date-time stamps, R5 per-feature docs, R6 1,000/1,500 LOC limits, enforcement, LLD deltas |
| 1.1 | 2026-08-17 | Corrected the §6.2 line-count command (`Measure-Object -Line` undercounts by skipping blank lines — replaced with `@(Get-Content).Count`). Added `docs/planning/` to §2.1. Added the §3.4 ABC exception for `_contract` modules. Renamed `sqli_*` → `sql_injection_*` and `idor/` → `broken_access_control/` throughout, matching LLD rev 1.1 §16.1. Marked §8 applied. |
