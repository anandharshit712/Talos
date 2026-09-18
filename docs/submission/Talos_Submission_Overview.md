# Talos — submission overview

**An open-source multi-agent system for attack detection, classification, and scope analysis.**

Most detection tooling answers *"did something bad happen?"* with a score. Talos answers three
questions and shows its work for each:

1. **Detection** — is this an attack?
2. **Classification** — which technique, mapped to MITRE ATT&CK and OWASP?
3. **Scope** — *what exactly was affected*, and did it succeed?

The third decides an analyst's next hour, and it is the one most tools leave out.

---

## See it in 60 seconds

```bash
python -m pip install -e ".[dev]"
talos demo
```

No database, no API key, no network, no container. `talos demo` runs two prepared attack chains
through the **real** pipeline and prints what every stage decided.

```
  event 1: GET /products -> 200   [203.0.113.50]
    -> sql_injection_detector: sql_injection (confidence 0.95)
        evidence: tautology/quoted_boolean_equality in query.id: ' OR '1'='1
    *** INCIDENT injection / critical (confidence 0.95, MITRE T1190)
        sql_injection on /products over 1 attempts -- succeeded (confidence 0.95)
        scope: endpoints=['/products']
  ...
  event 17: POST /login -> 302   [203.0.113.50]
    -> brute_force_detector: brute_force (confidence 0.90)
        evidence: 12 rejected HTTP logins for admin within 120s (threshold 10), from 1 source IP(s)
    *** INCIDENT auth_failure / high (confidence 0.90, MITRE T1110)
        brute_force on /login against admin over 12 attempts -- succeeded (confidence 0.90)
        scope: accounts=['admin'], endpoints=['/login']
```

That output — not the verdict, the **reasoning** — is the project's claim. A WAF prints "blocked".

**The same trace in a browser, with the log editable**, so you can add your own payload and watch
which detector claims it and on what evidence:

```bash
cd ui && npm install && npm run build && cd ..
talos serve            # http://127.0.0.1:8000/ui   (OpenAPI at /docs)
```

The page and the terminal call one function, so neither can show you a pipeline the other did not
run.

---

## What was measured, and how

Every number below is measured with **the model off**, over **459 events across 16 logs** (11
attack, 5 benign). Full method and caveats:
[`docs/operations/Talos_Evaluation_Results.md`](../operations/Talos_Evaluation_Results.md).

| Detector | Precision | Recall | Corpus |
|---|---|---|---|
| SQL injection | **1.00** | **0.89** | captured + hand-built |
| XSS | **1.00** | **0.98** | captured + hand-built |
| Web brute force | **1.00** | **1.00** | captured |
| SSH / RDP brute force | **1.00** | **1.00** | synthetic |
| Credential stuffing | **1.00** | **1.00** | captured + synthetic |
| IDOR | **1.00** | **1.00** | captured + synthetic |

**Zero false positives** across every benign corpus, and separately across 400 lines of real
internet scanner traffic taken off a production host. Latency, model off: **p50 0.11 ms, p95
0.79 ms** per event.

The word *captured* is doing work there. Real attack strings were fired through a live nginx over
a real HTTP round-trip and frozen from its access log, so the detectors meet URL-encodings and a
request line they did not author. That distinction cost us: the hand-built SQL injection fixture
scored a perfect 1.00, and the captured corpus scored **0.65** — a corpus grading its own author.
Closing that honestly is what took recall to 0.89. The five residual misses are documented rather
than papered over.

---

## How it works

```
log line -> Parser -> NormalizedEvent
                          |
              Orchestrator  (routes by domain only)
                          |
              Domain Agent  (web | network)
                          |
             Type Classifier  (which attack category?)
                          |
          Attack-Type Sub-Agent  (injection | auth_failure | ...)
                          |
              Child Detectors  -> Verdict (confidence + evidence + scope)
                          |
             Verdict Aggregator -> IncidentReport (JSON)
```

Each level knows less about attacks than the level below it. Adding an attack type means
implementing two interfaces and adding config; the orchestrator is never edited.

Two commitments shape everything:

- **Deterministic first, model second.** A regex/statistical layer makes the primary decision. An
  LLM is consulted only on genuinely borderline payloads, and only to render reasoning. Every
  detector works with the model unreachable — `used_llm=false` is a supported mode, not a
  degraded one, and the demo above runs in it deliberately.
- **Every verdict carries its evidence.** Matched pattern, statistic, or baseline deviation, with
  the event ids behind it. A confidence figure without evidence is not shippable output.

---

## What is deliberately not here

Stating the limits is part of the submission; a reviewer will find them anyway.

- **Two domains only — web and network.** A scope limit on *breadth*, not on build quality:
  storage, concurrency, error handling and security posture inside those two are built to deploy.
- **No Docker or Kubernetes this cycle.** The development machine cannot carry them, so everything
  installs and runs natively. This constrains packaging, not architecture.
- **SSH/RDP corpora are synthetic.** Capturing them needs a live sshd and a brute-force tool.
  The trigger to fix it is recorded rather than quietly ignored.
- **The confidence curve is empty on purpose.** The statistical path produces zero wrong verdicts
  in-distribution, so a correction curve would have nothing to correct. Fabricating one from
  out-of-distribution data would mis-tune a detector that is already right. Documented, with the
  one overconfident regime named and pinned by a test.
- **No authentication on the API.** It binds loopback and says so when told to bind anything else.

---

## Where to look

| To see | Read |
|---|---|
| The reasoning, live | `talos demo`, then `/ui` |
| How it is built | [Talos_HLD.md](../architecture/Talos_HLD.md), [Talos_LLD.md](../architecture/Talos_LLD.md) |
| Why it is built that way | [the problem statement](Talos_Problem_Statement_and_Solution_Document.md) |
| What the numbers mean | [Talos_Evaluation_Results.md](../operations/Talos_Evaluation_Results.md) |
| What is actually finished | [Talos_Build_Tracker.md](../planning/Talos_Build_Tracker.md) |
| The rules the repo enforces on itself | [Talos_Engineering_Standards.md](../standards/Talos_Engineering_Standards.md) |

The repository enforces its own structure: `python tools/checks/run_all_checks.py` fails the build
on an undocumented directory, a filename that does not say what it does, or a module over 1,500
lines. `make check` runs that plus lint, types and 796 tests.
