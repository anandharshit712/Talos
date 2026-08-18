# Talos

**A multi-agent system for attack detection, classification, and scope analysis.**

Most detection tooling answers *"did something bad happen?"* with a score. Talos answers three
questions, and shows its work for each:

1. **Detection** — is this an attack?
2. **Classification** — which technique, mapped to MITRE ATT&CK and OWASP?
3. **Scope** — *what exactly was affected*, and did the attack succeed?

The third is the one that decides an analyst's next hour, and it is the one most tools leave out.

## How it works

Telemetry is normalised into a single event contract, then routed down a hierarchy where each
level knows less about attacks than the level below it:

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

Two design commitments shape everything:

- **Deterministic first, model second.** A regex/statistical layer makes the primary detection
  decision. An LLM is invoked only for genuinely borderline payloads, and only to render
  reasoning. Every detector works with the model unreachable — `used_llm=false` is a supported
  mode, not a failure mode.
- **Every verdict carries its evidence.** Matched pattern, statistic, or baseline deviation, with
  the event IDs backing it. A confidence figure without evidence is not shippable output.

Adding a new attack type means implementing two interfaces and adding config — the orchestrator
is never edited. See [LLD §13](docs/architecture/Talos_LLD.md) for the worked example.

## Status

**Pre-alpha, under active development.** The current slice covers Web + Network domains and 8
leaf detectors. That is a limit on **breadth, not build quality** — everything inside it is built
to deploy (HLD §1.5). The end-to-end pipeline runs today for SSH brute force; see the
[build tracker](docs/planning/Talos_Build_Tracker.md) for exactly what is finished and the
[implementation plan](docs/planning/Talos_Implementation_Plan.md) for what is scheduled.

## Quickstart

```bash
git clone https://github.com/anandharshit712/Talos.git
cd Talos
python -m pip install -e ".[dev]"
pre-commit install

cp .env.example .env        # add provider keys, or leave them blank to run statistics-only
```

Create the database, then scan a log:

```bash
python scripts/apply_migrations.py --db talos.db
talos scan tests/fixtures/logs/network_ssh_brute_force_sshd.log --db talos.db --pretty
```

Reports go to stdout as JSON and to `out/reports/`; diagnostics and the run summary go to stderr,
so `talos scan file.log | jq` works unfiltered. The fixture above produces two incidents — the
brute-force burst crossing its threshold, then the escalation when a login finally succeeds:

```
brute_force on bastion-01 against root over 8 attempts  -- did not succeed (confidence 0.70)  [medium]
brute_force on bastion-01 against root over 12 attempts -- succeeded      (confidence 0.90)  [high]
```

With no provider key configured, no model is contacted and `used_llm` is false on every verdict.
With keys set, the same run produces the same two incidents with the same severities and counts —
only the narrative changes, written by the routed model, and `used_llm` becomes true. Detection is
statistical; the model words it (LLD §8).

Verify the toolchain:

```bash
make check                  # R1-R6 rule checks, lint, types, tests
```

On Windows without `make`:

```powershell
.\scripts\run_checks.ps1 -Full
```

## Documentation

| Document | Contents |
|---|---|
| [Engineering Standards](docs/standards/Talos_Engineering_Standards.md) | repository rules R1–R6 and their enforcement |
| [Implementation Plan](docs/planning/Talos_Implementation_Plan.md) | phases, gates, cut order |
| [High-Level Design](docs/architecture/Talos_HLD.md) | architecture, model strategy, NFRs |
| [Low-Level Design](docs/architecture/Talos_LLD.md) | module layout, contracts, detector algorithms |
| [Data Flow Diagram](docs/architecture/Talos_DFD.md) | process decomposition, data dictionary |
| [docs/features/](docs/features/) | one folder per feature: design, detection logic, testing |

## Contributing

Every change is subject to R1–R6, enforced by `python tools/checks/run_all_checks.py` in
pre-commit and CI. The two that surprise people:

- **Filenames are checked against a closed role-suffix vocabulary.** `sqli_helper.py` is
  rejected; `sql_injection_detector.py` is not.
- **Files have a 1,500-line hard cap with no waiver.** See
  [standards §6.5](docs/standards/Talos_Engineering_Standards.md) for the split playbook.

New features need their `docs/features/<slug>/` folder in the same commit as their first code
file. `python tools/checks/check_feature_docs.py` will tell you if it is missing.

## License

Not yet chosen — see the `TODO` in `pyproject.toml`. Talos is intended to be open-source.
