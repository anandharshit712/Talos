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

**Pre-alpha, under active development.** Hackathon slice: Web + Network domains, 8 leaf
detectors. See the [implementation plan](docs/planning/Talos_Implementation_Plan.md) for what
exists and what is scheduled.

## Quickstart

```bash
git clone https://github.com/anandharshit712/Talos.git
cd Talos
python -m pip install -e ".[dev]"
pre-commit install

cp .env.example .env        # add your NIM API key, or leave it blank to run statistics-only
```

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
