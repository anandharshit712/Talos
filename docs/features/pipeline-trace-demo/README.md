# Feature — Pipeline-Trace Demo

**Status:** in-progress
**Code:** `src/talos/output/demo_trace_engine.py`, `src/talos/cli/main_cli.py` (`talos demo`)
**Data:** `docs/submission/demo_web_chain.log`, `docs/submission/demo_network_chain.log`

The P9 differentiator. A WAF prints "blocked"; Talos shows *why*. `talos demo` runs two prepared
attack chains through the real pipeline and prints the annotated trace — for every event, what it
was routed to, the evidence a detector found, its confidence, and the incident it aggregated into.

Two chains, one per domain:

- **Web** — SQL injection (four pattern classes), then the same actor pivots to a login brute force
  that lands. Two detectors, three incidents, the classifier routing each event.
- **Network** — an SSH brute force that escalates from medium to high the moment it succeeds.

The model is off: the demo cannot depend on a free-tier endpoint, and detection is statistical
anyway. `--json` emits the same trace the P9 trace-visualiser (web UI) will render.

| Document | For |
|---|---|
| [design.md](design.md) | why the trace is computed once and shared by both faces |
| [behaviour.md](behaviour.md) | what each chain shows, and the trace structure |
| [testing.md](testing.md) | how the trace is pinned |
| [changelog.md](changelog.md) | history |
