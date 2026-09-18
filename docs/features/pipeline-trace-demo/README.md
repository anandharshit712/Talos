# Feature — Pipeline-Trace Demo

**Status:** stable
**Code:** `src/talos/output/demo_trace_engine.py`, `src/talos/cli/main_cli.py` (`talos demo`),
`src/talos/output/api/trace_routes.py`, `ui/` (the browser face)
**Data:** `docs/submission/demo_web_chain.log`, `docs/submission/demo_network_chain.log`

The P9 differentiator. A WAF prints "blocked"; Talos shows *why*. `talos demo` runs two prepared
attack chains through the real pipeline and prints the annotated trace — for every event, what it
was routed to, the evidence a detector found, its confidence, and the incident it aggregated into.

Two chains, one per domain:

- **Web** — SQL injection (four pattern classes), then the same actor pivots to a login brute force
  that lands. Two detectors, three incidents, the classifier routing each event.
- **Network** — an SSH brute force that escalates from medium to high the moment it succeeds.

The model is off: the demo cannot depend on a free-tier endpoint, and detection is statistical
anyway.

**Two faces, one computation.** `talos demo` renders the trace to a terminal; the trace
visualiser at `http://127.0.0.1:8000/ui` renders the same `Trace` in a browser, where a log can
be edited and re-run against the live pipeline. Both call `demo_trace_engine.trace_for`, so a
difference between them could only ever be a rendering difference -- neither can reach a
different pipeline. The page is built with `cd ui && npm install && npm run build`; without that
build `talos serve` still runs and `/ui` says how to produce it.

| Document | For |
|---|---|
| [design.md](design.md) | why the trace is computed once and shared by both faces |
| [behaviour.md](behaviour.md) | what each chain shows, and the trace structure |
| [testing.md](testing.md) | how the trace is pinned |
| [changelog.md](changelog.md) | history |
