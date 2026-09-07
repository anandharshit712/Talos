# Changelog — Pipeline-Trace Demo

## 2026-09-07 — the demo script (P9)

- Added `demo_trace_engine.py`: runs a log through the real instrumented pipeline and returns a
  serialisable `Trace` of the reasoning — verdicts, evidence, confidence, aggregated incident.
- Added the `talos demo` subcommand: renders the trace to a terminal, `--json` for the UI.
- Added the two prepared chains under `docs/submission/`.
- The trace-visualiser (web UI) is next; it consumes `Trace.to_dict()` unchanged.
