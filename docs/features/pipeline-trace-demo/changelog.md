# Changelog — Pipeline-Trace Demo

## 2026-09-18 — the trace visualiser (P9)

- Added `GET /trace/chains` and `POST /trace`: the prepared chains with their logs, and any
  submitted log run through the real pipeline, returned as `Trace.to_dict()`.
- Added `ui/`: a React + Tailwind page served by `talos serve` at `/ui`. It opens on the web
  chain already traced, and the log is editable so a reviewer can add a payload and watch which
  detector claims it.
- Moved the chain table, the parser choice and the cold baseline out of `main_cli` into
  `demo_trace_engine` (`DEMO_CHAINS`, `trace_for`). The terminal and the browser now call one
  function; before this the CLI owned wiring the API would have had to copy.
- `POST /trace` bounds what one request can ask for (`output.api.max_trace_log_chars`,
  `max_trace_log_lines`) and runs the pipeline on a worker thread, because `build_trace` owns
  its own event loop and would otherwise both raise and block the server.
- Status: in-progress → **stable**.

## 2026-09-07 — the demo script (P9)

- Added `demo_trace_engine.py`: runs a log through the real instrumented pipeline and returns a
  serialisable `Trace` of the reasoning — verdicts, evidence, confidence, aggregated incident.
- Added the `talos demo` subcommand: renders the trace to a terminal, `--json` for the UI.
- Added the two prepared chains under `docs/submission/`.
- The trace-visualiser (web UI) is next; it consumes `Trace.to_dict()` unchanged.
