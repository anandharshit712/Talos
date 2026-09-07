# Design — Pipeline-Trace Demo

## One computation, two faces

`build_trace()` in `demo_trace_engine.py` runs a log through the **real** orchestrator and records,
per event, the verdicts (with evidence and confidence) and the incident they aggregated into. It
returns a plain dataclass `Trace` that `to_dict()` serialises.

Both faces of the demo read that one structure: `talos demo` renders it to a terminal, and the P9
trace-visualiser serves `to_dict()` as JSON to a browser. Neither owns the reasoning — the engine
does — so a terminal run and a browser run can never disagree.

## Why the pipeline is instrumented, not re-implemented

The orchestrator returns only the aggregated incident; the per-event verdicts — the middle of the
reasoning the demo exists to show — are visible only as they leave the domain agent. So each agent
is wrapped by a recorder that keeps the last event's verdicts, exactly as the P8 metrics harness
does. The real `EventOrchestrator` still runs; nothing about detection is re-created for the demo.

## Offline by construction

`build_trace` forces the model off. A demo that depends on a reachable endpoint is a demo that
fails in the room, and detection is statistical regardless — the model only words the narrative.
