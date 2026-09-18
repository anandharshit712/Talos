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

## The second face: the trace visualiser

`ui/` is a Vite + React + Tailwind page, built to `ui/dist/` and mounted by the FastAPI app at
`/ui`. It calls two routes and holds no detection logic of its own:

- `GET /trace/chains` — the prepared chains with their logs, so the page opens on a real trace
  rather than on an empty form.
- `POST /trace` — a domain and raw log text, back as `Trace.to_dict()`.

Three decisions are worth the words:

**The log on screen is editable, and the page re-runs the real pipeline.** A canned animation
would have been easier to make impressive and would have proved nothing. A reviewer can paste a
payload and watch which detector claims it, on what evidence, at what confidence — which is the
only claim the demo actually makes.

**Events that fired nothing are still rendered, quietly.** They are not noise. A run where
fifteen ordinary requests stay silent is what makes the two that fire mean anything, and the
0-false-positive result in the P8 evaluation is otherwise invisible.

**The page is a build artifact, and its absence is not an error.** `ui/dist/` is git-ignored, so
a fresh clone has no page until `npm install && npm run build`. `talos serve` must not depend on
that: the API is the product and the page is a face on it, so an unbuilt `/ui` answers 503 with
the command that builds it rather than 404-ing into what looks like a broken deployment.

## Bounding what a browser can ask for

`POST /trace` accepts text from whoever can reach the port and runs every line of it through
parsers and detectors. Detector handling does not change — log content was already treated as
data rather than instruction, delimited and length-bounded before any prompt (HLD §11/§13) — so
what is new is volume, not trust. `output.api.max_trace_log_chars` and `max_trace_log_lines` cap
it, and the run happens on a worker thread: `build_trace` owns its own event loop, so calling it
inline would both raise inside the running loop and block every other request for the scan.
