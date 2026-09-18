# Testing — Pipeline-Trace Demo

## How to run

```bash
talos demo                      # both chains, annotated trace
talos demo --chain web --json   # the structure the web UI consumes
python -m pytest tests/unit/output/test_demo_trace_engine.py
python -m pytest tests/unit/output/api/test_trace_routes.py

cd ui && npm install && npm run build   # then talos serve, and open /ui
npm run typecheck                       # TypeScript strict, the page's own gate
```

## Cases covered (`test_demo_trace_engine.py`)

- the web chain produces both an `injection` and an `auth_failure` incident, and fires both the
  `sql_injection` and `brute_force` techniques
- the network chain escalates: the last incident is `high` severity, confidence non-decreasing
- every firing verdict carries evidence and a confidence in `[0, 1]` — a verdict without evidence
  is exactly what the trace exists to make impossible to ship
- `to_dict()` round-trips through `json.dumps`, so the visualiser can consume it
- both chains run with the model off (`used_llm is False`)

## Cases covered (`test_trace_routes.py`)

The route tests go through the **real** pipeline rather than a stub, because that is the claim
under test: the browser is served what the pipeline concluded, not a rendering of it.

- a submitted burst comes back as routing, evidence and confidence -- every firing verdict
  carries evidence, and no verdict is a bare boolean
- the prepared web chain traces identically through HTTP and in the terminal, ignoring the
  incident ids, which are minted per run
- an unknown domain is a 422, not a silently empty trace
- an unparseable log is an ordinary 200 with `skipped` set -- the page stays up and says so
- a log past `max_trace_log_lines` is a 413: the endpoint runs whatever it is given, so the work
  one request can ask for is bounded
- a log whose payload reads like an instruction ("ignore previous instructions...") is still
  detected as the tautology it is -- submitted text is data, never direction
- the route never touches the orchestrator or the verdict store (both are tripwires in the test)
- `/ui` is either the built page or a 503 saying how to build it, never a bare 404
