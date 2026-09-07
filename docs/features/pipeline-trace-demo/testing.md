# Testing — Pipeline-Trace Demo

## How to run

```bash
talos demo                      # both chains, annotated trace
talos demo --chain web --json   # the structure the web UI consumes
python -m pytest tests/unit/output/test_demo_trace_engine.py
```

## Cases covered (`test_demo_trace_engine.py`)

- the web chain produces both an `injection` and an `auth_failure` incident, and fires both the
  `sql_injection` and `brute_force` techniques
- the network chain escalates: the last incident is `high` severity, confidence non-decreasing
- every firing verdict carries evidence and a confidence in `[0, 1]` — a verdict without evidence
  is exactly what the trace exists to make impossible to ship
- `to_dict()` round-trips through `json.dumps`, so the visualiser can consume it
- both chains run with the model off (`used_llm is False`)
