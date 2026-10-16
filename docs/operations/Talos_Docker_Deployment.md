# Talos — Running on Docker

**Document type:** Operations runbook
**Files:** [`deploy/docker/Dockerfile`](../../deploy/docker/Dockerfile),
[`deploy/compose/talos_stack.yaml`](../../deploy/compose/talos_stack.yaml),
[`.dockerignore`](../../.dockerignore)

The native install (README quickstart) remains the primary path. The container stack is the
same service with PostgreSQL brought along, for a machine that has Docker and not a native
PostgreSQL.

## What the stack runs

| Service | Image | Role |
|---|---|---|
| `db` | `postgres:17` (as CI) | Data in the `pgdata` named volume. |
| `migrate` | `talos:local` | One shot: `scripts/apply_migrations.py --engine postgres`, then exits. Re-running is a no-op — the ledger table records what ran. |
| `talos` | `talos:local` | `talos serve` — the report API, OpenAPI at `/docs`, the trace visualiser at `/ui`. Starts only after `migrate` succeeds. |

The image is built in two stages: Node builds `ui/dist/`, then Python 3.12 installs Talos
**editable** at `/app`. Editable is load-bearing, not a convenience: Talos finds `config/`,
`data/samples/`, `ui/dist/` and `.env` relative to the repository root
(`talos.core.settings.repository_root`). Under a plain `pip install .` that root resolves into
`/usr/local/lib/python3.12`, every YAML file is skipped, and the service runs on the model
defaults without saying so. The container runs as an unprivileged `talos` user.

## Start, check, stop

```bash
docker compose -f deploy/compose/talos_stack.yaml up -d --build
docker compose -f deploy/compose/talos_stack.yaml ps          # talos: healthy
curl http://127.0.0.1:8000/healthz                            # {"status":"ok","storage":"ok"}

docker compose -f deploy/compose/talos_stack.yaml down        # keep the database
docker compose -f deploy/compose/talos_stack.yaml down -v     # and drop it
```

The healthcheck calls `/healthz`, which round-trips the database, so `healthy` means incidents
can actually be recorded — not merely that the process is up.

## Configuration

| Variable (host shell or a compose `.env`) | Default | Effect |
|---|---|---|
| `TALOS_DB_PASSWORD` | `talos` | PostgreSQL password, used by both `db` and the DSN. Set it for anything beyond a laptop. |
| `TALOS_PORT` | `8000` | Host port; always bound to `127.0.0.1`. |
| `TALOS_LLM__ENABLED` | `true` | `false` runs the statistical path only (`used_llm=false`). |

Provider keys are read from the repository's `.env` at **run time** (`env_file`, optional). They
are never copied into the image — `.dockerignore` excludes `.env`. Any other `TALOS_*` setting can
be added under the `talos` service's `environment:`; precedence is unchanged (env wins over YAML).

## Feeding it logs

`talos replay` is in the image. Mount the log and point it at the service:

```bash
docker compose -f deploy/compose/talos_stack.yaml run --rm \
  -v "$PWD/tests/fixtures/logs:/logs:ro" talos \
  talos replay /logs/network_ssh_brute_force_sshd.log --year 2026 --url http://talos:8000
curl 'http://127.0.0.1:8000/reports?limit=10'
```

A natively installed `talos replay … --url http://127.0.0.1:8000` works against the container
equally well.

## Security posture

- **The API has no authentication.** Inside the container it binds `0.0.0.0` (the loopback
  default would be unreachable) and logs the warning that says so; the stack publishes the port
  on the host's loopback only. Do not change the publish address without putting an
  authenticating proxy in front.
- The database port is not published at all; only the stack's network reaches it.

## State across restarts

`talos serve` holds its event window and repeat-suppression memory in process (LLD §12). A
container restart starts both empty, exactly as a native restart does; the incidents already
recorded stay in PostgreSQL.

## Verified

2026-10-16, Docker Desktop 4.95 / Engine 29.8 (WSL2): fresh `down -v` → `up --build`, healthcheck
`healthy`, `/healthz`, `/ui` and `/trace/chains` served, port bound to `127.0.0.1` only, process
uid 10001. The six owner-supplied end-to-end scenarios (brute force, credential stuffing, scheduled
scanner, blocked SQLi, second organisation, busy hour; 43 incidents) replayed against it with
`TALOS_LLM__ENABLED=false` all matched their expected output field for field, and the reports were
identical to the same scenarios run natively on Windows apart from the per-run random event ids.
