"""``talos`` -- the console entry point (standards 1.3; there is never a root launcher).

P2 ships one subcommand::

    talos scan tests/fixtures/logs/network_ssh_brute_force_sshd.log

It reads a log file, runs every line through the real pipeline -- parser, window, orchestrator,
domain agent, classifier, sub-agent, detector, aggregator, sinks -- and writes incident reports
to the configured sinks.

Models are optional. With provider keys set, narratives are model-written and `used_llm` is true;
with none set, every detector falls back to its templated narrative and `used_llm` is false. Both
paths produce the same detections, because detection is statistical and the model only words it.

``serve`` runs the same pipeline behind the report API, and ``replay`` streams a log file
into a running one -- the demo path, and the only one that exercises the HTTP surface end to
end. Incidents persist to PostgreSQL from P6.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from talos.output.demo_trace_engine import Trace

from talos.core.agent_contracts import DetectionContext
from talos.core.error_types import TalosError
from talos.core.logging_setup import configure_logging
from talos.core.settings import TalosSettings, load_env_file
from talos.domains.network.network_domain_agent import NetworkDomainAgent
from talos.domains.web.web_domain_agent import WebDomainAgent
from talos.ingestion.parser_contract import BaseParser
from talos.ingestion.parsers.network_log_parser import NetworkLogParser
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.llm.model_router import build_router
from talos.orchestrator.agent_registry import AgentRegistry
from talos.orchestrator.event_orchestrator import EventOrchestrator
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.output.sinks.json_file_sink import JsonFileSink
from talos.output.sinks.stdout_sink import StdoutSink
from talos.storage.baseline_store import BaselineStore
from talos.storage.event_window_store import EventWindowStore
from talos.storage.postgres_connection_pool import PostgresConnectionPool
from talos.storage.verdict_log_store import VerdictLogStore

_log = logging.getLogger("talos.cli")

Sink = StdoutSink | JsonFileSink


class _NoBaseline:
    """Every account cold, nothing learned. Only used when no store is supplied.

    It satisfies ``BaselineReader`` and deliberately lacks ``record_access``, so the baseliner
    declines to learn rather than racing a store that cannot lock.
    """

    async def get(self, account: str) -> Any | None:
        return None

    async def put(self, baseline: Any) -> None:
        return None


@dataclass
class ScanResult:
    """What one scan did, reported to the operator on stderr."""

    events: int = 0
    skipped_lines: int = 0
    incidents: int = 0


def build_orchestrator(
    settings: TalosSettings,
    verdict_log: VerdictLogStore,
    baseline_store: BaselineStore | Any | None = None,
) -> EventOrchestrator:
    """Wire the pipeline. Registering a domain agent is the whole integration surface.

    ``baseline_store`` is optional so a caller that only exercises the stateless detectors --
    every test that is not about IDOR -- can pass a double instead of provisioning PostgreSQL.
    """
    router = build_router(settings)
    _log.info(
        "model providers available",
        extra={"providers": router.providers or ["none -- templated narratives only"]},
    )
    ctx = DetectionContext(
        event_window=EventWindowStore(
            ttl_seconds=settings.storage.event_window_ttl_seconds,
            max_events_per_key=settings.storage.event_window_max_events,
        ),
        baseline_store=baseline_store if baseline_store is not None else _NoBaseline(),
        model_client=router,
        settings=settings,
        verdict_log=verdict_log,
    )
    registry = AgentRegistry()
    registry.register_domain_agent(NetworkDomainAgent())
    registry.register_domain_agent(WebDomainAgent())
    return EventOrchestrator(registry, VerdictAggregator(settings), ctx)


def build_sinks(settings: TalosSettings, pretty: bool) -> list[Sink]:
    """Instantiate the sinks named in configuration, skipping ones this phase cannot serve."""
    sinks: list[Sink] = []
    for name in settings.output.sinks:
        if name == "stdout":
            sinks.append(StdoutSink(indent=2 if pretty else None))
        elif name == "json_file":
            sinks.append(JsonFileSink(settings.output.report_dir))
        else:
            _log.warning("unknown or not-yet-available sink, skipping", extra={"sink": name})
    return sinks


async def scan_file(
    path: Path, parser: BaseParser, orchestrator: EventOrchestrator, sinks: list[Sink]
) -> ScanResult:
    """Stream one log file through the pipeline, emitting every incident as it is produced."""
    result = ScanResult()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for event in parser.parse_stream(handle):
            result.events += 1
            report = await orchestrator.submit(event)
            if report is None:
                continue
            result.incidents += 1
            for sink in sinks:
                sink.emit(report)
    result.skipped_lines = parser.parse_errors
    return result


async def _scan_with_storage(args: argparse.Namespace, settings: TalosSettings) -> ScanResult:
    """Open the pool, run the scan, and always give the connections back.

    The pool is opened here rather than in ``build_orchestrator`` because the caller owns its
    lifetime: every store shares one pool, and closing it is the scan's job, not a store's.
    """
    database = settings.storage.database
    pool = PostgresConnectionPool(args.dsn or database.resolve_dsn(), database)
    try:
        orchestrator = build_orchestrator(settings, VerdictLogStore(pool), BaselineStore(pool))
        parser: BaseParser = (
            WebLogParser() if args.domain == "web" else NetworkLogParser(default_year=args.year)
        )
        return await scan_file(args.file, parser, orchestrator, build_sinks(settings, args.pretty))
    finally:
        await pool.close()


def _run_scan(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        print(f"no such log file: {args.file}", file=sys.stderr)
        return 2

    settings = TalosSettings.load(config_dir=args.config_dir)
    configure_logging(args.log_level or settings.log_level)

    result = asyncio.run(_scan_with_storage(args, settings))

    print(
        f"scanned {args.file}: {result.events} event(s), "
        f"{result.skipped_lines} line(s) skipped, {result.incidents} incident(s)",
        file=sys.stderr,
    )
    return 0


def _run_demo(args: argparse.Namespace) -> int:
    """Run the prepared chains through the real pipeline and print the reasoning, not just the
    verdict. The trace is what makes Talos more than a WAF regex (HLD P9), so it is the whole
    output: every event, what it was routed to, the evidence, and the incident it aggregated into.

    The chains and the run itself live in ``demo_trace_engine``, not here: the browser's trace
    visualiser serves the same structure, and a second copy of the wiring is a second pipeline
    to keep in step.
    """
    from talos.output.demo_trace_engine import DEFAULT_SYSLOG_YEAR, DEMO_CHAINS, trace_for

    settings = TalosSettings.load(config_dir=args.config_dir)
    configure_logging(args.log_level or "WARNING")  # the trace is the output; keep logs out of it

    chains = DEMO_CHAINS
    if args.chain != "all":
        chains = tuple(c for c in DEMO_CHAINS if c.domain == args.chain)

    for chain in chains:
        lines = (
            args.file.read_text(encoding="utf-8").splitlines()
            if args.file is not None
            else chain.lines()
        )
        trace = trace_for(
            chain.domain,
            lines,
            settings,
            title=chain.title,
            year=args.year or DEFAULT_SYSLOG_YEAR,
        )
        if args.json:
            print(json.dumps(trace.to_dict(), indent=2, default=str))
        else:
            print(_render_trace(trace))
    return 0


def _render_trace(trace: Trace) -> str:
    """The annotated pipeline trace, one block per event that produced a verdict."""
    rule = "=" * 64
    out = [
        "",
        rule,
        f"  {trace.title}",
        f"  {trace.events} events | {trace.incidents} incident(s) | "
        f"model {'on' if trace.used_llm else 'off (statistical path)'}",
        rule,
    ]
    for step in trace.steps:
        firing = [v for v in step.verdicts if v.attack_detected]
        if not firing and step.incident is None:
            continue
        out.append(f"\n  event {step.index}: {step.summary}   [{step.source}]")
        for verdict in firing:
            out.append(
                f"    -> {verdict.detector}: {verdict.technique} "
                f"(confidence {verdict.confidence:.2f})"
            )
            for evidence in verdict.evidence[:1]:
                out.append(f"        evidence: {evidence.detail}")
        incident = step.incident
        if incident is not None:
            scope = ", ".join(
                part
                for part in (
                    f"accounts={incident.affected_accounts}" if incident.affected_accounts else "",
                    f"endpoints={incident.affected_endpoints}"
                    if incident.affected_endpoints
                    else "",
                    f"hosts={incident.affected_hosts}" if incident.affected_hosts else "",
                )
                if part
            )
            out.append(
                f"    *** INCIDENT {incident.category} / {incident.severity} "
                f"(confidence {incident.confidence:.2f}, MITRE {', '.join(incident.mitre)})"
            )
            out.append(f"        {incident.summary}")
            out.append(f"        scope: {scope}")
    out.append("")
    return "\n".join(out)


def _run_serve(args: argparse.Namespace) -> int:
    """Run the report API. Blocks until interrupted."""
    import uvicorn

    from talos.output.api.api_server import create_app

    settings = TalosSettings.load(config_dir=args.config_dir)
    configure_logging(args.log_level or settings.log_level)

    api = settings.output.api
    host = args.host or api.host
    port = args.port or api.port
    if host not in ("127.0.0.1", "localhost", "::1"):
        # Talos has no authentication. Binding anything else publishes an unauthenticated
        # incident feed, so say so rather than letting a flag do it quietly.
        _log.warning(
            "binding a non-loopback address: the API has no authentication",
            extra={"host": host, "port": port},
        )

    _log.info("serving the report API", extra={"host": host, "port": port, "docs": "/docs"})
    uvicorn.run(create_app(settings, dsn=args.dsn), host=host, port=port, log_config=None)
    return 0


def _run_replay(args: argparse.Namespace) -> int:
    """Stream a log file into a running server, one event per request."""
    if not args.file.is_file():
        print(f"no such log file: {args.file}", file=sys.stderr)
        return 2

    settings = TalosSettings.load(config_dir=args.config_dir)
    configure_logging(args.log_level or settings.log_level)

    parser: BaseParser = (
        WebLogParser() if args.domain == "web" else NetworkLogParser(default_year=args.year)
    )
    result = replay_file(
        args.file,
        parser,
        args.url,
        rate=args.rate,
        timeout=args.timeout,
        pretty=args.pretty,
    )

    print(
        f"replayed {args.file} to {args.url}: {result.events} event(s), "
        f"{result.skipped_lines} line(s) skipped, {result.incidents} incident(s)",
        file=sys.stderr,
    )
    return 0


def replay_file(
    path: Path,
    parser: BaseParser,
    url: str,
    *,
    rate: float = 0.0,
    timeout: float = 10.0,
    pretty: bool = False,
) -> ScanResult:
    """POST every parsed event to ``url``, printing each incident the server returns.

    Synchronous on purpose: replay is a demo and diagnostic tool, and one request at a time is
    what makes the trace readable. Sending concurrently would also reorder events, and the
    windowed detectors read order.
    """
    import httpx

    result = ScanResult()
    endpoint = url.rstrip("/") + "/events"
    with (
        httpx.Client(timeout=timeout) as client,
        path.open(encoding="utf-8", errors="replace") as handle,
    ):
        for event in parser.parse_stream(handle):
            result.events += 1
            response = client.post(
                endpoint,
                content=event.model_dump_json(),
                headers={"content-type": "application/json"},
            )
            if response.status_code == 204:
                pass  # analysed, nothing fired -- the common case
            elif response.is_success:
                result.incidents += 1
                print(json.dumps(response.json(), indent=2 if pretty else None))
            else:
                _log.warning(
                    "server rejected an event",
                    extra={"status": response.status_code, "event_id": event.event_id},
                )
            if rate > 0:
                time.sleep(rate)
    result.skipped_lines = parser.parse_errors
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="talos", description="Talos attack detection pipeline.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="run a log file through the pipeline")
    scan.add_argument("file", type=Path, help="log file to scan")
    scan.add_argument(
        "--dsn",
        default=None,
        help="PostgreSQL DSN for the verdict log (default: the variable named by "
        "talos.storage.database.dsn_env)",
    )
    scan.add_argument(
        "--config-dir", type=Path, default=None, help="directory holding the YAML config"
    )
    scan.add_argument(
        "--domain",
        choices=("network", "web"),
        default="network",
        help="telemetry the file holds; picks the parser (default: network)",
    )
    scan.add_argument("--year", type=int, default=None, help="year for year-less syslog stamps")
    scan.add_argument("--pretty", action="store_true", help="indent the JSON written to stdout")
    scan.add_argument("--log-level", default=None, help="DEBUG | INFO | WARNING | ERROR")
    scan.set_defaults(handler=_run_scan)

    demo = subcommands.add_parser(
        "demo", help="run the prepared attack chains and print the annotated pipeline trace"
    )
    demo.add_argument(
        "--chain",
        choices=("all", "web", "network"),
        default="all",
        help="which prepared chain to run (default: all)",
    )
    demo.add_argument(
        "--file",
        type=Path,
        default=None,
        help="run a custom log instead of the prepared chain (use with --chain to pick the parser)",
    )
    demo.add_argument("--json", action="store_true", help="emit the trace as JSON, not a table")
    demo.add_argument(
        "--config-dir", type=Path, default=None, help="directory holding the YAML config"
    )
    demo.add_argument("--year", type=int, default=None, help="year for year-less syslog stamps")
    demo.add_argument("--log-level", default=None, help="DEBUG | INFO | WARNING | ERROR")
    demo.set_defaults(handler=_run_demo)

    serve = subcommands.add_parser("serve", help="run the report API")
    serve.add_argument("--host", default=None, help="bind address (default: talos.output.api.host)")
    serve.add_argument(
        "--port", type=int, default=None, help="port (default: talos.output.api.port)"
    )
    serve.add_argument("--dsn", default=None, help="PostgreSQL DSN for the stores")
    serve.add_argument(
        "--config-dir", type=Path, default=None, help="directory holding the YAML config"
    )
    serve.add_argument("--log-level", default=None, help="DEBUG | INFO | WARNING | ERROR")
    serve.set_defaults(handler=_run_serve)

    replay = subcommands.add_parser("replay", help="stream a log file into a running server")
    replay.add_argument("file", type=Path, help="log file to replay")
    replay.add_argument(
        "--url", default="http://127.0.0.1:8000", help="base URL of a running talos serve"
    )
    replay.add_argument(
        "--rate",
        type=float,
        default=0.0,
        help="seconds to wait between events; 0 is as fast as the server accepts them",
    )
    replay.add_argument("--timeout", type=float, default=10.0, help="per-request timeout, seconds")
    replay.add_argument(
        "--pretty", action="store_true", help="indent the reports the server returns"
    )
    replay.add_argument(
        "--domain",
        choices=("network", "web"),
        default="network",
        help="telemetry the file holds; picks the parser (default: network)",
    )
    replay.add_argument("--year", type=int, default=None, help="year for year-less syslog stamps")
    replay.add_argument(
        "--config-dir", type=Path, default=None, help="directory holding the YAML config"
    )
    replay.add_argument("--log-level", default=None, help="DEBUG | INFO | WARNING | ERROR")
    replay.set_defaults(handler=_run_replay)

    return parser


def _force_utf8_streams() -> None:
    """Make stdout and stderr carry any character a report can contain.

    JSON is UTF-8 by specification, but the Windows console hands Python a cp1252 stream, and
    ``str.write`` of one unencodable character raises rather than mangling it -- so a single
    non-ASCII byte anywhere in a report kills the run *at output time*, after the detection
    work is done. Observed with a model narrative containing a non-breaking hyphen (U+2011);
    the same crash is reachable without a model at all, because a UTF-8 payload in a request
    path is copied verbatim into the evidence. That makes it attacker-triggerable, and
    "fail-safe for reporting" does not survive a report that cannot be printed.

    ``backslashreplace`` is the belt to that braces: on a console that still cannot encode, an
    escape sequence is printed instead of an exception being raised.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue  # a stream replaced by a test or a harness; nothing to reconfigure
        # A stream that refuses to be reconfigured is still a usable stream.
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def main(argv: Sequence[str] | None = None) -> int:
    _force_utf8_streams()
    # Provider keys live in .env and are not settings fields, so nothing loads them unless an
    # entry point does. Before this call the CLI ran with three keys on disk and no providers.
    load_env_file()
    args = build_parser().parse_args(argv)
    try:
        exit_code: int = args.handler(args)
    except TalosError as exc:
        # Configuration and storage failures are fatal and actionable; print the fix, not a
        # traceback. Anything else is a bug and keeps its traceback.
        print(f"talos: {exc}", file=sys.stderr)
        return 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
