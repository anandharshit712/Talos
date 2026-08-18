"""``talos`` -- the console entry point (standards 1.3; there is never a root launcher).

P2 ships one subcommand::

    talos scan tests/fixtures/logs/network_ssh_brute_force_sshd.log

It reads a log file, runs every line through the real pipeline -- parser, window, orchestrator,
domain agent, classifier, sub-agent, detector, aggregator, sinks -- and writes incident reports
to the configured sinks.

Models are optional. With provider keys set, narratives are model-written and `used_llm` is true;
with none set, every detector falls back to its templated narrative and `used_llm` is false. Both
paths produce the same detections, because detection is statistical and the model only words it.

``serve`` and ``replay`` arrive in P7.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from talos.core.agent_contracts import DetectionContext
from talos.core.error_types import TalosError
from talos.core.logging_setup import configure_logging
from talos.core.settings import TalosSettings
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
from talos.storage.event_window_store import EventWindowStore
from talos.storage.verdict_log_store import VerdictLogStore

_log = logging.getLogger("talos.cli")

Sink = StdoutSink | JsonFileSink


class _EmptyBaselineStore:
    """Stands in for the P6 baseline store. Cold start is the correct answer until then."""

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


def build_orchestrator(settings: TalosSettings, verdict_log: VerdictLogStore) -> EventOrchestrator:
    """Wire the pipeline. Registering a domain agent is the whole integration surface."""
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
        baseline_store=_EmptyBaselineStore(),
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


def _run_scan(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        print(f"no such log file: {args.file}", file=sys.stderr)
        return 2

    settings = TalosSettings.load(config_dir=args.config_dir)
    configure_logging(args.log_level or settings.log_level)

    verdict_log = VerdictLogStore(args.db or settings.db_path)
    try:
        orchestrator = build_orchestrator(settings, verdict_log)
        parser: BaseParser = (
            WebLogParser() if args.domain == "web" else NetworkLogParser(default_year=args.year)
        )
        result = asyncio.run(
            scan_file(args.file, parser, orchestrator, build_sinks(settings, args.pretty))
        )
    finally:
        verdict_log.close()

    print(
        f"scanned {args.file}: {result.events} event(s), "
        f"{result.skipped_lines} line(s) skipped, {result.incidents} incident(s)",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="talos", description="Talos attack detection pipeline.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="run a log file through the pipeline")
    scan.add_argument("file", type=Path, help="log file to scan")
    scan.add_argument("--db", type=Path, default=None, help="SQLite path for the verdict log")
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
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
