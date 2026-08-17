"""A parser must survive its input: bad lines are counted, never raised (LLD 5.1, 11)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from talos.ingestion.parser_contract import BaseParser
from talos.schemas.event_schema import Actor, NormalizedEvent, Target


class _OkLinesParser(BaseParser):
    """Parses lines containing "ok"; everything else is unreadable."""

    domain = "network"

    def parse_line(self, raw: str) -> NormalizedEvent | None:
        if "ok" not in raw:
            return None
        return NormalizedEvent(
            event_id=raw.strip(),
            timestamp=datetime(2026, 8, 15, 10, 15, tzinfo=UTC),
            domain="network",
            telemetry_source="sshd",
            actor=Actor(source_ip="203.0.113.7"),
            target=Target(host="bastion-01"),
            raw=raw,
        )


def test_unparseable_lines_are_counted_not_raised() -> None:
    parser = _OkLinesParser()
    events = list(parser.parse_stream(["ok one", "garbage", "ok two", "\x00binary"]))
    assert len(events) == 2
    assert parser.parse_errors == 2


def test_blank_lines_are_neither_events_nor_errors() -> None:
    parser = _OkLinesParser()
    assert list(parser.parse_stream(["", "   ", "\n"])) == []
    assert parser.parse_errors == 0


def test_stream_is_lazy() -> None:
    """A live tail must yield as it reads, not after the file ends."""
    stream = _OkLinesParser().parse_stream(iter(["ok one", "ok two"]))
    assert next(stream) is not None


def test_contract_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        BaseParser()  # type: ignore[abstract]
