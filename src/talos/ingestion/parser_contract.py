"""``BaseParser`` -- raw telemetry in, ``NormalizedEvent`` out (LLD 5.1).

A parser never raises on bad input. Log files contain truncated lines, interleaved writes from
other daemons, and formats the parser was never told about; a stream that dies on the first of
them detects nothing for the rest of the file. Unparseable lines return ``None``, are counted,
and the stream continues (LLD 11).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator

from talos.schemas.event_schema import NormalizedEvent


class BaseParser(ABC):
    """Turns one telemetry format into the pipeline's single event contract."""

    domain: str

    def __init__(self) -> None:
        self.parse_errors = 0
        """Lines this parser could not read. Reported by the CLI, never raised."""

    @abstractmethod
    def parse_line(self, raw: str) -> NormalizedEvent | None:
        """Parse one line. ``None`` means "not a line I understand" -- never an exception."""

    def parse_stream(self, lines: Iterable[str]) -> Iterator[NormalizedEvent]:
        """Parse every line, skipping and counting the ones that do not map."""
        for line in lines:
            if not line.strip():
                continue
            event = self.parse_line(line)
            if event is None:
                self.parse_errors += 1
                continue
            yield event
