"""Write incident reports to stdout as JSON, one object per line.

Reports go to stdout and diagnostics go to stderr (``core/logging_setup.py``), so
``talos scan file.log | jq`` works without a filter step.
"""

from __future__ import annotations

import sys
from typing import IO

from talos.schemas.report_schema import IncidentReport


class StdoutSink:
    """JSON Lines on stdout."""

    name = "stdout"

    def __init__(self, stream: IO[str] | None = None, indent: int | None = None) -> None:
        self._stream = stream
        self._indent = indent
        """``None`` keeps one report per line; set an integer for a human-readable demo."""

    def emit(self, report: IncidentReport) -> None:
        stream = self._stream if self._stream is not None else sys.stdout
        stream.write(report.model_dump_json(indent=self._indent) + "\n")
        stream.flush()
