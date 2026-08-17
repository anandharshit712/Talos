"""Write each incident report to its own JSON file under the configured report directory.

One file per incident, named by ``incident_id``: a SIEM pickup directory, and the artifact the
evaluation harness (P8) reads back.
"""

from __future__ import annotations

from pathlib import Path

from talos.core.error_types import StorageError
from talos.schemas.report_schema import IncidentReport


class JsonFileSink:
    """``<report_dir>/<incident_id>.json``, pretty-printed for human review."""

    name = "json_file"

    def __init__(self, report_dir: Path | str) -> None:
        self.report_dir = Path(report_dir)

    def emit(self, report: IncidentReport) -> None:
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            path = self.report_dir / f"{report.incident_id}.json"
            path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        except OSError as exc:
            # Fail-safe for reporting: a report that cannot be written must be heard about,
            # not dropped silently into a directory nobody can create.
            raise StorageError(f"cannot write report to {self.report_dir}: {exc}") from exc
