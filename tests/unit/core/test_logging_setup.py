"""Structured logs are only useful if they parse: one JSON object per line, on stderr."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator

import pytest

from talos.core.logging_setup import configure_logging


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    configure_logging("DEBUG", stream=stream)
    yield stream
    logging.getLogger().handlers.clear()


def _lines(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def test_record_is_one_json_object(captured: io.StringIO) -> None:
    logging.getLogger("talos.test").info("pipeline started")
    (record,) = _lines(captured)
    assert record["level"] == "INFO"
    assert record["logger"] == "talos.test"
    assert record["message"] == "pipeline started"
    assert str(record["timestamp"]).endswith("+00:00")


def test_extra_fields_are_merged_not_dropped(captured: io.StringIO) -> None:
    """The pipeline trace lives in these fields -- losing them loses the transparency story."""
    logging.getLogger("talos.test").info(
        "verdict emitted", extra={"detector": "ssh_brute_force_detector", "confidence": 0.91}
    )
    (record,) = _lines(captured)
    assert record["detector"] == "ssh_brute_force_detector"
    assert record["confidence"] == 0.91


def test_exception_is_rendered_into_the_object(captured: io.StringIO) -> None:
    try:
        raise ValueError("detector exploded")
    except ValueError:
        logging.getLogger("talos.test").exception("detector failed")
    (record,) = _lines(captured)
    assert "ValueError: detector exploded" in str(record["exception"])


def test_level_filters_below_threshold() -> None:
    stream = io.StringIO()
    configure_logging("WARNING", stream=stream)
    logging.getLogger("talos.test").debug("noise")
    logging.getLogger("talos.test").warning("signal")
    assert [record["message"] for record in _lines(stream)] == ["signal"]
    logging.getLogger().handlers.clear()


def test_configure_is_idempotent() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    configure_logging("INFO", stream=stream)
    logging.getLogger("talos.test").info("once")
    assert len(_lines(stream)) == 1
    logging.getLogger().handlers.clear()
