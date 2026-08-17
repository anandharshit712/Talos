"""The error hierarchy exists so callers can catch a boundary, not a bug."""

from __future__ import annotations

import pytest

from talos.core.error_types import (
    ConfigError,
    DetectionError,
    ModelError,
    ParseError,
    StorageError,
    TalosError,
)

ERRORS = (ConfigError, ParseError, DetectionError, ModelError, StorageError)


@pytest.mark.parametrize("error", ERRORS)
def test_every_error_is_catchable_as_talos_error(error: type[TalosError]) -> None:
    with pytest.raises(TalosError):
        raise error("boom")


@pytest.mark.parametrize("error", ERRORS)
def test_errors_do_not_catch_each_other(error: type[TalosError]) -> None:
    """Separate classes only pay off if each names exactly one boundary."""
    others = [other for other in ERRORS if other is not error]
    with pytest.raises(error):
        try:
            raise error("boom")
        except tuple(others):  # pragma: no cover - reaching this is the failure
            pytest.fail(f"{error.__name__} was caught by a sibling error class")


def test_talos_error_does_not_swallow_unrelated_exceptions() -> None:
    with pytest.raises(KeyboardInterrupt):
        try:
            raise KeyboardInterrupt
        except TalosError:  # pragma: no cover - must not match
            pytest.fail("TalosError caught a KeyboardInterrupt")
