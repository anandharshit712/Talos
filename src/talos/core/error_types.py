"""The ``TalosError`` hierarchy (LLD 11).

One base class so a caller can catch everything Talos raises without also swallowing
``KeyboardInterrupt`` or a genuine bug, and one subclass per failure boundary so the
fail-open/fail-safe split is expressible: detection failures are caught and degraded, while
configuration failures are raised and stop the process.
"""

from __future__ import annotations


class TalosError(Exception):
    """Base class for every error Talos raises deliberately."""


class ConfigError(TalosError):
    """Configuration is missing, malformed, or internally inconsistent.

    Fatal by design: a system whose thresholds did not load must not start and quietly
    detect nothing.
    """


class ParseError(TalosError):
    """A telemetry line could not be parsed.

    Never fatal -- the parser skips the line, counts it, and continues (LLD 11).
    """


class DetectionError(TalosError):
    """A detector or sub-agent failed while evaluating an event.

    Caught by the domain agent, which degrades to a low-confidence inconclusive verdict. A
    broken detector must not silence the pipeline.
    """


class ModelError(TalosError):
    """An LLM call failed, timed out, or returned unparseable output.

    Recoverable: retry, then the fallback model, then a templated narrative with
    ``used_llm=False``.
    """


class StorageError(TalosError):
    """A store could not read or write.

    Includes the case of a schema that does not exist yet -- stores never create their own
    tables, so a missing table means migrations were not applied (standards 4.4 rule 5).
    """
