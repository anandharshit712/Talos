"""``TalosSettings`` -- the single configuration surface (LLD 10).

Precedence, lowest first::

    model defaults  <  config/default.yaml  <  config/thresholds.yaml
                    <  config/model_routing.yaml  <  config/local.yaml  <  TALOS_* env vars

The YAML files are merged key by key, so an overlay states only what it changes. Every file
is rooted at a single ``talos:`` key, which this loader strips -- a stray top-level key in a
config file is then a loud error instead of a silently ignored setting.

Secrets never come from YAML and never become settings fields. ``config/model_routing.yaml``
names the environment variable holding each provider key (``api_key_env``); the router reads it
at build time. Nothing in this module can hold a credential, so nothing can log or serialise one.

Detectors read tunables from ``ctx.settings``; nothing in ``src/`` carries a threshold as a
module-level literal (standards 2.3).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import dotenv_values, load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from talos.core.constants import DOMAINS
from talos.core.error_types import ConfigError

_log = logging.getLogger(__name__)

#: Environment overrides for *where* config lives, read before any settings object exists.
ENV_FILE = ".env"
CONFIG_DIR_ENV = "TALOS_CONFIG_DIR"
CONFIG_PATH_ENV = "TALOS_CONFIG_PATH"

#: Every config file is rooted at this key.
ROOT_KEY = "talos"

#: Merged in this order; each may be absent, in which case the model defaults stand.
BASE_CONFIG_FILES = ("default.yaml", "thresholds.yaml", "model_routing.yaml")

#: Developer overlay, applied last. Git-ignored, so its absence is the normal case.
DEFAULT_OVERLAY_FILE = "local.yaml"


# ---------------------------------------------------------------------------
# Configuration blocks
# ---------------------------------------------------------------------------


class _Block(BaseModel):
    """Base for config blocks: a mistyped key is an error, not a silently ignored setting."""

    model_config = ConfigDict(extra="forbid")


class SourceFormats(_Block):
    """Log formats a domain's parser will attempt, in order."""

    formats: list[str] = Field(min_length=1)


class IngestionSettings(_Block):
    web: SourceFormats = Field(
        default_factory=lambda: SourceFormats(formats=["combined", "nginx_json", "waf_json"])
    )
    network: SourceFormats = Field(
        default_factory=lambda: SourceFormats(formats=["sshd_syslog", "rdp_evtx"])
    )


class RateThresholds(_Block):
    """Window and failure count for a rate-based detector (LLD 7.3)."""

    window_seconds: int = Field(gt=0)
    fail_threshold: int = Field(gt=0)


class CredentialStuffingThresholds(_Block):
    """Breadth-based thresholds: many accounts, few tries each (LLD 7.3.2)."""

    window_seconds: int = Field(default=300, gt=0)
    distinct_accounts: int = Field(default=15, gt=0)
    fails_per_account_max: int = Field(default=3, gt=0)


class IdorThresholds(_Block):
    """Baseline maturity and enumeration-run length (LLD 7.4)."""

    min_baseline_observations: int = Field(default=50, gt=0)
    sequential_run_len: int = Field(default=5, gt=1)


class RateConfidenceSettings(_Block):
    """How a rate detector turns an attempt count into a confidence (LLD 7.3.1, 9).

    Shared by all four rate-based detectors, and the first thing P8 calibration will move.
    """

    base: float = Field(default=0.70, ge=0.0, le=1.0)
    """Confidence at exactly the failure threshold."""
    per_extra_attempt: float = Field(default=0.02, ge=0.0, le=1.0)
    """Added for each failure above the threshold."""
    cap: float = Field(default=0.95, ge=0.0, le=1.0)
    success_floor: float = Field(default=0.90, ge=0.0, le=1.0)
    """Floor applied when the burst was followed by a successful authentication."""


class StorageSettings(_Block):
    """Bounds on the in-memory event window (LLD 12, NFR-7)."""

    event_window_ttl_seconds: int = Field(default=900, gt=0)
    event_window_max_events: int = Field(default=2000, gt=0)
    """Per key, not in total -- one noisy source must not evict every other key."""


class DetectionSettings(_Block):
    rate_confidence: RateConfidenceSettings = Field(default_factory=RateConfidenceSettings)
    brute_force: RateThresholds = Field(
        default_factory=lambda: RateThresholds(window_seconds=120, fail_threshold=10)
    )
    credential_stuffing: CredentialStuffingThresholds = Field(
        default_factory=CredentialStuffingThresholds
    )
    ssh_brute_force: RateThresholds = Field(
        default_factory=lambda: RateThresholds(window_seconds=120, fail_threshold=8)
    )
    rdp_brute_force: RateThresholds = Field(
        default_factory=lambda: RateThresholds(window_seconds=120, fail_threshold=8)
    )
    idor: IdorThresholds = Field(default_factory=IdorThresholds)


class ClassifierSettings(_Block):
    min_confidence_floor: float = Field(default=0.35, ge=0.0, le=1.0)


class AggregationSettings(_Block):
    """How verdicts combine into one incident (LLD 4.3)."""

    corroboration_boost: float = Field(default=0.05, ge=0.0, le=1.0)
    """Added to the top confidence for each *additional* detector that fired independently."""

    suppress_duplicates: bool = True
    """Report an ongoing attack once, not once per event past the threshold.

    A windowed detector fires again on every subsequent event in the same burst. Emitting all of
    them is alert spam, so the orchestrator reports the first crossing and stays quiet until the
    incident materially escalates. Set false to see every firing.
    """

    escalation_attempt_factor: float = Field(default=2.0, ge=1.0)
    """Re-report a suppressed incident once its attempt count grows by this factor."""


class LlmSettings(_Block):
    """Resilience and prompt-hardening knobs (LLD 8.3, HLD 11/13)."""

    enabled: bool = True
    """Master switch. ``false`` builds a router with no clients, so every call returns ``None``
    and the whole pipeline runs its statistical path -- a supported mode, not a degraded one."""

    request_timeout_seconds: float = Field(default=20.0, gt=0)
    max_retries: int = Field(default=1, ge=0)
    fallback_confidence_penalty: float = Field(default=0.85, gt=0.0, le=1.0)
    max_payload_chars: int = Field(default=2000, gt=0)


class OutputSettings(_Block):
    sinks: list[str] = Field(default_factory=lambda: ["stdout", "json_file"])
    report_dir: Path = Path("out/reports")


class ProviderProfile(_Block):
    """One inference endpoint. All supported providers speak the OpenAI dialect (LLD 8.1)."""

    base_url: str = Field(min_length=1)
    api_key_env: str = Field(min_length=1)
    """Name of the environment variable holding the key -- never the key itself."""


class FallbackRoute(_Block):
    """Where a route goes when its primary provider fails (LLD 8.3)."""

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)


class ModelRoute(_Block):
    """One routing entry: which model answers for one detector or classifier (LLD 8.2)."""

    tier: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    fallback: FallbackRoute | None = None


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def repository_root() -> Path:
    """The repository root, located relative to this module (``src/talos/core/``)."""
    return Path(__file__).resolve().parents[3]


def default_config_dir() -> Path:
    """The repository's ``config/`` directory, located relative to this module."""
    return repository_root() / "config"


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Merge ``overlay`` into ``base`` key by key, recursing into nested mappings."""
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, Mapping):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _read_config_file(path: Path) -> dict[str, Any]:
    """Read one ``talos:``-rooted YAML file and return its body."""
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict) or set(loaded) != {ROOT_KEY}:
        raise ConfigError(
            f"{path}: every config file holds exactly one top-level '{ROOT_KEY}:' key"
        )
    body = loaded[ROOT_KEY]
    if body is None:
        return {}
    if not isinstance(body, dict):
        raise ConfigError(f"{path}: '{ROOT_KEY}:' must contain a mapping")
    return body


def load_env_file(path: Path | None = None) -> list[str]:
    """Read ``.env`` into ``os.environ`` and return the names it set, never the values.

    Provider keys are deliberately not settings fields (nothing that can log a credential),
    so pydantic's ``env_file`` never sees them -- only an entry point loading the file does.
    Called by every entry point; never by library code, because a function that quietly
    rewrites the process environment is not one a detector should be able to reach.

    Real environment variables win: ``override=False``. A value already exported is a
    deliberate choice, and a stale ``.env`` should not undo it.
    """
    target = path or repository_root() / ENV_FILE
    if not target.is_file():
        return []
    names = [name for name, value in dotenv_values(target).items() if value]
    load_dotenv(target, override=False)
    return sorted(names)


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value) if value else None


def load_config_mapping(
    config_dir: Path | None = None, overlay: Path | None = None
) -> dict[str, Any]:
    """Merge the config tree into one mapping, ready to validate.

    Missing files are skipped: the model defaults are complete and valid on their own, and
    ``local.yaml`` is git-ignored so its absence is the normal case rather than an error.
    """
    directory = config_dir or _env_path(CONFIG_DIR_ENV) or default_config_dir()
    overlay_path = overlay or _env_path(CONFIG_PATH_ENV) or directory / DEFAULT_OVERLAY_FILE

    merged: dict[str, Any] = {}
    for name in BASE_CONFIG_FILES:
        path = directory / name
        if path.is_file():
            merged = _deep_merge(merged, _read_config_file(path))
        else:
            _log.debug("config file not present, using defaults: %s", path)
    if overlay_path.is_file():
        merged = _deep_merge(merged, _read_config_file(overlay_path))
    else:
        _log.debug("no config overlay at %s", overlay_path)
    return merged


#: Where :meth:`TalosSettings.load` is currently reading from. Handed to the YAML settings
#: source, which pydantic-settings constructs itself and gives no other way to parameterise.
# ponytail: module-level handoff, guarded by try/finally in load(). Settings are built once at
# startup, before any worker task exists; make it a ContextVar if that ever stops being true.
_CONFIG_LOCATION: tuple[Path | None, Path | None] = (None, None)


class _YamlConfigSource(PydanticBaseSettingsSource):
    """Feeds the merged config tree in below the environment."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        raise NotImplementedError  # pragma: no cover - the whole mapping is built at once

    def __call__(self) -> dict[str, Any]:
        config_dir, overlay = _CONFIG_LOCATION
        return load_config_mapping(config_dir, overlay)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TalosSettings(BaseSettings):
    """Loaded, validated configuration for one Talos process."""

    model_config = SettingsConfigDict(
        env_prefix="TALOS_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Config blocks are named model_routing / ModelRoute; pydantic's default 'model_'
        # protected namespace warns on field names it has no reason to reserve here.
        protected_namespaces=(),
    )

    enabled_domains: list[str] = Field(default_factory=lambda: list(DOMAINS))
    ingestion: IngestionSettings = Field(default_factory=IngestionSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    classifier: ClassifierSettings = Field(default_factory=ClassifierSettings)
    aggregation: AggregationSettings = Field(default_factory=AggregationSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    llm: LlmSettings = Field(default_factory=LlmSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    providers: dict[str, ProviderProfile] = Field(default_factory=dict)
    routing: dict[str, ModelRoute] = Field(default_factory=dict)
    calibration: dict[str, dict[str, float]] = Field(default_factory=dict)
    """Per-detector calibration curve parameters, measured in P8 (LLD 9)."""

    # --- environment-only: paths and runtime knobs -----------------------------------------
    #
    # No provider fields live here. A provider is a base_url plus the *name* of the variable
    # holding its key, declared under talos.providers and read by the router (LLD 8.1). Keeping
    # a second copy of that here is how the two drift apart.

    db_path: Path = Path("talos.db")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("enabled_domains")
    @classmethod
    def _known_domains(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(DOMAINS))
        if unknown:
            raise ValueError(f"unknown domain(s) {unknown}; known domains are {list(DOMAINS)}")
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Highest precedence first: explicit args, environment, .env, then the YAML tree."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            _YamlConfigSource(settings_cls),
            file_secret_settings,
        )

    @classmethod
    def load(cls, config_dir: Path | None = None, overlay: Path | None = None) -> TalosSettings:
        """Build settings from the config tree and the environment.

        Raises :class:`ConfigError` on any invalid value: a process whose thresholds did not
        load must not start and quietly detect nothing.
        """
        global _CONFIG_LOCATION
        previous = _CONFIG_LOCATION
        _CONFIG_LOCATION = (config_dir, overlay)
        try:
            return cls()
        except ValidationError as exc:
            raise ConfigError(f"invalid Talos configuration:\n{exc}") from exc
        finally:
            _CONFIG_LOCATION = previous

    def route_for(self, component: str) -> ModelRoute | None:
        """Return the routing entry for a detector or classifier name, if one is configured."""
        return self.routing.get(component)

    def provider_for(self, name: str) -> ProviderProfile:
        """Return a provider profile by name, or fail loudly naming what is configured."""
        try:
            return self.providers[name]
        except KeyError:
            raise ConfigError(
                f"routing references provider {name!r}, which has no entry under "
                f"talos.providers (configured: {sorted(self.providers)})"
            ) from None
