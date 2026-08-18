"""Configuration precedence and validation (LLD 10).

Precedence is the whole point of the module, so it is tested as a ladder: base files, then the
overlay, then the environment, each beating the one below while leaving untouched keys alone.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from talos.core.error_types import ConfigError
from talos.core.settings import TalosSettings, default_config_dir, load_env_file

BASE_YAML = """
talos:
  detection:
    ssh_brute_force: { window_seconds: 120, fail_threshold: 8 }
  classifier:
    min_confidence_floor: 0.35
"""


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No TALOS_* leakage from the developer's shell, and no stray .env in the way."""
    for key in list(os.environ):
        if key.startswith("TALOS_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


def _config_dir(tmp_path: Path, **files: str) -> Path:
    directory = tmp_path / "config"
    directory.mkdir(exist_ok=True)
    (directory / "default.yaml").write_text(BASE_YAML, encoding="utf-8")
    for name, content in files.items():
        (directory / f"{name}.yaml").write_text(content, encoding="utf-8")
    return directory


def test_repository_config_loads(tmp_path: Path) -> None:
    """The committed config/ tree is valid, which is the only way the CLI ever starts."""
    settings = TalosSettings.load(config_dir=default_config_dir(), overlay=tmp_path / "absent.yaml")
    assert settings.detection.ssh_brute_force.fail_threshold == 8
    assert settings.detection.credential_stuffing.distinct_accounts == 15
    assert settings.classifier.min_confidence_floor == 0.35
    assert settings.llm.fallback_confidence_penalty == 0.85
    route = settings.routing["sql_injection_detector"]
    assert route.tier == "code"
    assert route.provider in settings.providers
    assert route.fallback is not None
    assert route.fallback.provider in settings.providers
    assert settings.provider_for("nim").api_key_env == "TALOS_NIM_API_KEY"


def test_defaults_stand_when_no_config_exists(tmp_path: Path) -> None:
    settings = TalosSettings.load(config_dir=tmp_path / "nowhere")
    assert settings.detection.ssh_brute_force.fail_threshold == 8
    assert settings.enabled_domains == ["web", "network"]
    assert settings.routing == {}


def test_overlay_beats_base_and_leaves_siblings_alone(tmp_path: Path) -> None:
    directory = _config_dir(tmp_path)
    overlay = directory / "local.yaml"
    overlay.write_text(
        "talos:\n  detection:\n    ssh_brute_force: { fail_threshold: 3 }\n", encoding="utf-8"
    )
    settings = TalosSettings.load(config_dir=directory)
    assert settings.detection.ssh_brute_force.fail_threshold == 3
    assert settings.detection.ssh_brute_force.window_seconds == 120


def test_environment_beats_the_overlay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = _config_dir(tmp_path)
    (directory / "local.yaml").write_text(
        "talos:\n  detection:\n    ssh_brute_force: { fail_threshold: 3 }\n", encoding="utf-8"
    )
    monkeypatch.setenv("TALOS_DETECTION__SSH_BRUTE_FORCE__FAIL_THRESHOLD", "2")
    settings = TalosSettings.load(config_dir=directory)
    assert settings.detection.ssh_brute_force.fail_threshold == 2
    assert settings.detection.ssh_brute_force.window_seconds == 120


def test_env_file_loads_keys_without_overriding_the_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider keys are not settings fields, so this is the only thing that puts them in the
    environment. A value already exported is a deliberate choice and must survive."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "# a comment",
                "TALOS_NIM_API_KEY=from-file",
                "TALOS_GROQ_API_KEY=also-from-file",
                "TALOS_MISTRAL_API_KEY=",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("TALOS_NIM_API_KEY", "from-shell")

    loaded = load_env_file(env_file)

    assert loaded == ["TALOS_GROQ_API_KEY", "TALOS_NIM_API_KEY"], "blank values are not keys"
    assert os.environ["TALOS_NIM_API_KEY"] == "from-shell", "the shell wins"
    assert os.environ["TALOS_GROQ_API_KEY"] == "also-from-file"
    assert "from-file" not in str(loaded), "names are returned, never values"


def test_missing_env_file_is_not_an_error(tmp_path: Path) -> None:
    assert load_env_file(tmp_path / "absent") == []


def test_env_example_documents_only_real_settings(tmp_path: Path) -> None:
    """.env.example lists ~20 variables and their defaults by hand. Hand-written reference
    documentation rots silently; this is the only thing that stops it."""
    example = Path(__file__).resolve().parents[3] / ".env.example"
    pattern = re.compile(r"^#?\s*(TALOS_[A-Z0-9_]+)=(.*)$", re.MULTILINE)
    documented = pattern.findall(example.read_text(encoding="utf-8"))
    assert len(documented) > 15, "the reference section vanished"

    # Keys and loader inputs are read from os.environ directly, not through a settings field.
    not_fields = {
        "TALOS_NIM_API_KEY",
        "TALOS_GROQ_API_KEY",
        "TALOS_MISTRAL_API_KEY",
        "TALOS_CONFIG_DIR",
        "TALOS_CONFIG_PATH",
    }
    settings = TalosSettings.load(config_dir=default_config_dir(), overlay=tmp_path / "absent.yaml")

    for name, shown in documented:
        if name in not_fields:
            continue
        value: object = settings
        for part in name.removeprefix("TALOS_").lower().split("__"):
            value = value[part] if isinstance(value, dict) else getattr(value, part, _MISSING)
            assert value is not _MISSING, f"{name} names no setting"
        assert _same_value(shown.strip(), value), f"{name} documents {shown!r}, actual {value!r}"


_MISSING = object()


def _same_value(shown: str, actual: object) -> bool:
    if isinstance(actual, Path):
        return Path(shown) == actual
    try:
        return json.loads(shown) == actual
    except ValueError:
        return shown == str(actual)


def test_llm_switches_off_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """.env.example documents TALOS_LLM__ENABLED=false; this is the assertion behind that line."""
    directory = _config_dir(tmp_path)
    assert TalosSettings.load(config_dir=directory).llm.enabled is True

    monkeypatch.setenv("TALOS_LLM__ENABLED", "false")
    settings = TalosSettings.load(config_dir=directory)
    assert settings.llm.enabled is False
    assert settings.llm.max_payload_chars == 2000


def test_settings_cannot_hold_a_credential(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No key is a settings field, so nothing here can log or serialise one.

    Provider keys are read by the router from the variable each provider names in
    ``api_key_env``. A settings field holding the key would be a second copy that drifts.
    """
    monkeypatch.setenv("TALOS_NIM_API_KEY", "nvapi-secret")
    settings = TalosSettings.load(config_dir=_config_dir(tmp_path))
    assert "nvapi-secret" not in repr(settings)
    assert "nvapi-secret" not in settings.model_dump_json()
    assert not [name for name in type(settings).model_fields if "key" in name]


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("talos:\n  detection:\n    ssh_brute_force: { fail_threshold: 0 }\n", "zero threshold"),
        ("talos:\n  classifier:\n    min_confidence_flor: 0.4\n", "mistyped key"),
        ("talos:\n  enabled_domains: [mars]\n", "unknown domain"),
        ("detection:\n  ssh_brute_force: { fail_threshold: 4 }\n", "missing talos: root"),
        ("talos: [not, a, mapping]\n", "root is not a mapping"),
    ],
)
def test_bad_configuration_is_fatal(tmp_path: Path, content: str, reason: str) -> None:
    """A process whose config did not load must not start and quietly detect nothing."""
    directory = _config_dir(tmp_path)
    (directory / "local.yaml").write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        TalosSettings.load(config_dir=directory)


def test_config_path_environment_variable_selects_the_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _config_dir(tmp_path)
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_text(
        "talos:\n  detection:\n    ssh_brute_force: { fail_threshold: 5 }\n", encoding="utf-8"
    )
    monkeypatch.setenv("TALOS_CONFIG_PATH", str(elsewhere))
    assert TalosSettings.load(config_dir=directory).detection.ssh_brute_force.fail_threshold == 5


def test_route_for_unrouted_component_is_none(tmp_path: Path) -> None:
    settings = TalosSettings.load(config_dir=_config_dir(tmp_path))
    assert settings.route_for("ssrf_detector") is None


def test_every_route_names_a_configured_provider() -> None:
    """A routing entry pointing at an undeclared provider is a startup failure, not a 404."""
    settings = TalosSettings.load(config_dir=default_config_dir(), overlay=Path("absent.yaml"))
    for name, route in settings.routing.items():
        assert route.provider in settings.providers, name
        if route.fallback is not None:
            assert route.fallback.provider in settings.providers, name


def test_unknown_provider_fails_loudly(tmp_path: Path) -> None:
    settings = TalosSettings.load(config_dir=_config_dir(tmp_path))
    with pytest.raises(ConfigError, match=r"has no entry under talos\.providers"):
        settings.provider_for("carrier-pigeon")


def test_provider_profiles_carry_no_secrets() -> None:
    """Config names the environment variable; the key itself never enters the YAML tree."""
    settings = TalosSettings.load(config_dir=default_config_dir(), overlay=Path("absent.yaml"))
    for profile in settings.providers.values():
        assert profile.api_key_env.startswith("TALOS_")
        assert profile.base_url.startswith("https://")
