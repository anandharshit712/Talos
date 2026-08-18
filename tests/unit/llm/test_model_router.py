"""Route resolution, cross-provider fallback, the penalty, and the no-model path (LLD 8.2/8.3)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from talos.core.error_types import ModelError
from talos.core.settings import TalosSettings, default_config_dir
from talos.llm.model_client import ModelClient
from talos.llm.model_router import ModelRouter, build_router

SCHEMA = {"type": "object", "required": ["narrative"]}
ROUTED = "ssh_brute_force_detector"


class _ScriptedClient(ModelClient):
    """Answers, or fails, exactly as the test says."""

    def __init__(self, reply: dict[str, Any] | None = None, error: str | None = None) -> None:
        self.reply = reply
        self.error = error
        self.calls: list[str] = []

    async def complete(
        self,
        *,
        model: str,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int,
        timeout_s: float,
    ) -> dict[str, Any]:
        self.calls.append(model)
        if self.error is not None:
            raise ModelError(self.error)
        assert self.reply is not None
        return self.reply


@pytest.fixture
def settings() -> TalosSettings:
    """The real routing table, so these tests break when the config does."""
    return TalosSettings.load(config_dir=default_config_dir(), overlay=Path("absent.yaml"))


def _ask(router: ModelRouter, component: str = ROUTED):
    return asyncio.run(router.complete_for(component, prompt="p", schema=SCHEMA))


def test_primary_answer_carries_full_confidence(settings: TalosSettings) -> None:
    route = settings.routing[ROUTED]
    router = ModelRouter(settings, {route.provider: _ScriptedClient({"narrative": "ok"})})
    outcome = _ask(router)
    assert outcome is not None
    assert outcome.data == {"narrative": "ok"}
    assert outcome.model == route.model
    assert outcome.confidence_multiplier == 1.0
    assert route.provider in outcome.route_reason


def test_fallback_answers_when_the_primary_fails(settings: TalosSettings) -> None:
    route = settings.routing[ROUTED]
    assert route.fallback is not None
    primary = _ScriptedClient(error="HTTP 503")
    fallback = _ScriptedClient({"narrative": "from the spare"})
    router = ModelRouter(settings, {route.provider: primary, route.fallback.provider: fallback})
    outcome = _ask(router)
    assert outcome is not None
    assert outcome.model == route.fallback.model
    assert primary.calls and fallback.calls


def test_fallback_costs_confidence_and_says_so(settings: TalosSettings) -> None:
    """A degraded answer must be visibly degraded in the report, not silently equal."""
    route = settings.routing[ROUTED]
    assert route.fallback is not None
    router = ModelRouter(
        settings,
        {
            route.provider: _ScriptedClient(error="timeout"),
            route.fallback.provider: _ScriptedClient({"narrative": "spare"}),
        },
    )
    outcome = _ask(router)
    assert outcome is not None
    assert outcome.confidence_multiplier == settings.llm.fallback_confidence_penalty
    assert "fallback" in outcome.route_reason
    assert route.provider in outcome.route_reason  # names what failed


def test_both_failing_returns_none_not_an_exception(settings: TalosSettings) -> None:
    route = settings.routing[ROUTED]
    assert route.fallback is not None
    router = ModelRouter(
        settings,
        {
            route.provider: _ScriptedClient(error="down"),
            route.fallback.provider: _ScriptedClient(error="also down"),
        },
    )
    assert _ask(router) is None


def test_no_client_for_the_provider_is_not_an_error(settings: TalosSettings) -> None:
    """A fresh clone with no keys must detect, not crash."""
    assert _ask(ModelRouter(settings, {})) is None


def test_unrouted_component_returns_none(settings: TalosSettings) -> None:
    router = ModelRouter(settings, {"nim": _ScriptedClient({"narrative": "ok"})})
    assert _ask(router, "ssrf_detector") is None


def test_missing_primary_key_skips_straight_to_the_fallback(settings: TalosSettings) -> None:
    """One key configured is a supported setup, not a broken one."""
    route = settings.routing[ROUTED]
    assert route.fallback is not None
    fallback = _ScriptedClient({"narrative": "spare"})
    router = ModelRouter(settings, {route.fallback.provider: fallback})
    outcome = _ask(router)
    assert outcome is not None
    assert outcome.model == route.fallback.model
    assert outcome.confidence_multiplier < 1.0


def test_fallbacks_cross_provider_boundaries(settings: TalosSettings) -> None:
    """A fallback on the same provider does not survive that provider being down."""
    for name, route in settings.routing.items():
        if route.fallback is not None:
            assert route.fallback.provider != route.provider, name


def test_build_router_enables_only_providers_with_keys(
    settings: TalosSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    for profile in settings.providers.values():
        monkeypatch.delenv(profile.api_key_env, raising=False)
    assert build_router(settings).providers == []

    monkeypatch.setenv(settings.providers["nim"].api_key_env, "a-key")
    assert build_router(settings).providers == ["nim"]


def test_build_router_ignores_a_blank_key(
    settings: TalosSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(settings.providers["nim"].api_key_env, "   ")
    assert "nim" not in build_router(settings).providers


def test_llm_disabled_yields_no_providers_even_with_keys(
    settings: TalosSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The off switch beats a present key -- otherwise it is not an off switch."""
    for profile in settings.providers.values():
        monkeypatch.setenv(profile.api_key_env, "a-key")
    assert build_router(settings).providers != []

    settings.llm.enabled = False
    assert build_router(settings).providers == []


def test_disabled_router_returns_none_rather_than_raising(
    settings: TalosSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Detectors read None as 'no model reachable', which is their tested fallback path."""
    monkeypatch.setenv(settings.providers["nim"].api_key_env, "a-key")
    settings.llm.enabled = False
    router = build_router(settings)
    component = next(iter(settings.routing))
    assert asyncio.run(router.complete_for(component, prompt="p", schema=SCHEMA)) is None
