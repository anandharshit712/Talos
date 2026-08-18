"""Agent-to-model resolution, with fallback and its penalty (LLD 8.2, 8.3).

A detector names itself and gets an answer. Which provider served it, whether the primary was
tried first, and what a fallback costs in confidence are the router's business — a detector that
knew about providers would have to be edited every time one changed.

Three states, and the third is the interesting one:

* the route's primary answers → full confidence
* the primary fails, the fallback answers → ``confidence_multiplier`` below 1.0, recorded in
  ``route_reason`` so the report says *why* it is less sure
* nothing answers, or nothing is configured → ``None``, and the caller uses its templated path
  with ``used_llm=False``

That third state is deliberately ordinary. No key configured is the normal case on a fresh clone,
and the pipeline has to keep detecting.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from talos.core.agent_contracts import ModelOutcome
from talos.core.error_types import ModelError
from talos.core.settings import ModelRoute, TalosSettings
from talos.llm.model_client import ModelClient, OpenAiCompatibleClient

_log = logging.getLogger(__name__)

DEFAULT_MAX_TOKENS = 512


class ModelRouter:
    """Resolves a component name to a model call, and survives that call failing."""

    def __init__(self, settings: TalosSettings, clients: dict[str, ModelClient]) -> None:
        self._settings = settings
        self._clients = clients

    @property
    def providers(self) -> list[str]:
        """Provider names with a usable client. Empty means every call returns ``None``."""
        return sorted(self._clients)

    async def complete_for(
        self,
        component: str,
        *,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> ModelOutcome | None:
        route = self._settings.route_for(component)
        if route is None:
            _log.debug("no route configured", extra={"component": component})
            return None

        primary = await self._try(
            route.provider, route.model, prompt, schema, max_tokens, component
        )
        if primary is not None:
            return ModelOutcome(
                data=primary,
                model=route.model,
                route_reason=f"{route.tier} tier via {route.provider}",
            )

        if route.fallback is None:
            return None

        penalty = self._settings.llm.fallback_confidence_penalty
        fallback = await self._try(
            route.fallback.provider, route.fallback.model, prompt, schema, max_tokens, component
        )
        if fallback is None:
            _log.warning(
                "primary and fallback both unavailable, using the templated path",
                extra={"component": component},
            )
            return None

        return ModelOutcome(
            data=fallback,
            model=route.fallback.model,
            route_reason=(
                f"{route.tier} tier fallback via {route.fallback.provider} after "
                f"{route.provider} failed; confidence x{penalty}"
            ),
            confidence_multiplier=penalty,
        )

    async def _try(
        self,
        provider: str,
        model: str,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int,
        component: str,
    ) -> dict[str, Any] | None:
        """One attempt against one provider. Never raises -- failure is a routing outcome."""
        client = self._clients.get(provider)
        if client is None:
            _log.debug(
                "provider has no client, skipping",
                extra={"provider": provider, "component": component},
            )
            return None
        try:
            return await client.complete(
                model=model,
                prompt=prompt,
                schema=schema,
                max_tokens=max_tokens,
                timeout_s=self._settings.llm.request_timeout_seconds,
            )
        except ModelError as exc:
            _log.warning(
                "model call failed",
                extra={
                    "provider": provider,
                    "model": model,
                    "component": component,
                    "error": str(exc),
                },
            )
            return None


def build_router(settings: TalosSettings) -> ModelRouter:
    """Build a router with a client for every provider whose key is present.

    A provider without its key is simply absent, so an operator with one key gets that provider
    and templated narratives everywhere else, rather than a stack trace. ``talos.llm.enabled:
    false`` skips every provider, which is how the statistical path is exercised deliberately
    rather than by unsetting secrets.
    """
    clients: dict[str, ModelClient] = {}
    if not settings.llm.enabled:
        _log.info("llm disabled by configuration, statistical path only")
        return ModelRouter(settings, clients)
    for name, profile in settings.providers.items():
        key = os.environ.get(profile.api_key_env, "").strip()
        if not key:
            _log.info(
                "provider key not set, provider disabled",
                extra={"provider": name, "variable": profile.api_key_env},
            )
            continue
        clients[name] = OpenAiCompatibleClient(
            provider=name,
            base_url=profile.base_url,
            api_key=key,
            max_retries=settings.llm.max_retries,
        )
    return ModelRouter(settings, clients)


def routed_models(settings: TalosSettings) -> list[tuple[str, ModelRoute]]:
    """Every configured route, for diagnostics and the availability check."""
    return sorted(settings.routing.items())
