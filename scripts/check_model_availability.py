"""Ping every model in ``config/model_routing.yaml`` and report which ones answer.

A free-tier model can be withdrawn at short notice, and a routing entry that 404s is only
discovered when a detector needs it -- which, on the current schedule, would be during
evaluation or a demo. This script turns that into a five-second check.

It reads the routing table rather than carrying its own list, so it cannot drift from what the
pipeline will actually call. Keys come from the environment (or ``.env``) and are never printed.

Usage::

    python scripts/check_model_availability.py              # every routed model
    python scripts/check_model_availability.py --provider nim
    python scripts/check_model_availability.py --primary-only

Exit code is non-zero when any checked model failed, so CI can gate on it.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from talos.core.settings import (  # noqa: E402 - path set up immediately above
    TalosSettings,
    load_env_file,
)

#: Small enough to cost nothing, long enough to prove the model generates.
PROBE_MESSAGES = [{"role": "user", "content": "Reply with the single word: ok"}]
PROBE_MAX_TOKENS = 8
PROBE_TIMEOUT_S = 45.0


@dataclass
class Probe:
    """One model to check, and where it came from."""

    agent: str
    role: str  # "primary" or "fallback"
    provider: str
    model: str


@dataclass
class Result:
    probe: Probe
    ok: bool
    detail: str
    latency_ms: int


def probes_from(settings: TalosSettings, primary_only: bool) -> list[Probe]:
    """Every model the routing table points at, primary first, de-duplicated."""
    found: list[Probe] = []
    seen: set[tuple[str, str]] = set()
    for agent, route in sorted(settings.routing.items()):
        candidates = [Probe(agent, "primary", route.provider, route.model)]
        if route.fallback is not None and not primary_only:
            candidates.append(
                Probe(agent, "fallback", route.fallback.provider, route.fallback.model)
            )
        for probe in candidates:
            key = (probe.provider, probe.model)
            if key in seen:
                continue
            seen.add(key)
            found.append(probe)
    return found


def check_key(settings: TalosSettings, provider: str) -> str | None:
    """Return the API key for a provider, or ``None`` when its variable is unset."""
    return os.environ.get(settings.provider_for(provider).api_key_env, "").strip() or None


def probe_model(settings: TalosSettings, probe: Probe, key: str) -> Result:
    """Send one tiny completion and classify what came back."""
    profile = settings.provider_for(probe.provider)
    started = time.monotonic()
    try:
        response = httpx.post(
            f"{profile.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": probe.model,
                "messages": PROBE_MESSAGES,
                "max_tokens": PROBE_MAX_TOKENS,
                "temperature": 0,
            },
            timeout=PROBE_TIMEOUT_S,
        )
    except httpx.HTTPError as exc:
        return Result(probe, False, f"transport: {type(exc).__name__}", _ms(started))

    elapsed = _ms(started)
    if response.status_code == 200:
        return Result(probe, True, _first_words(response.json()), elapsed)
    return Result(probe, False, f"HTTP {response.status_code}: {_error_text(response)}", elapsed)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _first_words(payload: dict[str, Any], limit: int = 40) -> str:
    """The model's own reply, trimmed -- proof it generated rather than merely accepted."""
    try:
        content = payload["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return "200 but no message content"
    flattened = " ".join(str(content).split())
    return flattened[:limit] or "200, empty reply"


def _error_text(response: httpx.Response, limit: int = 120) -> str:
    """The provider's error message, never the request that carried the key."""
    try:
        body = response.json()
    except ValueError:
        return " ".join(response.text.split())[:limit]
    if isinstance(body, dict):
        error = body.get("error") or body.get("detail") or body
        if isinstance(error, dict):
            error = error.get("message") or error
        return " ".join(str(error).split())[:limit]
    return " ".join(str(body).split())[:limit]


def report(results: list[Result], missing_keys: list[str]) -> int:
    """Print a table and return the exit code."""
    width = max((len(r.probe.model) for r in results), default=10)
    print(f"\n{'STATUS':7} {'PROVIDER':8} {'MODEL':{width}} {'MS':>6}  DETAIL")
    print("-" * (7 + 9 + width + 9 + 40))
    for result in results:
        status = "ok" if result.ok else "FAIL"
        print(
            f"{status:7} {result.probe.provider:8} {result.probe.model:{width}} "
            f"{result.latency_ms:6}  {result.detail}"
        )

    failures = [r for r in results if not r.ok]
    print()
    for provider in missing_keys:
        print(f"  skipped {provider}: its API key variable is unset")
    print(f"{len(results) - len(failures)}/{len(results)} models responded")
    if failures:
        print("\nRouting entries that will not work as configured:")
        for result in failures:
            print(f"  {result.probe.agent} ({result.probe.role}) -> {result.probe.model}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that every routed model responds.")
    parser.add_argument("--provider", help="check only one provider (nim, groq, mistral)")
    parser.add_argument("--primary-only", action="store_true", help="skip fallback models")
    parser.add_argument("--config-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    load_env_file(REPO_ROOT / ".env")
    settings = TalosSettings.load(config_dir=args.config_dir)
    if not settings.routing:
        print("no routing table configured", file=sys.stderr)
        return 2

    probes = probes_from(settings, args.primary_only)
    if args.provider:
        probes = [p for p in probes if p.provider == args.provider]

    results: list[Result] = []
    missing_keys: list[str] = []
    for probe in probes:
        key = check_key(settings, probe.provider)
        if key is None:
            if probe.provider not in missing_keys:
                missing_keys.append(probe.provider)
            continue
        results.append(probe_model(settings, probe, key))

    return report(results, missing_keys)


if __name__ == "__main__":
    sys.exit(main())
