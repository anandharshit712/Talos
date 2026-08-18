"""Web attack-type routing (LLD 6).

Cheap static signals first, exactly as the network classifier does, and for the same reason: at
roughly 40 requests per minute a model call per event would cap the pipeline below the speed of
reading the log file. Only events the static pass cannot place reach a model, and its answer is
accepted only if it names a category from the closed list.

The order of the checks matters. Injection markers are tested before the auth-endpoint check,
because a payload posted to `/login` is an injection attempt against the login form, not a
failed login — and routing it to the auth sub-agent would hand a SQLi payload to a detector that
counts failures.
"""

from __future__ import annotations

import logging
import re

from talos.core.agent_contracts import DetectionContext, TypeClassifier
from talos.core.constants import (
    CATEGORY_AUTH_FAILURE,
    CATEGORY_BROKEN_ACCESS_CONTROL,
    CATEGORY_INJECTION,
    CATEGORY_UNCLASSIFIED,
    DOMAIN_WEB,
)
from talos.detection.patterns.pattern_engine import (
    extract_web_payloads,
    is_actionable,
    match_patterns,
)
from talos.detection.patterns.sql_injection_pattern_rules import SQL_INJECTION_RULES
from talos.detection.patterns.xss_pattern_rules import XSS_RULES
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.event_schema import NormalizedEvent

_log = logging.getLogger(__name__)

#: Paths that mean "this request is an authentication attempt".
AUTH_ENDPOINT = re.compile(
    r"/(?:login|signin|sign-in|auth|authenticate|session|token|oauth|register|password)", re.I
)

#: A path ending in an identifier is an object access -- the raw material for IDOR (P6).
OBJECT_PATH = re.compile(r"/(?:\d+|[0-9a-f]{8,})/?$", re.I)

#: Static confidences. Deliberately modest: the classifier routes, the detector decides.
INJECTION_CONFIDENCE = 0.7
AUTH_CONFIDENCE = 0.6
OBJECT_ACCESS_CONFIDENCE = 0.5
UNCLASSIFIED_CONFIDENCE = 0.3

ALLOWED_CATEGORIES = frozenset(
    {
        CATEGORY_INJECTION,
        CATEGORY_AUTH_FAILURE,
        CATEGORY_BROKEN_ACCESS_CONTROL,
        CATEGORY_UNCLASSIFIED,
    }
)

ROUTE_SCHEMA = {"type": "object", "required": ["category", "confidence"]}
ROUTE_MAX_TOKENS = 160


class WebTypeClassifier(TypeClassifier):
    """Routes a web event to the category that owns it."""

    domain = DOMAIN_WEB

    async def classify(self, event: NormalizedEvent, ctx: DetectionContext) -> tuple[str, float]:
        static = self._static_route(event)
        category, confidence = static

        if confidence < ctx.settings.classifier.min_confidence_floor:
            category, confidence = await self._refine(event, static, ctx)

        if confidence < ctx.settings.classifier.min_confidence_floor:
            return CATEGORY_UNCLASSIFIED, confidence
        return category, confidence

    def _static_route(self, event: NormalizedEvent) -> tuple[str, float]:
        """Cheap signals only: pattern markers, then endpoint shape."""
        if event.request is None:
            return CATEGORY_UNCLASSIFIED, UNCLASSIFIED_CONFIDENCE

        payloads = extract_web_payloads(event)
        if self._has_injection_markers(payloads):
            # Checked first: a payload aimed at /login is injection, not a failed login.
            return CATEGORY_INJECTION, INJECTION_CONFIDENCE

        path = event.request.path or ""
        if AUTH_ENDPOINT.search(path):
            return CATEGORY_AUTH_FAILURE, AUTH_CONFIDENCE
        if OBJECT_PATH.search(path) or event.target.resource_id:
            return CATEGORY_BROKEN_ACCESS_CONTROL, OBJECT_ACCESS_CONFIDENCE
        return CATEGORY_UNCLASSIFIED, UNCLASSIFIED_CONFIDENCE

    def _has_injection_markers(self, payloads: dict[str, str]) -> bool:
        """Reuses the detectors' own tables, so routing cannot disagree with detection."""
        if not payloads:
            return False
        return is_actionable(match_patterns(payloads, SQL_INJECTION_RULES)) or is_actionable(
            match_patterns(payloads, XSS_RULES)
        )

    async def _refine(
        self, event: NormalizedEvent, static: tuple[str, float], ctx: DetectionContext
    ) -> tuple[str, float]:
        """Put an unplaceable request to the routing model; keep the static answer otherwise."""
        request = event.request
        prompt = render_prompt(
            "web_type_classifier_route_v1",
            method=request.method if request else "unknown",
            status=request.status_code if request else "unknown",
            telemetry_source=event.telemetry_source,
            static_category=static[0],
            static_confidence=static[1],
            observed=seal_payload(
                " | ".join(
                    [
                        f"path: {request.path if request else 'unknown'}",
                        f"host: {event.target.host or 'unknown'}",
                        f"account: {event.actor.account or 'unknown'}",
                        *(f"{key}: {value}" for key, value in extract_web_payloads(event).items()),
                    ]
                ),
                ctx.settings.llm.max_payload_chars,
            ),
        )
        outcome = await ctx.model_client.complete_for(
            "web_type_classifier", prompt=prompt, schema=ROUTE_SCHEMA, max_tokens=ROUTE_MAX_TOKENS
        )
        if outcome is None:
            return static

        category = str(outcome.data.get("category", "")).strip()
        if category not in ALLOWED_CATEGORIES:
            _log.warning(
                "routing model proposed a category outside the closed list, ignoring it",
                extra={"proposed": category[:40], "event_id": event.event_id},
            )
            return static
        try:
            confidence = float(outcome.data.get("confidence", 0.0))
        except (TypeError, ValueError):
            return static
        return category, round(min(max(confidence, 0.0), 1.0) * outcome.confidence_multiplier, 3)
