"""Network attack-type routing (LLD 6).

**Static first, model only on the ambiguous ones.** Auth-bearing telemetry routes to
``network_brute_force`` on cheap signals alone. Only events the static pass cannot place -- the
ones that would otherwise be dropped as ``unclassified`` -- are put to a model, and even then its
answer is accepted only if it names a category from the closed list.

That ordering is not an optimisation. The free tier allows roughly 40 requests per minute, so a
model call on every event would cap the pipeline below the speed of reading the log file (see
``../../../../docs/research/Talos_Model_Selection_Research.md`` 7). Static-first is what keeps
throughput a property of the parser rather than of a provider.
"""

from __future__ import annotations

import logging

from talos.core.agent_contracts import DetectionContext, TypeClassifier
from talos.core.constants import (
    CATEGORY_NETWORK_BRUTE_FORCE,
    CATEGORY_UNCLASSIFIED,
    DOMAIN_NETWORK,
)
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.event_schema import NormalizedEvent

_log = logging.getLogger(__name__)

#: Confidence of the static route. Deliberately modest: the static layer is a router, not a
#: detector, and the leaf detector is what carries a calibrated number.
STATIC_AUTH_CONFIDENCE = 0.60

#: What the static pass scores an event it cannot place. Below the floor by design, so these
#: are exactly the events that reach the model.
UNCLASSIFIED_CONFIDENCE = 0.30

#: Protocols whose failed authentications the brute-force sub-agent handles.
BRUTE_FORCE_PROTOCOLS = frozenset({"ssh", "rdp"})

#: The only categories this classifier may emit. A model naming anything else is ignored.
ALLOWED_CATEGORIES = frozenset({CATEGORY_NETWORK_BRUTE_FORCE, CATEGORY_UNCLASSIFIED})

#: Routing is a small decision; it does not need a long reply.
ROUTE_SCHEMA = {"type": "object", "required": ["category", "confidence"]}
ROUTE_MAX_TOKENS = 160


class NetworkTypeClassifier(TypeClassifier):
    """Routes a network event to the category that owns it."""

    domain = DOMAIN_NETWORK

    async def classify(self, event: NormalizedEvent, ctx: DetectionContext) -> tuple[str, float]:
        if event.auth is not None and event.auth.protocol in BRUTE_FORCE_PROTOCOLS:
            static = (CATEGORY_NETWORK_BRUTE_FORCE, STATIC_AUTH_CONFIDENCE)
        else:
            static = (CATEGORY_UNCLASSIFIED, UNCLASSIFIED_CONFIDENCE)

        category, confidence = static
        if confidence < ctx.settings.classifier.min_confidence_floor:
            # Only what the static pass could not place is worth a model call.
            category, confidence = await self._refine(event, static, ctx)

        if confidence < ctx.settings.classifier.min_confidence_floor:
            return CATEGORY_UNCLASSIFIED, confidence
        return category, confidence

    async def _refine(
        self, event: NormalizedEvent, static: tuple[str, float], ctx: DetectionContext
    ) -> tuple[str, float]:
        """Put an ambiguous event to the routing model. Falls back to the static answer.

        The model is a second opinion on routing, never an authority: a category outside the
        closed list, an unparseable confidence, or no model at all leaves ``static`` standing.
        """
        prompt = render_prompt(
            "network_type_classifier_route_v1",
            telemetry_source=event.telemetry_source,
            protocol=event.auth.protocol if event.auth else "none",
            outcome=event.auth.outcome if event.auth else "none",
            static_category=static[0],
            static_confidence=static[1],
            # Host, account, and the line itself all come from the log, so all three are
            # attacker-chosen: sealed together rather than quoted as facts (HLD 11/13).
            observed=seal_payload(
                f"host: {event.target.host or 'unknown'} | "
                f"account: {event.actor.account or 'unknown'} | "
                f"raw: {event.raw}",
                ctx.settings.llm.max_payload_chars,
            ),
        )
        outcome = await ctx.model_client.complete_for(
            "network_type_classifier",
            prompt=prompt,
            schema=ROUTE_SCHEMA,
            max_tokens=ROUTE_MAX_TOKENS,
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
        confidence = min(max(confidence, 0.0), 1.0) * outcome.confidence_multiplier
        return category, round(confidence, 3)
