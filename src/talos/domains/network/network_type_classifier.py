"""Network attack-type routing (LLD 6).

**Static path only in P2.** Auth-bearing telemetry routes to ``network_brute_force``; flow
records return ``unclassified`` -- port scan and DDoS are reserved, not silently mishandled.
P3 adds the model refinement step behind ``llm/prompts/network_type_classifier_route_v1.md``,
on top of this working static short-circuit rather than in place of it.
"""

from __future__ import annotations

from talos.core.agent_contracts import DetectionContext, TypeClassifier
from talos.core.constants import (
    CATEGORY_NETWORK_BRUTE_FORCE,
    CATEGORY_UNCLASSIFIED,
    DOMAIN_NETWORK,
)
from talos.schemas.event_schema import NormalizedEvent

#: Confidence of the static route. Deliberately modest: the static layer is a router, not a
#: detector, and the leaf detector is what carries a calibrated number.
STATIC_AUTH_CONFIDENCE = 0.60

#: Protocols whose failed authentications the brute-force sub-agent handles.
BRUTE_FORCE_PROTOCOLS = frozenset({"ssh", "rdp"})


class NetworkTypeClassifier(TypeClassifier):
    """Routes a network event to the category that owns it."""

    domain = DOMAIN_NETWORK

    async def classify(self, event: NormalizedEvent, ctx: DetectionContext) -> tuple[str, float]:
        if event.auth is not None and event.auth.protocol in BRUTE_FORCE_PROTOCOLS:
            category, confidence = CATEGORY_NETWORK_BRUTE_FORCE, STATIC_AUTH_CONFIDENCE
        else:
            category, confidence = CATEGORY_UNCLASSIFIED, 0.30

        # P3: a small model refines (category, confidence) here, with this pair as the fallback.
        if confidence < ctx.settings.classifier.min_confidence_floor:
            return CATEGORY_UNCLASSIFIED, confidence
        return category, confidence
