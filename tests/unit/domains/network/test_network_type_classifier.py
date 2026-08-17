"""Static routing for the network domain -- no model involved in P2 (LLD 6)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext
from talos.domains.network.network_type_classifier import NetworkTypeClassifier
from talos.schemas.event_schema import NormalizedEvent

EventFactory = Callable[..., NormalizedEvent]


def _classify(ctx: DetectionContext, event: object) -> tuple[str, float]:
    return asyncio.run(NetworkTypeClassifier().classify(event, ctx))  # type: ignore[arg-type]


def test_ssh_auth_routes_to_brute_force(
    detection_ctx: DetectionContext, make_ssh_event: EventFactory
) -> None:
    category, confidence = _classify(detection_ctx, make_ssh_event())
    assert category == "network_brute_force"
    assert confidence == 0.60


def test_rdp_auth_routes_to_the_same_category(
    detection_ctx: DetectionContext, make_ssh_event: EventFactory
) -> None:
    """P5 adds the RDP detector behind the category the classifier already emits."""
    event = make_ssh_event()
    rdp = event.model_copy(update={"auth": event.auth.model_copy(update={"protocol": "rdp"})})  # type: ignore[union-attr]
    assert _classify(detection_ctx, rdp)[0] == "network_brute_force"


def test_flow_only_telemetry_is_unclassified(
    detection_ctx: DetectionContext, make_ssh_event: EventFactory
) -> None:
    """Port scan and DDoS are reserved, not silently mishandled."""
    flow = make_ssh_event().model_copy(update={"auth": None, "telemetry_source": "netflow"})
    assert _classify(detection_ctx, flow)[0] == "unclassified"


def test_confidence_floor_demotes_a_weak_route(
    detection_ctx: DetectionContext, make_ssh_event: EventFactory
) -> None:
    detection_ctx.settings.classifier.min_confidence_floor = 0.9
    assert _classify(detection_ctx, make_ssh_event())[0] == "unclassified"


def test_classifier_does_not_call_a_model(
    detection_ctx: DetectionContext, make_ssh_event: EventFactory
) -> None:
    _classify(detection_ctx, make_ssh_event())
    assert detection_ctx.model_client.prompts == []  # type: ignore[attr-defined]
