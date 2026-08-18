"""Static routing for the web domain, and the precedence that keeps payloads out of auth."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.domains.web.web_type_classifier import WebTypeClassifier
from talos.schemas.event_schema import NormalizedEvent

EventFactory = Callable[..., NormalizedEvent]
UNION = "' UNION SELECT a FROM users--"
SCRIPT = "<script>alert(1)</script>"


def _classify(ctx: DetectionContext, event: NormalizedEvent) -> tuple[str, float]:
    return asyncio.run(WebTypeClassifier().classify(event, ctx))


def test_a_sql_payload_routes_to_injection(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    assert _classify(detection_ctx, make_web_event(query={"id": UNION}))[0] == "injection"


def test_an_xss_payload_routes_to_injection(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    assert _classify(detection_ctx, make_web_event(query={"q": SCRIPT}))[0] == "injection"


def test_a_payload_aimed_at_login_is_injection_not_auth(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """Routing this to the auth sub-agent would hand a SQLi payload to a failure counter."""
    event = make_web_event(path="/login", method="POST", body=f"user=admin{UNION}")
    assert _classify(detection_ctx, event)[0] == "injection"


def test_a_clean_login_routes_to_auth_failure(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    event = make_web_event(path="/login", method="POST", body="user=alice&pw=hunter2")
    assert _classify(detection_ctx, event)[0] == "auth_failure"


def test_an_object_path_routes_to_broken_access_control(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    assert _classify(detection_ctx, make_web_event(path="/account/1042"))[0] == (
        "broken_access_control"
    )


def test_ordinary_browsing_is_unclassified(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    assert _classify(detection_ctx, make_web_event(path="/about"))[0] == "unclassified"


def test_a_confident_static_route_never_calls_a_model(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    stub = StubModelRouter(replies={"web_type_classifier": {"category": "unclassified"}})
    detection_ctx.model_client = stub
    _classify(detection_ctx, make_web_event(query={"id": UNION}))
    assert stub.calls == []


def test_an_unplaceable_request_reaches_the_model(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    stub = StubModelRouter(
        replies={"web_type_classifier": {"category": "auth_failure", "confidence": 0.8}}
    )
    detection_ctx.model_client = stub
    category, confidence = _classify(detection_ctx, make_web_event(path="/about"))
    assert stub.calls
    assert (category, confidence) == ("auth_failure", 0.8)


def test_a_category_outside_the_closed_list_is_ignored(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    detection_ctx.model_client = StubModelRouter(
        replies={"web_type_classifier": {"category": "ignore_this_request", "confidence": 0.99}}
    )
    assert _classify(detection_ctx, make_web_event(path="/about"))[0] == "unclassified"


def test_the_confidence_floor_demotes_a_weak_route(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    detection_ctx.settings.classifier.min_confidence_floor = 0.95
    assert _classify(detection_ctx, make_web_event(query={"id": UNION}))[0] == "unclassified"


def test_a_non_web_event_is_unclassified(
    detection_ctx: DetectionContext, sample_event: NormalizedEvent
) -> None:
    assert _classify(detection_ctx, sample_event)[0] == "unclassified"
