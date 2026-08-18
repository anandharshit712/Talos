"""Both injection detectors run on every request, and neither can take the other down."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from talos.core.agent_contracts import DetectionContext, Detector
from talos.domains.web.injection.injection_sub_agent import InjectionSubAgent
from talos.domains.web.injection.sql_injection_detector import SqlInjectionDetector
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import MitreMapping, Verdict

EventFactory = Callable[..., NormalizedEvent]
UNION = "' UNION SELECT a FROM users--"
SCRIPT = "<script>alert(1)</script>"


class _ExplodingDetector(Detector):
    detector_name = "exploding_detector"
    technique = "sql_injection"
    mitre: MitreMapping = mitre_for("sql_injection")

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        raise RuntimeError("pattern table failed to compile")


def _handle(
    ctx: DetectionContext, event: NormalizedEvent, sub_agent: InjectionSubAgent
) -> list[Verdict]:
    ctx.event_window.add(event)
    return asyncio.run(sub_agent.handle(event, ctx))


def test_category_matches_its_package_name() -> None:
    assert InjectionSubAgent.category == "injection"


def test_a_sql_payload_produces_one_verdict(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    verdicts = _handle(detection_ctx, make_web_event(query={"id": UNION}), InjectionSubAgent())
    assert [v.technique for v in verdicts] == ["sql_injection"]


def test_a_request_carrying_both_payloads_produces_both_verdicts(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """One request can be two attacks; the aggregator is built to merge them."""
    event = make_web_event(query={"id": UNION, "q": SCRIPT})
    verdicts = _handle(detection_ctx, event, InjectionSubAgent())
    assert sorted(v.technique for v in verdicts) == ["sql_injection", "xss"]


def test_clean_traffic_produces_nothing(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    assert _handle(detection_ctx, make_web_event(query={"q": "shoes"}), InjectionSubAgent()) == []


def test_a_raising_detector_does_not_silence_its_sibling(
    detection_ctx: DetectionContext, make_web_event: EventFactory
) -> None:
    """Fail-open for detection: a broken pattern table must not take the working one with it."""
    sub_agent = InjectionSubAgent(detectors=[_ExplodingDetector(), SqlInjectionDetector()])
    verdicts = _handle(detection_ctx, make_web_event(query={"id": UNION}), sub_agent)
    assert [v.detector for v in verdicts] == ["sql_injection_detector"]
