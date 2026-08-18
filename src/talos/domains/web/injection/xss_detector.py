"""Cross-site scripting -- ``technique="xss"``, MITRE T1059.007, OWASP A03 (LLD 7.2).

Same shape as the SQL detector: deterministic patterns decide, the model judges only what they
flag as borderline, and corroboration-grade noise is cleared without either.

**Reflected versus stored is the part that needs the event window.** A payload that comes back in
the same response is reflected -- one victim, the person who clicked. The same payload signature
arriving at one endpoint and later appearing at a *different* one is stored: it is now in the
application's data, and every subsequent visitor renders it. That distinction changes who is
affected, so it belongs in scope rather than in prose.

Stored detection is best-effort by design. It sees a second sighting only if both requests are
still inside the event window, so a payload planted on Monday and rendered on Friday reads as
reflected. Recorded as a known limitation rather than implied to be complete.
"""

from __future__ import annotations

import uuid

from talos.core.agent_contracts import DetectionContext, Detector, ModelOutcome
from talos.core.constants import CATEGORY_INJECTION, DOMAIN_WEB, MODEL_NAME_NONE
from talos.detection.patterns.pattern_engine import (
    PatternHit,
    affected_fields,
    distinct_classes,
    extract_web_payloads,
    is_actionable,
    match_patterns,
)
from talos.detection.patterns.xss_pattern_rules import (
    REFLECTED_STATUS,
    XSS_RULES,
    is_unambiguous,
    payload_signature,
)
from talos.knowledge.mitre_mapping import mitre_for
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict
from talos.storage.event_window_store import source_ip_key

#: Certainty for a decisive pattern -- an actual script element, a bound event handler.
STATIC_CONFIDENCE = 0.93

#: A borderline payload with no model available is a lead, not a finding.
BORDERLINE_FALLBACK_CONFIDENCE = 0.42

#: A stored payload affects every later visitor, so it outranks a reflected one.
STORED_CONFIDENCE_FLOOR = 0.9

JUDGE_SCHEMA = {"type": "object", "required": ["is_xss", "confidence"]}
JUDGE_MAX_TOKENS = 300

#: How far back to look for the same payload arriving at another endpoint.
STORED_LOOKBACK_SECONDS = 900


class XssDetector(Detector):
    """Pattern pre-filter, model for the obfuscated cases, event window for stored-vs-reflected."""

    detector_name = "xss_detector"
    technique = "xss"
    mitre = mitre_for("xss")

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        payloads = extract_web_payloads(event)
        if not payloads:
            return None

        hits = match_patterns(payloads, XSS_RULES)
        if not is_actionable(hits):
            return None

        outcome: ModelOutcome | None = None
        if is_unambiguous(hits):
            confidence = STATIC_CONFIDENCE
            reasoning = _static_reasoning(hits)
        else:
            outcome = await self._judge(event, hits, payloads, ctx)
            if outcome is None:
                confidence = BORDERLINE_FALLBACK_CONFIDENCE
                reasoning = (
                    f"{_static_reasoning(hits)} No model was reachable to judge the obfuscated "
                    f"payload, so this is reported as a lead rather than a finding."
                )
            elif not outcome.data.get("is_xss", False):
                return None
            else:
                confidence = _judged_confidence(outcome)
                reasoning = str(outcome.data.get("reasoning") or _static_reasoning(hits))

        variant, echoed_endpoints = self._classify_variant(event, hits, ctx)
        if variant == "stored":
            confidence = max(confidence, STORED_CONFIDENCE_FLOOR)
            reasoning = (
                f"{reasoning} The same payload signature was already seen at "
                f"{', '.join(echoed_endpoints)}, so it is stored rather than reflected: every "
                f"later visitor to those endpoints renders it."
            )

        return Verdict(
            verdict_id=uuid.uuid4().hex,
            event_ids=[event.event_id],
            detector=self.detector_name,
            domain=DOMAIN_WEB,
            category=CATEGORY_INJECTION,
            technique=self.technique,
            attack_detected=True,
            confidence=round(confidence, 3),
            mitre=self.mitre,
            scope=_scope(event, echoed_endpoints),
            evidence=_evidence(event, hits, variant),
            reasoning=reasoning,
            model=(
                ModelInfo(name=outcome.model, route_reason=outcome.route_reason, used_llm=True)
                if outcome is not None
                else ModelInfo(
                    name=MODEL_NAME_NONE,
                    route_reason="deterministic pattern match, no model needed",
                    used_llm=False,
                )
            ),
        )

    def _classify_variant(
        self, event: NormalizedEvent, hits: list[PatternHit], ctx: DetectionContext
    ) -> tuple[str, list[str]]:
        """``stored`` when this payload signature already appeared at another endpoint.

        Returns the variant and the other endpoints that carried it, which become report scope.
        """
        signature = payload_signature(hits)
        if not signature:
            return "reflected", []

        endpoints: set[str] = set()
        recent = ctx.event_window.query(key=source_ip_key(event), within=STORED_LOOKBACK_SECONDS)
        for earlier in recent:
            if earlier.event_id == event.event_id or earlier.target.endpoint is None:
                continue
            if earlier.target.endpoint == event.target.endpoint:
                continue
            earlier_hits = match_patterns(extract_web_payloads(earlier), XSS_RULES)
            if earlier_hits and payload_signature(earlier_hits) == signature:
                endpoints.add(earlier.target.endpoint)

        return ("stored", sorted(endpoints)) if endpoints else ("reflected", [])

    async def _judge(
        self,
        event: NormalizedEvent,
        hits: list[PatternHit],
        payloads: dict[str, str],
        ctx: DetectionContext,
    ) -> ModelOutcome | None:
        limit = ctx.settings.llm.max_payload_chars
        prompt = render_prompt(
            "xss_detector_judge_v1",
            endpoint=event.target.endpoint or "unknown",
            method=event.request.method if event.request else "unknown",
            status=event.request.status_code if event.request else "unknown",
            pattern_classes=", ".join(distinct_classes(hits)) or "none",
            rule_names=", ".join(sorted({hit.name for hit in hits})),
            observed=seal_payload(
                " | ".join(f"{field}: {value}" for field, value in payloads.items()), limit
            ),
        )
        return await ctx.model_client.complete_for(
            self.detector_name, prompt=prompt, schema=JUDGE_SCHEMA, max_tokens=JUDGE_MAX_TOKENS
        )


def infer_reflected(event: NormalizedEvent) -> bool | None:
    """Did the payload come back to the requester? ``None`` when the log does not say."""
    status = event.request.status_code if event.request else None
    if status is None:
        return None
    return status in REFLECTED_STATUS


def _scope(event: NormalizedEvent, echoed_endpoints: list[str]) -> Scope:
    endpoints = [event.target.endpoint] if event.target.endpoint else []
    endpoints.extend(endpoint for endpoint in echoed_endpoints if endpoint not in endpoints)
    return Scope(
        affected_endpoints=sorted(endpoints),
        affected_hosts=[event.target.host] if event.target.host else [],
        affected_accounts=[event.actor.account] if event.actor.account else [],
        attempt_count=1,
        source_diversity=1,
        succeeded=infer_reflected(event),
        window_start=event.timestamp,
        window_end=event.timestamp,
    )


def _evidence(event: NormalizedEvent, hits: list[PatternHit], variant: str) -> list[Evidence]:
    evidence = [
        Evidence(kind="matched_pattern", detail=hit.describe(), references=[event.event_id])
        for hit in hits
    ]
    evidence.append(
        Evidence(
            kind="statistic",
            detail=f"payload classified as {variant} XSS",
            references=[event.event_id],
        )
    )
    evidence.append(Evidence(kind="log_line", detail=event.raw, references=[event.event_id]))
    return evidence


def _static_reasoning(hits: list[PatternHit]) -> str:
    classes = ", ".join(distinct_classes(hits))
    fields = ", ".join(affected_fields(hits))
    return (
        f"Cross-site scripting patterns matched in {fields}: {classes}. "
        f"{len(hits)} rule(s) fired on request content."
    )


def _judged_confidence(outcome: ModelOutcome) -> float:
    try:
        confidence = float(outcome.data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = BORDERLINE_FALLBACK_CONFIDENCE
    return min(max(confidence, 0.0), 1.0) * outcome.confidence_multiplier
