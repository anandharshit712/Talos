"""SQL injection -- ``technique="sql_injection"``, MITRE T1190, OWASP A03 (LLD 7.1).

**The deterministic layer is the detector; the model is an edge-case judge.** Pattern classes in
`detection/patterns/sql_injection_pattern_rules.py` decide. A decisive hit -- `UNION SELECT`, a
stacked `; DROP` -- produces a verdict with no model call at all. Only genuinely borderline hits
are put to a code-aware model, and a request whose only signal is corroboration-grade noise is
cleared without either.

That ordering is what makes the precision number meaningful: the P4 gate is measured with the
model stubbed out, so the deterministic layer has to carry it alone (plan P4).

`succeeded` comes from the response, not the payload. A blocked 403 and a 200 that returned rows
are the same attack and a completely different incident.
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
from talos.detection.patterns.sql_injection_pattern_rules import (
    SQL_INJECTION_RULES,
    infer_target_table,
    is_unambiguous,
)
from talos.knowledge.mitre_mapping import mitre_for
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict

#: Confidence for a payload the static layer is certain about. Not 1.0: a rule match is strong
#: evidence of an attempt, never proof of intent, and P8 calibration has to have somewhere to go.
STATIC_CONFIDENCE = 0.95

#: Floor for a borderline payload when no model is reachable. Low enough to read as a lead.
BORDERLINE_FALLBACK_CONFIDENCE = 0.45

#: What the judge model is asked for, and how much room it gets.
JUDGE_SCHEMA = {"type": "object", "required": ["is_injection", "confidence"]}
JUDGE_MAX_TOKENS = 300

#: Statuses that mean the request reached the application and returned content.
SUCCESS_STATUS = frozenset({200, 201, 202})

#: Statuses that mean something rejected it before it mattered.
BLOCKED_STATUS = frozenset({400, 401, 403, 406, 429, 501})


class SqlInjectionDetector(Detector):
    """Deterministic pattern pre-filter, with a code-aware model for the borderline cases."""

    detector_name = "sql_injection_detector"
    technique = "sql_injection"
    mitre = mitre_for("sql_injection")

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        payloads = extract_web_payloads(event)
        if not payloads:
            return None

        hits = match_patterns(payloads, SQL_INJECTION_RULES)
        if not is_actionable(hits):
            # Either nothing matched, or only corroboration-grade noise did. The static layer
            # clears it; no model is asked, because asking is how markup becomes a false positive.
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
                    f"{_static_reasoning(hits)} No model was reachable to judge the borderline "
                    f"payload, so this is reported as a lead rather than a finding."
                )
            elif not outcome.data.get("is_injection", False):
                # The judge exists to say no. A borderline payload it clears is not a verdict.
                return None
            else:
                confidence = _judged_confidence(outcome)
                reasoning = str(outcome.data.get("reasoning") or _static_reasoning(hits))

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
            scope=_scope(event, payloads),
            evidence=_evidence(event, hits),
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

    async def _judge(
        self,
        event: NormalizedEvent,
        hits: list[PatternHit],
        payloads: dict[str, str],
        ctx: DetectionContext,
    ) -> ModelOutcome | None:
        """Put a borderline payload to the code-aware model. ``None`` means judge it statically."""
        limit = ctx.settings.llm.max_payload_chars
        prompt = render_prompt(
            "sql_injection_detector_judge_v1",
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


def infer_success(event: NormalizedEvent) -> bool | None:
    """Did the payload reach the application and come back with content?

    ``None`` when the log does not say. Guessing here would put a fabricated `succeeded` into a
    report, and `succeeded` is the field an analyst acts on first.
    """
    status = event.request.status_code if event.request else None
    if status is None:
        return None
    if status in BLOCKED_STATUS:
        return False
    if status in SUCCESS_STATUS:
        return True
    if status >= 500:
        # A 500 on an injected payload usually means the payload reached the database and broke
        # the query -- reportable as reaching the backend, not as successful extraction.
        return True
    return None


def _scope(event: NormalizedEvent, payloads: dict[str, str]) -> Scope:
    endpoint = event.target.endpoint
    table = infer_target_table(payloads)
    return Scope(
        affected_endpoints=[endpoint] if endpoint else [],
        affected_objects=[table] if table else [],
        affected_hosts=[event.target.host] if event.target.host else [],
        affected_accounts=[event.actor.account] if event.actor.account else [],
        attempt_count=1,
        source_diversity=1,
        succeeded=infer_success(event),
        window_start=event.timestamp,
        window_end=event.timestamp,
    )


def _evidence(event: NormalizedEvent, hits: list[PatternHit]) -> list[Evidence]:
    """One entry per matched rule, plus the raw line. An analyst can re-check every one."""
    evidence = [
        Evidence(kind="matched_pattern", detail=hit.describe(), references=[event.event_id])
        for hit in hits
    ]
    evidence.append(Evidence(kind="log_line", detail=event.raw, references=[event.event_id]))
    return evidence


def _static_reasoning(hits: list[PatternHit]) -> str:
    classes = ", ".join(distinct_classes(hits))
    fields = ", ".join(affected_fields(hits))
    return (
        f"SQL injection patterns matched in {fields}: {classes}. "
        f"{len(hits)} rule(s) fired on request content."
    )


def _judged_confidence(outcome: ModelOutcome) -> float:
    """Clamp the model's number and apply any fallback penalty it carries."""
    try:
        confidence = float(outcome.data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = BORDERLINE_FALLBACK_CONFIDENCE
    confidence = min(max(confidence, 0.0), 1.0) * outcome.confidence_multiplier
    return confidence
