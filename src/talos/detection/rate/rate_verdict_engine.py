"""Verdict assembly shared by every rate-based detector (LLD 7.3).

``rate_engine.py`` counts; this turns what it counted into a ``Verdict``. The four rate detectors
-- SSH, RDP, web brute force, credential stuffing -- differ in exactly three things: what
telemetry they accept, what they call the statistic they fired on, and how they word the
narrative when no model is reachable. Those three stay in the detector. The confidence curve, the
narration call, the ``Scope``, and the ``ModelInfo`` bookkeeping live here, once, so a change to
any of them cannot land in three detectors and miss the fourth.

**The model narrates; it never decides.** ``attack_detected`` and every count are fixed before
narration is attempted, and every failure mode of the call -- no key, no route, a timeout,
malformed JSON, a reply with no narrative in it -- lands on the detector's template with
``used_llm=False``. That is a supported path, not a degraded one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from talos.core.agent_contracts import DetectionContext, ModelOutcome
from talos.core.constants import MODEL_NAME_NONE
from talos.core.settings import RateConfidenceSettings
from talos.detection.rate.rate_engine import RateSignal
from talos.knowledge.mitre_mapping import mitre_for
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict

#: The narrative model is asked for exactly one field, and told so.
NARRATIVE_SCHEMA = {"type": "object", "required": ["narrative"]}

#: Enough for three sentences. A narrative longer than this is not a narrative.
NARRATIVE_MAX_TOKENS = 220

#: The prompt every rate detector narrates through.
NARRATIVE_PROMPT = "rate_detector_narrate_v2"


@dataclass(frozen=True)
class RateVerdictSpec:
    """The detector's identity and the numbers its confidence is read from."""

    detector_name: str
    technique: str
    domain: str
    category: str
    protocol: str
    """``ssh`` | ``rdp`` | ``http`` -- quoted in the evidence and the prompt's fact list."""
    window_seconds: int
    threshold: int
    score_count: int
    """What the confidence curve measures against ``threshold``.

    Failures for a depth detector; distinct accounts for a breadth one. Splitting it from
    ``RateSignal.count`` is what lets credential stuffing share the curve: its severity comes
    from how many accounts were touched, not from a total that grows with either dimension.
    """


async def assemble_rate_verdict(
    *,
    signal: RateSignal,
    spec: RateVerdictSpec,
    ctx: DetectionContext,
    evidence: list[Evidence],
    template_narrative: str,
) -> Verdict:
    """Turn a ``RateSignal`` into the finished ``Verdict``, narrating it if a model answers."""
    confidence = rate_confidence(
        spec.score_count,
        spec.threshold,
        ctx.settings.detection.rate_confidence,
        succeeded=signal.succeeded,
    )
    outcome = await narrate_rate_signal(signal, spec, ctx)
    if outcome is not None:
        confidence = round(confidence * outcome.confidence_multiplier, 3)

    return Verdict(
        verdict_id=uuid.uuid4().hex,
        event_ids=list(signal.event_ids),
        detector=spec.detector_name,
        domain=spec.domain,
        category=spec.category,
        technique=spec.technique,
        attack_detected=True,
        confidence=confidence,
        mitre=mitre_for(spec.technique),
        scope=Scope(
            affected_accounts=list(signal.accounts),
            affected_endpoints=list(signal.endpoints),
            affected_hosts=list(signal.hosts),
            attempt_count=signal.count,
            source_diversity=len(signal.sources),
            succeeded=signal.succeeded,
            window_start=signal.window_start,
            window_end=signal.window_end,
        ),
        evidence=evidence,
        reasoning=(
            str(outcome.data["narrative"]) if outcome is not None else template_narrative
        ),
        model=(
            ModelInfo(name=outcome.model, route_reason=outcome.route_reason, used_llm=True)
            if outcome is not None
            else ModelInfo(
                name=MODEL_NAME_NONE,
                route_reason="statistical detection, no model used",
                used_llm=False,
            )
        ),
    )


def rate_confidence(
    score_count: int, threshold: int, curve: RateConfidenceSettings, *, succeeded: bool
) -> float:
    """Scale with how far past the threshold the burst went; floor it on a trailing success."""
    score = min(curve.cap, curve.base + curve.per_extra_attempt * (score_count - threshold))
    if succeeded:
        score = max(score, curve.success_floor)
    return round(score, 3)


async def narrate_rate_signal(
    signal: RateSignal, spec: RateVerdictSpec, ctx: DetectionContext
) -> ModelOutcome | None:
    """Ask the routed model to word the finding. ``None`` means "use the template"."""
    prompt = render_prompt(
        NARRATIVE_PROMPT,
        technique=spec.technique,
        protocol=spec.protocol,
        attempt_count=signal.count,
        account_count=len(signal.accounts),
        window_seconds=spec.window_seconds,
        threshold=spec.threshold,
        source_count=len(signal.sources),
        succeeded=str(signal.succeeded).lower(),
        # Accounts, hosts, and endpoints all come out of the log, so an attacker picks them
        # too. They are sealed with the raw lines rather than presented as trusted facts
        # (HLD 11/13).
        observed=seal_payload(
            " | ".join(
                [
                    f"accounts: {', '.join(signal.accounts) or 'unknown'}",
                    f"hosts: {', '.join(signal.hosts) or 'unknown'}",
                    f"endpoints: {', '.join(signal.endpoints) or 'none'}",
                    f"sources: {', '.join(signal.sources)}",
                    *signal.sample_lines,
                ]
            ),
            ctx.settings.llm.max_payload_chars,
        ),
    )
    outcome = await ctx.model_client.complete_for(
        spec.detector_name,
        prompt=prompt,
        schema=NARRATIVE_SCHEMA,
        max_tokens=NARRATIVE_MAX_TOKENS,
    )
    if outcome is None:
        return None
    narrative = str(outcome.data.get("narrative", "")).strip()
    return outcome if narrative else None


def statistic_evidence(signal: RateSignal, detail: str) -> list[Evidence]:
    """The statistic that fired, the lines behind it, and the success if there was one."""
    evidence = [Evidence(kind="statistic", detail=detail, references=list(signal.event_ids))]
    evidence.extend(
        Evidence(kind="log_line", detail=line, references=[]) for line in signal.sample_lines
    )
    if signal.succeeded:
        who = ", ".join(signal.succeeded_accounts)
        evidence.append(
            Evidence(
                kind="statistic",
                detail=(
                    f"a successful authentication for {who} followed the failed burst"
                    if who
                    else "a successful authentication followed the failed burst"
                ),
                references=list(signal.event_ids),
            )
        )
    return evidence
