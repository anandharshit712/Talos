"""IDOR -- ``technique="idor"``, MITRE T1083/T1530, OWASP A01 (LLD 7.4).

The category with nothing to match. ``GET /api/orders/1002`` is byte-identical whether the caller
owns order 1002 or is walking the id space, so the deterministic layer here is not a pattern
table but four features measured against what this account has done before.

| Feature | Reads | Answers |
|---|---|---|
| ``outside_range`` | the baseline's range | an id outside everything this account has touched |
| ``sequential_run`` | the event window | consecutive ids in one window -- enumeration's signature |
| ``novel_endpoint`` | the baseline's endpoints | a part of the application new to this account |
| ``access_rate`` | the event window | how many objects this account is pulling per window |

``sequential_run`` carries the most weight because it is the only feature that is hard to produce
by accident, and it comes from the **window** rather than the baseline: once an enumeration run
starts, each id widens the learned range, so ``outside_range`` catches the initial jump and the
run carries the rest.

**Cold start returns a verdict that does not fire.** Below the maturity threshold the scorer
emits ``attack_detected=False`` with a low confidence and evidence saying why. The aggregator
drops non-firing verdicts, so an unfamiliar account produces no incident -- but the record shows
Talos looked and knew it lacked history, which is the honest answer and not silence.

**Scope is the deliverable.** ``affected_objects`` lists exactly the ids accessed outside the
learned pattern. "Someone read things they should not have" is not actionable; "these eleven
order ids, in sequence, by this account" is.
"""

from __future__ import annotations

import uuid

from talos.core.agent_contracts import DetectionContext, Detector, ModelOutcome
from talos.core.constants import CATEGORY_BROKEN_ACCESS_CONTROL, DOMAIN_WEB, MODEL_NAME_NONE
from talos.core.settings import IdorThresholds
from talos.detection.baseline.access_baseline import (
    AccessBaseline,
    is_mature,
    numeric_id,
    outside_numeric_range,
)
from talos.domains.web.broken_access_control.access_baseliner import (
    endpoint_template,
    is_object_access,
    object_id_of,
)
from talos.knowledge.mitre_mapping import mitre_for
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict
from talos.storage.event_window_store import account_key

JUDGE_SCHEMA = {"type": "object", "required": ["is_idor", "confidence"]}
JUDGE_MAX_TOKENS = 400

#: How many ids of the account's history the judge is shown. Enough to see a pattern, bounded
#: so a long-lived account cannot push the prompt past its context window.
HISTORY_SAMPLE = 40


class DeviationFeatures:
    """The four measured features, and the deterministic score they produce."""

    def __init__(
        self,
        *,
        outside_range: bool,
        sequential_run: int,
        novel_endpoint: bool,
        access_count: int,
        run_ids: list[str],
    ) -> None:
        self.outside_range = outside_range
        self.sequential_run = sequential_run
        """Length of the longest consecutive-id run in the window that includes this access."""
        self.novel_endpoint = novel_endpoint
        self.access_count = access_count
        self.run_ids = run_ids
        """The ids forming that run -- the out-of-pattern objects, for scope."""

    def score(self, idor: IdorThresholds) -> float:
        """Weighted, normalised by total weight so the result is always in ``[0, 1]``."""
        weights = idor.weights
        contributions = (
            (weights.outside_range, 1.0 if self.outside_range else 0.0),
            (
                weights.sequential_run,
                1.0 if self.sequential_run >= idor.sequential_run_len else 0.0,
            ),
            (weights.novel_endpoint, 1.0 if self.novel_endpoint else 0.0),
            (weights.access_rate, min(self.access_count / idor.access_rate_saturation, 1.0)),
        )
        total = sum(weight for weight, _ in contributions)
        if total <= 0:
            return 0.0
        return round(sum(weight * value for weight, value in contributions) / total, 3)

    def describe(self, idor: IdorThresholds) -> list[str]:
        """One phrase per feature that actually contributed. Empty features say nothing."""
        parts: list[str] = []
        if self.outside_range:
            parts.append("the object id falls outside every id this account has accessed before")
        if self.sequential_run >= idor.sequential_run_len:
            parts.append(
                f"{self.sequential_run} consecutive object ids were requested within "
                f"{idor.window_seconds}s (threshold {idor.sequential_run_len})"
            )
        if self.novel_endpoint:
            parts.append("the endpoint is new for this account")
        if self.access_count > 1:
            parts.append(f"{self.access_count} object accesses in the window")
        return parts


class DeviationScorer(Detector):
    """Scores one object access against the account's learned pattern."""

    detector_name = "deviation_scorer"
    technique = "idor"
    mitre = mitre_for("idor")

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        if not is_object_access(event):
            return None

        account = event.actor.account
        assert account is not None  # is_object_access checked it
        idor = ctx.settings.detection.idor

        baseline = await ctx.baseline_store.get(account)
        if baseline is None or not is_mature(baseline, idor.min_baseline_observations):
            return self._immature_verdict(event, baseline, idor)

        features = self._measure(event, baseline, ctx)
        stat_score = features.score(idor)
        if stat_score < idor.low_score_floor:
            return None

        outcome = await self._judge(event, baseline, features, ctx)
        confidence = _blend(stat_score, outcome, idor)
        reasoning = self._reasoning(features, stat_score, outcome, idor)

        return Verdict(
            verdict_id=uuid.uuid4().hex,
            event_ids=[event.event_id],
            detector=self.detector_name,
            domain=DOMAIN_WEB,
            category=CATEGORY_BROKEN_ACCESS_CONTROL,
            technique=self.technique,
            attack_detected=True,
            confidence=round(confidence, 3),
            mitre=self.mitre,
            scope=_scope(event, features),
            evidence=_evidence(event, features, stat_score, idor),
            reasoning=reasoning,
            model=(
                ModelInfo(name=outcome.model, route_reason=outcome.route_reason, used_llm=True)
                if outcome is not None
                else ModelInfo(
                    name=MODEL_NAME_NONE,
                    route_reason="statistical deviation scoring, no model reachable",
                    used_llm=False,
                )
            ),
        )

    def _measure(
        self, event: NormalizedEvent, baseline: AccessBaseline, ctx: DetectionContext
    ) -> DeviationFeatures:
        """Measure the four features. Two read the baseline, two read the event window."""
        object_id = object_id_of(event)
        assert object_id is not None
        idor = ctx.settings.detection.idor

        key = account_key(event)
        recent = (
            ctx.event_window.query(key=key, within=idor.window_seconds) if key is not None else []
        )
        accessed = [
            found for found in (object_id_of(earlier) for earlier in recent) if found is not None
        ]
        run_ids = _longest_run_containing(accessed, object_id)

        # The template, never the raw path: the raw path carries the object id, so every
        # access would read as a novel endpoint and the feature would say nothing.
        template = endpoint_template(event)
        return DeviationFeatures(
            outside_range=outside_numeric_range(baseline, object_id),
            sequential_run=len(run_ids),
            novel_endpoint=bool(template and template not in baseline.endpoints),
            access_count=len(accessed),
            run_ids=run_ids,
        )

    def _immature_verdict(
        self, event: NormalizedEvent, baseline: AccessBaseline | None, idor: IdorThresholds
    ) -> Verdict:
        """A verdict that does not fire, so the record shows Talos looked and lacked history."""
        observed = 0 if baseline is None else baseline.observations
        detail = (
            f"baseline immature: {observed} of {idor.min_baseline_observations} observations "
            f"required for this account, so deviation cannot be measured yet"
        )
        return Verdict(
            verdict_id=uuid.uuid4().hex,
            event_ids=[event.event_id],
            detector=self.detector_name,
            domain=DOMAIN_WEB,
            category=CATEGORY_BROKEN_ACCESS_CONTROL,
            technique=self.technique,
            attack_detected=False,
            confidence=idor.immature_confidence,
            mitre=self.mitre,
            scope=Scope(
                affected_accounts=[event.actor.account] if event.actor.account else [],
                affected_endpoints=[event.target.endpoint] if event.target.endpoint else [],
                attempt_count=1,
                source_diversity=1,
                window_start=event.timestamp,
                window_end=event.timestamp,
            ),
            evidence=[Evidence(kind="statistic", detail=detail, references=[event.event_id])],
            reasoning=(
                f"An account with {observed} recorded accesses has no pattern to deviate from. "
                f"Reporting no finding rather than treating an unfamiliar account as a "
                f"suspicious one."
            ),
            model=ModelInfo(
                name=MODEL_NAME_NONE,
                route_reason="cold start, nothing to judge",
                used_llm=False,
            ),
        )

    async def _judge(
        self,
        event: NormalizedEvent,
        baseline: AccessBaseline,
        features: DeviationFeatures,
        ctx: DetectionContext,
    ) -> ModelOutcome | None:
        """Put the access and the account's history to the reasoning model."""
        limit = ctx.settings.llm.max_payload_chars
        idor = ctx.settings.detection.idor
        prompt = render_prompt(
            "deviation_scorer_judge_v1",
            account=seal_payload(event.actor.account or "unknown", 120),
            endpoint=event.target.endpoint or "unknown",
            method=event.request.method if event.request else "unknown",
            status=event.request.status_code if event.request else "unknown",
            object_id=object_id_of(event) or "unknown",
            observations=baseline.observations,
            known_range=(
                f"{baseline.numeric_min}..{baseline.numeric_max}"
                if baseline.numeric_min is not None
                else "no numeric ids recorded"
            ),
            known_endpoints=", ".join(sorted(baseline.endpoints)[:HISTORY_SAMPLE]) or "none",
            features="; ".join(features.describe(idor)) or "none measured",
            recent_ids=seal_payload(", ".join(features.run_ids[:HISTORY_SAMPLE]) or "none", limit),
            history=seal_payload(
                ", ".join(baseline.seen_object_ids[-HISTORY_SAMPLE:]) or "none", limit
            ),
        )
        return await ctx.model_client.complete_for(
            self.detector_name, prompt=prompt, schema=JUDGE_SCHEMA, max_tokens=JUDGE_MAX_TOKENS
        )

    def _reasoning(
        self,
        features: DeviationFeatures,
        stat_score: float,
        outcome: ModelOutcome | None,
        idor: IdorThresholds,
    ) -> str:
        statistical = (
            f"Access deviates from this account's learned pattern (score {stat_score:.2f}): "
            f"{'; '.join(features.describe(idor))}."
        )
        if outcome is None:
            return (
                f"{statistical} No model was reachable, so the deterministic score stands on "
                f"its own."
            )
        judged = str(outcome.data.get("reasoning") or "").strip()
        return f"{statistical} {judged}" if judged else statistical


def _longest_run_containing(accessed: list[str], object_id: str) -> list[str]:
    """The longest run of consecutive numeric ids in ``accessed`` that includes ``object_id``.

    Returns the ids in ascending order, or a single-element list when there is no run -- an
    isolated access is a run of one, which no threshold treats as enumeration.
    """
    current = numeric_id(object_id)
    if current is None:
        return [object_id]

    numbers = {value for value in (numeric_id(found) for found in accessed) if value is not None}
    numbers.add(current)

    low = current
    while low - 1 in numbers:
        low -= 1
    high = current
    while high + 1 in numbers:
        high += 1
    return [str(value) for value in range(low, high + 1)]


def _scope(event: NormalizedEvent, features: DeviationFeatures) -> Scope:
    """Exactly which objects fell outside the pattern -- the point of this detector."""
    endpoint = endpoint_template(event)
    return Scope(
        affected_accounts=[event.actor.account] if event.actor.account else [],
        affected_endpoints=[endpoint] if endpoint else [],
        affected_objects=features.run_ids,
        affected_hosts=[event.target.host] if event.target.host else [],
        attempt_count=max(features.access_count, 1),
        source_diversity=1,
        succeeded=_succeeded(event),
        window_start=event.timestamp,
        window_end=event.timestamp,
    )


def _succeeded(event: NormalizedEvent) -> bool | None:
    """Did the application serve the object? ``None`` when the log does not say.

    A 200 on an object outside the account's pattern is the case that matters: the access
    control did not stop it. A 403 is the control working, and still worth reporting as an
    attempt.
    """
    status = event.request.status_code if event.request else None
    if status is None:
        return None
    return 200 <= status < 300


def _evidence(
    event: NormalizedEvent, features: DeviationFeatures, stat_score: float, idor: IdorThresholds
) -> list[Evidence]:
    evidence = [
        Evidence(kind="statistic", detail=phrase, references=[event.event_id])
        for phrase in features.describe(idor)
    ]
    if features.sequential_run >= idor.sequential_run_len:
        evidence.append(
            Evidence(
                kind="statistic",
                detail=(f"object ids outside the learned pattern: {', '.join(features.run_ids)}"),
                references=[event.event_id],
            )
        )
    evidence.append(
        Evidence(
            kind="statistic",
            detail=f"deterministic deviation score {stat_score:.2f}",
            references=[event.event_id],
        )
    )
    evidence.append(Evidence(kind="log_line", detail=event.raw, references=[event.event_id]))
    return evidence


def _blend(stat_score: float, outcome: ModelOutcome | None, idor: IdorThresholds) -> float:
    """Combine the deterministic score with the judge's, if one answered.

    With no model the statistical score is the answer -- ``used_llm=False`` is a supported mode,
    not a degraded one. A fallback model's answer is discounted by its own multiplier before it
    is allowed to move anything.
    """
    if outcome is None:
        return stat_score
    if not outcome.data.get("is_idor", False):
        # The judge disagrees. It cannot veto the deterministic layer, but it caps how confident
        # the report is allowed to be: a contested finding is a lead.
        return min(stat_score, idor.low_score_floor)
    try:
        judged = float(outcome.data.get("confidence", 0.0))
    except (TypeError, ValueError):
        return stat_score
    judged = min(max(judged, 0.0), 1.0) * outcome.confidence_multiplier
    weight = idor.judge_weight
    return min(stat_score * (1.0 - weight) + judged * weight, 1.0)
