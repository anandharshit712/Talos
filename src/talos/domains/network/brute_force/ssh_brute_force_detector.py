"""SSH brute force -- ``technique="brute_force"``, MITRE T1110 (LLD 7.3.3).

Keyed on ``(host, account)``: the question an analyst asks is "is someone grinding *this*
account on *this* box", not "is there SSH noise on the internet". The trailing success is the
signal that separates honeypot background radiation from an initial-access event, so it drives
both the confidence floor and the report's severity.

**The detection is statistical; the model only narrates it.** The threshold decides, and the
narrative model turns the resulting ``RateSignal`` into readable prose. With no model in play
the detector emits a templated narrative and ``used_llm=False`` -- a fully supported mode, not a
degraded one. Nothing a model says can change ``attack_detected`` or the attempt count.
"""

from __future__ import annotations

import uuid

from talos.core.agent_contracts import DetectionContext, Detector, ModelOutcome
from talos.core.constants import CATEGORY_NETWORK_BRUTE_FORCE, DOMAIN_NETWORK, MODEL_NAME_NONE
from talos.detection.rate.rate_engine import RateConfig, RateEngine, RateSignal
from talos.knowledge.mitre_mapping import mitre_for
from talos.llm.model_client import render_prompt, seal_payload
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict
from talos.storage.event_window_store import host_account_key

#: The narrative model is asked for exactly one field, and told so.
NARRATIVE_SCHEMA = {"type": "object", "required": ["narrative"]}

#: Enough for three sentences. A narrative longer than this is not a narrative.
NARRATIVE_MAX_TOKENS = 220


class SshBruteForceDetector(Detector):
    """Threshold-over-window on failed sshd authentications for one account on one host."""

    detector_name = "ssh_brute_force_detector"
    technique = "brute_force"
    mitre = mitre_for("brute_force")

    def __init__(self) -> None:
        self._engine = RateEngine()

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        if event.auth is None or event.auth.protocol != "ssh":
            return None

        thresholds = ctx.settings.detection.ssh_brute_force
        signal = self._engine.evaluate(
            event,
            ctx.event_window,
            RateConfig(
                window_seconds=thresholds.window_seconds,
                fail_threshold=thresholds.fail_threshold,
                key_fn=host_account_key,
            ),
        )
        if signal is None:
            return None

        confidence = self._confidence(signal, thresholds.fail_threshold, ctx)
        outcome = await self._narrate_with_model(signal, thresholds.window_seconds, ctx)
        if outcome is not None:
            confidence = round(confidence * outcome.confidence_multiplier, 3)

        return Verdict(
            verdict_id=uuid.uuid4().hex,
            event_ids=list(signal.event_ids),
            detector=self.detector_name,
            domain=DOMAIN_NETWORK,
            category=CATEGORY_NETWORK_BRUTE_FORCE,
            technique=self.technique,
            attack_detected=True,
            confidence=confidence,
            mitre=self.mitre,
            scope=Scope(
                affected_accounts=list(signal.accounts),
                affected_hosts=list(signal.hosts),
                attempt_count=signal.count,
                source_diversity=len(signal.sources),
                succeeded=signal.succeeded,
                window_start=signal.window_start,
                window_end=signal.window_end,
            ),
            evidence=self._evidence(signal, thresholds.window_seconds, thresholds.fail_threshold),
            reasoning=(
                str(outcome.data["narrative"])
                if outcome is not None
                else self._narrative(signal, thresholds.window_seconds)
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

    async def _narrate_with_model(
        self, signal: RateSignal, window_seconds: int, ctx: DetectionContext
    ) -> ModelOutcome | None:
        """Ask the routed model to word the finding. ``None`` means use the template.

        Every failure mode lands on the template: no key, no route, a timeout, malformed JSON, a
        reply with no narrative in it. The verdict is already complete before this is called.
        """
        limit = ctx.settings.llm.max_payload_chars
        prompt = render_prompt(
            "rate_detector_narrate_v1",
            technique=self.technique,
            protocol="ssh",
            attempt_count=signal.count,
            window_seconds=window_seconds,
            threshold=ctx.settings.detection.ssh_brute_force.fail_threshold,
            source_count=len(signal.sources),
            succeeded=str(signal.succeeded).lower(),
            # Account and host names come out of the log, so an attacker picks them too. They
            # are sealed with the raw lines rather than presented as trusted facts (HLD 11/13).
            observed=seal_payload(
                " | ".join(
                    [
                        f"accounts: {', '.join(signal.accounts) or 'unknown'}",
                        f"hosts: {', '.join(signal.hosts) or 'unknown'}",
                        f"sources: {', '.join(signal.sources)}",
                        *signal.sample_lines,
                    ]
                ),
                limit,
            ),
        )
        outcome = await ctx.model_client.complete_for(
            self.detector_name,
            prompt=prompt,
            schema=NARRATIVE_SCHEMA,
            max_tokens=NARRATIVE_MAX_TOKENS,
        )
        if outcome is None:
            return None
        narrative = str(outcome.data.get("narrative", "")).strip()
        return outcome if narrative else None

    def _confidence(self, signal: RateSignal, threshold: int, ctx: DetectionContext) -> float:
        """Scale with how far past the threshold the burst went; floor it on success."""
        curve = ctx.settings.detection.rate_confidence
        score = min(curve.cap, curve.base + curve.per_extra_attempt * (signal.count - threshold))
        if signal.succeeded:
            score = max(score, curve.success_floor)
        return round(score, 3)

    def _evidence(self, signal: RateSignal, window_seconds: int, threshold: int) -> list[Evidence]:
        """The statistic that fired, the lines behind it, and the success if there was one."""
        evidence = [
            Evidence(
                kind="statistic",
                detail=(
                    f"{signal.count} failed ssh authentications for {signal.key.split(':', 1)[1]} "
                    f"within {window_seconds}s (threshold {threshold}), "
                    f"from {len(signal.sources)} source IP(s)"
                ),
                references=list(signal.event_ids),
            )
        ]
        evidence.extend(
            Evidence(kind="log_line", detail=line, references=[]) for line in signal.sample_lines
        )
        if signal.succeeded:
            evidence.append(
                Evidence(
                    kind="statistic",
                    detail="a successful authentication followed the failed burst",
                    references=list(signal.event_ids),
                )
            )
        return evidence

    def _narrative(self, signal: RateSignal, window_seconds: int) -> str:
        """Templated reasoning. P3 swaps in a model-written one and sets ``used_llm=True``."""
        accounts = ", ".join(signal.accounts) or "an unnamed account"
        hosts = ", ".join(signal.hosts) or "an unnamed host"
        sources = ", ".join(signal.sources)
        outcome = (
            "A successful login followed the burst, so treat this as a probable initial access."
            if signal.succeeded
            else "No successful login followed, so the attempt appears unsuccessful so far."
        )
        return (
            f"{signal.count} failed SSH authentications targeted {accounts} on {hosts} "
            f"within {window_seconds} seconds, from {sources}. {outcome}"
        )
