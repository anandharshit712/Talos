"""SSH brute force -- ``technique="brute_force"``, MITRE T1110 (LLD 7.3.3).

Keyed on ``(host, account)``: the question an analyst asks is "is someone grinding *this*
account on *this* box", not "is there SSH noise on the internet". The trailing success is the
signal that separates honeypot background radiation from an initial-access event, so it drives
both the confidence floor and the report's severity.

No LLM. The statistical path produces a templated narrative and ``used_llm=False`` -- a fully
supported mode, not a degraded one (P3 adds the narrative model on top of this).
"""

from __future__ import annotations

import uuid

from talos.core.agent_contracts import DetectionContext, Detector
from talos.core.constants import CATEGORY_NETWORK_BRUTE_FORCE, DOMAIN_NETWORK, MODEL_NAME_NONE
from talos.detection.rate.rate_engine import RateConfig, RateEngine, RateSignal
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict
from talos.storage.event_window_store import host_account_key


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
            reasoning=self._narrative(signal, thresholds.window_seconds),
            model=ModelInfo(
                name=MODEL_NAME_NONE,
                route_reason="statistical detection, no model required",
                used_llm=False,
            ),
        )

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
