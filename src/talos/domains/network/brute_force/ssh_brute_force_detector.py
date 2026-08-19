"""SSH brute force -- ``technique="brute_force"``, MITRE T1110 (LLD 7.3.3).

Keyed on ``(host, account)``: the question an analyst asks is "is someone grinding *this*
account on *this* box", not "is there SSH noise on the internet". The trailing success is the
signal that separates honeypot background radiation from an initial-access event, so it drives
both the confidence floor and the report's severity.

**The detection is statistical; the model only narrates it.** The threshold decides. With no
model in play the detector emits the templated narrative below and ``used_llm=False`` -- a fully
supported mode, not a degraded one. Nothing a model says can change ``attack_detected`` or the
attempt count; ``rate_verdict_engine`` enforces that for all four rate detectors.
"""

from __future__ import annotations

from talos.core.agent_contracts import DetectionContext, Detector
from talos.core.constants import CATEGORY_NETWORK_BRUTE_FORCE, DOMAIN_NETWORK
from talos.detection.rate.rate_engine import RateConfig, RateEngine, RateSignal
from talos.detection.rate.rate_verdict_engine import (
    RateVerdictSpec,
    assemble_rate_verdict,
    statistic_evidence,
)
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict
from talos.storage.event_window_store import host_account_key


class SshBruteForceDetector(Detector):
    """Threshold-over-window on failed sshd authentications for one account on one host."""

    detector_name = "ssh_brute_force_detector"
    technique = "brute_force"
    mitre = mitre_for("brute_force")

    #: The protocol whose logins this detector owns. ``rdp_brute_force_detector`` is the same
    #: detector with a different one; they stay separate files so a threshold, a piece of
    #: evidence wording, or a model route can move for one without touching the other.
    protocol = "ssh"

    def __init__(self) -> None:
        self._engine = RateEngine()

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        if event.auth is None or event.auth.protocol != self.protocol:
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

        return await assemble_rate_verdict(
            signal=signal,
            spec=RateVerdictSpec(
                detector_name=self.detector_name,
                technique=self.technique,
                domain=DOMAIN_NETWORK,
                category=CATEGORY_NETWORK_BRUTE_FORCE,
                protocol=self.protocol,
                window_seconds=thresholds.window_seconds,
                threshold=thresholds.fail_threshold,
                score_count=signal.count,
            ),
            ctx=ctx,
            evidence=statistic_evidence(
                signal,
                f"{signal.count} failed {self.protocol} authentications for "
                f"{signal.key.split(':', 1)[1]} within {thresholds.window_seconds}s "
                f"(threshold {thresholds.fail_threshold}), "
                f"from {len(signal.sources)} source IP(s)",
            ),
            template_narrative=self._narrative(signal, thresholds.window_seconds),
        )

    def _narrative(self, signal: RateSignal, window_seconds: int) -> str:
        """Templated reasoning, used whenever no model answers."""
        accounts = ", ".join(signal.accounts) or "an unnamed account"
        hosts = ", ".join(signal.hosts) or "an unnamed host"
        outcome = (
            "A successful login followed the burst, so treat this as a probable initial access."
            if signal.succeeded
            else "No successful login followed, so the attempt appears unsuccessful so far."
        )
        return (
            f"{signal.count} failed {self.protocol.upper()} authentications targeted {accounts} "
            f"on {hosts} within {window_seconds} seconds, from "
            f"{', '.join(signal.sources)}. {outcome}"
        )
