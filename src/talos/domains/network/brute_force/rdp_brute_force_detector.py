"""RDP brute force -- ``technique="brute_force"``, MITRE T1110 (LLD 7.3.3).

The SSH detector with a different protocol filter and its own thresholds. Kept as its own file
rather than folded into that one because the two diverge on the things that matter operationally:
an exposed RDP endpoint is a named top ransomware initial-access vector, so its threshold, its
routing, and the wording of its evidence are tuned separately, and a change to one must not
silently move the other. The shared part -- the counting, the confidence curve, the narration --
is in ``detection/rate/``, not copied here.

Fed by the Windows Security events the network parser reads: 4625 (failed logon) and 4624
(successful logon) with logon type 10, RemoteInteractive, which is what an RDP session is.
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


class RdpBruteForceDetector(Detector):
    """Threshold-over-window on failed RDP logons for one account on one host."""

    detector_name = "rdp_brute_force_detector"
    technique = "brute_force"
    mitre = mitre_for("brute_force")
    protocol = "rdp"

    def __init__(self) -> None:
        self._engine = RateEngine()

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        if event.auth is None or event.auth.protocol != self.protocol:
            return None

        thresholds = ctx.settings.detection.rdp_brute_force
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
                f"{signal.count} failed RDP logons for {signal.key.split(':', 1)[1]} "
                f"within {thresholds.window_seconds}s "
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
            "A logon then succeeded, so treat this as a probable initial access -- an exposed "
            "RDP endpoint is a leading ransomware entry point."
            if signal.succeeded
            else "No logon succeeded, so the attempt appears unsuccessful so far."
        )
        return (
            f"{signal.count} failed RDP logons targeted {accounts} on {hosts} within "
            f"{window_seconds} seconds, from {', '.join(signal.sources)}. {outcome}"
        )
