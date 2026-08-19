"""Web brute force -- ``technique="brute_force"``, MITRE T1110 (LLD 7.3.1).

Depth against one account: the same maths as the SSH detector, over HTTP telemetry, keyed on the
account rather than on ``(host, account)`` because a web login is served by whatever box the load
balancer picked and grinding one account across three app servers is one attack, not three.

**Keyed on the account, never on the source IP.** LLD 7.3.1 allows either, and the choice
matters: keying on the source would fire this detector on the same window credential stuffing
owns, so one attack would arrive as two verdicts with two techniques. Depth is measured per
account here; breadth per source is ``credential_stuffing_detector``'s job, and the two keys are
what keep them from colliding.

The account comes from the parser, which reads the submitted username off the login request
(``web_log_parser.derive_http_auth``). A log that names no account produces no key, so no
verdict -- one of the honest limits recorded in this feature's ``detection-logic.md``.
"""

from __future__ import annotations

from talos.core.agent_contracts import DetectionContext, Detector
from talos.core.constants import CATEGORY_AUTH_FAILURE, DOMAIN_WEB
from talos.detection.rate.rate_engine import RateConfig, RateEngine, RateSignal
from talos.detection.rate.rate_verdict_engine import (
    RateVerdictSpec,
    assemble_rate_verdict,
    statistic_evidence,
)
from talos.knowledge.mitre_mapping import mitre_for
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.verdict_schema import Verdict
from talos.storage.event_window_store import account_key

#: The protocol this detector reads. HTTP auth outcomes are derived by the web parser.
PROTOCOL = "http"


class BruteForceDetector(Detector):
    """Threshold-over-window on failed HTTP logins for one account."""

    detector_name = "brute_force_detector"
    technique = "brute_force"
    mitre = mitre_for("brute_force")

    def __init__(self) -> None:
        self._engine = RateEngine()

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        if event.auth is None or event.auth.protocol != PROTOCOL:
            return None

        thresholds = ctx.settings.detection.brute_force
        signal = self._engine.evaluate(
            event,
            ctx.event_window,
            RateConfig(
                window_seconds=thresholds.window_seconds,
                fail_threshold=thresholds.fail_threshold,
                key_fn=account_key,
            ),
        )
        if signal is None:
            return None

        return await assemble_rate_verdict(
            signal=signal,
            spec=RateVerdictSpec(
                detector_name=self.detector_name,
                technique=self.technique,
                domain=DOMAIN_WEB,
                category=CATEGORY_AUTH_FAILURE,
                protocol=PROTOCOL,
                window_seconds=thresholds.window_seconds,
                threshold=thresholds.fail_threshold,
                score_count=signal.count,
            ),
            ctx=ctx,
            evidence=statistic_evidence(
                signal,
                f"{signal.count} rejected HTTP logins for "
                f"{signal.key.split(':', 1)[1]} within {thresholds.window_seconds}s "
                f"(threshold {thresholds.fail_threshold}), "
                f"from {len(signal.sources)} source IP(s)",
            ),
            template_narrative=self._narrative(signal, thresholds.window_seconds),
        )

    def _narrative(self, signal: RateSignal, window_seconds: int) -> str:
        """Templated reasoning, used whenever no model answers."""
        accounts = ", ".join(signal.accounts) or "an unnamed account"
        endpoints = ", ".join(signal.endpoints) or "the login endpoint"
        outcome = (
            f"A login for {', '.join(signal.succeeded_accounts)} then succeeded, so treat this "
            "as a probable account takeover."
            if signal.succeeded
            else "No login succeeded, so the attempt appears unsuccessful so far."
        )
        return (
            f"{signal.count} HTTP login attempts for {accounts} were rejected at {endpoints} "
            f"within {window_seconds} seconds, from {', '.join(signal.sources)}. {outcome}"
        )
