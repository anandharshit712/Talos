"""Credential stuffing -- ``technique="credential_stuffing"``, MITRE T1110.004 (LLD 7.3.2).

**Breadth, not depth.** A stuffing run replays a leaked credential dump: two or three tries per
account across hundreds of accounts, which is *below* every brute-force threshold on every
account it touches. Counting failures harder never finds it -- the shape is the signal.

So the window is keyed on the source, and two conditions have to hold together:

* **many distinct accounts** -- at least ``distinct_accounts`` of them in the window, and
* **few tries each** -- no single account past ``fails_per_account_max``.

The second condition is what makes the verdict a claim rather than a guess. Without it, one
account ground 200 times from one IP satisfies "many failures from one source" and would be
reported as stuffing when it is brute force; with it, that window is rejected here and picked up
by ``brute_force_detector``, which is keyed per account. The two detectors are complements, and
``tests/unit/domains/web/auth_failure/test_auth_failure_discrimination.py`` asserts both
directions rather than only the one this file cares about.

Confidence is read from how many accounts were touched, not from the failure total: a run over
400 accounts is worse than one over 20 even when the second retried more.

**What this deliberately does not catch yet.** LLD 7.3.2 describes a *rotating* source set, and
keying the window on one source cannot see a run split across fifty proxies with three accounts
each. Catching that needs a window keyed on nothing at all, and a global window fires on fifteen
unrelated people mistyping their passwords unless a source-set heuristic is added beside it --
precision this corpus cannot yet calibrate. The single-source and small-source-set shapes are
detected now; the rotating case is listed in the build tracker's deferred items, and P8 decides
against a real capture whether the global window earns its false positives.
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
from talos.storage.event_window_store import source_ip_key

#: The protocol this detector reads. HTTP auth outcomes are derived by the web parser.
PROTOCOL = "http"


class CredentialStuffingDetector(Detector):
    """Many accounts, few tries each, one source -- the shape of a replayed credential dump."""

    detector_name = "credential_stuffing_detector"
    technique = "credential_stuffing"
    mitre = mitre_for("credential_stuffing")

    def __init__(self) -> None:
        self._engine = RateEngine()

    async def evaluate(self, event: NormalizedEvent, ctx: DetectionContext) -> Verdict | None:
        if event.auth is None or event.auth.protocol != PROTOCOL:
            return None

        thresholds = ctx.settings.detection.credential_stuffing
        signal = self._engine.evaluate(
            event,
            ctx.event_window,
            RateConfig(
                window_seconds=thresholds.window_seconds,
                # Reaching N distinct accounts takes at least N failures, so the account
                # threshold doubles as the cheapest possible pre-filter on the failure count.
                fail_threshold=thresholds.distinct_accounts,
                key_fn=source_ip_key,
            ),
        )
        if signal is None or not self._is_broad_and_shallow(signal, ctx):
            return None

        account_count = len(signal.accounts)
        deepest = max(signal.fails_per_account.values(), default=0)
        return await assemble_rate_verdict(
            signal=signal,
            spec=RateVerdictSpec(
                detector_name=self.detector_name,
                technique=self.technique,
                domain=DOMAIN_WEB,
                category=CATEGORY_AUTH_FAILURE,
                protocol=PROTOCOL,
                window_seconds=thresholds.window_seconds,
                threshold=thresholds.distinct_accounts,
                score_count=account_count,
            ),
            ctx=ctx,
            evidence=statistic_evidence(
                signal,
                f"{signal.count} rejected HTTP logins across {account_count} distinct accounts "
                f"from {', '.join(signal.sources)} within {thresholds.window_seconds}s "
                f"(threshold {thresholds.distinct_accounts} accounts), "
                f"at most {deepest} attempt(s) against any one account",
            ),
            template_narrative=self._narrative(signal, thresholds.window_seconds, deepest),
        )

    def _is_broad_and_shallow(self, signal: RateSignal, ctx: DetectionContext) -> bool:
        """Both halves of the shape, or it is somebody else's attack."""
        thresholds = ctx.settings.detection.credential_stuffing
        if len(signal.accounts) < thresholds.distinct_accounts:
            return False
        return (
            max(signal.fails_per_account.values(), default=0) <= thresholds.fails_per_account_max
        )

    def _narrative(self, signal: RateSignal, window_seconds: int, deepest: int) -> str:
        """Templated reasoning, used whenever no model answers."""
        endpoints = ", ".join(signal.endpoints) or "the login endpoint"
        outcome = (
            f"Logins for {', '.join(signal.succeeded_accounts)} then succeeded, so treat those "
            "accounts as compromised."
            if signal.succeeded
            else "No login succeeded, so no account appears compromised yet."
        )
        return (
            f"{', '.join(signal.sources)} attempted logins for {len(signal.accounts)} distinct "
            f"accounts at {endpoints} within {window_seconds} seconds, with at most {deepest} "
            f"attempt(s) per account -- the breadth-over-depth shape of a replayed credential "
            f"dump rather than a password guess. {outcome}"
        )
