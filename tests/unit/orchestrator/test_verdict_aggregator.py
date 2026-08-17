"""Dedupe, scope merge, severity, corroboration, actions (LLD 4.3)."""

from __future__ import annotations

from datetime import UTC, datetime

from talos.core.settings import TalosSettings
from talos.orchestrator.verdict_aggregator import VerdictAggregator
from talos.schemas.event_schema import Actor, AuthEvent, NormalizedEvent, Target
from talos.schemas.verdict_schema import Scope, Verdict

TRIGGERING_EVENT = NormalizedEvent(
    event_id="trigger",
    timestamp=datetime(2026, 8, 15, 10, 15, tzinfo=UTC),
    domain="network",
    telemetry_source="sshd",
    actor=Actor(source_ip="203.0.113.7", account="root"),
    target=Target(host="bastion-01", port=22),
    auth=AuthEvent(protocol="ssh", outcome="failure", reason="invalid_password"),
    raw="Aug 15 10:15:00 bastion-01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
)


def _aggregate(
    settings: TalosSettings, verdicts: list[Verdict], event: NormalizedEvent | None = None
):
    return VerdictAggregator(settings).aggregate(event or TRIGGERING_EVENT, verdicts)


def test_single_verdict_becomes_an_incident(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    report = _aggregate(talos_settings, [sample_verdict])
    assert report is not None
    assert report.category == "network_brute_force"
    assert report.verdicts == [sample_verdict]
    assert report.confidence == sample_verdict.confidence
    assert report.mitre_techniques[0].technique_id == "T1110"


def test_no_firing_verdict_means_no_incident(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    """ "Nothing fired" is None, never an empty report (LLD 11)."""
    inconclusive = sample_verdict.model_copy(update={"attack_detected": False})
    assert _aggregate(talos_settings, [inconclusive]) is None


def test_duplicate_verdicts_are_collapsed_keeping_the_confident_one(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    weaker = sample_verdict.model_copy(update={"confidence": 0.4, "verdict_id": "weaker"})
    report = _aggregate(talos_settings, [sample_verdict, weaker])
    assert report is not None
    assert len(report.verdicts) == 1
    assert report.verdicts[0].confidence == 0.91


def test_scopes_are_unioned_and_success_wins(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    other = sample_verdict.model_copy(
        update={
            "verdict_id": "second",
            "detector": "rdp_brute_force_detector",
            "event_ids": ["other-event"],
            "scope": Scope(
                affected_accounts=["admin"],
                affected_hosts=["bastion-02"],
                attempt_count=40,
                source_diversity=3,
                succeeded=True,
            ),
        }
    )
    report = _aggregate(talos_settings, [sample_verdict, other])
    assert report is not None
    scope = report.aggregate_scope
    assert scope.affected_accounts == ["admin", "root"]
    assert scope.affected_hosts == ["bastion-01", "bastion-02"]
    assert scope.attempt_count == 40
    assert scope.source_diversity == 3
    assert scope.succeeded is True


def test_independent_detectors_corroborate(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    other = sample_verdict.model_copy(
        update={
            "verdict_id": "second",
            "detector": "rdp_brute_force_detector",
            "event_ids": ["other-event"],
            "confidence": 0.8,
        }
    )
    report = _aggregate(talos_settings, [sample_verdict, other])
    assert report is not None
    assert report.confidence == 0.96  # 0.91 + one 0.05 corroboration boost


def test_severity_rises_when_the_attack_succeeded(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    blocked = _aggregate(talos_settings, [sample_verdict])
    landed = _aggregate(
        talos_settings,
        [sample_verdict.model_copy(update={"scope": Scope(succeeded=True, attempt_count=12)})],
    )
    assert blocked is not None and blocked.severity == "medium"
    assert landed is not None and landed.severity == "high"


def test_low_confidence_drops_severity(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    unsure = sample_verdict.model_copy(update={"confidence": 0.3})
    report = _aggregate(talos_settings, [unsure])
    assert report is not None
    assert report.severity == "low"


def test_actions_name_the_source_and_the_account(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    report = _aggregate(talos_settings, [sample_verdict])
    assert report is not None
    joined = " | ".join(report.recommended_actions)
    assert "203.0.113.7" in joined
    assert "root" in joined


def test_successful_attack_adds_containment_actions(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    landed = sample_verdict.model_copy(
        update={"scope": sample_verdict.scope.model_copy(update={"succeeded": True})}
    )
    report = _aggregate(talos_settings, [landed])
    assert report is not None
    assert any("rotate credentials" in action for action in report.recommended_actions)


def test_summary_reads_as_one_triage_line(
    talos_settings: TalosSettings, sample_verdict: Verdict
) -> None:
    report = _aggregate(talos_settings, [sample_verdict])
    assert report is not None
    assert report.summary.startswith("brute_force on bastion-01")
    assert "did not succeed" in report.summary
