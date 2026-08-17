"""``VerdictAggregator`` -- verdicts in, one ``IncidentReport`` out (LLD 4.3).

Five steps: dedupe, merge scope, score severity, combine confidence, recommend actions. The
contributing verdicts travel into the report untouched -- the trace is the deliverable, so
nothing that produced the conclusion is summarised away.

An aggregation where no verdict claims an attack returns ``None``. Inconclusive verdicts still
ride along inside a report that some other verdict created, but they never create one
themselves: "we looked and found nothing" is a different claim from "nothing fired" (LLD 11).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from talos.core.constants import SEVERITIES, Severity
from talos.core.settings import TalosSettings
from talos.knowledge.mitre_mapping import mitre_all
from talos.schemas.event_schema import NormalizedEvent
from talos.schemas.report_schema import IncidentReport
from talos.schemas.verdict_schema import MitreMapping, Scope, Verdict

#: Severity floor per category, before the success and confidence adjustments.
CATEGORY_BASE_SEVERITY: dict[str, Severity] = {
    "injection": "high",
    "broken_access_control": "high",
    "auth_failure": "medium",
    "network_brute_force": "medium",
}

#: Applied when nothing more specific is registered.
DEFAULT_BASE_SEVERITY: Severity = "medium"

#: Below this, a verdict is a lead rather than a finding, and severity steps down one level.
LOW_CONFIDENCE = 0.5

#: Category -> action templates. ``{accounts}``, ``{hosts}``, ``{sources}``, ``{endpoints}``,
#: and ``{objects}`` are filled from the merged scope.
CATEGORY_ACTIONS: dict[str, tuple[str, ...]] = {
    "network_brute_force": (
        "block source IP {sources} at the perimeter",
        "review authentication history for {accounts} on {hosts}",
    ),
    "auth_failure": (
        "block or rate-limit source IP {sources}",
        "force a password reset for {accounts}",
    ),
    "injection": (
        "block source IP {sources}",
        "review and patch input handling on {endpoints}",
    ),
    "broken_access_control": (
        "revoke the session for {accounts}",
        "audit access to objects {objects}",
    ),
}

#: Added when the attack is known to have succeeded, for any category.
SUCCESS_ACTIONS = (
    "rotate credentials for {accounts} -- the attempt succeeded",
    "hunt for follow-on activity on {target}",
)


class VerdictAggregator:
    """Merges the verdicts raised for one event into a single incident."""

    def __init__(self, settings: TalosSettings) -> None:
        self._settings = settings

    def aggregate(self, event: NormalizedEvent, verdicts: list[Verdict]) -> IncidentReport | None:
        """Return the incident these verdicts describe, or ``None`` if none of them fired."""
        deduped = self._dedupe(verdicts)
        firing = [verdict for verdict in deduped if verdict.attack_detected]
        if not firing:
            return None

        scope = self._merge_scope(firing)
        confidence = self._aggregate_confidence(firing)
        leading = max(firing, key=lambda verdict: verdict.confidence)
        severity = self._severity(leading.category, confidence, scope.succeeded)

        return IncidentReport(
            incident_id=uuid.uuid4().hex,
            domain=event.domain,
            category=leading.category,
            summary=self._summary(leading, scope),
            severity=severity,
            confidence=confidence,
            verdicts=deduped,
            aggregate_scope=scope,
            mitre_techniques=self._techniques(firing),
            recommended_actions=self._actions(leading.category, scope, event),
        )

    def _dedupe(self, verdicts: list[Verdict]) -> list[Verdict]:
        """One verdict per (technique, event set); the most confident duplicate wins."""
        best: dict[tuple[str, tuple[str, ...]], Verdict] = {}
        for verdict in verdicts:
            key = (verdict.technique, tuple(sorted(verdict.event_ids)))
            incumbent = best.get(key)
            if incumbent is None or verdict.confidence > incumbent.confidence:
                best[key] = verdict
        return sorted(best.values(), key=lambda verdict: verdict.confidence, reverse=True)

    def _merge_scope(self, verdicts: list[Verdict]) -> Scope:
        """Union the lists, take the widest window, and let any success win."""
        scopes = [verdict.scope for verdict in verdicts]
        successes = [scope.succeeded for scope in scopes if scope.succeeded is not None]
        starts = [scope.window_start for scope in scopes if scope.window_start is not None]
        ends = [scope.window_end for scope in scopes if scope.window_end is not None]
        counts = [scope.attempt_count for scope in scopes if scope.attempt_count is not None]
        diversity = [
            scope.source_diversity for scope in scopes if scope.source_diversity is not None
        ]

        return Scope(
            affected_accounts=_union(scope.affected_accounts for scope in scopes),
            affected_endpoints=_union(scope.affected_endpoints for scope in scopes),
            affected_objects=_union(scope.affected_objects for scope in scopes),
            affected_hosts=_union(scope.affected_hosts for scope in scopes),
            attempt_count=max(counts) if counts else None,
            source_diversity=max(diversity) if diversity else None,
            succeeded=any(successes) if successes else None,
            window_start=min(starts) if starts else None,
            window_end=max(ends) if ends else None,
        )

    def _aggregate_confidence(self, verdicts: list[Verdict]) -> float:
        """Max confidence, nudged up when independent detectors corroborate each other."""
        highest = max(verdict.confidence for verdict in verdicts)
        distinct_detectors = len({verdict.detector for verdict in verdicts})
        boost = self._settings.aggregation.corroboration_boost * (distinct_detectors - 1)
        return round(min(1.0, highest + boost), 3)

    def _severity(self, category: str, confidence: float, succeeded: bool | None) -> Severity:
        """Category floor, one step up if the attack landed, one step down if we are unsure."""
        index = SEVERITIES.index(CATEGORY_BASE_SEVERITY.get(category, DEFAULT_BASE_SEVERITY))
        if succeeded:
            index += 1
        if confidence < LOW_CONFIDENCE:
            index -= 1
        return SEVERITIES[max(0, min(index, len(SEVERITIES) - 1))]

    def _techniques(self, verdicts: list[Verdict]) -> list[MitreMapping]:
        """Every ATT&CK technique implied by the firing verdicts, de-duplicated, ordered."""
        seen: dict[str, MitreMapping] = {}
        for verdict in verdicts:
            for mapping in mitre_all(verdict.technique):
                seen.setdefault(mapping.technique_id, mapping)
        return [seen[technique_id] for technique_id in sorted(seen)]

    def _summary(self, leading: Verdict, scope: Scope) -> str:
        """One line an analyst can triage on without opening the verdicts."""
        target = ", ".join(scope.affected_hosts or scope.affected_endpoints) or "an unnamed target"
        accounts = ", ".join(scope.affected_accounts)
        against = f" against {accounts}" if accounts else ""
        attempts = f" over {scope.attempt_count} attempts" if scope.attempt_count else ""
        outcome = "succeeded" if scope.succeeded else "did not succeed"
        return (
            f"{leading.technique} on {target}{against}{attempts} -- {outcome} "
            f"(confidence {leading.confidence:.2f})"
        )

    def _actions(self, category: str, scope: Scope, event: NormalizedEvent) -> list[str]:
        """Fill the category's action templates from the merged scope."""
        hosts = ", ".join(scope.affected_hosts)
        endpoints = ", ".join(scope.affected_endpoints)
        fields = {
            "accounts": ", ".join(scope.affected_accounts) or "the targeted account",
            "hosts": hosts or "the affected host",
            "endpoints": endpoints or "the affected endpoint",
            "objects": ", ".join(scope.affected_objects) or "the listed objects",
            "target": hosts or endpoints or "the affected asset",
            "sources": _sources_phrase(scope, event),
        }
        templates = list(CATEGORY_ACTIONS.get(category, ()))
        if scope.succeeded:
            templates.extend(SUCCESS_ACTIONS)
        return [template.format(**fields).strip() for template in templates]


def _union(value_lists: Iterable[list[str]]) -> list[str]:
    """Sorted union of several string lists, so report fields are stable across runs."""
    merged: set[str] = set()
    for values in value_lists:
        merged.update(values)
    return sorted(merged)


def _sources_phrase(scope: Scope, event: NormalizedEvent) -> str:
    """``Scope`` counts source IPs but does not name them; the triggering event does."""
    source = event.actor.source_ip
    others = (scope.source_diversity or 1) - 1
    return source if others <= 0 else f"{source} and {others} other source address(es)"
