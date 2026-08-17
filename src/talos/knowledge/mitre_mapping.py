"""MITRE ATT&CK technique lookup for every technique Talos can emit (LLD 2.2, 7).

Two tables rather than one, because one technique string does not always mean one ATT&CK id:
IDOR is both a discovery behaviour (T1083) and a data-access one (T1530), and the LLD names
both. ``TECHNIQUE_CATALOG`` holds the ATT&CK facts keyed by id; ``ATTACK_TECHNIQUE_IDS`` maps
Talos' own ``Verdict.technique`` strings onto them, primary id first.

Detectors call :func:`mitre_for` for the single mapping a ``Verdict`` carries; the aggregator
calls :func:`mitre_all` to fill ``IncidentReport.mitre_techniques``. Nothing constructs a
``MitreMapping`` literal anywhere else -- a technique id typed by hand in a detector is a
mapping that no test can find.
"""

from __future__ import annotations

from talos.schemas.verdict_schema import MitreMapping

#: ATT&CK facts, keyed by technique id. Enterprise matrix, v15 naming.
TECHNIQUE_CATALOG: dict[str, MitreMapping] = {
    "T1110": MitreMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
    ),
    "T1110.004": MitreMapping(
        technique_id="T1110.004",
        technique_name="Brute Force: Credential Stuffing",
        tactic="Credential Access",
    ),
    "T1190": MitreMapping(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
    ),
    "T1059.007": MitreMapping(
        technique_id="T1059.007",
        technique_name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
    ),
    "T1083": MitreMapping(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
    ),
    "T1530": MitreMapping(
        technique_id="T1530",
        technique_name="Data from Cloud Storage",
        tactic="Collection",
    ),
}

#: ``Verdict.technique`` -> ATT&CK ids, most specific first. The first entry is the mapping the
#: verdict carries; the rest are reported alongside it at incident level.
ATTACK_TECHNIQUE_IDS: dict[str, tuple[str, ...]] = {
    "sql_injection": ("T1190",),
    "xss": ("T1059.007",),
    "brute_force": ("T1110",),
    "credential_stuffing": ("T1110.004", "T1110"),
    "idor": ("T1083", "T1530"),
}


def technique_by_id(technique_id: str) -> MitreMapping:
    """Return the ATT&CK mapping for a technique id, e.g. ``T1110.004``."""
    try:
        return TECHNIQUE_CATALOG[technique_id]
    except KeyError:
        raise KeyError(
            f"unknown ATT&CK technique id {technique_id!r}; add it to TECHNIQUE_CATALOG"
        ) from None


def mitre_for(technique: str) -> MitreMapping:
    """Return the primary ATT&CK mapping for a Talos technique, e.g. ``credential_stuffing``."""
    return technique_by_id(_ids_for(technique)[0])


def mitre_all(technique: str) -> list[MitreMapping]:
    """Return every ATT&CK mapping that applies to a Talos technique, primary first."""
    return [technique_by_id(technique_id) for technique_id in _ids_for(technique)]


def _ids_for(technique: str) -> tuple[str, ...]:
    try:
        return ATTACK_TECHNIQUE_IDS[technique]
    except KeyError:
        raise KeyError(
            f"unknown Talos technique {technique!r}; every technique a detector emits must be "
            f"registered in ATTACK_TECHNIQUE_IDS"
        ) from None
