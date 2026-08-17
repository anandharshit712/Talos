"""Every technique a detector emits must resolve to ATT&CK -- the P1 gate."""

from __future__ import annotations

import pytest

from talos.knowledge.mitre_mapping import (
    ATTACK_TECHNIQUE_IDS,
    TECHNIQUE_CATALOG,
    mitre_all,
    mitre_for,
    technique_by_id,
)

#: Every ``Verdict.technique`` string the eight leaf detectors of the slice emit (LLD 7).
SLICE_TECHNIQUES = ("sql_injection", "xss", "brute_force", "credential_stuffing", "idor")


@pytest.mark.parametrize("technique", SLICE_TECHNIQUES)
def test_every_slice_technique_resolves(technique: str) -> None:
    mapping = mitre_for(technique)
    assert mapping.technique_id.startswith("T")
    assert mapping.technique_name
    assert mapping.tactic


def test_catalog_covers_every_referenced_id() -> None:
    referenced = {tid for ids in ATTACK_TECHNIQUE_IDS.values() for tid in ids}
    assert referenced <= set(TECHNIQUE_CATALOG)


def test_primary_mapping_is_the_most_specific_one() -> None:
    assert mitre_for("credential_stuffing").technique_id == "T1110.004"
    assert mitre_for("brute_force").technique_id == "T1110"


def test_idor_reports_both_applicable_techniques() -> None:
    """LLD 7.4 maps IDOR to discovery and to data access; the report carries both."""
    assert [m.technique_id for m in mitre_all("idor")] == ["T1083", "T1530"]


def test_mappings_are_immutable() -> None:
    with pytest.raises(ValueError, match="frozen"):
        TECHNIQUE_CATALOG["T1110"].technique_name = "something else"


def test_unknown_technique_fails_loudly() -> None:
    with pytest.raises(KeyError, match="unknown Talos technique"):
        mitre_for("ssrf")
    with pytest.raises(KeyError, match="unknown ATT&CK technique id"):
        technique_by_id("T9999")
