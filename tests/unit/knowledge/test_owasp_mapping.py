"""OWASP coverage must not drift from ATT&CK coverage."""

from __future__ import annotations

import pytest

from talos.knowledge.mitre_mapping import ATTACK_TECHNIQUE_IDS
from talos.knowledge.owasp_mapping import (
    OWASP_CATEGORIES,
    OWASP_CATEGORY_IDS,
    owasp_by_id,
    owasp_for,
)


def test_both_frameworks_cover_the_same_techniques() -> None:
    """A verdict carries both mappings, so a technique missing from either is a hole."""
    assert set(OWASP_CATEGORY_IDS) == set(ATTACK_TECHNIQUE_IDS)


def test_every_referenced_category_exists() -> None:
    assert set(OWASP_CATEGORY_IDS.values()) <= set(OWASP_CATEGORIES)


@pytest.mark.parametrize(
    ("technique", "category_id"),
    [
        ("sql_injection", "A03:2021"),
        ("xss", "A03:2021"),
        ("brute_force", "A07:2021"),
        ("credential_stuffing", "A07:2021"),
        ("idor", "A01:2021"),
    ],
)
def test_technique_maps_to_expected_category(technique: str, category_id: str) -> None:
    assert owasp_for(technique).category_id == category_id


def test_categories_are_immutable() -> None:
    with pytest.raises(ValueError, match="frozen"):
        owasp_by_id("A03:2021").name = "Injection (2017)"


def test_unknown_technique_fails_loudly() -> None:
    with pytest.raises(KeyError, match="unknown Talos technique"):
        owasp_for("ssrf")
    with pytest.raises(KeyError, match="unknown OWASP category id"):
        owasp_by_id("A99:2021")
