"""OWASP Top 10 (2021) lookup for every technique Talos can emit.

The same shape as ``mitre_mapping``: reference facts in one table, Talos' own technique
strings mapped onto them in another. Reports carry both frameworks because they answer
different questions -- ATT&CK says what the adversary did, OWASP says which class of
application weakness let them.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class OwaspCategory(BaseModel):
    """One OWASP Top 10 category."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category_id: str = Field(min_length=1)
    """e.g. ``A03:2021``."""
    name: str = Field(min_length=1)


#: OWASP Top 10 2021 categories that the hackathon slice can produce.
OWASP_CATEGORIES: dict[str, OwaspCategory] = {
    "A01:2021": OwaspCategory(category_id="A01:2021", name="Broken Access Control"),
    "A03:2021": OwaspCategory(category_id="A03:2021", name="Injection"),
    "A07:2021": OwaspCategory(
        category_id="A07:2021", name="Identification and Authentication Failures"
    ),
}

#: ``Verdict.technique`` -> OWASP category id.
OWASP_CATEGORY_IDS: dict[str, str] = {
    "sql_injection": "A03:2021",
    "xss": "A03:2021",
    "brute_force": "A07:2021",
    "credential_stuffing": "A07:2021",
    "idor": "A01:2021",
}


def owasp_by_id(category_id: str) -> OwaspCategory:
    """Return an OWASP category by its id, e.g. ``A03:2021``."""
    try:
        return OWASP_CATEGORIES[category_id]
    except KeyError:
        raise KeyError(
            f"unknown OWASP category id {category_id!r}; add it to OWASP_CATEGORIES"
        ) from None


def owasp_for(technique: str) -> OwaspCategory:
    """Return the OWASP category for a Talos technique, e.g. ``sql_injection``."""
    try:
        category_id = OWASP_CATEGORY_IDS[technique]
    except KeyError:
        raise KeyError(
            f"unknown Talos technique {technique!r}; every technique a detector emits must be "
            f"registered in OWASP_CATEGORY_IDS"
        ) from None
    return owasp_by_id(category_id)
