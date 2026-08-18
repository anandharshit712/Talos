"""Per-pattern-class positives, and the benign corpus that keeps precision honest (plan P4)."""

from __future__ import annotations

import pytest

from talos.detection.patterns.pattern_engine import distinct_classes, is_actionable, match_patterns
from talos.detection.patterns.sql_injection_pattern_rules import (
    SQL_INJECTION_RULES,
    infer_target_table,
    is_unambiguous,
)


def hits(payload: str):
    return match_patterns({"query.id": payload}, SQL_INJECTION_RULES)


# --- positives, one per class ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected_class"),
    [
        ("1' OR '1'='1", "tautology"),
        ("1 OR 1=1--", "tautology"),
        ("admin'--", "tautology"),
        ("' UNION SELECT username,password FROM users--", "union"),
        ("1 UNION/**/SELECT null,version()", "union"),
        ("x' UNION SELECT table_name FROM information_schema.tables--", "union"),
        ("2026; DROP TABLE invoices", "stacked"),
        ("1; EXEC xp_cmdshell('whoami')", "stacked"),
        ("x' AND SLEEP(5)--", "blind"),
        ("1 AND 1=2", "blind"),
    ],
)
def test_attack_payload_fires_its_class(payload: str, expected_class: str) -> None:
    found = hits(payload)
    assert is_actionable(found), payload
    assert expected_class in distinct_classes(found), payload


@pytest.mark.parametrize(
    "payload",
    [
        "1' OR '1'='1",
        "' UNION SELECT username,password FROM users--",
        "2026; DROP TABLE invoices",
        "x' AND SLEEP(5)--",
        "1 UNION/**/SELECT null,version()",
    ],
)
def test_decisive_payloads_need_no_model(payload: str) -> None:
    """The static layer carries the gate; escalating these would waste the request budget."""
    assert is_unambiguous(hits(payload))


def test_case_and_spacing_do_not_evade() -> None:
    assert is_unambiguous(hits("1 UnIoN   SeLeCt 1,2"))


# --- the benign corpus -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "O'Brien",
        "d'Artagnan",
        "select a plan",
        "union square hotel",
        "SELECT",
        "3 or 4 items",
        "drop me a line",
        "insert coin",
        "price < 100 and rating > 4",
        "user@example.com",
        "1=1 is a tautology, discuss",
        "I need help -- urgent",
        "The Comment -- with dashes",
        "#hashtag",
        "café",
        "shoes",
        "1042",
    ],
)
def test_benign_lookalikes_do_not_fire(payload: str) -> None:
    """A precision claim is only as good as its benign corpus (plan P4)."""
    assert not is_actionable(hits(payload)), f"false positive on {payload!r}"


def test_a_lone_comment_marker_is_corroboration_not_a_finding() -> None:
    found = hits("I need help -- urgent")
    assert found, "the marker should still be recorded"
    assert not is_actionable(found)


# --- helpers ------------------------------------------------------------------------------------


def test_families_corroborating_are_decisive_without_any_single_one_being() -> None:
    """One ambiguous signal is noise; two families at once in one parameter is a payload.

    Also proves the corroboration path is reachable at all: only ``blind`` and ``evasion`` can
    fire ambiguously *and* actionably, so a threshold above two would make this branch dead code.
    Corroboration-only hits do not count toward it -- noise must not manufacture certainty.
    """
    combined = match_patterns({"query.id": "%2527 AND 1=3"}, SQL_INJECTION_RULES)
    assert not any(hit.unambiguous for hit in combined)
    assert len(distinct_classes(combined)) >= 2
    assert is_unambiguous(combined)


def test_the_named_table_sharpens_scope() -> None:
    """Read from the payload, not the matched fragment: "UNION SELECT" has no table in it."""
    assert infer_target_table({"query.id": "' UNION SELECT a FROM customers--"}) == "customers"


def test_no_table_named_is_none() -> None:
    assert infer_target_table({"query.id": "1' OR '1'='1"}) is None
