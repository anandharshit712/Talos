"""Payload extraction, matching, and the corroboration-only guard (LLD 7.1, 7.2)."""

from __future__ import annotations

import re
from collections.abc import Callable

from talos.detection.patterns.pattern_engine import (
    EXCERPT_CHARS,
    PatternHit,
    PatternRule,
    affected_fields,
    distinct_classes,
    excerpt,
    extract_web_payloads,
    has_unambiguous,
    is_actionable,
    match_patterns,
)
from talos.schemas.event_schema import NormalizedEvent

EventFactory = Callable[..., NormalizedEvent]

DECISIVE = PatternRule(
    pattern_class="decisive",
    name="obvious",
    pattern=re.compile(r"attack"),
    unambiguous=True,
)
NOISY = PatternRule(
    pattern_class="noise",
    name="punctuation",
    pattern=re.compile(r"--"),
    unambiguous=False,
    corroborating_only=True,
)
BORDERLINE = PatternRule(
    pattern_class="maybe",
    name="worth_a_look",
    pattern=re.compile(r"suspicious"),
    unambiguous=False,
)
RULES = (DECISIVE, NOISY, BORDERLINE)


def test_every_attacker_controlled_field_is_extracted(make_web_event: EventFactory) -> None:
    event = make_web_event(path="/search", query={"q": "shoes", "page": "2"}, body="note=hi")
    assert extract_web_payloads(event) == {
        "path": "/search",
        "query.q": "shoes",
        "query.page": "2",
        "body": "note=hi",
    }


def test_empty_values_are_not_payloads(make_web_event: EventFactory) -> None:
    payloads = extract_web_payloads(make_web_event(query={"q": ""}))
    assert "query.q" not in payloads


def test_a_non_web_event_has_no_payloads(sample_event: NormalizedEvent) -> None:
    assert extract_web_payloads(sample_event) == {}


def test_matching_reports_the_field_it_fired_on(make_web_event: EventFactory) -> None:
    event = make_web_event(query={"q": "attack"}, body="clean")
    hits = match_patterns(extract_web_payloads(event), RULES)
    assert [hit.field for hit in hits] == ["query.q"]
    assert hits[0].name == "obvious"


def test_one_rule_can_fire_on_several_fields(make_web_event: EventFactory) -> None:
    event = make_web_event(query={"a": "attack", "b": "attack"})
    assert len(match_patterns(extract_web_payloads(event), RULES)) == 2


def test_corroboration_only_hits_never_make_the_detector_act() -> None:
    """A hyphen in prose must not spend a model call, nor invite a model to agree with it."""
    hits = match_patterns({"query.q": "I need help -- urgently"}, RULES)
    assert hits, "the rule should still record a hit"
    assert not is_actionable(hits)
    assert not has_unambiguous(hits)


def test_a_borderline_hit_is_actionable_but_not_certain() -> None:
    hits = match_patterns({"query.q": "something suspicious"}, RULES)
    assert is_actionable(hits)
    assert not has_unambiguous(hits)


def test_a_decisive_hit_is_both() -> None:
    hits = match_patterns({"query.q": "attack"}, RULES)
    assert is_actionable(hits)
    assert has_unambiguous(hits)


def test_no_hits_is_not_actionable() -> None:
    assert not is_actionable(match_patterns({"query.q": "ordinary text"}, RULES))


def test_summaries_are_sorted_and_deduplicated() -> None:
    hits = match_patterns({"query.b": "attack -- suspicious", "query.a": "attack"}, RULES)
    assert distinct_classes(hits) == ["decisive", "maybe", "noise"]
    assert affected_fields(hits) == ["query.a", "query.b"]


def test_excerpts_are_bounded_and_flattened() -> None:
    long_text = "A" * (EXCERPT_CHARS + 50)
    trimmed = excerpt(long_text)
    assert trimmed.endswith("[+50 chars]")
    assert excerpt("two\n\nlines   here") == "two lines here"


def test_hit_describes_itself_for_evidence() -> None:
    hit = PatternHit("union", "union_select", "query.id", "UNION SELECT", unambiguous=True)
    assert hit.describe() == "union/union_select in query.id: UNION SELECT"
