"""The deterministic pre-filter both injection detectors share (LLD 7.1, 7.2).

SQLi and XSS differ in their pattern tables and in nothing else: both read the same request
fields, match the same way, and need the same evidence out the other end. Building that once is
what lets a new pattern family be a table rather than a module.

**The static layer decides; the model only judges what the static layer flags as borderline.**
A rule carries `unambiguous` — `UNION SELECT` is not a false positive waiting to happen, while a
bare `--` in a comment field very much is. Unambiguous hits produce a verdict with no model call
at all, which is both faster and the thing that keeps precision measurable (HLD 8).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from talos.schemas.event_schema import NormalizedEvent

#: How much of a matched payload travels into evidence. Enough to recognise, not enough to let a
#: megabyte of request body into a report or a prompt.
EXCERPT_CHARS = 160


@dataclass(frozen=True)
class PatternRule:
    """One named signal, and how much weight a match carries on its own."""

    pattern_class: str
    """Family the rule belongs to: ``tautology``, ``union``, ``script_tag``, ..."""
    name: str
    """Specific rule, unique within its class. Appears verbatim in evidence."""
    pattern: re.Pattern[str]
    unambiguous: bool
    """True when a match is decisive on its own, so no model judgement is needed."""
    corroborating_only: bool = False
    """True when a match must never, on its own, make this detector act.

    Some signals are worth counting but fire constantly on ordinary content: a bare ``--`` in
    prose, ``<b>bold</b>`` in a comment field. Left actionable they would send every such request
    to a model -- burning a 40-requests-per-minute budget on punctuation, and inviting the model
    to agree that markup is an attack. They corroborate other classes and nothing more.
    """
    note: str = ""
    """Why this rule is safe to fire on, or what it deliberately excludes."""


@dataclass(frozen=True)
class PatternHit:
    """One rule matching one field of one request."""

    pattern_class: str
    name: str
    field: str
    """Where it matched: ``query.id``, ``body``, ``path``."""
    excerpt: str
    unambiguous: bool
    corroborating_only: bool = False

    def describe(self) -> str:
        """Evidence line: what matched, where, and what it looked like."""
        return f"{self.pattern_class}/{self.name} in {self.field}: {self.excerpt}"


def extract_web_payloads(event: NormalizedEvent) -> dict[str, str]:
    """Every attacker-controlled string on a web request, keyed by where it came from.

    The path is included because injection through a path segment is ordinary. Headers are not:
    they are attacker-controlled, but matching them produces false positives from scanners and
    referrers at a rate that would swamp the corpus. A header-borne payload is a documented gap
    rather than an accident.
    """
    request = event.request
    if request is None:
        return {}

    payloads: dict[str, str] = {}
    if request.path:
        payloads["path"] = request.path
    for key, value in request.query_params.items():
        if value:
            payloads[f"query.{key}"] = value
    if request.body:
        payloads["body"] = request.body
    return payloads


def match_patterns(payloads: dict[str, str], rules: tuple[PatternRule, ...]) -> list[PatternHit]:
    """Every rule that fires, against every field. Deterministic and order-stable."""
    hits: list[PatternHit] = []
    for field, value in payloads.items():
        for rule in rules:
            found = rule.pattern.search(value)
            if found is None:
                continue
            hits.append(
                PatternHit(
                    pattern_class=rule.pattern_class,
                    name=rule.name,
                    field=field,
                    excerpt=excerpt(found.group(0)),
                    unambiguous=rule.unambiguous,
                    corroborating_only=rule.corroborating_only,
                )
            )
    return hits


def has_unambiguous(hits: list[PatternHit]) -> bool:
    """True when at least one hit is decisive on its own."""
    return any(hit.unambiguous for hit in hits)


def is_actionable(hits: list[PatternHit]) -> bool:
    """True when something fired that is allowed to make the detector act.

    Corroboration-only hits are excluded: a request whose sole signal is ``--`` in a sentence is
    cleared by the static layer, never escalated. This is the guard that keeps benign markup from
    consuming the model budget and from being put to a model that might agree with it.
    """
    return any(not hit.corroborating_only for hit in hits)


def distinct_classes(hits: list[PatternHit]) -> list[str]:
    """Pattern families represented, sorted. Several families at once is itself a signal."""
    return sorted({hit.pattern_class for hit in hits})


def affected_fields(hits: list[PatternHit]) -> list[str]:
    """Request fields that carried a payload, sorted."""
    return sorted({hit.field for hit in hits})


def excerpt(text: str, limit: int = EXCERPT_CHARS) -> str:
    """Flatten and bound a matched fragment for evidence and prompts."""
    flattened = " ".join(text.split())
    if len(flattened) <= limit:
        return flattened
    return f"{flattened[:limit]}... [+{len(flattened) - limit} chars]"
