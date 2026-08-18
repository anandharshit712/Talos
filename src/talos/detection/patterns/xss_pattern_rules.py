"""Cross-site scripting pattern table — the classes from LLD 7.2.

Same discipline as the SQL table: every rule is written against the benign lookalike that would
otherwise defeat it. A comment field legitimately contains `<b>bold</b>`, a bug report
legitimately contains the word `onerror`, and a CMS legitimately posts HTML. So the rules require
an *executable* construct — a script element, an event handler bound to an attribute, a
`javascript:` URI — not the presence of angle brackets or a handler's name in prose.

Encoded variants get their own class because `%3Cscript%3E` after one decode pass means the
sender encoded twice, and the parser decodes exactly once (LLD 5.2). That is intent, not markup.
"""

from __future__ import annotations

import re

from talos.detection.patterns.pattern_engine import PatternHit, PatternRule

_I = re.IGNORECASE

#: HTML event handlers worth matching. Bound to `=` in the rule so the bare word in prose is safe.
_EVENT_HANDLERS = (
    "onerror|onload|onclick|onmouseover|onfocus|onblur|onsubmit|onchange|onanimationstart|"
    "ontoggle|onbeforeprint|onpageshow|onwheel|oncopy"
)

XSS_RULES: tuple[PatternRule, ...] = (
    # --- script elements --------------------------------------------------------------------
    PatternRule(
        pattern_class="script_tag",
        name="script_element",
        pattern=re.compile(r"<\s*script[\s>/]", _I),
        unambiguous=True,
        note="an actual script element. <b>bold</b> and other markup cannot reach this",
    ),
    PatternRule(
        pattern_class="script_tag",
        name="script_src_remote",
        pattern=re.compile(r"<\s*script[^>]{0,120}\bsrc\s*=", _I),
        unambiguous=True,
        note="remote script inclusion -- the payload does not even have to fit in the parameter",
    ),
    PatternRule(
        pattern_class="script_tag",
        name="svg_or_iframe_vector",
        pattern=re.compile(r"<\s*(?:svg|iframe|embed|object|math)[^>]{0,80}\bon\w+\s*=", _I),
        unambiguous=True,
        note="element that executes without a script tag, carrying a handler",
    ),
    # --- event handlers ---------------------------------------------------------------------
    PatternRule(
        pattern_class="event_handler",
        name="handler_assignment",
        pattern=re.compile(rf"\b(?:{_EVENT_HANDLERS})\s*=\s*['\"(]?\s*\w", _I),
        unambiguous=True,
        note="onerror=alert -- the handler must be assigned something. The word 'onerror' in a "
        "sentence, or 'onerror' with no assignment, does not match",
    ),
    PatternRule(
        pattern_class="event_handler",
        name="handler_with_payload_function",
        pattern=re.compile(
            rf"\b(?:{_EVENT_HANDLERS})\s*=\s*[^>]{{0,80}}"
            r"(?:alert|prompt|confirm|eval|fetch|document\.cookie)\s*\(",
            _I,
        ),
        unambiguous=True,
        note="a handler wired to a function that proves execution",
    ),
    PatternRule(
        pattern_class="event_handler",
        name="unlisted_handler_in_tag",
        pattern=re.compile(r"<[^>]{0,80}\bon[a-z]{3,20}\s*=\s*['\"(]?\s*\w", _I),
        unambiguous=False,
        note="an attribute inside a tag that is shaped like an event handler but is not one of "
        "the names above -- onpointerdown, onauxclick, or tomorrow's addition. Genuinely "
        "borderline, so it is judged rather than assumed: this is the case the model tier "
        "exists for, and without it the XSS judge path would be unreachable",
    ),
    # --- javascript: and data: URIs ---------------------------------------------------------
    PatternRule(
        pattern_class="uri_scheme",
        name="javascript_uri",
        pattern=re.compile(r"javascript\s*:\s*[\w$]", _I),
        unambiguous=True,
        note="tolerates the whitespace and entity padding filters miss",
    ),
    PatternRule(
        pattern_class="uri_scheme",
        name="data_uri_html",
        pattern=re.compile(r"data\s*:\s*text/html", _I),
        unambiguous=True,
        note="a document smuggled into an attribute",
    ),
    # --- encoded variants -------------------------------------------------------------------
    PatternRule(
        pattern_class="encoded",
        name="encoded_script_tag",
        pattern=re.compile(r"(?:%3c|&lt;|\\u003c|&#0*60;)\s*script", _I),
        unambiguous=True,
        note="the parser decodes once, so an encoded tag surviving that was encoded twice",
    ),
    PatternRule(
        pattern_class="encoded",
        name="html_entity_handler",
        pattern=re.compile(rf"&#x?0*(?:6f|111);?\s*n?(?:{_EVENT_HANDLERS})?", _I),
        unambiguous=False,
        corroborating_only=True,
        note="entity-encoded handler prefix. Ambiguous: entity encoding is also just correct "
        "escaping, which is the opposite of an attack",
    ),
    PatternRule(
        pattern_class="encoded",
        name="base64_script_payload",
        pattern=re.compile(r"base64\s*,\s*[A-Za-z0-9+/]{24,}={0,2}", _I),
        unambiguous=False,
        corroborating_only=True,
        note="base64 in a URI is ordinary for images; only suspicious with other signals",
    ),
    # --- attribute breakout -----------------------------------------------------------------
    PatternRule(
        pattern_class="breakout",
        name="quote_then_tag",
        pattern=re.compile(r"['\"]\s*>\s*<\s*\w+", _I),
        unambiguous=True,
        note="closing an attribute and a tag to start a new element -- '\"><script is the shape",
    ),
    PatternRule(
        pattern_class="breakout",
        name="tag_close_then_handler",
        pattern=re.compile(rf">\s*<[^>]{{0,60}}\b(?:{_EVENT_HANDLERS})\s*=", _I),
        unambiguous=True,
        note="breakout followed by a handler",
    ),
    PatternRule(
        pattern_class="breakout",
        name="bare_angle_bracket_pair",
        pattern=re.compile(r"<\s*/?\s*\w+[^>]{0,40}>"),
        unambiguous=False,
        corroborating_only=True,
        note="any HTML-looking fragment. Deliberately ambiguous: <b>bold</b> in a comment field "
        "is the single most common benign lookalike in the corpus",
    ),
)

#: Distinct families that together make an otherwise ambiguous set decisive. Two, for the same
#: reason as the SQL table: only ``encoded`` and ``breakout`` can fire ambiguously here, so a
#: higher threshold would make the corroboration path unreachable.
CORROBORATION_THRESHOLD = 2

#: Status codes that mean the payload was served back rather than rejected.
REFLECTED_STATUS = frozenset({200, 201, 202, 302})


def is_unambiguous(hits: list[PatternHit]) -> bool:
    """True when the static layer alone is enough to call this XSS.

    Either a decisive rule fired, or enough distinct **actionable** families fired together that
    the combination is decisive. Corroboration-only hits are excluded from that count on purpose:
    noise-grade signals may support a finding, but two of them must never manufacture certainty
    on their own -- otherwise ``<b>bold</b>`` beside one borderline signal would read as proof.
    """
    if any(hit.unambiguous for hit in hits):
        return True
    families = {hit.pattern_class for hit in hits if not hit.corroborating_only}
    return len(families) >= CORROBORATION_THRESHOLD


def payload_signature(hits: list[PatternHit]) -> str:
    """A stable key for "this same payload", used to spot a stored payload rendering later.

    Built from the matched fragments rather than the whole request: the same payload arrives at
    one endpoint and renders at another, so anything path-dependent would never match twice.
    """
    fragments = sorted({hit.excerpt.lower() for hit in hits})
    return "|".join(fragments)[:200]
