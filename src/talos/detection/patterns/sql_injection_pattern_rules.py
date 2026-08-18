"""SQL injection pattern table — five classes from LLD 7.1.

**Every rule is written against its benign lookalike.** A surname is `O'Brien`, a search box
receives `select a plan`, a comment field contains `--`, and a product filter legitimately holds
`1=1` in nobody's application but does hold `id=1`. A rule that fires on those buys recall with
precision, and precision is the number this detector is judged on (P4 gate: ≥90%).

So the rules demand SQL *syntax*, not SQL *vocabulary*: a quote followed by a boolean operator
followed by a comparison, not the word `OR`. Where a signal cannot be made precise on its own —
a lone comment marker, a bare `sleep(` — it is marked ambiguous and goes to the model, which is
what the model tier exists for.

R6 watch item (plan §4): if this table grows past ~700 lines, the patterns move to
`config/patterns/sql_injection_patterns.yaml` and this module becomes a loader and compiler.
"""

from __future__ import annotations

import re

from talos.detection.patterns.pattern_engine import PatternHit, PatternRule

_I = re.IGNORECASE

#: Quote characters an attacker uses to break out of a string literal, raw or once-decoded.
_QUOTE = r"['\"`]"

SQL_INJECTION_RULES: tuple[PatternRule, ...] = (
    # --- tautology: the classic authentication bypass ---------------------------------------
    PatternRule(
        pattern_class="tautology",
        name="quoted_boolean_equality",
        pattern=re.compile(
            rf"{_QUOTE}\s*(?:or|and)\s+{_QUOTE}?\w+{_QUOTE}?\s*(?:=|<>|!=|like)\s*"
            rf"{_QUOTE}?\w+{_QUOTE}?",
            _I,
        ),
        unambiguous=True,
        note="' OR '1'='1 -- requires a quote break plus an operator plus a comparison, so a "
        "surname like O'Brien or a phrase like 'and more' cannot reach it",
    ),
    PatternRule(
        pattern_class="tautology",
        name="numeric_always_true",
        pattern=re.compile(r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b", _I),
        unambiguous=True,
        note="OR 1=1, AND 7=7 -- the same number both sides is the tell; 'and 1=2' is caught by "
        "the blind-pair rule instead",
    ),
    PatternRule(
        pattern_class="tautology",
        name="quote_terminated_comment",
        pattern=re.compile(rf"{_QUOTE}\s*(?:--|#|/\*)", _I),
        unambiguous=True,
        note="a quote immediately followed by a comment marker closes a literal and discards the "
        "rest of the statement; prose does not do this",
    ),
    # --- union-based extraction -------------------------------------------------------------
    PatternRule(
        pattern_class="union",
        name="union_select",
        pattern=re.compile(r"\bunion\s+(?:all\s+)?select\b", _I),
        unambiguous=True,
        note="UnIoN SeLeCt is covered by the case-insensitive flag; inline comments are handled "
        "by the evasion class",
    ),
    PatternRule(
        pattern_class="union",
        name="union_comment_obfuscated",
        pattern=re.compile(r"\bunion\s*(?:/\*.*?\*/\s*)+(?:all\s*)?select\b", _I | re.DOTALL),
        unambiguous=True,
        note="UNION/**/SELECT -- comment padding between the keywords",
    ),
    PatternRule(
        pattern_class="union",
        name="select_from_information_schema",
        pattern=re.compile(r"\bfrom\s+information_schema\.\w+", _I),
        unambiguous=True,
        note="schema enumeration; no application sends this in a parameter",
    ),
    # --- stacked queries --------------------------------------------------------------------
    PatternRule(
        pattern_class="stacked",
        name="statement_terminator_then_ddl",
        pattern=re.compile(
            r";\s*(?:drop|insert|update|delete|create|alter|truncate|exec|execute)\s+\w+", _I
        ),
        unambiguous=True,
        note="; DROP TABLE -- a second statement smuggled after a terminator",
    ),
    PatternRule(
        pattern_class="stacked",
        name="stored_procedure_call",
        pattern=re.compile(r"\b(?:exec|execute)\s*\(?\s*(?:xp_|sp_)\w+", _I),
        unambiguous=True,
        note="xp_cmdshell and friends: command execution through the database",
    ),
    # --- blind injection --------------------------------------------------------------------
    PatternRule(
        pattern_class="blind",
        name="time_delay_function",
        pattern=re.compile(r"\b(?:sleep|pg_sleep|waitfor\s+delay|benchmark)\s*\(", _I),
        unambiguous=True,
        note="a timing oracle; benign traffic has no reason to name a delay function",
    ),
    PatternRule(
        pattern_class="blind",
        name="boolean_probe_pair",
        pattern=re.compile(r"\b(?:and|or)\s+(\d+)\s*=\s*(?!\1\b)\d+", _I),
        unambiguous=False,
        note="AND 1=2 -- the false half of a boolean oracle. Ambiguous alone: a filter string "
        "can contain it, so this goes to the model unless another class also fired",
    ),
    PatternRule(
        pattern_class="blind",
        name="conditional_substring",
        pattern=re.compile(r"\b(?:substring|substr|mid|ascii|char)\s*\(\s*(?:select|\w+\s*,)", _I),
        unambiguous=False,
        note="character-at-a-time extraction; the same functions appear in legitimate SQL, so a "
        "match in a request parameter is suspicious rather than conclusive",
    ),
    # --- comment and encoding evasion -------------------------------------------------------
    PatternRule(
        pattern_class="evasion",
        name="inline_comment_in_keyword",
        pattern=re.compile(r"\b(?:se|un|sel|uni)\w*/\*.*?\*/\w*", _I | re.DOTALL),
        unambiguous=True,
        note="SEL/**/ECT -- comment padding inside a keyword has one purpose",
    ),
    PatternRule(
        pattern_class="evasion",
        name="hex_encoded_string",
        pattern=re.compile(r"\b0x[0-9a-f]{16,}\b", _I),
        unambiguous=False,
        corroborating_only=True,
        note="long hex literals smuggle strings past quote filters, but also appear in legitimate "
        "tokens and hashes -- ambiguous by design",
    ),
    PatternRule(
        pattern_class="evasion",
        name="double_encoded_quote",
        pattern=re.compile(r"%25(?:27|22)", _I),
        unambiguous=False,
        note="%2527 survives one decode as %27. The parser decodes exactly once (LLD 5.2), so "
        "seeing this after decoding means someone encoded twice on purpose",
    ),
    PatternRule(
        pattern_class="evasion",
        name="comment_marker",
        pattern=re.compile(r"(?:--\s|#|/\*)"),
        unambiguous=False,
        corroborating_only=True,
        note="a bare comment marker. Ambiguous on its own -- '--' is ordinary in prose and in "
        "hyphenated text -- so it only matters alongside another class",
    ),
)

#: Distinct families that, appearing together, upgrade an otherwise ambiguous set to a confident
#: finding. Two, not three: the table only has two families capable of firing ambiguously
#: (``blind`` and ``evasion``), so a threshold of three could never be reached and the whole
#: corroboration path would be dead code. A test asserts it is reachable.
CORROBORATION_THRESHOLD = 2


def is_unambiguous(hits: list[PatternHit]) -> bool:
    """True when the static layer alone is enough to call this SQL injection.

    Either a decisive rule fired, or enough distinct **actionable** families fired together that
    the combination is decisive. Corroboration-only hits are excluded from that count on purpose:
    noise-grade signals may support a finding, but two of them must never manufacture certainty
    on their own -- otherwise ``<b>bold</b>`` beside one borderline signal would read as proof.
    """
    if any(hit.unambiguous for hit in hits):
        return True
    families = {hit.pattern_class for hit in hits if not hit.corroborating_only}
    return len(families) >= CORROBORATION_THRESHOLD


def infer_target_table(payloads: dict[str, str]) -> str | None:
    """The table an attacker named, when the payload names one. Sharpens report scope.

    Reads the payloads rather than the hits: a hit's excerpt is only the matched fragment, and
    ``UNION SELECT`` does not contain the table name that follows it.
    """
    for value in payloads.values():
        found = re.search(r"\bfrom\s+([a-z_][\w.]*)", value, _I)
        if found:
            return found.group(1)
    return None
