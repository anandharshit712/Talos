"""**A P8 calibration diagnostic, not a gate.** Attack *vocabulary* in ordinary prose.

The fixture is 32 lines a real search box, bug tracker, or code-help site would receive: people
*discussing* SQL and XSS, not attacking. `how do I write a UNION SELECT`, `sanitise <script> tags`,
`sleep(5) in javascript vs mysql`. It exists to answer a question the in-distribution corpus
cannot: is the static confidence honest when the input is adversarial free text?

The answer, measured, is **mostly yes with a documented edge**. Seven of the 32 fire, and the
seven divide cleanly:

* **Four are not really false positives.** `<script>`, `javascript:`, `<svg onload=>` submitted to
  a request parameter *are* the XSS surface — a normal app reflects or stores them, and the user's
  intent does not change that. Calling them benign is a property of a discussion site, not of the
  input. The detector is right to fire.
* **Three are genuinely ambiguous** — `OR 1=1`, `and 1=1`, `sleep(5)`. In a numeric parameter these
  are canonical injection; in a sentence they are prose, and an access log cannot tell the field
  types apart. They are correct for the target app class (params carry values, not essays) and a
  documented limitation on a discussion-oriented one.

One clean win came out of writing this: `UNION SELECT` followed by prose (`... across two tables`)
used to fire and no longer does — the rule now requires a column list. That was lossless, proven by
the captured-payload recall holding at 0.89 (LLD §16.15).

**This test pins the count so the edge cannot silently widen.** A rise fails; a fall is an
improvement the author must lower the baseline to acknowledge. It never asserts zero — that would
be asserting the detector ignores a script tag in a parameter.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from memory_baseline_store import MemoryBaselineStore
from stub_model_client import StubModelRouter

from talos.core.agent_contracts import DetectionContext
from talos.core.settings import TalosSettings
from talos.domains.web.web_domain_agent import WebDomainAgent
from talos.ingestion.parsers.web_log_parser import WebLogParser
from talos.storage.event_window_store import EventWindowStore

pytestmark = pytest.mark.e2e

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "logs" / "web_attack_vocabulary_in_prose.log"
)
CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"

#: The documented out-of-distribution rate: 7 of 32 prose lines carry a real attack indicator.
#: Four are the XSS surface (a script tag in a parameter is dangerous whatever the user meant);
#: three are ambiguous tautology/timing signals. Lower is better; this must not rise.
DOCUMENTED_FIRINGS = 7


class _Recording:
    def __init__(self) -> None:
        self.reports: list = []

    async def append(self, report: object) -> None:
        self.reports.append(report)


def _fired() -> list[tuple[str, float, str]]:
    settings = TalosSettings.load(config_dir=CONFIG_DIR)
    settings.llm.enabled = False
    ctx = DetectionContext(
        event_window=EventWindowStore(
            ttl_seconds=settings.storage.event_window_ttl_seconds,
            max_events_per_key=settings.storage.event_window_max_events,
        ),
        baseline_store=MemoryBaselineStore(),
        model_client=StubModelRouter(),
        settings=settings,
        verdict_log=_Recording(),
    )
    agent = WebDomainAgent()
    parser = WebLogParser()
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()

    async def run() -> list[tuple[str, float, str]]:
        out = []
        for event in parser.parse_stream(lines):
            ctx.event_window.add(event)
            for verdict in await agent.process(event, ctx):
                if verdict.attack_detected:
                    out.append(
                        (
                            verdict.technique,
                            verdict.confidence,
                            event.request.query_params.get("q", ""),
                        )
                    )
        return out

    return asyncio.run(run())


def test_the_prose_corpus_parses() -> None:
    assert FIXTURE.exists()
    assert len(FIXTURE.read_text(encoding="utf-8").splitlines()) == 32


def test_attack_vocabulary_in_prose_stays_at_the_documented_rate() -> None:
    fired = _fired()
    assert len(fired) <= DOCUMENTED_FIRINGS, (
        f"out-of-distribution firings rose to {len(fired)} (documented {DOCUMENTED_FIRINGS}); "
        f"if this is a real precision regression, fix it -- if intended, update the baseline. "
        f"fired: {[(t, round(c, 2), q[:40]) for t, c, q in fired]}"
    )


def test_no_union_select_prose_fires() -> None:
    """The one clean win: UNION SELECT followed by natural language no longer fires (P8)."""
    fired = _fired()
    union_prose = [q for _, _, q in fired if "union select across" in q.lower()]
    assert union_prose == [], union_prose
