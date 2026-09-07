"""**The P8 gate.** Runs ``metrics_harness`` over the labelled corpus and holds it to the bar.

The harness explains the labelling rules; this file only decides what counts as passing:

* **Zero false positives on the benign corpus.** Not "high precision" -- zero. At this corpus
  size any non-zero rate has error bars too wide to state honestly, so the bar is the one that
  survives being quoted: *nothing fired on benign traffic*. Where a detector cannot reach it,
  the threshold that can is the one that ships, and the recall given up is recorded.
* **Windowed detectors must catch every attack log.** One log, one attack, no excuses.
* **Payload detectors keep the P4 targets** -- precision >= 0.90, recall >= 0.85 per line.
* **Calibration is asserted only where there is data for it.** A bucket holding three verdicts
  cannot confirm or deny NFR-3, and pretending otherwise is how a measurement becomes a claim.
* **Latency p95 stays sub-second** per event (NFR-1), with the model off.

Run ``pytest tests/e2e/test_corpus_metrics_gate.py -s`` to read the tables. The JSON written to
``out/metrics/`` is what ``docs/operations/Talos_Evaluation_Results.md`` quotes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from metrics_harness import CORPUS, REPO_ROOT, Measurement, Score, measure, render

pytestmark = pytest.mark.e2e

#: Below this a bucket cannot say anything about calibration, so it is reported and not asserted.
MIN_BUCKET_SAMPLES = 10

#: How far a well-populated bucket may sit from its own midpoint claim (NFR-3).
CALIBRATION_TOLERANCE = 0.15

#: Carried over from the P4 gate, which measured these two the same way.
PER_LINE_PRECISION_TARGET = 0.90
PER_LINE_RECALL_TARGET = 0.85

#: NFR-1: the classifier is sub-second, and with no model in the loop everything else is faster.
LATENCY_P95_CEILING_MS = 1000.0


@pytest.fixture(scope="module")
def measured() -> Measurement:
    """One corpus run shared by every assertion below -- it is the expensive part."""
    out = measure(use_llm=False)
    print(render(out))
    destination = REPO_ROOT / "out" / "metrics" / "corpus_metrics.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(out.as_dict(), indent=2) + "\n", encoding="utf-8")
    return out


def test_the_corpus_actually_ran(measured: Measurement) -> None:
    """A harness that silently parsed nothing would pass every other test in this file."""
    assert measured.events > 0, "no events parsed -- check the fixture paths"
    assert measured.incidents > 0, "no incidents at all, so nothing below is measuring detection"
    assert measured.scores, "no technique was scored"


def test_the_benign_corpus_stays_silent(measured: Measurement) -> None:
    """The bar, and the only assertion here that is not a threshold argument."""
    assert measured.false_positive_detail == [], (
        f"{measured.false_positives} false positive(s) on benign traffic: "
        f"{measured.false_positive_detail}"
    )


def test_every_windowed_attack_log_is_detected(measured: Measurement) -> None:
    windowed = {case.technique for case in CORPUS if not case.is_benign and not case.per_line}
    missed = [
        technique
        for technique in windowed
        if technique and measured.score_for(technique).false_negatives > 0
    ]
    assert missed == [], f"windowed detectors missed an entire attack log: {missed}"


@pytest.mark.parametrize("technique", ["sql_injection", "xss"])
def test_payload_detectors_keep_the_p4_targets(measured: Measurement, technique: str) -> None:
    score = measured.score_for(technique)
    assert score.true_positives > 0, f"{technique} fired on nothing at all"
    assert score.precision >= PER_LINE_PRECISION_TARGET, f"precision {score.precision:.2f}"
    assert score.recall >= PER_LINE_RECALL_TARGET, f"recall {score.recall:.2f}"


def test_no_confidence_band_is_overconfident(measured: Measurement) -> None:
    """NFR-3 in the direction that can hurt: claiming 0.9 and being right 0.6 of the time.

    Under-confidence is deliberately not a failure here -- see ``Bucket.overconfidence``.
    """
    populated = [b for b in measured.buckets.values() if b.verdicts >= MIN_BUCKET_SAMPLES]
    if not populated:
        pytest.skip(
            f"no confidence band holds {MIN_BUCKET_SAMPLES} verdicts yet "
            f"(largest: {max((b.verdicts for b in measured.buckets.values()), default=0)})"
        )
    off = [
        (b.lower, round(b.claim, 2), round(b.observed, 2), b.verdicts)
        for b in populated
        if b.overconfidence > CALIBRATION_TOLERANCE
    ]
    assert off == [], f"overconfident bands (lower, claim, observed, n): {off}"


def test_calibration_is_reported_as_measurable_or_not(measured: Measurement) -> None:
    """The P8 finding, pinned so it cannot be quietly lost.

    NFR-3 asks whether a 90%-confidence verdict is right 90% of the time. That needs verdicts
    that turned out **wrong**, and this corpus produces none -- every band reads 1.00 by
    construction. So the gate records "not measurable" rather than reporting a calibration it
    did not measure. When the corpus grows hard negatives, this flips on its own.
    """
    if measured.wrong_verdicts == 0:
        assert measured.as_dict()["calibration_measurable"] is False
        pytest.skip(
            "calibration unmeasurable: 0 wrong verdicts in the corpus. Every confidence band "
            "reads 1.00 whatever it claimed. Needs hard negatives -- P8 corpus open item."
        )
    assert measured.as_dict()["calibration_measurable"] is True


def test_latency_stays_within_nfr_1(measured: Measurement) -> None:
    p95 = measured.percentile(0.95)
    assert p95 < LATENCY_P95_CEILING_MS, f"p95 {p95:.1f}ms per event"


def test_nothing_reached_a_model(measured: Measurement) -> None:
    """The whole gate is measured on the statistical path, so this must hold or it is void."""
    assert measured.used_llm is False


def test_the_score_arithmetic_is_right() -> None:
    """The figures every other test reads come out of these four lines, so pin them."""
    score = Score(true_positives=8, false_positives=2, false_negatives=4)
    assert score.precision == 0.8
    assert score.recall == 8 / 12
    assert score.f1 == pytest.approx(2 * 0.8 * (8 / 12) / (0.8 + 8 / 12))
    empty = Score()
    assert empty.precision == 1.0 and empty.recall == 1.0 and empty.f1 == 1.0


def test_the_results_file_is_written(measured: Measurement) -> None:
    """``Talos_Evaluation_Results.md`` quotes this file, so its shape is part of the gate."""
    path = Path(REPO_ROOT / "out" / "metrics" / "corpus_metrics.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["corpus"]["events"] == measured.events
    assert payload["used_llm"] is False
    assert set(payload) >= {"corpus", "detectors", "calibration", "latency_ms", "false_positives"}
