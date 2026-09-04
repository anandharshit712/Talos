"""The learned access pattern: what it remembers, what it forgets, and when it is mature.

The bounds are the interesting part. A baseline is read and rewritten on every object access, so
it must stay small -- and every eviction rule is a chance to forget the thing the detector was
about to need.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from talos.detection.baseline.access_baseline import (
    AccessBaseline,
    is_mature,
    new_baseline,
    numeric_id,
    observe,
    outside_numeric_range,
)

AT = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

BOUNDS = {"max_object_ids": 5, "max_endpoints": 3}


def _record(
    baseline: AccessBaseline, *ids: str, endpoint: str | None = "/api/orders"
) -> AccessBaseline:
    for index, object_id in enumerate(ids):
        baseline = observe(
            baseline,
            object_id=object_id,
            endpoint=endpoint,
            at=AT + timedelta(seconds=index),
            **BOUNDS,
        )
    return baseline


# --- the empty case -------------------------------------------------------------------------


def test_a_new_baseline_is_immature() -> None:
    """An account Talos has never seen is not a suspicious account."""
    baseline = new_baseline("alice", AT)
    assert baseline.observations == 0
    assert not is_mature(baseline, min_observations=1)


def test_maturity_is_reached_at_the_threshold_not_after_it() -> None:
    baseline = _record(new_baseline("alice", AT), *[str(1000 + n) for n in range(3)])
    assert not is_mature(baseline, min_observations=4)
    assert is_mature(baseline, min_observations=3)


# --- numeric ids ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1002", 1002),
        ("  1002  ", 1002),
        ("-7", -7),
        ("order-1002", None),
        ("1002a", None),
        ("2f9d8c1e-0000-4000-8000-000000000000", None),
        ("", None),
        ("1_002", None),
    ],
)
def test_only_plain_integers_are_numeric_ids(raw: str, expected: int | None) -> None:
    """A loose parse would invent a numeric range for opaque ids, then call every one an outlier."""
    assert numeric_id(raw) == expected


def test_the_range_widens_to_cover_every_numeric_id_seen() -> None:
    baseline = _record(new_baseline("alice", AT), "1005", "1002", "1009")
    assert (baseline.numeric_min, baseline.numeric_max) == (1002, 1009)


def test_non_numeric_ids_do_not_disturb_the_range() -> None:
    baseline = _record(new_baseline("alice", AT), "1005", "order-x", "1009")
    assert (baseline.numeric_min, baseline.numeric_max) == (1005, 1009)


def test_an_id_inside_the_learned_range_is_not_a_deviation() -> None:
    baseline = _record(new_baseline("alice", AT), "1000", "1010")
    assert not outside_numeric_range(baseline, "1005")


def test_an_id_beyond_either_end_is_a_deviation() -> None:
    baseline = _record(new_baseline("alice", AT), "1000", "1010")
    assert outside_numeric_range(baseline, "999")
    assert outside_numeric_range(baseline, "1011")


def test_the_boundaries_themselves_are_not_deviations() -> None:
    baseline = _record(new_baseline("alice", AT), "1000", "1010")
    assert not outside_numeric_range(baseline, "1000")
    assert not outside_numeric_range(baseline, "1010")


def test_an_unanswerable_range_question_is_not_evidence() -> None:
    """No numeric history, or a non-numeric id: neither is grounds for an accusation."""
    assert not outside_numeric_range(new_baseline("alice", AT), "1005")
    assert not outside_numeric_range(_record(new_baseline("alice", AT), "1000"), "order-x")


def test_eviction_never_narrows_the_learned_range() -> None:
    """The range is what stops an old id from becoming an outlier once its entry is evicted."""
    baseline = _record(new_baseline("alice", AT), *[str(1000 + n) for n in range(8)])

    assert "1000" not in baseline.seen_object_ids  # evicted, cap is 5
    assert baseline.numeric_min == 1000
    assert not outside_numeric_range(baseline, "1000")


# --- bounded collections --------------------------------------------------------------------


def test_object_ids_are_capped_and_the_oldest_goes_first() -> None:
    baseline = _record(new_baseline("alice", AT), *[str(1000 + n) for n in range(8)])
    assert baseline.seen_object_ids == ["1003", "1004", "1005", "1006", "1007"]


def test_re_accessing_an_id_refreshes_it_rather_than_duplicating_it() -> None:
    baseline = _record(new_baseline("alice", AT), "1001", "1002", "1003", "1001")
    assert baseline.seen_object_ids == ["1002", "1003", "1001"]
    assert baseline.observations == 4


def test_every_access_counts_toward_maturity_even_a_repeat() -> None:
    """Observations is not the collection size: both collections are bounded, maturity is not."""
    baseline = _record(new_baseline("alice", AT), *["1001"] * 6)
    assert baseline.seen_object_ids == ["1001"]
    assert baseline.observations == 6


def test_endpoint_counts_accumulate() -> None:
    baseline = new_baseline("alice", AT)
    baseline = _record(baseline, "1001", "1002", endpoint="/api/orders")
    baseline = _record(baseline, "1003", endpoint="/api/invoices")
    assert baseline.endpoints == {"/api/orders": 2, "/api/invoices": 1}


def test_a_missing_endpoint_is_skipped_not_recorded_as_empty() -> None:
    baseline = _record(new_baseline("alice", AT), "1001", endpoint=None)
    assert baseline.endpoints == {}
    assert baseline.observations == 1


def test_endpoints_are_capped_and_the_least_used_goes_first() -> None:
    baseline = new_baseline("alice", AT)
    baseline = _record(baseline, "1001", "1002", "1003", endpoint="/busy")
    baseline = _record(baseline, "1004", "1005", endpoint="/medium")
    baseline = _record(baseline, "1006", endpoint="/rare")
    baseline = _record(baseline, "1007", endpoint="/newest")

    assert "/rare" not in baseline.endpoints
    assert set(baseline.endpoints) == {"/busy", "/medium", "/newest"}


def test_a_novel_endpoint_survives_its_own_arrival_on_a_full_baseline() -> None:
    """It is the least-used by definition, so naive eviction would drop it immediately -- and
    endpoint novelty is one of the deviation features, so it must be learnable."""
    baseline = new_baseline("alice", AT)
    baseline = _record(baseline, "1001", "1002", endpoint="/a")
    baseline = _record(baseline, "1003", "1004", endpoint="/b")
    baseline = _record(baseline, "1005", "1006", endpoint="/c")

    baseline = _record(baseline, "1007", endpoint="/brand-new")

    assert "/brand-new" in baseline.endpoints
    assert len(baseline.endpoints) == 3


# --- housekeeping ---------------------------------------------------------------------------


def test_observe_does_not_mutate_the_baseline_it_was_given() -> None:
    """The store folds inside a transaction and decides when to write; a hidden mutation there
    would leave a rolled-back transaction with an updated in-memory baseline."""
    original = _record(new_baseline("alice", AT), "1001")
    snapshot = original.model_copy(deep=True)

    observe(original, object_id="9999", endpoint="/other", at=AT, **BOUNDS)

    assert original == snapshot


def test_updated_at_tracks_the_latest_access() -> None:
    later = AT + timedelta(hours=3)
    baseline = observe(
        new_baseline("alice", AT), object_id="1001", endpoint="/a", at=later, **BOUNDS
    )
    assert baseline.updated_at == later


def test_the_model_round_trips_through_json() -> None:
    """It is persisted as jsonb and read back on the hot path, so the shape must survive."""
    baseline = _record(new_baseline("alice", AT), "1001", "1002")
    assert AccessBaseline.model_validate_json(baseline.model_dump_json()) == baseline
