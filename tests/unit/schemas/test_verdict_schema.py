"""A ``Verdict`` that cannot justify itself must not be constructible (LLD 2.2, 11)."""

from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from talos.schemas.verdict_schema import Evidence, ModelInfo, Scope, Verdict


def test_round_trip_is_lossless(sample_verdict: Verdict) -> None:
    reloaded = Verdict.model_validate_json(sample_verdict.model_dump_json())
    assert reloaded == sample_verdict


def test_created_at_defaults_to_aware_utc(sample_verdict: Verdict) -> None:
    assert sample_verdict.created_at.tzinfo is not None
    assert sample_verdict.created_at.utcoffset() == UTC.utcoffset(None)


def test_evidence_cannot_be_empty(sample_verdict: Verdict) -> None:
    """Fail-safe for reporting: no verdict ships without an artifact behind it."""
    with pytest.raises(ValidationError):
        Verdict.model_validate(sample_verdict.model_dump() | {"evidence": []})


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_confidence_stays_within_zero_to_one(sample_verdict: Verdict, confidence: float) -> None:
    with pytest.raises(ValidationError):
        Verdict.model_validate(sample_verdict.model_dump() | {"confidence": confidence})


def test_scope_defaults_are_empty_not_none() -> None:
    """Aggregation unions these lists; ``None`` would make every merge a null check."""
    scope = Scope()
    assert scope.affected_accounts == []
    assert scope.affected_objects == []
    assert scope.succeeded is None


def test_statistical_verdict_records_no_model() -> None:
    info = ModelInfo(name="none", route_reason="statistical path", used_llm=False)
    assert info.used_llm is False


def test_evidence_kind_is_a_closed_vocabulary() -> None:
    with pytest.raises(ValidationError):
        Evidence(kind="vibes", detail="looked wrong")  # type: ignore[arg-type]
