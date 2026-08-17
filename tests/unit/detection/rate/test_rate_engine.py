"""Threshold, window, and success-after-burst -- the edges the whole rate family shares."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from talos.core.agent_contracts import DetectionContext
from talos.detection.rate.rate_engine import RateConfig, RateEngine
from talos.schemas.event_schema import NormalizedEvent
from talos.storage.event_window_store import host_account_key

CONFIG = RateConfig(window_seconds=120, fail_threshold=8, key_fn=host_account_key)

EventFactory = Callable[..., list[NormalizedEvent]]


def _feed(ctx: DetectionContext, events: list[NormalizedEvent]) -> NormalizedEvent:
    for event in events:
        ctx.event_window.add(event)
    return events[-1]


def test_at_threshold_fires(
    ctx_and_engine: tuple[DetectionContext, RateEngine], ssh_events: EventFactory
) -> None:
    ctx, engine = ctx_and_engine
    last = _feed(ctx, ssh_events(8))
    signal = engine.evaluate(last, ctx.event_window, CONFIG)
    assert signal is not None
    assert signal.count == 8


def test_one_under_threshold_stays_silent(
    ctx_and_engine: tuple[DetectionContext, RateEngine], ssh_events: EventFactory
) -> None:
    ctx, engine = ctx_and_engine
    last = _feed(ctx, ssh_events(7))
    assert engine.evaluate(last, ctx.event_window, CONFIG) is None


def test_failures_outside_the_window_do_not_count(
    ctx_and_engine: tuple[DetectionContext, RateEngine], ssh_events: EventFactory
) -> None:
    """Eight failures spread over an hour is maintenance noise, not a burst."""
    ctx, engine = ctx_and_engine
    last = _feed(ctx, ssh_events(8, spacing_seconds=600))
    assert engine.evaluate(last, ctx.event_window, CONFIG) is None


def test_success_after_the_burst_is_reported(
    ctx_and_engine: tuple[DetectionContext, RateEngine], ssh_events: EventFactory
) -> None:
    """The highest-value analyst signal: the grind worked."""
    ctx, engine = ctx_and_engine
    last = _feed(ctx, ssh_events(10, succeeded=True))
    signal = engine.evaluate(last, ctx.event_window, CONFIG)
    assert signal is not None
    assert signal.succeeded is True
    assert signal.count == 10  # the success is not counted as a failure


def test_success_before_the_burst_is_not_credited_to_it(
    ctx_and_engine: tuple[DetectionContext, RateEngine],
    ssh_events: EventFactory,
    make_ssh_event: Callable[..., NormalizedEvent],
) -> None:
    ctx, engine = ctx_and_engine
    ctx.event_window.add(make_ssh_event(outcome="success", offset_seconds=0))
    events = [make_ssh_event(offset_seconds=offset) for offset in range(10, 10 + 8 * 5, 5)]
    last = _feed(ctx, events)
    signal = engine.evaluate(last, ctx.event_window, CONFIG)
    assert signal is not None
    assert signal.succeeded is False


def test_signal_carries_scope_material(
    ctx_and_engine: tuple[DetectionContext, RateEngine],
    ssh_events: EventFactory,
    make_ssh_event: Callable[..., NormalizedEvent],
) -> None:
    ctx, engine = ctx_and_engine
    events = ssh_events(8)
    events.extend(
        make_ssh_event(source_ip="198.51.100.9", offset_seconds=offset) for offset in (41, 42)
    )
    last = _feed(ctx, events)
    signal = engine.evaluate(last, ctx.event_window, CONFIG)
    assert signal is not None
    assert signal.accounts == ("root",)
    assert signal.hosts == ("bastion-01",)
    assert signal.sources == ("198.51.100.9", "203.0.113.7")
    assert len(signal.event_ids) == signal.count
    assert 1 <= len(signal.sample_lines) <= 3


def test_non_auth_event_is_not_this_engine_s_business(
    ctx_and_engine: tuple[DetectionContext, RateEngine], ssh_events: EventFactory
) -> None:
    ctx, engine = ctx_and_engine
    last = _feed(ctx, ssh_events(10))
    flow_only = last.model_copy(update={"auth": None})
    assert engine.evaluate(flow_only, ctx.event_window, CONFIG) is None


def test_unkeyable_event_is_skipped(
    ctx_and_engine: tuple[DetectionContext, RateEngine], ssh_events: EventFactory
) -> None:
    ctx, engine = ctx_and_engine
    last = _feed(ctx, ssh_events(10))
    anonymous = last.model_copy(update={"actor": last.actor.model_copy(update={"account": None})})
    assert engine.evaluate(anonymous, ctx.event_window, CONFIG) is None


@pytest.fixture
def ctx_and_engine(detection_ctx: DetectionContext) -> tuple[DetectionContext, RateEngine]:
    return detection_ctx, RateEngine()
