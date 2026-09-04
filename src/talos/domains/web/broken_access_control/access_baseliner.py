"""Feeds one account's access baseline from live events (LLD 7.4).

Deliberately not a detector. It emits no ``Verdict`` and makes no model call: folding an access
into a baseline is bookkeeping, and putting a model in front of it would add a per-event network
call to the hot path for a decision that is arithmetic.

**Two ordering rules, and both are load-bearing.**

*Score before you learn.* If the current access is folded in first, its object id is already in
``seen_object_ids`` and inside ``numeric_min..numeric_max``, so ``outside_range`` is false by
construction and the detector can never fire on the very event that should trip it.

*Learn only from traffic that scored clean.* An enumeration run is exactly the traffic that would
teach the baseline that walking the id space is normal for this account. Recording an access the
scorer just flagged is how a detector trains itself to stop detecting -- so the sub-agent records
only when nothing fired.
"""

from __future__ import annotations

import logging
import re

from talos.core.agent_contracts import DetectionContext
from talos.core.error_types import StorageError
from talos.schemas.event_schema import NormalizedEvent

_log = logging.getLogger(__name__)

#: A trailing path segment that reads as an object id. Mirrors the web parser's own rule, and
#: covers the hex/uuid case the parser leaves alone so an opaque id still counts as an access.
OBJECT_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8,})$", re.I)


def object_id_of(event: NormalizedEvent) -> str | None:
    """The object this request names, or ``None`` when it does not name one.

    Prefers the parser's ``resource_id`` and falls back to the trailing path segment, so an
    opaque identifier the parser skipped is still an object access -- it simply contributes no
    numeric range.
    """
    if event.target.resource_id:
        return event.target.resource_id
    path = (event.request.path if event.request else None) or event.target.endpoint
    if not path:
        return None
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return last if OBJECT_SEGMENT.match(last) else None


def endpoint_template(event: NormalizedEvent) -> str | None:
    """The endpoint with its trailing object id removed -- ``/api/orders/1002`` -> ``/api/orders``.

    The **template** is what "has this account used this endpoint before" can be asked about.
    Keying on the raw path instead makes every single object access a novel endpoint forever,
    turns ``novel_endpoint`` into a constant, and grows the bounded endpoints map by one entry
    per object -- which then evicts the real endpoints. Found by a discriminator test that fired
    on a legitimate user opening one new record (LLD rev 1.13).
    """
    path = (event.request.path if event.request else None) or event.target.endpoint
    if not path:
        return None
    trimmed = path.rstrip("/")
    head, separator, last = trimmed.rpartition("/")
    if separator and OBJECT_SEGMENT.match(last):
        return head or "/"
    return trimmed or "/"


def is_object_access(event: NormalizedEvent) -> bool:
    """Whether this event is one account reaching for one identified object."""
    return bool(event.actor.account) and object_id_of(event) is not None


class AccessBaseliner:
    """Records object accesses against the account's baseline."""

    component_name = "access_baseliner"

    async def record(self, event: NormalizedEvent, ctx: DetectionContext) -> None:
        """Fold this access into the account's baseline. A storage failure is not fatal.

        Fail-open for detection: a baseline that could not be written costs future accuracy for
        that account, and losing the pipeline instead would cost every detector on every event.
        """
        account = event.actor.account
        object_id = object_id_of(event)
        if account is None or object_id is None:
            return

        idor = ctx.settings.detection.idor
        recorder = getattr(ctx.baseline_store, "record_access", None)
        if recorder is None:
            # The Protocol only promises get/put. A store without the locked read-modify-write
            # (the P2 stand-in, or a test double) simply learns nothing rather than racing.
            _log.debug(
                "baseline store does not support locked updates, not learning",
                extra={"account": account, "store": type(ctx.baseline_store).__name__},
            )
            return

        try:
            await recorder(
                account,
                object_id=object_id,
                endpoint=endpoint_template(event),
                at=event.timestamp,
                max_object_ids=idor.max_seen_object_ids,
                max_endpoints=idor.max_endpoints,
            )
        except StorageError:
            _log.warning(
                "could not update the access baseline; this account learns nothing from this event",
                extra={"account": account, "event_id": event.event_id},
            )
