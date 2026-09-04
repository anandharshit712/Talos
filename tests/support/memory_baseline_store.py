"""An in-memory ``BaselineStore`` for tests that need the pipeline, not the database.

It runs the **real** update rule -- ``access_baseline.observe`` -- so a baseline built through
this store matures exactly as one built through PostgreSQL. What it drops is persistence and the
per-account lock, and neither is what an end-to-end pipeline test is about: the locked
read-modify-write has its own live suite in ``tests/integration/``.

The same reasoning as the in-memory verdict log. A test that needs a server to prove a classifier
routes correctly is a test nobody runs.
"""

from __future__ import annotations

from talos.detection.baseline.access_baseline import AccessBaseline, new_baseline, observe
from talos.schemas.event_schema import UtcDatetime


class MemoryBaselineStore:
    """Satisfies ``BaselineReader`` plus ``record_access``, entirely in process."""

    def __init__(self) -> None:
        self.baselines: dict[str, AccessBaseline] = {}

    async def get(self, account: str) -> AccessBaseline | None:
        return self.baselines.get(account)

    async def put(self, baseline: AccessBaseline) -> None:
        self.baselines[baseline.account] = baseline

    async def record_access(
        self,
        account: str,
        *,
        object_id: str,
        endpoint: str | None,
        at: UtcDatetime,
        max_object_ids: int,
        max_endpoints: int,
    ) -> AccessBaseline:
        current = self.baselines.get(account) or new_baseline(account, at)
        updated = observe(
            current,
            object_id=object_id,
            endpoint=endpoint,
            at=at,
            max_object_ids=max_object_ids,
            max_endpoints=max_endpoints,
        )
        self.baselines[account] = updated
        return updated
