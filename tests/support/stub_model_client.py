"""A model router double: records what was asked, returns what the test decided (LLD 14).

Every detector on the LLM path must be testable with no network, no key, and no provider. This
stands in for ``ModelRouter`` in ``DetectionContext.model_client`` and gives a test three levers:

* ``StubModelRouter()`` — unreachable model, so callers take their templated path
* ``StubModelRouter(replies={"ssh_brute_force_detector": {"narrative": "..."}})`` — a canned answer
* ``StubModelRouter(replies=..., confidence_multiplier=0.85)`` — as if a fallback answered

``prompts`` holds every prompt sent, which is how the prompt-injection tests assert that
attacker-controlled text arrived sealed rather than as instructions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from talos.core.agent_contracts import ModelOutcome


@dataclass
class RecordedCall:
    """One request the stub received."""

    component: str
    prompt: str
    schema: dict[str, Any]
    max_tokens: int


@dataclass
class StubModelRouter:
    """Satisfies the ``ModelCaller`` protocol without leaving the process."""

    replies: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Component name -> the JSON body to return. Absent means "no model available"."""
    model_name: str = "stub-model"
    route_reason: str = "stub"
    confidence_multiplier: float = 1.0
    calls: list[RecordedCall] = field(default_factory=list)

    async def complete_for(
        self,
        component: str,
        *,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int = 512,
    ) -> ModelOutcome | None:
        self.calls.append(RecordedCall(component, prompt, schema, max_tokens))
        reply = self.replies.get(component)
        if reply is None:
            return None
        return ModelOutcome(
            data=reply,
            model=self.model_name,
            route_reason=self.route_reason,
            confidence_multiplier=self.confidence_multiplier,
        )

    @property
    def prompts(self) -> list[str]:
        """Just the prompt texts, in order."""
        return [call.prompt for call in self.calls]

    def prompt_for(self, component: str) -> str:
        """The last prompt sent for one component. Fails loudly if there was none."""
        for call in reversed(self.calls):
            if call.component == component:
                return call.prompt
        raise AssertionError(f"no model call was made for {component!r}")
