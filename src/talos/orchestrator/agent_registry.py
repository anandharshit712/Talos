"""``AgentRegistry`` -- the extensibility mechanism (LLD 4.1, HLD NFR-4).

Domain agents register themselves at startup; the orchestrator asks this registry for a domain
and gets whatever was registered. Adding a domain touches this map and nothing else.
"""

from __future__ import annotations

from talos.core.agent_contracts import DomainAgent
from talos.core.error_types import ConfigError


class AgentRegistry:
    """Domain name -> the agent that owns it."""

    def __init__(self) -> None:
        self._domain_agents: dict[str, DomainAgent] = {}

    def register_domain_agent(self, agent: DomainAgent) -> None:
        """Register one domain agent. Registering a domain twice is a wiring bug."""
        if agent.domain in self._domain_agents:
            raise ConfigError(f"domain '{agent.domain}' already has a registered agent")
        self._domain_agents[agent.domain] = agent

    def get(self, domain: str) -> DomainAgent | None:
        """The agent for a domain, or ``None`` when nothing handles it.

        ``None`` rather than an exception: an event from an unconfigured domain is a routing
        miss the orchestrator logs and moves past, not a reason to stop reading the stream.
        """
        return self._domain_agents.get(domain)

    def domains(self) -> list[str]:
        return sorted(self._domain_agents)
