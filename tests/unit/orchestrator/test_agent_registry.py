"""The registry is the entire integration surface for a new domain (LLD 4.1)."""

from __future__ import annotations

import pytest

from talos.core.error_types import ConfigError
from talos.domains.network.network_domain_agent import NetworkDomainAgent
from talos.orchestrator.agent_registry import AgentRegistry


def test_registered_agent_is_returned_by_domain() -> None:
    registry = AgentRegistry()
    agent = NetworkDomainAgent()
    registry.register_domain_agent(agent)
    assert registry.get("network") is agent
    assert registry.domains() == ["network"]


def test_unknown_domain_is_none_not_an_exception() -> None:
    """An event from an unconfigured domain is a routing miss, not a reason to stop reading."""
    assert AgentRegistry().get("mainframe") is None


def test_registering_a_domain_twice_is_a_wiring_bug() -> None:
    registry = AgentRegistry()
    registry.register_domain_agent(NetworkDomainAgent())
    with pytest.raises(ConfigError, match="already has a registered agent"):
        registry.register_domain_agent(NetworkDomainAgent())
