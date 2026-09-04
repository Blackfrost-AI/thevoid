"""Tests for the curated attack-scenario library (roadmap R-6)."""

import pytest

from scenarios import (
    Scenario,
    ScenarioLibrary,
    scenario_library,
)


# ─── Catalog integrity ───────────────────────────────────────────────


def test_library_has_builtin_scenarios():
    names = scenario_library.names()
    assert len(names) >= 5
    for expected in (
        "baseline-network", "mcp-critical", "cloud-hygiene",
        "llm-trust", "crypto-persistence",
    ):
        assert expected in names


def test_each_scenario_has_required_fields():
    for s in scenario_library.list():
        assert isinstance(s.name, str) and s.name
        assert isinstance(s.description, str) and s.description
        assert s.version
        assert isinstance(s.phases, (list, tuple))
        assert isinstance(s.mitre_techniques, (list, tuple))
        assert s.name == s.name.lower()   # names always normalized


def test_no_unknown_phases_in_scenarios():
    """Each scenario phase must be real — registered in the phase registry."""
    from agent.phase_registry import PhaseRegistry
    r = PhaseRegistry()
    registered = set(r.phases)
    for s in scenario_library.list():
        for phase in s.phases:
            assert phase in registered, \
                f"{s.name}: unknown phase in registry: {phase!r}"


# ─── Fetch ───────────────────────────────────────────────────────────


def test_get_by_name():
    for s in scenario_library.list():
        retrieved = scenario_library.get(s.name)
        assert retrieved.name == s.name


def test_get_normalizes_names():
    for s in scenario_library.list():
        retrieved = scenario_library.get(s.name.upper())
        assert retrieved.name == s.name


def test_get_unknown_scenario_raises():
    with pytest.raises(KeyError, match="unknown scenario"):
        scenario_library.get("no-such-scenario")


def test_get_phases():
    for s in scenario_library.list():
        phases = scenario_library.get_phases(s.name)
        assert phases == list(s.phases)


# ─── Catalog mutation ────────────────────────────────────────────────


def test_register_new_scenario():
    lib = ScenarioLibrary()
    lib.register(Scenario(
        name="demo-new",
        description="Extra scenario",
        phases=("recon",),
        mitre_techniques=("T1046",),
        version="1.0",
    ))
    assert "demo-new" in lib.names()
    assert lib.get("demo-new").name == "demo-new"


def test_register_duplicate_raises():
    lib = ScenarioLibrary()
    with pytest.raises(ValueError, match="already registered"):
        lib.register(Scenario(
            name="baseline-network",
            description="Clash",
            phases=(),
            mitre_techniques=(),
            version="1.0",
        ))


# ─── ShadowAgent integration ──────────────────────────────────────


def test_agent_set_and_clear_scenario():
    from agent.shadow_agent import ShadowAgent
    agent = ShadowAgent.__new__(ShadowAgent)
    agent._scenario_library = None
    agent._scenario_phases = None
    agent.scenario = None

    agent.set_scenario("mcp-critical")
    assert agent.scenario == "mcp-critical"

    info = agent.get_scenario()
    assert info["name"] == "mcp-critical"
    assert info["phases"] == ["mcp_scan", "mcp_attack", "mcp_chain", "mcp_c2"]

    agent.set_scenario(None)
    assert agent.scenario is None
    assert agent._scenario_phases is None


def test_agent_set_unknown_scenario_raises():
    from agent.shadow_agent import ShadowAgent
    agent = ShadowAgent.__new__(ShadowAgent)
    agent._scenario_library = None

    with pytest.raises(KeyError, match="unknown scenario"):
        agent.set_scenario("no-such-scenario")


def test_agent_phases_for_mode_with_scenario():
    """Scenario overrides mode — and authorization still applies."""
    from agent.shadow_agent import ShadowAgent
    agent = ShadowAgent.__new__(ShadowAgent)
    agent._scenario_library = None
    agent._scenario_phases = None
    agent.scenario = None
    agent.extra_denied_phases = set()
    agent.authz = None
    agent.MODE_PHASES = {"full": ["recon", "exploit"]}

    # No scenario → mode-driven
    assert agent.phases_for_mode("full") == ["recon", "exploit"]

    # Scenario replaces mode
    agent.set_scenario("mcp-critical")
    phases = agent.phases_for_mode("full")
    assert phases == ["mcp_scan", "mcp_attack", "mcp_chain", "mcp_c2"]

    # Authorization still applies after scenario
    class _Gate:
        def filter_phases(self, p):
            return [x for x in p if x != "mcp_c2"]
    agent.authz = _Gate()
    phases = agent.phases_for_mode("full")
    assert "mcp_c2" not in phases

    agent.set_scenario(None)
    assert agent.phases_for_mode("full") == ["recon", "exploit"]
