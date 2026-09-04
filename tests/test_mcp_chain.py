"""THE VOID — Tests for MCPChain module: MCP attack chaining and cascade detection."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.mcp_chain import (
    MCPChain, ChainNode, ChainEdge, AttackChain, CascadeResult,
    NODE_TYPES, EDGE_PRECONDITIONS, NODE_ENTRY, NODE_PIVOT,
    NODE_OBJECTIVE, NODE_LATERAL, NODE_SINK,
    TECHNIQUE_PROMPT_INJECTION, TECHNIQUE_TOOL_INVOCATION,
    TECHNIQUE_CREDENTIAL_THEFT, TECHNIQUE_RCE, TECHNIQUE_DATA_EXFIL,
    TECHNIQUE_TOOL_POISONING, TECHNIQUE_AUTH_BYPASS,
    TECHNIQUE_FILESYSTEM_TRAVERSAL, TECHNIQUE_TOOL_SHADOWING,
    TECHNIQUE_CONFUSED_DEPUTY, TECHNIQUE_PERSISTENT_ACCESS,
    TECHNIQUE_LATERAL_MOVEMENT,
    _node_id, _finding_to_node, _edge_probability,
)
from core.executor import Executor
from core.target import Target
from core.boneyard import Boneyard
from core.warlog import WarLog


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS TESTS — ChainNode
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainNode:
    """Tests for ChainNode dataclass."""

    def test_init(self):
        n = ChainNode(id="n-1", node_type="entry_point")
        assert n.id == "n-1"
        assert n.node_type == "entry_point"
        assert n.finding_ref is None
        assert n.server == ""
        assert n.technique == ""
        assert n.severity == "info"
        assert n.confidence == 0.0

    def test_init_full(self):
        n = ChainNode(id="n-2", node_type="pivot",
                      finding_ref="ref-1", server="s1",
                      technique="tool_poisoning", severity="high",
                      confidence=0.9, description="test",
                      evidence="evidence", metadata={"k": "v"})
        assert n.finding_ref == "ref-1"
        assert n.confidence == 0.9
        assert n.metadata == {"k": "v"}

    def test_to_dict(self):
        n = ChainNode(id="n-1", node_type="entry_point",
                      server="s1", confidence=0.8)
        d = n.to_dict()
        assert d["id"] == "n-1"
        assert d["node_type"] == "entry_point"
        assert d["server"] == "s1"
        assert d["confidence"] == 0.8

    def test_to_dict_roundtrip(self):
        n = ChainNode(id="n-1", node_type="pivot", technique="rce")
        d = n.to_dict()
        n2 = ChainNode.from_dict(d)
        assert n2.id == n.id
        assert n2.node_type == n.node_type
        assert n2.technique == n.technique

    def test_from_dict_defaults(self):
        n = ChainNode.from_dict({"id": "n-1"})
        assert n.id == "n-1"
        assert n.node_type == "pivot"
        assert n.confidence == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS TESTS — ChainEdge
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainEdge:
    """Tests for ChainEdge dataclass."""

    def test_init(self):
        e = ChainEdge(from_node="n-1", to_node="n-2",
                      technique="prompt_injection")
        assert e.from_node == "n-1"
        assert e.to_node == "n-2"
        assert e.technique == "prompt_injection"
        assert e.probability == 1.0

    def test_to_dict(self):
        e = ChainEdge(from_node="n-1", to_node="n-2",
                      technique="rce", probability=0.8)
        d = e.to_dict()
        assert d["from_node"] == "n-1"
        assert d["to_node"] == "n-2"
        assert d["probability"] == 0.8

    def test_from_dict(self):
        e = ChainEdge.from_dict({"from_node": "n-1", "to_node": "n-2",
                                  "technique": "rce"})
        assert e.from_node == "n-1"
        assert e.probability == 1.0


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS TESTS — AttackChain
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackChain:
    """Tests for AttackChain dataclass."""

    def test_init(self):
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[], edges=[])
        assert chain.chain_id == "c-1"
        assert chain.name == "test"
        assert chain.nodes == []
        assert chain.edges == []
        assert chain.total_probability == 1.0

    def test_init_with_nodes_and_edges(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="objective")
        e1 = ChainEdge(from_node="n-1", to_node="n-2",
                       technique="tool_poisoning", probability=0.8)
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2], edges=[e1],
                             total_probability=0.8)
        assert len(chain.nodes) == 2
        assert len(chain.edges) == 1
        assert chain.total_probability == 0.8

    def test_get_node(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="objective")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2], edges=[])
        assert chain.get_node("n-1") is n1
        assert chain.get_node("n-2") is n2
        assert chain.get_node("n-99") is None

    def test_get_edges_from(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="pivot")
        n3 = ChainNode(id="n-3", node_type="objective")
        e1 = ChainEdge(from_node="n-1", to_node="n-2", technique="rce")
        e2 = ChainEdge(from_node="n-2", to_node="n-3", technique="exfil")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2, n3], edges=[e1, e2])
        edges = chain.get_edges_from("n-1")
        assert len(edges) == 1
        assert edges[0].to_node == "n-2"

    def test_get_edges_to(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="pivot")
        n3 = ChainNode(id="n-3", node_type="objective")
        e1 = ChainEdge(from_node="n-1", to_node="n-2", technique="rce")
        e2 = ChainEdge(from_node="n-2", to_node="n-3", technique="exfil")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2, n3], edges=[e1, e2])
        edges = chain.get_edges_to("n-3")
        assert len(edges) == 1
        assert edges[0].from_node == "n-2"

    def test_entry_nodes(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="pivot")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2], edges=[])
        entries = chain.entry_nodes()
        assert len(entries) == 1
        assert entries[0].id == "n-1"

    def test_sink_nodes(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="objective")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2], edges=[])
        sinks = chain.sink_nodes()
        assert len(sinks) == 1
        assert sinks[0].id == "n-2"

    def test_to_dict(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1], edges=[])
        d = chain.to_dict()
        assert d["chain_id"] == "c-1"
        assert len(d["nodes"]) == 1

    def test_to_dict_roundtrip(self):
        n1 = ChainNode(id="n-1", node_type="entry_point")
        e1 = ChainEdge(from_node="n-1", to_node="n-2",
                       technique="rce", probability=0.7)
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1], edges=[e1])
        d = chain.to_dict()
        chain2 = AttackChain.from_dict(d)
        assert chain2.chain_id == "c-1"
        assert len(chain2.nodes) == 1
        assert len(chain2.edges) == 1


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS TESTS — CascadeResult
# ═══════════════════════════════════════════════════════════════════════════════

class TestCascadeResult:
    """Tests for CascadeResult dataclass."""

    def test_init(self):
        cr = CascadeResult(cascade_id="cs-1", chain_id="c-1",
                           path=[], cumulative_probability=0.5,
                           pattern="tool_poison_exfil")
        assert cr.cascade_id == "cs-1"
        assert cr.cumulative_probability == 0.5

    def test_to_dict(self):
        cr = CascadeResult(cascade_id="cs-1", chain_id="c-1",
                           path=[{"from": "n-1", "to": "n-2"}],
                           cumulative_probability=0.5,
                           pattern="tool_poison_exfil",
                           cross_server=True)
        d = cr.to_dict()
        assert d["cascade_id"] == "cs-1"
        assert d["cross_server"] is True

    def test_from_dict(self):
        d = {"cascade_id": "cs-1", "chain_id": "c-1",
             "path": [], "cumulative_probability": 0.5,
             "pattern": "test", "cross_server": False}
        cr = CascadeResult.from_dict(d)
        assert cr.cascade_id == "cs-1"
        assert cr.cumulative_probability == 0.5


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestModuleConstants:
    """Tests for module-level constants."""

    def test_technique_constants(self):
        assert TECHNIQUE_PROMPT_INJECTION == "prompt_injection"
        assert TECHNIQUE_TOOL_INVOCATION == "tool_invocation"
        assert TECHNIQUE_CREDENTIAL_THEFT == "credential_theft"
        assert TECHNIQUE_RCE == "rce"
        assert TECHNIQUE_DATA_EXFIL == "data_exfil"
        assert TECHNIQUE_TOOL_POISONING == "tool_poisoning"
        assert TECHNIQUE_AUTH_BYPASS == "auth_bypass"
        assert TECHNIQUE_FILESYSTEM_TRAVERSAL == "filesystem_traversal"
        assert TECHNIQUE_TOOL_SHADOWING == "tool_shadowing"
        assert TECHNIQUE_CONFUSED_DEPUTY == "confused_deputy"
        assert TECHNIQUE_PERSISTENT_ACCESS == "persistent_access"
        assert TECHNIQUE_LATERAL_MOVEMENT == "lateral_movement"

    def test_node_types(self):
        assert isinstance(NODE_TYPES, set)
        assert len(NODE_TYPES) == 5
        assert "entry_point" in NODE_TYPES
        assert "pivot" in NODE_TYPES
        assert "objective" in NODE_TYPES
        assert "lateral" in NODE_TYPES
        assert "sink" in NODE_TYPES

    def test_edge_preconditions(self):
        assert isinstance(EDGE_PRECONDITIONS, dict)
        assert len(EDGE_PRECONDITIONS) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL FUNCTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestModuleFunctions:
    """Tests for module-level functions."""

    def test_node_id(self):
        finding = {"type": "cve", "cve": "CVE-2025-6514"}
        nid = _node_id(finding, 0)
        assert isinstance(nid, str)
        assert len(nid) > 0

    def test_finding_to_node(self):
        finding = {
            "type": "cve",
            "severity": "high",
            "cve": "CVE-2025-6514",
            "attack_class": None,
            "evidence": "test",
            "confidence": 0.8,
            "endpoint": "/tools",
            "details": {"key": "val"},
        }
        node = _finding_to_node(finding, 0)
        assert isinstance(node, ChainNode)
        assert node.node_type == "entry_point"  # first finding is entry

    def test_edge_probability(self):
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       confidence=0.8, server="s1")
        n2 = ChainNode(id="n-2", node_type="pivot",
                       confidence=0.9, server="s2")
        prob = _edge_probability(n1, n2, "rce")
        assert 0.0 <= prob <= 1.0

    def test_edge_probability_same_server(self):
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       confidence=0.8, server="s1")
        n2 = ChainNode(id="n-2", node_type="pivot",
                       confidence=0.8, server="s1")
        prob = _edge_probability(n1, n2, "rce")
        assert 0.0 <= prob <= 1.0


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain INIT & BASIC
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainInit:
    """Tests for MCPChain class initialization."""

    def test_init_default(self):
        m = MCPChain()
        assert m.executor is not None
        assert m.boneyard is None
        assert m.warlog is None
        assert m.chains == {}
        assert m.cascades == {}

    def test_init_custom(self):
        e = Executor()
        b = Boneyard()
        w = WarLog()
        m = MCPChain(executor=e, boneyard=b, warlog=w)
        assert m.executor is e
        assert m.boneyard is b
        assert m.warlog is w

    def test_init_config(self):
        m = MCPChain()
        assert m.cascade_probability_threshold == 0.3
        assert m.max_chain_depth == 5
        assert m.max_nodes_per_chain == 20
        assert m.default_confidence_multiplier == 0.9


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain PUBLIC METHODS — Existence
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainPublicMethods:
    """Tests for MCPChain public API method existence."""

    def test_build_chain_exists(self):
        assert hasattr(MCPChain(), 'build_chain')

    def test_detect_cascades_exists(self):
        assert hasattr(MCPChain(), 'detect_cascades')

    def test_execute_chain_exists(self):
        assert hasattr(MCPChain(), 'execute_chain')

    def test_analyze_exists(self):
        assert hasattr(MCPChain(), 'analyze')

    def test_get_attack_graph_exists(self):
        assert hasattr(MCPChain(), 'get_attack_graph')

    def test_get_chain_exists(self):
        assert hasattr(MCPChain(), 'get_chain')

    def test_list_chains_exists(self):
        assert hasattr(MCPChain(), 'list_chains')

    def test_get_cascade_exists(self):
        assert hasattr(MCPChain(), 'get_cascade')

    def test_list_cascades_exists(self):
        assert hasattr(MCPChain(), 'list_cascades')

    def test_get_stats_exists(self):
        assert hasattr(MCPChain(), 'get_stats')

    def test_clear_exists(self):
        assert hasattr(MCPChain(), 'clear')

    def test_reset_exists(self):
        assert hasattr(MCPChain(), 'reset')


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain BUILD CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainBuildChain:
    """Tests for MCPChain.build_chain."""

    def test_build_chain_empty_findings(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        chain = m.build_chain([], t, chain_name="empty")
        assert isinstance(chain, AttackChain)
        assert chain.name == "empty"
        assert chain.nodes == []

    def test_build_chain_single_finding(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        findings = [{"type": "cve", "severity": "high",
                     "cve": "CVE-2025-6514", "confidence": 0.9,
                     "attack_class": None, "evidence": "test",
                     "endpoint": "/tools", "details": {}}]
        chain = m.build_chain(findings, t, chain_name="single")
        assert isinstance(chain, AttackChain)
        assert chain.name == "single"

    def test_build_chain_multiple_findings(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        findings = [
            {"type": "cve", "severity": "high", "cve": "CVE-2025-6514",
             "confidence": 0.9, "attack_class": None, "evidence": "test",
             "endpoint": "/tools", "details": {}},
            {"type": "cve", "severity": "critical", "cve": "CVE-2025-6515",
             "confidence": 0.95, "attack_class": None, "evidence": "test",
             "endpoint": "/tools", "details": {}},
            {"type": "attack_class", "severity": "high",
             "cve": None, "confidence": 0.85,
             "attack_class": "tool_poisoning", "evidence": "test",
             "endpoint": "/tools", "details": {}},
        ]
        chain = m.build_chain(findings, t, chain_name="multi")
        assert isinstance(chain, AttackChain)
        assert len(chain.nodes) > 0

    def test_build_chain_stored(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        chain = m.build_chain([], t, chain_name="store-test")
        assert chain.chain_id in m.chains

    def test_build_chain_default_name(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        chain = m.build_chain([], t)
        assert isinstance(chain.name, str)
        assert len(chain.name) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain DETECT CASCADES
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainDetectCascades:
    """Tests for MCPChain.detect_cascades."""

    def test_detect_cascades_empty_chain(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[], edges=[])
        result = m.detect_cascades(chain, t)
        assert isinstance(result, list)

    def test_detect_cascades_with_nodes(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       server="s1", confidence=0.9)
        n2 = ChainNode(id="n-2", node_type="pivot",
                       server="s1", confidence=0.8)
        n3 = ChainNode(id="n-3", node_type="objective",
                       server="s1", confidence=0.9)
        e1 = ChainEdge(from_node="n-1", to_node="n-2",
                       technique="rce", probability=0.8)
        e2 = ChainEdge(from_node="n-2", to_node="n-3",
                       technique="exfil", probability=0.7)
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2, n3], edges=[e1, e2],
                             total_probability=0.56)
        result = m.detect_cascades(chain, t)
        assert isinstance(result, list)

    def test_detect_cascades_cross_server(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       server="s1", confidence=0.9)
        n2 = ChainNode(id="n-2", node_type="pivot",
                       server="s2", confidence=0.8)
        e1 = ChainEdge(from_node="n-1", to_node="n-2",
                       technique="rce", probability=0.8)
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2], edges=[e1],
                             total_probability=0.8)
        result = m.detect_cascades(chain, t)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain EXECUTE CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainExecuteChain:
    """Tests for MCPChain.execute_chain."""

    def test_execute_chain_dry_run(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       server="s1", confidence=0.9)
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1], edges=[],
                             total_probability=1.0)
        result = m.execute_chain(chain, t, dry_run=True)
        assert isinstance(result, dict)
        assert result.get("dry_run") is True

    def test_execute_chain_with_edges(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       server="s1", confidence=0.9)
        n2 = ChainNode(id="n-2", node_type="objective",
                       server="s1", confidence=0.8)
        e1 = ChainEdge(from_node="n-1", to_node="n-2",
                       technique="rce", probability=0.8)
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2], edges=[e1],
                             total_probability=0.8)
        result = m.execute_chain(chain, t, dry_run=True)
        assert isinstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain ANALYZE
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainAnalyze:
    """Tests for MCPChain.analyze."""

    def test_analyze_empty_findings(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        result = m.analyze(t, findings=[])
        assert isinstance(result, dict)

    def test_analyze_with_findings(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        findings = [
            {"type": "cve", "severity": "high", "cve": "CVE-2025-6514",
             "confidence": 0.9, "attack_class": None, "evidence": "test",
             "endpoint": "/tools", "details": {}},
            {"type": "attack_class", "severity": "medium", "cve": None,
             "confidence": 0.8, "attack_class": "tool_poisoning",
             "evidence": "test", "endpoint": "/tools", "details": {}},
        ]
        result = m.analyze(t, findings=findings)
        assert isinstance(result, dict)
        assert "chain_count" in result or "chains" in result or "total_chains" in result

    def test_analyze_with_custom_name(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        result = m.analyze(t, findings=[], chain_name="custom")
        assert isinstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainInternalHelpers:
    """Tests for MCPChain internal helpers."""

    def test_build_edges_empty(self):
        m = MCPChain()
        result = m._build_edges([])
        assert result == []

    def test_determine_edge_technique(self):
        m = MCPChain()
        n1 = ChainNode(id="n-1", node_type="entry_point",
                       server="s1", technique="rce")
        n2 = ChainNode(id="n-2", node_type="pivot",
                       server="s2", technique="tool_poisoning")
        result = m._determine_edge_technique(n1, n2)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_topological_sort_empty(self):
        m = MCPChain()
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[], edges=[])
        result = m._topological_sort(chain)
        assert result == []

    def test_topological_sort_linear(self):
        m = MCPChain()
        n1 = ChainNode(id="n-1", node_type="entry_point")
        n2 = ChainNode(id="n-2", node_type="pivot")
        n3 = ChainNode(id="n-3", node_type="objective")
        e1 = ChainEdge(from_node="n-1", to_node="n-2", technique="rce")
        e2 = ChainEdge(from_node="n-2", to_node="n-3", technique="exfil")
        chain = AttackChain(chain_id="c-1", name="test",
                             nodes=[n1, n2, n3], edges=[e1, e2])
        result = m._topological_sort(chain)
        assert len(result) == 3
        assert result[0] == "n-1"
        assert result[1] == "n-2"
        assert result[2] == "n-3"

    def test_find_all_paths_empty(self):
        m = MCPChain()
        result = m._find_all_paths({}, "n-1", "n-2")
        assert isinstance(result, list)
        assert len(result) == 0

    def test_find_all_paths_linear(self):
        m = MCPChain()
        adj = {
            "n-1": [("n-2", 0.8, "rce")],
            "n-2": [("n-3", 0.7, "exfil")],
            "n-3": [],
        }
        result = m._find_all_paths(adj, "n-1", "n-3")
        assert len(result) >= 1

    def test_dfs_paths(self):
        m = MCPChain()
        adj = {
            "n-1": [("n-2", 0.8, "rce")],
            "n-2": [("n-3", 0.7, "exfil")],
            "n-3": [],
        }
        result = m._dfs_paths(adj, "n-1", "n-3", [])
        assert len(result) >= 1

    def test_identify_pattern(self):
        m = MCPChain()
        edges = [{"technique": "tool_poisoning"}, {"technique": "data_exfil"}]
        result = m._identify_pattern(edges)
        assert isinstance(result, str)

    def test_cascade_severity_critical(self):
        m = MCPChain()
        result = m._cascade_severity(0.95, cross_server=True)
        assert isinstance(result, str)

    def test_cascade_severity_low(self):
        m = MCPChain()
        result = m._cascade_severity(0.1, cross_server=False)
        assert isinstance(result, str)

    def test_execute_node_exists(self):
        assert hasattr(MCPChain(), '_execute_node')

    def test_store_chain_exists(self):
        assert hasattr(MCPChain(), '_store_chain')

    def test_log_chain_exists(self):
        assert hasattr(MCPChain(), '_log_chain')

    def test_store_cascades_exists(self):
        assert hasattr(MCPChain(), '_store_cascades')

    def test_log_cascades_exists(self):
        assert hasattr(MCPChain(), '_log_cascades')

    def test_store_summary_exists(self):
        assert hasattr(MCPChain(), '_store_summary')

    def test_log_summary_exists(self):
        assert hasattr(MCPChain(), '_log_summary')


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain MANAGEMENT METHODS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainManagement:
    """Tests for MCPChain management methods."""

    def test_get_chain_empty(self):
        m = MCPChain()
        result = m.get_chain("nonexistent")
        assert result is None

    def test_get_chain_exists(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        chain = m.build_chain([], t, chain_name="test")
        result = m.get_chain(chain.chain_id)
        assert result is not None
        assert result.chain_id == chain.chain_id

    def test_list_chains_empty(self):
        m = MCPChain()
        result = m.list_chains()
        assert result == []

    def test_list_chains(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        m.build_chain([], t, chain_name="test")
        result = m.list_chains()
        assert len(result) == 1

    def test_get_cascade_empty(self):
        m = MCPChain()
        result = m.get_cascade("nonexistent")
        assert result is None

    def test_list_cascades_empty(self):
        m = MCPChain()
        result = m.list_cascades()
        assert result == []

    def test_get_stats_empty(self):
        m = MCPChain()
        result = m.get_stats()
        assert isinstance(result, dict)

    def test_get_stats_with_chains(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        m.build_chain([], t, chain_name="test")
        result = m.get_stats()
        assert isinstance(result, dict)

    def test_clear(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        m.build_chain([], t, chain_name="test")
        m.clear()
        assert len(m.chains) == 0
        assert len(m.cascades) == 0

    def test_reset(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        m.build_chain([], t, chain_name="test")
        m.reset()
        assert len(m.chains) == 0
        assert len(m.cascades) == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPChain ATTACK GRAPH
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPChainAttackGraph:
    """Tests for MCPChain.get_attack_graph."""

    def test_attack_graph_empty(self):
        m = MCPChain()
        result = m.get_attack_graph()
        assert isinstance(result, dict)
        assert "chains" in result or "nodes" in result or "total_chains" in result

    def test_attack_graph_with_chains(self):
        m = MCPChain()
        t = Target(host="10.0.0.1")
        m.build_chain([], t, chain_name="test")
        result = m.get_attack_graph()
        assert isinstance(result, dict)
