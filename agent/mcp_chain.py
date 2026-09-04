"""THE VOID — MCPChain: MCP attack chaining and cascade detection.

Composes individual MCP findings into multi-step attack paths (DAGs) and
detects cross-server cascade patterns.  Stores attack graphs in boneyard
and logs cascades to warlog.

P2.2b of the VOID-CEP-2026-07 capability enhancement plan.
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.executor import Executor, CommandResult
from core.target import Target
from core.boneyard import Boneyard
from core.warlog import WarLog, LogLevel

logger = logging.getLogger("void.agent.mcp_chain")


# ─── Data structures ────────────────────────────────────────────────────

@dataclass
class ChainNode:
    """A single node in an attack chain graph."""
    id: str
    node_type: str          # entry_point / pivot / objective / lateral / sink
    finding_ref: Optional[str] = None   # boneyard ID
    server: str = ""
    technique: str = ""     # e.g. tool_poisoning, prompt_injection, rce
    severity: str = "info"
    confidence: float = 0.0
    description: str = ""
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type,
            "finding_ref": self.finding_ref,
            "server": self.server,
            "technique": self.technique,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChainNode":
        return cls(
            id=d["id"],
            node_type=d.get("node_type", "pivot"),
            finding_ref=d.get("finding_ref"),
            server=d.get("server", ""),
            technique=d.get("technique", ""),
            severity=d.get("severity", "info"),
            confidence=d.get("confidence", 0.0),
            description=d.get("description", ""),
            evidence=d.get("evidence", ""),
            metadata=d.get("metadata", {}),
        )


@dataclass
class ChainEdge:
    """A directed edge between two nodes in an attack chain."""
    from_node: str
    to_node: str
    technique: str          # e.g. prompt_injection, tool_invocation
    probability: float = 1.0   # 0.0–1.0
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_node": self.from_node,
            "to_node": self.to_node,
            "technique": self.technique,
            "probability": self.probability,
            "description": self.description,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChainEdge":
        return cls(
            from_node=d.get("from_node", d.get("from", "")),
            to_node=d.get("to_node", d.get("to", "")),
            technique=d.get("technique", ""),
            probability=d.get("probability", 1.0),
            description=d.get("description", ""),
            metadata=d.get("metadata", {}),
        )


@dataclass
class AttackChain:
    """A complete attack chain (DAG of nodes + edges)."""
    name: str
    chain_id: str = ""
    nodes: List[ChainNode] = field(default_factory=list)
    edges: List[ChainEdge] = field(default_factory=list)
    total_probability: float = 1.0
    objectives: List[str] = field(default_factory=list)
    max_depth: int = 5
    created_at: float = 0.0

    def __post_init__(self):
        if not self.chain_id:
            self.chain_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "total_probability": self.total_probability,
            "objectives": self.objectives,
            "max_depth": self.max_depth,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackChain":
        chain = cls(
            name=d["name"],
            chain_id=d.get("chain_id", ""),
            total_probability=d.get("total_probability", 1.0),
            objectives=d.get("objectives", []),
            max_depth=d.get("max_depth", 5),
            created_at=d.get("created_at", 0.0),
        )
        chain.nodes = [ChainNode.from_dict(n) for n in d.get("nodes", [])]
        chain.edges = [ChainEdge.from_dict(e) for e in d.get("edges", [])]
        return chain

    def get_node(self, node_id: str) -> Optional[ChainNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_edges_from(self, node_id: str) -> List[ChainEdge]:
        return [e for e in self.edges if e.from_node == node_id]

    def get_edges_to(self, node_id: str) -> List[ChainEdge]:
        return [e for e in self.edges if e.to_node == node_id]

    def entry_nodes(self) -> List[ChainNode]:
        """Nodes with no incoming edges (entry points)."""
        targets = {e.to_node for e in self.edges}
        return [n for n in self.nodes if n.id not in targets and n.node_type == "entry_point"]

    def sink_nodes(self) -> List[ChainNode]:
        """Nodes with no outgoing edges (objectives/sinks)."""
        sources = {e.from_node for e in self.edges}
        return [n for n in self.nodes if n.id not in sources and n.node_type == "objective"]


@dataclass
class CascadeResult:
    """A detected cascade pattern across multiple MCP servers."""
    cascade_id: str = ""
    chain_id: str = ""
    pattern: str = ""
    path: List[str] = field(default_factory=list)  # node IDs in order
    cumulative_probability: float = 1.0
    techniques: List[str] = field(default_factory=list)
    cross_server: bool = False
    servers: List[str] = field(default_factory=list)
    severity: str = "critical"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.cascade_id:
            self.cascade_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cascade_id": self.cascade_id,
            "chain_id": self.chain_id,
            "pattern": self.pattern,
            "path": self.path,
            "cumulative_probability": self.cumulative_probability,
            "techniques": self.techniques,
            "cross_server": self.cross_server,
            "servers": self.servers,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CascadeResult":
        return cls(
            cascade_id=d.get("cascade_id", ""),
            chain_id=d.get("chain_id", ""),
            pattern=d.get("pattern", ""),
            path=d.get("path", []),
            cumulative_probability=d.get("cumulative_probability", 1.0),
            techniques=d.get("techniques", []),
            cross_server=d.get("cross_server", False),
            servers=d.get("servers", []),
            severity=d.get("severity", "critical"),
            confidence=d.get("confidence", 0.0),
            evidence=d.get("evidence", []),
        )


# ─── Cascade template patterns ─────────────────────────────────────────

CASCADE_TEMPLATES = {
    "poison_inject_exfil": {
        "name": "Poison→Inject→Exfil",
        "techniques": ["tool_poisoning", "prompt_injection", "data_exfil"],
        "severity": "critical",
        "description": "Poisoned tool description → prompt injection → data exfiltration",
    },
    "bypass_read_move": {
        "name": "Bypass→Read→Move",
        "techniques": ["auth_bypass", "filesystem_traversal", "credential_theft"],
        "severity": "critical",
        "description": "Auth bypass → filesystem read → credential lateral movement",
    },
    "inject_rce_persist": {
        "name": "Inject→RCE→Persist",
        "techniques": ["prompt_injection", "rce", "persistent_access"],
        "severity": "high",
        "description": "Prompt injection → remote code execution → persistent access",
    },
    "shadow_confuse_exfil": {
        "name": "Shadow→Confuse→Exfil",
        "techniques": ["tool_shadowing", "confused_deputy", "data_exfil"],
        "severity": "high",
        "description": "Tool shadowing → confused deputy → data exfiltration",
    },
}


# ─── Node type constants ────────────────────────────────────────────────

NODE_ENTRY = "entry_point"
NODE_PIVOT = "pivot"
NODE_OBJECTIVE = "objective"
NODE_LATERAL = "lateral"
NODE_SINK = "sink"

NODE_TYPES = {NODE_ENTRY, NODE_PIVOT, NODE_OBJECTIVE, NODE_LATERAL, NODE_SINK}

# ─── Edge technique constants ───────────────────────────────────────────

TECHNIQUE_PROMPT_INJECTION = "prompt_injection"
TECHNIQUE_TOOL_INVOCATION = "tool_invocation"
TECHNIQUE_CREDENTIAL_THEFT = "credential_theft"
TECHNIQUE_RCE = "rce"
TECHNIQUE_DATA_EXFIL = "data_exfil"
TECHNIQUE_TOOL_POISONING = "tool_poisoning"
TECHNIQUE_AUTH_BYPASS = "auth_bypass"
TECHNIQUE_FILESYSTEM_TRAVERSAL = "filesystem_traversal"
TECHNIQUE_TOOL_SHADOWING = "tool_shadowing"
TECHNIQUE_CONFUSED_DEPUTY = "confused_deputy"
TECHNIQUE_PERSISTENT_ACCESS = "persistent_access"
TECHNIQUE_LATERAL_MOVEMENT = "lateral_movement"

# ─── Edge precondition table ────────────────────────────────────────────

EDGE_PRECONDITIONS: Dict[str, List[str]] = {
    TECHNIQUE_PROMPT_INJECTION: ["tool_poisoning", "tool_shadowing", "resource_poisoning",
                                 "prompt_injection", "confused_deputy"],
    TECHNIQUE_TOOL_INVOCATION: ["tool_poisoning", "tool_shadowing", "auth_bypass",
                                 "prompt_injection"],
    TECHNIQUE_CREDENTIAL_THEFT: ["filesystem_traversal", "auth_bypass", "tool_invocation"],
    TECHNIQUE_RCE: ["prompt_injection", "tool_invocation", "auth_bypass", "rce"],
    TECHNIQUE_DATA_EXFIL: ["prompt_injection", "tool_invocation", "confused_deputy",
                           "filesystem_traversal"],
    TECHNIQUE_LATERAL_MOVEMENT: ["credential_theft", "data_exfil", "rce"],
}

# ─── Severity ordering ──────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ─── Chain builder helpers ──────────────────────────────────────────────

def _node_id(finding: Dict[str, Any], idx: int) -> str:
    """Generate a stable node ID from a finding."""
    ftype = finding.get("type", "unknown")
    endpoint = finding.get("endpoint", "")
    server = finding.get("server", "")
    # Use endpoint server name if available
    if endpoint and "://" in endpoint:
        # Extract host:port from URL
        try:
            server = endpoint.split("://")[1].split("/")[0].split(":")[0]
        except (IndexError, ValueError):
            pass
    return f"{ftype}_{server or 'unknown'}_{idx}"


def _finding_to_node(finding: Dict[str, Any], idx: int) -> ChainNode:
    """Convert an MCPFinding dict to a ChainNode."""
    ftype = finding.get("type", "unknown")
    # Map finding type to node type
    node_type_map = {
        "tool_poisoning": NODE_ENTRY,
        "tool_shadowing": NODE_ENTRY,
        "resource_poisoning": NODE_ENTRY,
        "auth_bypass": NODE_ENTRY,
        "prompt_injection": NODE_PIVOT,
        "confused_deputy": NODE_PIVOT,
        "filesystem_traversal": NODE_PIVOT,
        "rce": NODE_OBJECTIVE,
        "data_exfil": NODE_OBJECTIVE,
        "credential_theft": NODE_OBJECTIVE,
        "persistent_access": NODE_SINK,
        "lateral_movement": NODE_LATERAL,
    }
    node_type = NODE_ENTRY if idx == 0 else node_type_map.get(ftype, NODE_PIVOT)
    server = finding.get("server", "")
    if not server:
        endpoint = finding.get("endpoint", "")
        if endpoint and "://" in endpoint:
            try:
                server = endpoint.split("://")[1].split("/")[0].split(":")[0]
            except (IndexError, ValueError):
                pass

    return ChainNode(
        id=_node_id(finding, idx),
        node_type=node_type,
        finding_ref=finding.get("boneyard_id"),
        server=server,
        technique=ftype,
        severity=finding.get("severity", "info"),
        confidence=finding.get("confidence", 0.0),
        description=finding.get("evidence", ftype),
        evidence=finding.get("evidence", ""),
        metadata=finding.get("details", {}),
    )


def _edge_probability(from_node: ChainNode, to_node: ChainNode,
                       edge_technique: str) -> float:
    """Compute edge probability from node confidences and technique."""
    base = (from_node.confidence + to_node.confidence) / 2.0
    # Apply technique-specific weights
    technique_weights = {
        TECHNIQUE_PROMPT_INJECTION: 0.85,
        TECHNIQUE_TOOL_INVOCATION: 0.90,
        TECHNIQUE_CREDENTIAL_THEFT: 0.80,
        TECHNIQUE_RCE: 0.75,
        TECHNIQUE_DATA_EXFIL: 0.70,
        TECHNIQUE_LATERAL_MOVEMENT: 0.65,
    }
    weight = technique_weights.get(edge_technique, 0.80)
    return min(1.0, base * weight)


# ─── Main class ─────────────────────────────────────────────────────────

class MCPChain:
    """MCP attack chaining and cascade detection engine.

    Composes individual MCP findings into multi-step attack paths (DAGs)
    and detects cross-server cascade patterns.

    Integration:
        - Boneyard: stores attack graphs and cascade results
        - WarLog: logs cascade detection events and chain execution
        - MCPAttack findings feed into this as input
    """

    def __init__(self, executor: Optional[Executor] = None,
                 boneyard: Optional[Boneyard] = None,
                 warlog: Optional[WarLog] = None):
        self.executor = executor or Executor()
        self.boneyard = boneyard
        self.warlog = warlog
        self.logger = logging.getLogger("void.agent.mcp_chain")

        # Attack chain graph storage
        self.chains: Dict[str, AttackChain] = {}
        self.cascades: Dict[str, CascadeResult] = {}

        # Configuration
        self.cascade_probability_threshold = 0.3
        self.max_chain_depth = 5
        self.max_nodes_per_chain = 20
        self.default_confidence_multiplier = 0.9

    # ─── Chain building ─────────────────────────────────────────────

    def build_chain(self, findings: List[Dict[str, Any]],
                    target: Target,
                    chain_name: Optional[str] = None) -> AttackChain:
        """Build an attack chain from MCP findings.

        Args:
            findings: List of MCPFinding dicts (from MCPAttack.scan).
            target: The target being assessed.
            chain_name: Optional name for the chain.

        Returns:
            AttackChain with nodes and edges populated.
        """
        if not findings:
            chain = AttackChain(name=chain_name or "empty_chain")
            self.chains[chain.chain_id] = chain
            return chain

        name = chain_name or f"chain_{target.value}"

        # Build nodes from findings
        nodes = []
        for idx, finding in enumerate(findings):
            if idx >= self.max_nodes_per_chain:
                self.logger.warning(
                    f"Chain node limit ({self.max_nodes_per_chain}) reached, "
                    f"truncating at index {idx}"
                )
                break
            node = _finding_to_node(finding, idx)
            nodes.append(node)

        if not nodes:
            chain = AttackChain(name=name)
            self.chains[chain.chain_id] = chain
            return chain

        # Build edges by matching nodes that can be linked
        edges = self._build_edges(nodes)

        # Determine objectives
        objectives = [n.id for n in nodes if n.node_type == NODE_OBJECTIVE]

        # Build chain
        chain = AttackChain(
            name=name,
            nodes=nodes,
            edges=edges,
            objectives=objectives,
            max_depth=self.max_chain_depth,
        )

        # Store in instance
        self.chains[chain.chain_id] = chain

        # Store in boneyard
        self._store_chain(chain, target)

        # Log to warlog
        self._log_chain(chain, target)

        self.logger.info(
            f"Chain built: {chain.name} — {len(chain.nodes)} nodes, "
            f"{len(chain.edges)} edges, {len(objectives)} objectives"
        )

        return chain

    def _build_edges(self, nodes: List[ChainNode]) -> List[ChainEdge]:
        """Build edges between nodes based on technique compatibility."""
        edges = []

        for i, src in enumerate(nodes):
            for j in range(i + 1, len(nodes)):
                tgt = nodes[j]
                edge_tech = self._determine_edge_technique(src, tgt)
                if edge_tech:
                    prob = _edge_probability(src, tgt, edge_tech)
                    edge = ChainEdge(
                        from_node=src.id,
                        to_node=tgt.id,
                        technique=edge_tech,
                        probability=prob,
                        description=f"{src.technique} → {tgt.technique} via {edge_tech}",
                    )
                    edges.append(edge)

        return edges

    def _determine_edge_technique(self, src: ChainNode,
                                   tgt: ChainNode) -> Optional[str]:
        """Determine the edge technique between two nodes, if any."""
        # Map source technique → possible edge techniques to target
        # This is a rule-based mapping from the design doc
        src_tech = src.technique
        tgt_tech = tgt.technique

        # Explicit mapping: (src_technique, tgt_technique) → edge_technique
        mapping = {
            (TECHNIQUE_TOOL_POISONING, TECHNIQUE_PROMPT_INJECTION): TECHNIQUE_PROMPT_INJECTION,
            (TECHNIQUE_TOOL_POISONING, TECHNIQUE_DATA_EXFIL): TECHNIQUE_DATA_EXFIL,
            (TECHNIQUE_TOOL_POISONING, TECHNIQUE_TOOL_INVOCATION): TECHNIQUE_TOOL_INVOCATION,
            (TECHNIQUE_TOOL_SHADOWING, TECHNIQUE_CONFUSED_DEPUTY): TECHNIQUE_CONFUSED_DEPUTY,
            (TECHNIQUE_TOOL_SHADOWING, TECHNIQUE_DATA_EXFIL): TECHNIQUE_DATA_EXFIL,
            (TECHNIQUE_AUTH_BYPASS, TECHNIQUE_FILESYSTEM_TRAVERSAL): TECHNIQUE_FILESYSTEM_TRAVERSAL,
            (TECHNIQUE_AUTH_BYPASS, TECHNIQUE_CREDENTIAL_THEFT): TECHNIQUE_CREDENTIAL_THEFT,
            (TECHNIQUE_AUTH_BYPASS, TECHNIQUE_RCE): TECHNIQUE_RCE,
            (TECHNIQUE_PROMPT_INJECTION, TECHNIQUE_RCE): TECHNIQUE_RCE,
            (TECHNIQUE_PROMPT_INJECTION, TECHNIQUE_DATA_EXFIL): TECHNIQUE_DATA_EXFIL,
            (TECHNIQUE_PROMPT_INJECTION, TECHNIQUE_CREDENTIAL_THEFT): TECHNIQUE_CREDENTIAL_THEFT,
            (TECHNIQUE_CONFUSED_DEPUTY, TECHNIQUE_DATA_EXFIL): TECHNIQUE_DATA_EXFIL,
            (TECHNIQUE_CONFUSED_DEPUTY, TECHNIQUE_RCE): TECHNIQUE_RCE,
            (TECHNIQUE_FILESYSTEM_TRAVERSAL, TECHNIQUE_CREDENTIAL_THEFT): TECHNIQUE_CREDENTIAL_THEFT,
            (TECHNIQUE_FILESYSTEM_TRAVERSAL, TECHNIQUE_DATA_EXFIL): TECHNIQUE_DATA_EXFIL,
            (TECHNIQUE_RCE, TECHNIQUE_PERSISTENT_ACCESS): TECHNIQUE_PERSISTENT_ACCESS,
            (TECHNIQUE_RCE, TECHNIQUE_LATERAL_MOVEMENT): TECHNIQUE_LATERAL_MOVEMENT,
            (TECHNIQUE_CREDENTIAL_THEFT, TECHNIQUE_LATERAL_MOVEMENT): TECHNIQUE_LATERAL_MOVEMENT,
            (TECHNIQUE_DATA_EXFIL, TECHNIQUE_LATERAL_MOVEMENT): TECHNIQUE_LATERAL_MOVEMENT,
        }

        edge_tech = mapping.get((src_tech, tgt_tech))
        if edge_tech:
            return edge_tech

        # Fallback: if src is an entry and tgt is a pivot, use tool_invocation
        if src.node_type == NODE_ENTRY and tgt.node_type == NODE_PIVOT:
            return TECHNIQUE_TOOL_INVOCATION

        # Fallback: if src is a pivot and tgt is an objective
        if src.node_type == NODE_PIVOT and tgt.node_type == NODE_OBJECTIVE:
            return TECHNIQUE_TOOL_INVOCATION

        return None

    def _store_chain(self, chain: AttackChain, target: Target) -> None:
        """Store attack chain in boneyard."""
        if not self.boneyard:
            return
        try:
            graph_dict = chain.to_dict()
            graph_dict["target"] = target.value
            graph_dict["type"] = "attack_chain"
            self.boneyard.store(
                category="mcp_attack_chain",
                data=graph_dict,
                tags=["mcp", "chain", "attack_chain", target.value],
            )
        except Exception as e:
            self.logger.warning(f"Failed to store chain in boneyard: {e}")

    def _log_chain(self, chain: AttackChain, target: Target) -> None:
        """Log chain build event to warlog."""
        if not self.warlog:
            return
        try:
            self.warlog.log(
                f"MCPChain: {chain.name} — {len(chain.nodes)} nodes, "
                f"{len(chain.edges)} edges",
                level=LogLevel.EXPLOIT,
                module="mcp_chain",
                target=target.value,
                data=chain.to_dict(),
            )
        except Exception as e:
            self.logger.warning(f"Failed to log chain to warlog: {e}")

    # ─── Cascade detection ──────────────────────────────────────────

    def detect_cascades(self, chain: AttackChain,
                        target: Optional[Target] = None) -> List[CascadeResult]:
        """Detect cascade patterns in an attack chain.

        A cascade is a path from an entry point to an objective with
        cumulative probability above the threshold.

        Args:
            chain: The attack chain to analyze.
            target: Optional target for boneyard/warlog storage.

        Returns:
            List of detected CascadeResult objects.
        """
        if not chain.nodes:
            return []

        cascades = []

        # Build adjacency list
        adj: Dict[str, List[Tuple[str, float, str]]] = {}
        for edge in chain.edges:
            if edge.from_node not in adj:
                adj[edge.from_node] = []
            adj[edge.from_node].append((edge.to_node, edge.probability, edge.technique))

        # Find all paths from entry nodes to objective nodes
        entry_nodes = chain.entry_nodes()
        objective_ids = {n.id for n in chain.nodes if n.node_type in (NODE_OBJECTIVE, NODE_SINK)}

        for entry in entry_nodes:
            paths = self._find_all_paths(adj, entry.id, objective_ids,
                                          chain.max_depth)
            for path_nodes, path_edges, path_prob in paths:
                if path_prob >= self.cascade_probability_threshold:
                    # Determine if cross-server
                    path_servers = set()
                    for nid in path_nodes:
                        node = chain.get_node(nid)
                        if node and node.server:
                            path_servers.add(node.server)
                    cross_server = len(path_servers) > 1

                    cascade = CascadeResult(
                        chain_id=chain.chain_id,
                        pattern=self._identify_pattern(path_edges),
                        path=path_nodes,
                        techniques=[e["technique"] for e in path_edges],
                        cumulative_probability=path_prob,
                        cross_server=cross_server,
                        servers=sorted(path_servers),
                        severity=self._cascade_severity(path_prob, cross_server),
                        confidence=min(1.0, path_prob * self.default_confidence_multiplier),
                        evidence=[e.get("description", "") for e in path_edges],
                    )
                    cascades.append(cascade)
                    self.cascades[cascade.cascade_id] = cascade

        # Store cascades in boneyard
        self._store_cascades(cascades, target)

        # Log cascades to warlog
        self._log_cascades(cascades, target)

        self.logger.info(
            f"Cascade detection: {len(cascades)} cascades found "
            f"in chain {chain.name}"
        )

        return cascades

    def _find_all_paths(self, adj: Dict[str, List[Tuple[str, float, str]]],
                        start: str, targets: Any,
                        max_depth: int = 5) -> List[Tuple[List[str], List[Dict], float]]:
        """Find all paths from start to any target node.

        Returns list of (node_ids, edge_dicts, cumulative_probability).
        """
        target_set: Set[str] = targets if isinstance(targets, set) else {targets}
        return self._dfs_paths(adj, start, target_set, [start])

    def _dfs_paths(self, adj: Dict[str, List[Tuple[str, float, str]]],
                   current: str, targets: Any,
                   path: List[str]) -> List[Tuple[List[str], List[Dict], float]]:
        """DFS to find all paths from current to targets."""
        target_set: Set[str] = targets if isinstance(targets, set) else {targets}
        results: List[Tuple[List[str], List[Dict], float]] = []

        if current in target_set and len(path) > 1:
            edges_list: List[Dict] = []
            prob = 1.0
            for i in range(len(path) - 1):
                for neighbor_id, edge_prob, edge_tech in adj.get(path[i], []):
                    if neighbor_id == path[i + 1]:
                        edges_list.append({
                            "from": path[i],
                            "to": neighbor_id,
                            "technique": edge_tech,
                            "probability": edge_prob,
                        })
                        prob *= edge_prob
                        break
            results.append((list(path), edges_list, prob))
            return results

        for neighbor_id, edge_prob, edge_tech in adj.get(current, []):
            if neighbor_id not in path:
                path.append(neighbor_id)
                results.extend(self._dfs_paths(adj, neighbor_id, target_set, path))
                path.pop()

        return results

    def _identify_pattern(self, path_edges: List[Dict]) -> str:
        """Identify which cascade pattern this path matches."""
        techniques = [e["technique"] for e in path_edges]

        for template_id, template in CASCADE_TEMPLATES.items():
            # Check if path techniques contain all template techniques
            if all(t in techniques for t in template["techniques"]):
                return template["name"]

        # Build a custom pattern name from techniques
        if techniques:
            return "→".join(t.replace("_", " ").title() for t in techniques)
        return "Unknown"

    def _cascade_severity(self, probability: float, cross_server: bool) -> str:
        """Determine cascade severity from probability and cross-server status."""
        if cross_server and probability >= 0.5:
            return "critical"
        if cross_server or probability >= 0.5:
            return "high"
        if probability >= 0.3:
            return "medium"
        return "low"

    def _store_cascades(self, cascades: List[CascadeResult],
                        target: Optional[Target]) -> None:
        """Store cascade results in boneyard."""
        if not self.boneyard:
            return
        for cascade in cascades:
            try:
                self.boneyard.store(
                    category="mcp_cascade",
                    data=cascade.to_dict(),
                    tags=["mcp", "cascade", target.value] if target else ["mcp", "cascade"],
                )
            except Exception as e:
                self.logger.warning(f"Failed to store cascade in boneyard: {e}")

    def _log_cascades(self, cascades: List[CascadeResult],
                      target: Optional[Target]) -> None:
        """Log cascade detection events to warlog."""
        if not self.warlog:
            return
        for cascade in cascades:
            try:
                self.warlog.log(
                    f"MCPChain cascade: {cascade.pattern} — "
                    f"{len(cascade.path)} nodes, "
                    f"cross_server={cascade.cross_server}, "
                    f"probability={cascade.cumulative_probability:.2f}",
                    level=LogLevel.CRITICAL if cascade.severity == "critical" else LogLevel.EXPLOIT,
                    module="mcp_chain",
                    target=target.value if target else None,
                    data=cascade.to_dict(),
                )
            except Exception as e:
                self.logger.warning(f"Failed to log cascade to warlog: {e}")

    # ─── Chain execution ────────────────────────────────────────────

    def execute_chain(self, chain: AttackChain,
                      target: Target,
                      dry_run: bool = True) -> Dict[str, Any]:
        """Execute an attack chain (simulate or actual exploitation).

        Args:
            chain: The attack chain to execute.
            target: The target to exploit.
            dry_run: If True, simulate without actual exploitation.

        Returns:
            Dict with execution results.
        """
        self.logger.info(
            f"Executing chain: {chain.name} "
            f"({'dry_run' if dry_run else 'live'})"
        )

        results: Dict[str, Any] = {
            "chain_id": chain.chain_id,
            "chain_name": chain.name,
            "dry_run": dry_run,
            "target": target.value,
            "steps": [],
            "success": True,
            "errors": [],
        }

        # Execute in topological order (entry → objective)
        entry_nodes = chain.entry_nodes()
        if not entry_nodes:
            results["success"] = False
            results["errors"].append("No entry nodes found")
            return results

        # Simple topological execution: process nodes in order
        visited = set()
        execution_order = self._topological_sort(chain)

        for node_id in execution_order:
            node = chain.get_node(node_id)
            if not node:
                continue

            step_result = self._execute_node(node, target, dry_run)
            results["steps"].append(step_result)
            visited.add(node_id)

            if not step_result.get("success", False):
                # Check if any edge from this node succeeds
                edges = chain.get_edges_from(node_id)
                if not edges:
                    results["success"] = False

        # Log execution
        self._log_execution(chain, target, results)

        return results

    def _topological_sort(self, chain: AttackChain) -> List[str]:
        """Topological sort of chain nodes (entry → objective)."""
        # Build in-degree map
        in_degree: Dict[str, int] = {n.id: 0 for n in chain.nodes}
        for edge in chain.edges:
            in_degree[edge.to_node] = in_degree.get(edge.to_node, 0) + 1

        # BFS from nodes with no incoming edges
        queue = [n.id for n in chain.nodes if in_degree.get(n.id, 0) == 0]
        result = []

        while queue:
            node_id = queue.pop(0)
            result.append(node_id)

            for edge in chain.get_edges_from(node_id):
                in_degree[edge.to_node] -= 1
                if in_degree[edge.to_node] == 0:
                    queue.append(edge.to_node)

        # Add any remaining nodes (cycles)
        for n in chain.nodes:
            if n.id not in result:
                result.append(n.id)

        return result

    def _execute_node(self, node: ChainNode, target: Target,
                      dry_run: bool) -> Dict[str, Any]:
        """Execute a single node in the chain."""
        step: Dict[str, Any] = {
            "node_id": node.id,
            "node_type": node.node_type,
            "technique": node.technique,
            "server": node.server,
            "success": True,
            "action": "simulate" if dry_run else "execute",
        }

        if dry_run:
            # Simulate — just return the node info
            step["evidence"] = node.evidence
            step["confidence"] = node.confidence
            return step

        # Live execution: use executor to run a tool or command
        if node.technique == TECHNIQUE_RCE:
            # RCE node: run a command
            cmd = ["echo", f"MCPChain RCE probe on {node.server}"]
            try:
                result = self.executor.run(cmd, timeout=10)
                step["exit_code"] = result.exit_code
                step["success"] = result.success
                step["output"] = result.stdout[:200] if result.stdout else ""
            except Exception as e:
                step["success"] = False
                step["error"] = str(e)
        elif node.technique in (TECHNIQUE_DATA_EXFIL, TECHNIQUE_CREDENTIAL_THEFT):
            # Exfil/cred theft: probe with curl
            endpoint = node.metadata.get("endpoint", "")
            if endpoint:
                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", endpoint]
                try:
                    result = self.executor.run(cmd, timeout=10)
                    step["http_code"] = result.stdout.strip() if result.stdout else ""
                    step["success"] = result.success
                except Exception as e:
                    step["success"] = False
                    step["error"] = str(e)
        else:
            # Generic node: simulate
            step["evidence"] = node.evidence
            step["confidence"] = node.confidence

        return step

    def _log_execution(self, chain: AttackChain, target: Target,
                       results: Dict[str, Any]) -> None:
        """Log chain execution to warlog."""
        if not self.warlog:
            return
        try:
            steps_ok = sum(1 for s in results["steps"] if s.get("success"))
            steps_total = len(results["steps"])
            self.warlog.log(
                f"MCPChain execution: {chain.name} — "
                f"{steps_ok}/{steps_total} steps succeeded, "
                f"{'dry_run' if results['dry_run'] else 'live'}",
                level=LogLevel.EXPLOIT,
                module="mcp_chain",
                target=target.value,
                data=results,
            )
        except Exception as e:
            self.logger.warning(f"Failed to log execution to warlog: {e}")

    # ─── Attack graph ───────────────────────────────────────────────

    def get_attack_graph(self) -> Dict[str, Any]:
        """Return the combined attack graph from all chains.

        Returns:
            Dict with nodes, edges, objectives, and metadata.
        """
        all_nodes = []
        all_edges = []
        all_objectives = []
        all_cascade_ids = []

        for chain in self.chains.values():
            all_nodes.extend(n.to_dict() for n in chain.nodes)
            all_edges.extend(e.to_dict() for e in chain.edges)
            all_objectives.extend(chain.objectives)

        for cascade in self.cascades.values():
            all_cascade_ids.append(cascade.cascade_id)

        return {
            "nodes": all_nodes,
            "edges": all_edges,
            "objectives": list(set(all_objectives)),
            "cascades": all_cascade_ids,
            "chain_count": len(self.chains),
            "cascade_count": len(self.cascades),
            "total_nodes": len(all_nodes),
            "total_edges": len(all_edges),
        }

    # ─── High-level analyze ─────────────────────────────────────────

    def analyze(self, target: Target,
                findings: List[Dict[str, Any]],
                chain_name: Optional[str] = None) -> Dict[str, Any]:
        """Full analysis pipeline: build chain, detect cascades, return summary.

        Args:
            target: The target to analyze.
            findings: MCPFinding dicts from MCPAttack.scan().
            chain_name: Optional name for the chain.

        Returns:
            Dict with chain, cascades, and summary stats.
        """
        self.logger.info(
            f"MCPChain analyzing {target.value}: {len(findings)} findings"
        )

        # Step 1: Build chain
        chain = self.build_chain(findings, target, chain_name=chain_name)

        # Step 2: Detect cascades
        cascades = self.detect_cascades(chain, target)

        # Step 3: Build attack graph
        attack_graph = self.get_attack_graph()

        # Step 4: Generate summary
        summary: Dict[str, Any] = {
            "target": target.value,
            "chain_id": chain.chain_id,
            "chain_name": chain.name,
            "chain_count": len(self.chains),
            "node_count": len(chain.nodes),
            "edge_count": len(chain.edges),
            "objective_count": len(chain.objectives),
            "cascade_count": len(cascades),
            "cross_server_cascades": sum(1 for c in cascades if c.cross_server),
            "attack_graph": attack_graph,
            "cascades": [c.to_dict() for c in cascades],
        }

        # Store summary in boneyard
        self._store_summary(summary, target)

        # Log summary to warlog
        self._log_summary(summary, target)

        self.logger.info(
            f"MCPChain analysis complete: {summary['node_count']} nodes, "
            f"{summary['edge_count']} edges, {summary['cascade_count']} cascades"
        )

        return summary

    def _store_summary(self, summary: Dict[str, Any], target: Target) -> None:
        """Store analysis summary in boneyard."""
        if not self.boneyard:
            return
        try:
            self.boneyard.store(
                category="mcp_chain_summary",
                data=summary,
                tags=["mcp", "chain", "summary", target.value],
            )
        except Exception as e:
            self.logger.warning(f"Failed to store summary in boneyard: {e}")

    def _log_summary(self, summary: Dict[str, Any], target: Target) -> None:
        """Log analysis summary to warlog."""
        if not self.warlog:
            return
        try:
            self.warlog.log(
                f"MCPChain analysis: {summary['node_count']} nodes, "
                f"{summary['edge_count']} edges, "
                f"{summary['cascade_count']} cascades, "
                f"{summary['cross_server_cascades']} cross-server",
                level=LogLevel.EXPLOIT,
                module="mcp_chain",
                target=target.value,
                data=summary,
            )
        except Exception as e:
            self.logger.warning(f"Failed to log summary to warlog: {e}")

    # ─── Utility methods ────────────────────────────────────────────

    def get_chain(self, chain_id: str) -> Optional[AttackChain]:
        """Get a chain by ID."""
        return self.chains.get(chain_id)

    def get_cascade(self, cascade_id: str) -> Optional[CascadeResult]:
        """Get a cascade by ID."""
        return self.cascades.get(cascade_id)

    def list_chains(self) -> List[Dict[str, Any]]:
        """List all chains with summary info."""
        return [
            {
                "chain_id": c.chain_id,
                "name": c.name,
                "node_count": len(c.nodes),
                "edge_count": len(c.edges),
                "objective_count": len(c.objectives),
            }
            for c in self.chains.values()
        ]

    def list_cascades(self) -> List[Dict[str, Any]]:
        """List all cascades with summary info."""
        return [
            {
                "cascade_id": c.cascade_id,
                "pattern": c.pattern,
                "probability": c.probability,
                "cross_server": c.cross_server,
                "severity": c.severity,
            }
            for c in self.cascades.values()
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Return stats about the current state."""
        return {
            "chain_count": len(self.chains),
            "cascade_count": len(self.cascades),
            "total_nodes": sum(len(c.nodes) for c in self.chains.values()),
            "total_edges": sum(len(c.edges) for c in self.chains.values()),
            "total_cascade_probability": sum(
                c.probability for c in self.cascades.values()
            ),
        }

    def clear(self) -> None:
        """Clear all chains and cascades."""
        self.chains.clear()
        self.cascades.clear()

    def reset(self) -> None:
        """Reset state and clear all stored data."""
        self.clear()
