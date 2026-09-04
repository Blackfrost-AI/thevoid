"""Curated attack-scenario library (roadmap R-6).

Defines a small catalog of *named* engagement profiles that drive a
ShadowAgent (and/or ChaosEngine) through a fixed, documented subset
of attack phases. Scenarios are autonomous attacker identities —

  baseline-network    standard network recon + attack-chain validation
  mcp-critical        MCP CVE + attack-class spotlight
  cloud-hygiene       AWS / Azure / GCP / K8s misconfig spotlight
  llm-trust           jailbreak / adversarial LLM testing
  crypto-persistence  crypto theft + persistence + scheduled exfil

… designed so engagements that mix scopes (network + cloud + MCP) can
be orchestrated at the CLI / scheduler with a single verb. They never
leak CVE-specific exploit behavior — those stay in engage modes.

Scenarios are pure data: ``phases`` lists MUST live in a
``ShadowAgent.MODE_PHASES`` style key/value, and are passed verbatim
through the phase registry as the dispatch target. Failure modes
(unknown phase, phase mismatch) are the registry's problem; scenarios
own only enumeration, description, and MITRE intent metadata.

The default register ships the five built-ins, but the API is open:
register() more scenarios at startup, or subclass the registry to
supply enterprise-specific catalogs.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Scenario:
    """One curated engagement profile.

    Determinism: equal to its public data contract. Treated as an
    ad-hoc Python primitive for free-form composition; persistence is
    on the (boneyard) side.
    """
    name: str
    description: str
    phases: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    version: str


def _build_builtins() -> Dict[str, Scenario]:
    """Build the default curated catalog."""
    return {
        s.name: s
        for s in [
            Scenario(
                name="baseline-network",
                description="Standard network attack-chain validation: recon + exploit + theft + C2.",
                phases=("recon", "exploit", "data_theft", "c2"),
                mitre_techniques=("T1046", "T1110", "T1005", "T1071"),
                version="1.0",
            ),
            Scenario(
                name="mcp-critical",
                description="MCP awareness spotlight: scan + CVE/attack + exploit chaining + C2.",
                phases=("mcp_scan", "mcp_attack", "mcp_chain", "mcp_c2"),
                mitre_techniques=("ALIAS:MCP-SCAN", "ALIAS:MCP-ATK", "ALIAS:MCP-CHAIN", "ALIAS:MCP-C2"),
                version="1.0",
            ),
            Scenario(
                name="cloud-hygiene",
                description="Cloud misconfiguration validation: configs + IAM + container posture.",
                phases=("cloud_attack", "k8s_attack"),
                mitre_techniques=("T1530", "T1613"),
                version="1.0",
            ),
            Scenario(
                name="llm-trust",
                description="Adversarial LLM trust validation: jailbreak + fuzzing + PyRIT/Garak probes.",
                phases=("llm_jailbreak", "advanced_jailbreak"),
                mitre_techniques=("ALIAS:LLM-JB", "ALIAS:LLM-JB"),
                version="1.0",
            ),
            Scenario(
                name="crypto-persistence",
                description="Asset theft + presence: crypto probes + persistence planting + scheduled exfil.",
                phases=("crypto_theft", "persistent_exfil", "zero_click"),
                mitre_techniques=("T1557", "T1053", "T1053"),
                version="1.0",
            ),
        ]
    }


_BUILTINS = _build_builtins()


class ScenarioLibrary:
    """In-memory catalog of attack scenarios. Pure data; hit the
    registry to enumerate, enumerate-by-name to fetch, serialize via
    ``to_dict``. Jurisdiction: ShadowAgent / ChaosEngine never write
    here; this is their read-only deployment surface.
    """

    def __init__(self) -> None:
        self._scenarios: Dict[str, Scenario] = dict(_BUILTINS)

    # ─── Enumeration ─────────────────────────────────────────────────
    def list(self) -> List[Scenario]:
        return sorted(self._scenarios.values(), key=lambda s: s.name)

    def names(self) -> List[str]:
        return sorted(self._scenarios)

    def describe(self) -> List[Dict[str, Any]]:
        return [asdict(s) for s in self.list()]

    # ─── Fetch ───────────────────────────────────────────────────────
    def get(self, name: str) -> Scenario:
        n = self._norm(name)
        if n not in self._scenarios:
            raise KeyError(
                f"unknown scenario: {name!r} "
                f"(registered: {', '.join(self.names())})"
            )
        return self._scenarios[n]

    def get_phases(self, name: str) -> List[str]:
        return list(self.get(name).phases)

    def get_mitre(self, name: str) -> List[str]:
        return list(self.get(name).mitre_techniques)

    # ─── Mutation (enterprise overrides) ─────────────────────────────
    def register(self, scenario: Scenario, override: bool = False) -> None:
        n = self._norm(scenario.name)
        if n in self._scenarios and not override:
            raise ValueError(
                f"scenario {scenario.name!r} already registered "
                "(pass override=True to replace)"
            )
        self._scenarios[n] = scenario

    # ─── Utility ─────────────────────────────────────────────────────
    @staticmethod
    def _norm(name: str) -> str:
        """Normalize name: lowercase + dashes only."""
        return (
            name.strip()
                .lower()
                .replace(" ", "-")
        )


# Module-level default registry — importable as ``from scenarios import
# scenario_library``, the ONLY read surface the ShadowAgent owns.
scenario_library = ScenarioLibrary()


__all__ = ["Scenario", "ScenarioLibrary", "scenario_library"]
