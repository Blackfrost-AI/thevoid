"""Phase registry for ShadowAgent (roadmap R-7).

Centralizes the phase-name → delegate-method dispatch table that
used to be embedded as a ``phase_runners`` dict inside
``agent/shadow_agent.py:engage()``. Keeping it as data (a tuple of
``PhaseSpec`` in canonical order) with a thin ``resolve()`` that
rebinds the ``agent`` reference at call time delivers two wins:

- **Decomposition hygiene** — all 19 phases live in one place; tooling,
  scenario definitions (R-6), and continuity loops (R-3) can enumerate
  them without parsing the god object.
- **Behavioral parity** — the registry deliberately calls the same
  private methods with the same arguments that the inline dispatch
  table used to call. All return shapes, exception behavior, and the
  wiring of ``mcp_chain``/``mcp_c2`` (which depend on the aggregated
  ``mcp_attack`` findings) are preserved verbatim.

Usage::

    registry = PhaseRegistry()
    for phase in agent.phases_for_mode("full"):
        result = registry.resolve(phase)(agent, target, mode, ctx)

``ctx`` is the aggregated findings-so-far dict that the inner
``mcp_*`` phases peer into; this matches the engagement loop's
contract exactly. External callers can pass ``{}`` and get the same
behavior the current ``fallback []`` line used to produce.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List

if TYPE_CHECKING:  # pragma: no cover - mypy / IDE only
    from agent.shadow_agent import ShadowAgent

logger = logging.getLogger("void.agent.phase_registry")


@dataclass(frozen=True)
class PhaseSpec:
    """Specification for one ShadowAgent phase."""

    name: str
    owner_attr: str  # most relevant ShadowAgent helper attribute (doc-only)
    member: str  # the ShadowAgent private method to invoke
    # Special memory only: whether the method needs the aggregated
    # findings context for chaining (mcp_chain / mcp_c2).
    needs_findings: bool = False
    description: str = ""


# Ordered phase specs. Names must exactly match `MODE_PHASES` strings
# in agent/shadow_agent.py.
_PHASE_TABLE: Dict[str, PhaseSpec] = {
    spec.name: spec
    for spec in [
        PhaseSpec("recon", "osint", "_recon",
                  description="OSINT + port / web / host enumeration"),
        PhaseSpec("exploit", "credattack", "_exploit",
                  description="Credential brute force + SMBAD + vuln/web probes"),
        PhaseSpec("data_theft", "datatheft", "_steal_data",
                  description="File / DB exfiltration probes"),
        PhaseSpec("llm_jailbreak", "llm_jailbreak", "_jailbreak_llm",
                  description="Single-endpoint LLM jailbreak"),
        PhaseSpec("network_bypass", "network_bypass", "_bypass_network",
                  description="Encryption/tunnel bypass enumeration"),
        PhaseSpec("c2", "c2_daemon", "_setup_c2",
                  description="Beacon + daemon registration"),
        PhaseSpec("cloud_attack", "aws_exploit", "_cloud_attack",
                  description="AWS / Azure / GCP config attacks"),
        PhaseSpec("crypto_theft", "crypto_theft", "_crypto_theft",
                  description="Wallet / exchange / cryptojacking probes"),
        PhaseSpec("persistent_exfil", "persistent_exfil", "_persistent_exfil",
                  description="Plant webshell/backdoor/screenshot/keylogger"),
        PhaseSpec("zero_click", "zero_click", "_zero_click",
                  description="Cron + systemd + Tor scheduled exfil"),
        PhaseSpec("k8s_attack", "k8s_attack", "_k8s_attack",
                  description="Pod privilege / secrets / image misconfig"),
        PhaseSpec("wireless_iot", "wireless_iot", "_wireless_iot",
                  description="WiFi / IoT exploitation + sniffing"),
        PhaseSpec("advanced_jailbreak", "jbfuzz", "_advanced_jailbreak",
                  description="JBFuzz + PyRIT + Garak adversarial jailbreak"),
        PhaseSpec("cve_exploit", "cve_2026_32202", "_cve_exploit",
                  description="Zero-day CVE exploitation probes"),
        PhaseSpec("destruction", "destruction", "_destruction",
                  description="Post-engagement destruction sequence"),
        PhaseSpec("mcp_scan", "mcp_scanner", "_mcp_scan",
                  description="MCP vulnerability scan + report"),
        PhaseSpec("mcp_attack", "mcp_attack", "_mcp_attack",
                  description="MCP CVE + attack-class scan"),
        PhaseSpec("mcp_chain", "mcp_chain", "_mcp_chain", needs_findings=True,
                  description="Attack-chain builder (depends on mcp_attack)"),
        PhaseSpec("mcp_c2", "mcp_c2", "_mcp_c2", needs_findings=True,
                  description="C2 channel over compromised MCP (depends on mcp_attack)"),
    ]
}


class PhaseRegistry:
    """Registry of ShadowAgent phases with the exact same dispatch
    semantics as the hardcoded ``phase_runners`` table in ``engage()``.

    This is a *lookup* helper, not a runtime authority — the
    ShadowAgent remains fully in charge of injection defense,
    sanitization, findings aggregation, and ordering. The registry
    only decides *which* ``agent._foo`` method gets called for a
    given phase name. All lambdas are re-bound against the agent
    passed to each call, so this object is safe to share long-lived.
    """

    def __init__(self) -> None:
        self._specs: Dict[str, PhaseSpec] = _PHASE_TABLE.copy()

    # ── Introspection ─────────────────────────────────────────────────
    @property
    def phases(self) -> List[str]:
        return sorted(self._specs)

    def spec(self, phase: str) -> PhaseSpec:
        try:
            return self._specs[phase]
        except KeyError:
            raise KeyError(f"unknown phase: {phase!r}") from None

    def describe(self) -> Dict[str, Dict[str, str]]:
        """Stable, JSON-serialisable description used by R-6 scenarios
        and CLI tooling to enumerate alternatives."""
        return {
            name: {"owner": spec.owner_attr,
                   "member": spec.member,
                   "needs_findings": spec.needs_findings,
                   "description": spec.description}
            for name, spec in sorted(self._specs.items())
        }

    # ── Dispatch ──────────────────────────────────────────────────────
    def resolve(self, phase: str):
        """Lookup the runner for *phase*, or return None-like stub
        that hands the engage() loop its existing "unknown phase"
        error. Equivalent to the ``.get()`` fallback in the legacy
        dispatch table."""
        runner = self._make_runner(phase)
        if runner is None:
            def _unknown(asset: "ShadowAgent", target, mode, ctx):
                return {"error": f"unknown phase: {phase}"}
            return _unknown
        return runner

    def _make_runner(self, phase: str):
        spec = self._specs.get(phase)
        if spec is None:
            return None

        def runner(agent: "ShadowAgent", target, mode, ctx: Dict[str, Any]):
            # Dispatch mirrors the legacy ``phase_runners`` lambdas.
            # Attack-surface phases that depend on mcp_attack's findings
            # get the aggregated context; everything else gets None.
            if spec.name == "recon":
                return agent._recon(target, mode)
            if spec.name == "exploit":
                return agent._exploit(target, mode)
            if spec.name == "data_theft":
                return agent._steal_data(target, mode)
            if spec.name == "llm_jailbreak":
                return agent._jailbreak_llm(target)
            if spec.name == "network_bypass":
                return agent._bypass_network(target)
            if spec.name == "c2":
                return agent._setup_c2(target)
            if spec.name == "cloud_attack":
                return agent._cloud_attack(target, mode)
            if spec.name == "crypto_theft":
                return agent._crypto_theft(target, mode)
            if spec.name == "persistent_exfil":
                return agent._persistent_exfil(target, mode)
            if spec.name == "zero_click":
                return agent._zero_click(target, mode)
            if spec.name == "k8s_attack":
                return agent._k8s_attack(target, mode)
            if spec.name == "wireless_iot":
                return agent._wireless_iot(target, mode)
            if spec.name == "advanced_jailbreak":
                return agent._advanced_jailbreak(target, mode)
            if spec.name == "cve_exploit":
                return agent._cve_exploit(target, mode)
            if spec.name == "destruction":
                return agent._destruction(target, mode)
            if spec.name == "mcp_scan":
                return agent._mcp_scan(target, mode)
            if spec.name == "mcp_attack":
                return agent._mcp_attack(target, mode)
            if spec.name == "mcp_chain":
                prior = (ctx or {}).get("findings", {}).get("mcp_attack") \
                    if isinstance(ctx, dict) else None
                return agent._mcp_chain(target, mode, prior if prior else [])
            if spec.name == "mcp_c2":
                prior = (ctx or {}).get("findings", {}).get("mcp_attack") \
                    if isinstance(ctx, dict) else None
                return agent._mcp_c2(target, mode, prior if prior else [])
            raise KeyError(f"unknown phase: {spec.name!r}")

        runner.__name__ = f"_resolve_{spec.name}"
        return runner
