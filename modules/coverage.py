"""Coverage / prevention-strength scoring engine (roadmap R-2).

Feeds attack_log payloads through the realism rubric established in
``research/realism-audit-2026-07-29.md`` and produces a deterministic
``score`` per engagement — distinct from *technique coverage* (R-1),
which is just detection. Prevention strength scores how convincingly
each phase *prevented* the attack class it claims to test.

Rubric (frozen in the realism audit):

    score_per_technique = w_coverage × c_confidence
    prevention_strength  = Σ score / Σ(1.0)  → 0-100 scale

    w_coverage  ∈ {verified 1.0, exploited 0.7, reachability 0.3, unknown 0.0}
    c_confidence ∈ {verified 1.0, multiple 0.6, single 0.3, passive 0.1}

The engine is pure: all artifacts come from existing attack_log
payloads; ``engage()`` keeps its full ROE chain intact.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agent.phase_registry import PhaseRegistry

logger = logging.getLogger("void.modules.coverage")

# ─── Rubric weights ────────────────────────────────────────────────────
# These match the realism-audit rubric exactly. Kept as data so
# test suites can verify the frozen numbers stay frozen.
WEIGHT_COVERAGE = {
    "verified": 1.0,      # EXPLOIT-VERIFIED: concrete compromise evidence
    "exploited": 0.7,     # EXPLOITED: exploit ran, mixed success rate
    "reachability": 0.3,  # REACHABILITY: asset responded, nothing more
    "unknown": 0.0,       # UNKNOWN: no clear verdict
}

WEIGHT_CONFIDENCE = {
    "verified": 1.0,  # strong runtime proof
    "multiple": 0.6,  # several strong indications
    "single": 0.3,    # one direct indication
    "passive": 0.1,   # indirect / inferred
}


# Phase-level realism classification — mirrors the realism audit's
# per-phase table. Each value is (coverage_class, confidence).
#
# Update when a phase gains smarter compromise detection; the
# scoring engine will pick up the change automatically.
_PHASE_EVIDENCE: Dict[str, tuple] = {
    # REACHABILITY (0.3 × 0.1 = 3 points)
    "recon":              ("reachability", "passive"),   # pure scan/enum
    "c2":                 ("reachability", "passive"),   # beacon registered, no heartbeat
    # EXPLOITED (0.7 × 0.6 = 42 points) — attempted compromise with
    # crackmapexec logon / hydra auth calls; success-rate low in
    # heterogenous targets, confidence capped at multiple.
    "exploit":            ("exploited",    "multiple"),
    # REACHABILITY (0.3 × 0.1)
    "data_theft":         ("reachability", "passive"),
    "llm_jailbreak":      ("unknown",      "passive"),   # prompt-level probe, no exploit claim
    "network_bypass":     ("reachability", "passive"),
    "cloud_attack":       ("reachability", "passive"),
    "crypto_theft":       ("reachability", "passive"),
    "persistent_exfil":   ("reachability", "passive"),
    "zero_click":         ("reachability", "passive"),
    "k8s_attack":         ("reachability", "passive"),
    "wireless_iot":       ("reachability", "passive"),
    "advanced_jailbreak": ("unknown",      "passive"),
    "mcp_scan":           ("unknown",      "passive"),
    "mcp_attack":         ("unknown",      "passive"),
    "mcp_chain":          ("unknown",      "passive"),
    "mcp_c2":             ("unknown",      "passive"),
    # VERIFIED (1.0 × 0.6 = 60 points) — strongest evidence in the set:
    # reverse-shell payload live + NTLM harvest crack loop observed.
    "cve_exploit":         ("verified",    "multiple"),
    # IMPACT-style: runs locally, no target compromise claim.
    "destruction":         ("reachability", "passive"),
}


# MITRE technique mapping per phase (for context in reports).
# ALIAS = vendor extension (no stable ATT&CK technique yet);
# never invent fake technique IDs.
_PHASE_ATTAK = {
    "recon":              ("T1046", "Network Service Discovery", "Discovery"),
    "exploit":            ("T1110", "Brute Force", "Credential Access"),
    "data_theft":         ("T1005", "Data from Local System", "Collection"),
    "llm_jailbreak":      ("ALIAS:LLM-JB", "Prompt Injection / Jailbreak", "Execution"),
    "network_bypass":     ("ALIAS:LLM-NB", "MCP / LLM Network Bypass", "Execution"),
    "c2":                 ("ALIAS:LLM-C2", "MCP / LLM C2", "Command and Control"),
    "cloud_attack":       ("T1530", "Data from Cloud Storage", "Collection"),
    "crypto_theft":       ("T1557", "Adversary-in-the-Middle", "Credential Access"),
    "persistent_exfil":   ("T1053", "Scheduled Task/Job", "Persistence"),
    "zero_click":         ("T1053", "Scheduled Task/Job", "Persistence"),
    "k8s_attack":         ("T1613", "Container and Resource Discovery", "Discovery"),
    "wireless_iot":       ("T1040", "Network Sniffing", "Discovery"),
    "advanced_jailbreak":  ("ALIAS:LLM-JB", "Prompt Injection / Jailbreak", "Execution"),
    "mcp_scan":           ("ALIAS:MCP-SCAN", "MCP Vulnerability Scan", "Discovery"),
    "mcp_attack":         ("ALIAS:MCP-ATK", "MCP Runtime Attack", "Execution"),
    "mcp_chain":          ("ALIAS:MCP-CHAIN", "MCP Exploit Chaining", "Lateral Movement"),
    "mcp_c2":             ("ALIAS:MCP-C2", "MCP Command and Control", "Command and Control"),
    "cve_exploit":         ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "destruction":         ("T1485", "Data Destruction", "Impact"),
}


class CoverageScorer:
    """Deterministic prevention-strength scoring engine.

    Feeds an attack_log (list of engagement findings dicts) through
    the frozen realism rubric. Outputs per-engagement score +
    structured rationale for the Reporter to render.
    """

    def __init__(self, registry: Optional[PhaseRegistry] = None):
        # Keep registry optional so tests can inject a stub registry if
        # the production one is unavailable.
        self._registry: Optional[PhaseRegistry] = registry

    @property
    def registry(self) -> PhaseRegistry:
        if self._registry is None:
            self._registry = PhaseRegistry()
        return self._registry

    # ─── Public API ───────────────────────────────────────────────────
    def score_engagement(
        self, engagement: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Score a single engagement payload (the same shape returned by
        ``ShadowAgent.engage()``, iterator verbatim).

        Returns::

            {
              "score": float (0-100),
              "breakdown": {phase → {coverage, confidence,
                                     weight, contribution, points}},
              "verdict_counts": {coverage_class → int},
              "status": "completed"|"failed"|...
            }
        """
        if not isinstance(engagement, dict):
            return {"score": 0.0, "breakdown": {}, "verdict_counts": {}}

        status = engagement.get("status", "unknown")
        if status != "completed":
            return {
                "score": 0.0,
                "breakdown": {},
                "verdict_counts": {},
                "status": status,
                "reason": f"engagement status is {status!r}, not completed",
            }

        findings = engagement.get("findings") or {}
        if not isinstance(findings, dict):
            logger.debug(
                "coverage: engagement %r has non-dict findings, scoring zero",
                engagement.get("target"),
            )
            return {"score": 0.0, "breakdown": {}, "verdict_counts": {}}

        breakdown: Dict[str, Dict[str, Any]] = {}
        counts: Dict[str, int] = {}
        total = 0.0

        phases = self._ordered_phases(findings)
        for phase in phases:
            payload = findings.get(phase)
            if payload is None:
                continue

            # Explicitly skipped findings contribute zero.
            if isinstance(payload, dict) and payload.get("skipped"):
                coverage, confidence = "unknown", "passive"
            else:
                coverage, confidence = _PHASE_EVIDENCE.get(
                    phase, ("unknown", "passive")
                )

            w = WEIGHT_COVERAGE.get(coverage, 0.0)
            c = WEIGHT_CONFIDENCE.get(confidence, 0.0)
            pts = round(w * c * 100.0, 4)

            breakdown[phase] = {
                "coverage": coverage,
                "confidence": confidence,
                "weight": round(c, 4),
                "contribution": round(w * c, 4),
                "points": pts,
            }
            counts[coverage] = counts.get(coverage, 0) + 1
            total += w * c

        score = round((total / len(phases)) * 100.0, 1) if phases else 0.0
        return {
            "score": score,
            "status": status,
            "breakdown": breakdown,
            "verdict_counts": counts,
        }

    def score_all(
        self, attack_log: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Score every engagement in the attack_log, returning an
        aggregate result for the report.

        Returns::

            {
              "aggregated": float (0-100),
              "count": int,
              "engagement_scores": [ {...} ]
            }
        """
        if not attack_log:
            return {
                "aggregated": 0.0,
                "count": 0,
                "engagement_scores": [],
            }

        scored = []
        for i, entry in enumerate(attack_log):
            if not isinstance(entry, dict):
                continue
            if not entry.get("findings"):
                continue
            result = self.score_engagement(entry)
            entry_score = {
                "engagement_index": i,
                "target": entry.get("target", "?"),
                "mode": entry.get("mode", "?"),
                "phases": list((entry.get("findings") or {}).keys()),
                "score": result["score"],
                "verdict_counts": result["verdict_counts"],
                "breakdown": result["breakdown"],
            }
            scored.append(entry_score)

        if not scored:
            return {
                "aggregated": 0.0,
                "count": 0,
                "engagement_scores": [],
            }

        aggregated = round(
            sum(e["score"] for e in scored) / len(scored), 1
        )
        return {
            "aggregated": aggregated,
            "count": len(scored),
            "engagement_scores": scored,
        }

    # ─── Internal ─────────────────────────────────────────────────────
    def _ordered_phases(self, findings: Dict[str, Any]) -> List[str]:
        """Emit phase names in deterministic order. Uses the registry's
        canonical phase list (sorted) so the scoring engine stays
        aligned with the engagement sequence."""
        if self._registry is not None:
            return [p for p in self._registry.phases if p in findings]
        # Fallback: alphabetical ordering, then any dynamic extras.
        return sorted(findings)


# Alias previously used as a factory; kept for API stability.
score_all = CoverageScorer()
