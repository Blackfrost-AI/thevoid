"""THE VOID — MITRE ATLAS coverage mapping (P2, roadmap R-1 style).

Maps ShadowAgent engagement phases to MITRE ATLAS technique IDs so every
detection the client produces can be attributed to a published AI attack
technique, and coverage gaps become enumerable.

Data integrity
--------------
* ``ATLAS_VERSION`` / ``CANONICAL_TECHNIQUES`` were extracted verbatim from
  ``mitre-atlas/atlas-data`` ``dist/v6/ATLAS-2026.09.yaml`` on 2026-09-29
  (a copy of the canonical ID/name/tactic dataset is kept alongside in
  ``research/`` for future audits).
* ``_MAPPING`` may only reference technique IDs present in
  ``CANONICAL_TECHNIQUES``; ``_validate_mapping()`` enforces this at import
  and raises if the mapping and the dataset ever diverge — the module fails
  closed rather than shipping a mapping to a technique that does not exist.
* Coverage percentages are reported against the live canonical ID set, not
  against the mapping's own ID set, so a stale local mapping cannot inflate
  the score.

Tactic names are deliberately **not** embedded here: the tactic→technique
linkage was not machine-readable in the 2026.09 bundle we parsed, and
guessing tactic blocks mis-files techniques. Report tactics from the
upstream matrix page, not from this table.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from core.warlog import WarLog

ATLAS_VERSION = "ATLAS-2026.09"

# Canonical base-technique IDs (sub-techniques omitted) and their published
# names. Source: mitre-atlas/atlas-data dist/v6/ATLAS-2026.09.yaml.
# 120 base techniques.
CANONICAL_TECHNIQUES: Dict[str, str] = {
    "AML.T0000": "Search Open Technical Databases",
    "AML.T0001": "Search Open AI Vulnerability Analysis",
    "AML.T0002": "Acquire Public AI Artifacts",
    "AML.T0003": "Search Victim-Owned Websites",
    "AML.T0004": "Search Application Repositories",
    "AML.T0005": "Create Proxy AI Model",
    "AML.T0006": "Active Scanning",
    "AML.T0007": "Discover AI Artifacts",
    "AML.T0008": "Acquire Infrastructure",
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0011": "User Execution",
    "AML.T0012": "Valid Accounts",
    "AML.T0013": "Discover AI Model Ontology",
    "AML.T0014": "Discover AI Model Family",
    "AML.T0015": "Evade AI Model",
    "AML.T0016": "Obtain Capabilities",
    "AML.T0017": "Develop Capabilities",
    "AML.T0018": "Manipulate AI Model",
    "AML.T0020": "Training Data Poisoning",
    "AML.T0021": "Establish Accounts",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0029": "Denial of AI Service",
    "AML.T0031": "Erode AI Model Integrity",
    "AML.T0034": "Cost Harvesting",
    "AML.T0035": "AI Artifact Collection",
    "AML.T0036": "Data from Information Repositories",
    "AML.T0037": "Data from Local System",
    "AML.T0040": "AI Model Inference API Access",
    "AML.T0041": "Physical Environment Access",
    "AML.T0042": "Verify Attack",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0044": "Full AI Model Access",
    "AML.T0046": "Spamming AI System with Chaff Data",
    "AML.T0047": "AI-Enabled Product or Service",
    "AML.T0048": "External Harms",
    "AML.T0049": "Exploit Public-Facing Application",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0052": "Phishing",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0059": "Erode Dataset Integrity",
    "AML.T0060": "Publish Hallucinated Entities",
    "AML.T0061": "LLM Prompt Self-Replication",
    "AML.T0062": "Discover LLM Hallucinations",
    "AML.T0063": "Discover AI Model Outputs",
    "AML.T0064": "Gather RAG-Indexed Targets",
    "AML.T0065": "LLM Prompt Crafting",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0069": "Discover LLM System Information",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    "AML.T0072": "Cyber Communication Channel",
    "AML.T0073": "Impersonation",
    "AML.T0074": "Masquerading",
    "AML.T0075": "Enterprise Resource Discovery",
    "AML.T0076": "Corrupt AI Model",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0078": "Drive-by Compromise",
    "AML.T0079": "Stage Capabilities",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0082": "RAG Credential Harvesting",
    "AML.T0083": "Credentials from AI Agent Configuration",
    "AML.T0084": "Discover AI Agent Configuration",
    "AML.T0085": "Data from AI Services",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0087": "Gather Victim Identity Information",
    "AML.T0088": "Generate Deepfakes",
    "AML.T0089": "Enterprise Environment Discovery",
    "AML.T0090": "OS Credential Dumping",
    "AML.T0091": "Use Alternate Authentication Material",
    "AML.T0092": "Manipulate User LLM Chat History",
    "AML.T0093": "Prompt Infiltration via Public-Facing Application",
    "AML.T0094": "Delay Execution of LLM Instructions",
    "AML.T0095": "Search Open Websites/Domains",
    "AML.T0096": "AI Service API",
    "AML.T0097": "Virtualization/Sandbox Evasion",
    "AML.T0098": "AI Agent Tool Credential Harvesting",
    "AML.T0099": "AI Agent Tool Data Poisoning",
    "AML.T0100": "AI Agent Clickbait",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
    "AML.T0102": "Generate Malicious Commands",
    "AML.T0103": "Deploy AI Agent",
    "AML.T0105": "Escape to Host",
    "AML.T0106": "Exploitation for Credential Access",
    "AML.T0107": "Exploitation for Defense Evasion",
    "AML.T0108": "AI Agent",
    "AML.T0109": "AI Supply Chain Rug Pull",
    "AML.T0110": "AI Agent Tool Poisoning",
    "AML.T0111": "AI Supply Chain Reputation Inflation",
    "AML.T0112": "Machine Compromise",
    "AML.T0113": "Steal Web Session Cookie",
    "AML.T0114": "AI Service Web Interface",
    "AML.T0115": "Publish Poisoned AI Artifacts",
    "AML.T0116": "Autonomous Reconnaissance",
    "AML.T0117": "Autonomous Attack-Path Adaptation",
    "AML.T0118": "Autonomous AI Agent Communication",
    "AML.T0119": "Exploit Automated Artifact Processing Pipeline",
    "AML.T0120": "AI Artifact Repository",
    "AML.T0121": "AI Agent Environment Reconstruction",
    "AML.T0122": "Exploitation of Remote Services",
    "AML.T0123": "Obfuscated Files or Information",
    "AML.T0124": "Autonomous Attack Orchestration",
    "AML.T0125": "Create Account",
    "AML.T0126": "Automated Collection",
    "AML.T0127": "Data Staged",
    "AML.T0128": "Compromise Infrastructure",
    "AML.T0129": "Triggers in Multimodal Inputs",
    "AML.T0130": "AI Agent Response Biasing",
    "AML.T0131": "Crafted AI Assistant Links",
    "AML.T0132": "Misconfigured or Publicly Exposed AI Services",
    "AML.T0133": "Discover AI Agent Runtime Capabilities",
    "AML.T0134": "AI Targeted Cloaking",
}

# Engagement phase -> technique IDs exercised by that phase. IDs marked
# (TBC) are candidate techniques the phase touches but whose exact ID
# depends on phase internals; they are validated the same way.
_MAPPING: Dict[str, List[str]] = {
    "recon": ["AML.T0003", "AML.T0006", "AML.T0116", "AML.T0007"],
    "exploit": ["AML.T0049", "AML.T0012", "AML.T0055", "AML.T0050",
                "AML.T0122", "AML.T0106"],
    "data_theft": ["AML.T0037", "AML.T0025", "AML.T0127"],
    "llm_jailbreak": ["AML.T0054", "AML.T0051", "AML.T0057", "AML.T0056"],
    "network_bypass": ["AML.T0072", "AML.T0097"],
    "c2": ["AML.T0072", "AML.T0118", "AML.T0079"],
    "cloud_attack": ["AML.T0055", "AML.T0128", "AML.T0090"],
    "crypto_theft": ["AML.T0034", "AML.T0035"],
    "persistent_exfil": ["AML.T0086", "AML.T0080"],
    "zero_click": ["AML.T0011", "AML.T0094"],
    "k8s_attack": ["AML.T0105", "AML.T0089"],
    "wireless_iot": ["AML.T0112", "AML.T0128"],
    "advanced_jailbreak": ["AML.T0054", "AML.T0065", "AML.T0068",
                           "AML.T0043"],
    "cve_exploit": ["AML.T0049", "AML.T0122"],
    "destruction": ["AML.T0101", "AML.T0031", "AML.T0029"],
    "mcp_scan": ["AML.T0084", "AML.T0081", "AML.T0133"],
    "mcp_attack": ["AML.T0110", "AML.T0053", "AML.T0051", "AML.T0098"],
    "mcp_chain": ["AML.T0124", "AML.T0117"],
    "mcp_c2": ["AML.T0118", "AML.T0110", "AML.T0053"],
}


def _validate_mapping() -> None:
    """Import-time integrity check: every mapped ID must exist in the
    canonical dataset. Raises RuntimeError (fail closed) on divergence."""
    unknown = {tid for ids in _MAPPING.values() for tid in ids
               if tid not in CANONICAL_TECHNIQUES}
    if unknown:
        raise RuntimeError(
            f"atlas_coverage mapping references unknown ATLAS IDs: "
            f"{sorted(unknown)} (dataset {ATLAS_VERSION})")


_validate_mapping()


def canonical_ids() -> List[str]:
    return sorted(CANONICAL_TECHNIQUES)


def known_ids() -> List[str]:
    """IDs referenced by the phase mapping."""
    return sorted({t for ids in _MAPPING.values() for t in ids})


def uncovered_ids() -> List[str]:
    return sorted(set(CANONICAL_TECHNIQUES) - set(known_ids()))


def techniques_for(phase: str) -> List[str]:
    """Technique IDs exercised by an engagement phase (empty if unknown)."""
    return list(_MAPPING.get(phase, []))


def phases_for(technique_id: str) -> List[str]:
    """Engagement phases whose execution can evidence this technique."""
    return sorted(p for p, ids in _MAPPING.items() if technique_id in ids)


def coverage_for(phases: List[str]) -> Dict[str, Any]:
    """ATLAS coverage summary for a run that executed ``phases``.

    Percentages are computed against the canonical ID set of this
    dataset version, so results are comparable across tool versions.
    Unknown phase names are ignored but reported under ``unknown_phases``
    so callers can detect caller bugs.
    """
    unknown = [p for p in phases if p not in _MAPPING]
    covered: Set[str] = set()
    per_phase: Dict[str, List[str]] = {}
    for p in phases:
        ids = _MAPPING.get(p, [])
        if ids:
            per_phase[p] = list(ids)
        covered |= set(ids)
    total = len(CANONICAL_TECHNIQUES)
    pct = round(100.0 * len(covered) / total, 1)
    return {
        "version": ATLAS_VERSION,
        "total_techniques": total,
        "covered_count": len(covered),
        "coverage_pct": pct,
        "covered": sorted(covered),
        "per_phase": per_phase,
        "uncovered_count": total - len(covered),
        "unknown_phases": unknown,
    }


def map_engagement(engagement: Dict[str, Any],
                   warlog: Optional[WarLog] = None) -> Dict[str, Any]:
    """Map an engagement result dict to ATLAS coverage and record it.

    The summary is written to the WarLog as evidence (module
    ``modules.atlas_coverage``) and its content hash is returned, so the
    engagement map itself can be pinned with ``WarLog.anchor_events()``
    alongside the raw event stream (P2 anchoring).
    """
    phases = [e["phase"] for e in engagement.get("phases", [])
              if isinstance(e, dict) and "phase" in e] or \
             list(engagement.get("phases_executed", []))
    summary = coverage_for(phases)
    if warlog is not None:
        warlog.log(
            f"atlas coverage: {summary['covered_count']}/"
            f"{summary['total_techniques']} techniques "
            f"({summary['coverage_pct']}%) @ {summary['version']}",
            module="modules.atlas_coverage",
            data={"summary": summary},
        )
    summary["evidence_hash"] = hashlib.sha256(
        json.dumps(summary, sort_keys=True).encode()
    ).hexdigest()
    return summary