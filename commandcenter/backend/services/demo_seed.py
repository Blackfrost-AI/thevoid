"""DEMO MODE seeder — deterministic, fictional stage scenario.

The Command Center demo mode swaps the ServiceBridge onto ISOLATED stores
(wiped fresh each enable) and seeds them with one fixed, fictional
engagement. Everything here is synthetic — clearly labelled, reproducible,
and segregated from live integrity claims:

  * Hostnames live under ``*.demo.void`` — cannot collide with real targets.
  * Every persisted finding/attack-step/warlog entry is tagged ``demo`` and
    its human-readable strings carry the ``DEMO:`` prefix.
  * Timestamps are pinned to a fixed epoch spread (hours, not wall-clock) so
    the same run always produces the same graph/timeline/coverage.
  * Phase→step/outcome mapping and payload phase names are imported from the
    REAL engine contracts (``agent.shadow_agent.PHASE_TO_STEP_TYPE`` /
    ``modules.coverage``) so CoverageScorer + Reporter score the demo through
    exactly the same code paths they use for live engagements.

The scenario: three stage hosts (edge firewall, domain controller, database)
walked through a six-phase kill chain (initial access → privesc → lateral →
persist → exfil → c2), plus a second lighter engagement for timeline/graph
variety. Outcomes mix success and failure so the UI shows honest verdict
colors.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("void.commandcenter.demo_seed")

#: Fixed epoch base — 2026-01-05T09:00:00Z. Deterministic timeline anchor.
DEMO_EPOCH_BASE = 1767603600.0

#: Seconds between phases of a single engagement chain.
DEMO_PHASE_SPACING = 187.0

#: Gap between the two engagements.
DEMO_ENGAGEMENT_GAP = 2600.0

DEMO_SCENARIO_NAME = "stage-scenario-1"
DEMO_OPERATOR = "THE VOID (DEMO)"
DEMO_ENGAGEMENT_NAME = "DEMO — Black Hat / DEF CON Stage Walkthrough"

# Narration for the guided CLI demo (`thevoid demo`). One block per chain
# entry: (title, MITRE label, narration lines). Order matches DEMO_CHAIN.
DEMO_NARRATION: List[Tuple[str, str, List[str]]] = [
    (
        "Initial access",
        "T1110 Brute Force",
        [
            "Credential attack against the exposed management interface",
            "Weak service account recovered after a short dictionary burst",
        ],
    ),
    (
        "Privilege escalation",
        "T1068 Exploitation for Privilege Escalation",
        [
            "Local privilege escalation foothold established",
            "Service binary escalation path exploited on the domain controller",
        ],
    ),
    (
        "Lateral movement",
        "T1021 Remote Services",
        [
            "Pivot attempt from the DC toward the database host",
            "BLOCKED — segmentation policy dropped the remote-services attempt",
        ],
    ),
    (
        "Persistence",
        "T1053 Scheduled Task/Job",
        [
            "Scheduled-task foothold planted for re-entry",
            "Survives reboot; the persistence hook is now in place",
        ],
    ),
    (
        "Exfiltration",
        "T1041 Exfiltration Over C2 Channel",
        [
            "Data staged and exfiltrated over the established C2 channel",
            "Exfil stream captured against the seeded sample corpus",
        ],
    ),
    (
        "Command & control",
        "MCP / LLM C2 (vendor alias)",
        [
            "MCP/LLM C2 beacon registered against the stage controller",
            "Session up — the engagement closes out on a live beacon",
        ],
    ),
]

# Fictional stage hosts: (name, ip, description)
DEMO_HOSTS: List[Tuple[str, str, str]] = [
    ("stage-fw01.demo.void", "203.0.113.10", "Edge firewall / gateway (fictional)"),
    ("stage-dc01.demo.void", "203.0.113.20", "Domain controller (fictional)"),
    ("stage-db01.demo.void", "203.0.113.30", "Backend database (fictional)"),
]

# Kill-chain step chain. step_type values match the boneyard attack_paths
# contract; technique ids are real ATT&CK ids reused as stage labels.
# (step_type, technique_id, technique_label, phase_name, outcome_type, success)
DEMO_CHAIN: List[Tuple[str, str, str, str, str, bool]] = [
    ("initial_access", "T1110", "Brute Force — credential attack on exposed service",
     "exploit", "access", True),
    ("privesc", "T1068", "Exploitation for Privilege Escalation",
     "cve_exploit", "privilege", True),
    ("lateral", "T1021", "Remote Services — pivot to next host",
     "data_theft", "data", False),
    ("persist", "T1053", "Scheduled Task/Job — foothold entrenchment",
     "destruction", "persistence", True),
    ("exfil", "T1041", "Exfiltration Over C2 Channel",
     "mcp_c2", "data", True),
    ("c2", "ALIAS:LLM-C2", "MCP / LLM C2 beacon (vendor alias)",
     "mcp_c2", "persistence", True),
]

# Shorter second engagement (first three phases) for graph/timeline variety.
DEMO_CHAIN_SHORT = DEMO_CHAIN[:3]

# Phase tool labels — mirror agent.phase_registry member names so steps look
# like real runner output.
_PHASE_TOOL: Dict[str, str] = {
    "exploit": "credattack",
    "cve_exploit": "cve_2026_32202",
    "data_theft": "datatheft",
    "destruction": "destruction",
    "mcp_c2": "mcp_c2",
    "recon": "osint",
}


def demo_attack_log_payload(
    target_name: str,
    chain: List[Tuple[str, str, str, str, str, bool]],
    started_epoch: float,
    mode: str = "demo",
) -> Dict[str, Any]:
    """Build one engagement payload in the exact ``ShadowAgent.engage()``
    findings shape, so ``CoverageScorer.score_engagement`` scores it through
    the real rubric. Phase keys use canonical registry names; findings carry
    a ``demo: true`` marker throughout.
    """
    findings: Dict[str, Any] = {}
    for i, (_st, _tid, _tlabel, phase, _ot, success) in enumerate(chain):
        findings[phase] = {
            "demo": True,
            "status": "success" if success else "failed",
            "phase": phase,
            "step_index": i + 1,
            "tool": _PHASE_TOOL.get(phase, phase),
            "note": "DEMO: deterministic seeded stage data — not a live engagement",
        }
    return {
        "target": target_name,
        "mode": mode,
        "started_at": started_epoch,
        "planned_phases": [ph for (_s, _t, _l, ph, _o, _ok) in chain],
        "findings": findings,
        "elapsed": round(DEMO_PHASE_SPACING * (len(chain) - 1), 2),
        "status": "completed",
        "demo": True,
    }


def seed_demo_boneyard(boneyard: Any) -> Dict[str, Any]:
    """Seed an isolated Boneyard with the deterministic demo scenario.

    Returns a summary of what was seeded. Uses only the public boneyard API
    with pinned epochs — HMAC chains stay valid because they cover stored
    values.
    """
    hosts_meta: Dict[str, str] = {}
    for name, ip, desc in DEMO_HOSTS:
        host_id = boneyard.ensure_host(
            ip=ip,
            hostname=name,
            data={"demo": True, "description": f"DEMO: {desc}"},
            epoch=DEMO_EPOCH_BASE,
        )
        hosts_meta[name] = host_id

    steps_total = 0
    outcomes_total = 0
    attack_log: List[Dict[str, Any]] = []

    engagements = [
        ("stage-dc01.demo.void", DEMO_CHAIN, DEMO_EPOCH_BASE + 120.0),
        ("stage-db01.demo.void", DEMO_CHAIN_SHORT,
         DEMO_EPOCH_BASE + DEMO_ENGAGEMENT_GAP),
    ]

    for host_name, chain, start_epoch in engagements:
        host_id = hosts_meta[host_name]
        parent_step_id = None
        for i, (step_type, tech_id, tech_label, phase, outcome_type, success) in enumerate(chain):
            epoch = start_epoch + i * DEMO_PHASE_SPACING
            status = "attempted" if success else "failed"
            step_id = boneyard.record_attack_step(
                host_id=host_id,
                step_type=step_type,
                technique=f"{tech_id} {tech_label}".strip(),
                description=f"DEMO: phase={phase} status={status}",
                parent_step_id=parent_step_id,
                outcome_status=status,
                detected_by="",
                tool_used=_PHASE_TOOL.get(phase, phase),
                duration_sec=round(DEMO_PHASE_SPACING, 1),
                epoch=epoch,
            )
            parent_step_id = step_id
            steps_total += 1

            boneyard.record_outcome(
                attack_path_id=step_id,
                outcome_type=outcome_type,
                success=success,
                evidence={
                    "demo": True,
                    "phase": phase,
                    "technique": tech_id,
                    "note": "DEMO: seeded evidence (fictional)",
                },
                output_raw="DEMO: deterministic seeded output — not live data",
                mitigation="" if success else "DEMO: blocked at this phase",
                epoch=epoch + 30.0,
            )
            outcomes_total += 1

        payload = demo_attack_log_payload(host_name, chain, start_epoch)
        attack_log.append(payload)
        # Persist under the same attack_* category contract the live agent
        # uses, so CoverageBridge.attack_log() reconstructs it verbatim.
        boneyard.store(
            f"attack_{host_name}_{int(start_epoch)}",
            payload,
            tags=["demo"],
            epoch=start_epoch,
        )

    # Recon findings for graph host coverage + boneyard panels.
    boneyard.store(
        "recon",
        {
            "title": "DEMO: stage recon sweep",
            "demo": True,
            "targets": [h[0] for h in DEMO_HOSTS],
            "open_ports": {h[0]: [22, 80, 443, 3389][: (i % 3) + 2]
                           for i, h in enumerate(DEMO_HOSTS)},
            "note": "DEMO: deterministic seeded recon — not live data",
        },
        tags=["demo"],
        epoch=DEMO_EPOCH_BASE + 60.0,
    )

    # A drift event so the Drift view has something to show on stage.
    boneyard.store(
        "drift",
        {
            "title": "DEMO: continuity drift event",
            "demo": True,
            "kind": "baseline_shift",
            "target": "stage-db01.demo.void",
            "phases": {
                "lateral": {
                    "expected": "blocked",
                    "observed": "reachable",
                }
            },
            "detail": "DEMO: seeded drift event for the stage demo",
            "severity": "info",
        },
        tags=["demo"],
        epoch=DEMO_EPOCH_BASE + DEMO_ENGAGEMENT_GAP + 300.0,
    )

    # Restart-safe C2 evidence exercises the browser's distinction between
    # a live in-process channel and a previously recorded channel.
    boneyard.store(
        "mcp_c2_channel",
        {
            "title": "DEMO: recorded MCP channel",
            "demo": True,
            "channel_id": "demo-channel-01",
            "status": "active",
            "target": "stage-db01.demo.void",
            "endpoint": "http://stage-db01.demo.void:8080/mcp",
            "tool_name": "search",
            "encoding": "base64",
            "established_at": DEMO_EPOCH_BASE + DEMO_ENGAGEMENT_GAP + 180.0,
            "beacon_count": 1,
            "task_count": 0,
        },
        tags=["demo", "mcp", "c2", "channel"],
        epoch=DEMO_EPOCH_BASE + DEMO_ENGAGEMENT_GAP + 180.0,
    )

    logger.info(
        "demo seed: %d hosts, %d steps, %d outcomes, %d attack_log payloads",
        len(hosts_meta), steps_total, outcomes_total, len(attack_log),
    )
    return {
        "hosts": len(hosts_meta),
        "steps": steps_total,
        "outcomes": outcomes_total,
        "engagements": len(attack_log),
        "attack_log": attack_log,
    }


def seed_demo_warlog(warlog: Any) -> int:
    """Seed an isolated WarLog with the demo event stream. Returns entry count.

    WarLog timestamps are wall-clock (WORM design), so the stream reads as a
    live feed; every message is DEMO-prefixed and tagged.
    """
    from core.warlog import LogLevel

    events: List[Tuple[str, LogLevel, str, str, Dict[str, Any]]] = [
        ("DEMO: stage scenario initialized", LogLevel.INFO, "demo", "stage",
         {"demo": True, "scenario": DEMO_SCENARIO_NAME}),
        ("DEMO: recon sweep across 3 stage hosts", LogLevel.RECON, "demo.recon",
         "stage-fw01.demo.void", {"demo": True, "hosts": 3}),
        ("DEMO: credential attack on exposed service (T1110)", LogLevel.EXPLOIT,
         "demo.exploit", "stage-dc01.demo.void", {"demo": True, "technique": "T1110"}),
        ("DEMO: privilege escalation foothold (T1068)", LogLevel.EXPLOIT,
         "demo.exploit", "stage-dc01.demo.void", {"demo": True, "technique": "T1068"}),
        ("DEMO: lateral pivot attempt — blocked at firewall", LogLevel.EXPLOIT,
         "demo.lateral", "stage-db01.demo.void", {"demo": True, "outcome": "failed"}),
        ("DEMO: exfiltration over C2 channel (T1041)", LogLevel.EXFIL,
         "demo.exfil", "stage-dc01.demo.void", {"demo": True, "technique": "T1041"}),
        ("DEMO: MCP/LLM C2 beacon registered", LogLevel.C2,
         "demo.c2", "stage-db01.demo.void", {"demo": True, "beacon": "demo-beacon-01"}),
        ("DEMO: stage engagement complete — prevention score computed",
         LogLevel.AGENT, "demo", "stage", {"demo": True}),
    ]
    count = 0
    for msg, level, module, target, data in events:
        try:
            warlog.log(msg, level=level, module=module, target=target, data=data)
            count += 1
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("demo warlog seed failed: %s", exc)
    return count
