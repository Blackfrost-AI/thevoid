"""THE VOID — CLI demo command (`thevoid demo`).

Guided, deterministic, narrated walkthrough of the seeded stage scenario,
ending in a prevention (coverage) score computed by the REAL rubric.

Design:
  * Zero network, zero real targets — the demo narrates the same fictional
    scenario used by Command Center DEMO MODE (demo_seed.py), so the story
    matches what the audience sees in the web UI.
  * Deterministic — same narration, same phases, same score every run.
  * The prevention score is produced by ``modules.coverage.CoverageScorer``
    over the exact seeded attack payloads — the same code path the
    ``/api/coverage`` endpoint uses. Nothing is fabricated.

Usage::

    thevoid demo                     # narrated stage walkthrough
    thevoid demo --json-output       # machine-readable
    thevoid demo --no-animate        # CI-friendly (no sleeps)
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

import click

# Shared console: cli/app.py owns the rich Console; keep this module free
# of click-group side effects so it can be tested in isolation.

PHASE_PAUSE = 1.4          # seconds between phases during animation
PHASE_OUTCOME_PAUSE = 0.9  # seconds after a phase resolves

# outcome → (symbol, style)
OUTCOME_STYLE = {
    True: ("✓", "green"),
    False: ("✗", "red"),
}


def _demo_scenario() -> Tuple[List[Tuple[str, str, str, str, str, bool]],
                              List[Tuple[str, str, List[str]]],
                              List[Tuple[str, str, str]],
                              str]:
    """Import the shared stage scenario (CLI + WebUI single source)."""
    from commandcenter.backend.services import demo_seed

    return (
        demo_seed.DEMO_CHAIN,
        demo_seed.DEMO_NARRATION,
        demo_seed.DEMO_HOSTS,
        demo_seed.DEMO_ENGAGEMENT_NAME,
    )


# ── Scenario projection ────────────────────────────────────────────────────────

# Map scenario phase names → (step_type, outcome_type, narrative label).
# These mirror agent.shadow_agent.PHASE_TO_STEP_TYPE / PHASE_TO_OUTCOME_TYPE
# so the projected chain matches what a live engagement would record.
_SCENARIO_PHASE_META = {
    "recon": ("initial_access", "access", "Reconnaissance sweep"),
    "exploit": ("initial_access", "access", "Initial-access exploit"),
    "llm_jailbreak": ("lateral", "access", "LLM jailbreak attempt"),
    "network_bypass": ("lateral", "access", "Network bypass / pivot"),
    "mcp_c2": ("c2", "persistence", "MCP / LLM C2 beacon"),
    "datatheft": ("exfil", "data", "Data theft / exfiltration"),
    "destruction": ("persist", "persistence", "Destructive foothold"),
    "mcp_chain": ("exfil", "data", "MCP tool-chain exploitation"),
    "mcp_attack": ("lateral", "access", "MCP attack-surface probing"),
    "mcp_scan": ("lateral", "access", "MCP endpoint scan"),
    "persistent_exfil": ("exfil", "data", "Persistent exfiltration"),
    "zero_click": ("initial_access", "access", "Zero-click exploit"),
    "k8s_attack": ("lateral", "access", "Kubernetes attack"),
    "wireless_iot": ("initial_access", "access", "Wireless / IoT attack"),
    "advanced_jailbreak": ("lateral", "access", "Advanced jailbreak"),
    "cve_exploit": ("privesc", "privilege", "CVE exploitation"),
    "cloud_attack": ("lateral", "access", "Cloud-environment attack"),
}


def _project_scenario(scenario) -> Tuple[List[Tuple[str, str, str, str, str, bool]],
                                          List[Tuple[str, str, List[str]]],
                                          str]:
    """Project a curated Scenario onto a deterministic demo chain.

    Returns (chain, narration, engagement_name). Deterministic outcome rule:
    the phase at index 1 (or the final phase if only one) is BLOCKED so the
    narration always shows a defensive win; the rest succeed.
    """
    phases = list(scenario.phases)
    if not phases:
        raise click.ClickException(f"scenario {scenario.name!r} has no phases")

    block_idx = min(1, len(phases) - 1)
    mitre = list(scenario.mitre_techniques or [])

    chain: List[Tuple[str, str, str, str, str, bool]] = []
    narration: List[Tuple[str, str, List[str]]] = []
    for i, phase in enumerate(phases):
        step_type, outcome_type, label = _SCENARIO_PHASE_META.get(
            phase, ("initial_access", "access", phase.replace("_", " ").title())
        )
        tech_id = mitre[i] if i < len(mitre) else "T0000"
        success = i != block_idx
        chain.append((step_type, tech_id, label, phase, outcome_type, success))
        narration.append((
            label,
            f"MITRE {tech_id}",
            [
                f"Phase: {phase}",
                ("BLOCKED — defensive control halted this step"
                 if not success else "Stage action executed on the seeded hosts"),
            ],
        ))

    display_name = getattr(scenario, "display_name", None) or scenario.name
    engagement_name = f"DEMO — Projected scenario: {display_name}"
    return chain, narration, engagement_name


def _resolve_scenario(name: str):
    """Resolve a curated scenario and project it onto fictional demo hosts."""
    from scenarios import scenario_library

    try:
        scenario = scenario_library.get(name)
    except KeyError as exc:
        raise click.ClickException(str(exc)) from exc
    return _project_scenario(scenario)


def _compute_scores(chain, hosts) -> Dict[str, Any]:
    """Score the seeded scenario through the REAL CoverageScorer."""
    from commandcenter.backend.services import demo_seed
    from modules.coverage import CoverageScorer

    payloads = [
        demo_seed.demo_attack_log_payload(
            target_name=hosts[1][0],  # stage-dc01.demo.void
            chain=chain,
            started_epoch=demo_seed.DEMO_EPOCH_BASE + 120.0,
        ),
        demo_seed.demo_attack_log_payload(
            target_name=hosts[2][0],  # stage-db01.demo.void
            chain=demo_seed.DEMO_CHAIN_SHORT,
            started_epoch=demo_seed.DEMO_EPOCH_BASE + demo_seed.DEMO_ENGAGEMENT_GAP,
        ),
    ]
    return CoverageScorer().score_all(payloads)


def run_demo(console: Any, json_out: bool = False,
             animate: bool = True, speed: float = 1.0,
             scenario_name: Optional[str] = None) -> Dict[str, Any]:
    """Run the narrated demo. Returns the result payload.

    When ``animate`` is False there are no sleeps (CI / capture mode).
    When ``scenario_name`` is given, that curated scenario from the
    scenario library is projected onto the fictional demo hosts instead
    of the default stage walkthrough.
    """
    hosts = _demo_scenario()[2]

    if scenario_name:
        chain, narration, engagement_name = _resolve_scenario(scenario_name)
    else:
        chain, narration, _hosts, engagement_name = _demo_scenario()
    scores = _compute_scores(chain, hosts)
    eng_score = (scores.get("engagement_scores") or [{}])[0]

    payload = {
        "scenario": scenario_name or "stage-scenario-1",
        "demo": True,
        "engagement": engagement_name,
        "hosts": [{"name": n, "ip": ip, "desc": d} for n, ip, d in hosts],
        "phases": [
            {
                "index": i + 1,
                "step_type": st,
                "technique": tid,
                "label": tlabel,
                "phase": ph,
                "success": ok,
                "narration": narration[i][2] if i < len(narration) else [],
            }
            for i, (st, tid, tlabel, ph, _ot, ok) in enumerate(chain)
        ],
        "prevention": {
            "score": eng_score.get("score"),
            "rubric": "R-2 CoverageScorer (real engine, not simulated)",
            "verdict": eng_score.get("verdict"),
            "verdict_counts": eng_score.get("verdict_counts"),
            "weights": eng_score.get("weights"),
            "aggregated": scores.get("aggregated"),
            "engagement_count": scores.get("count"),
        },
    }

    if json_out:
        click.echo(json.dumps(payload, indent=2, default=str))
        return payload

    pause = lambda s: time.sleep(s / max(speed, 0.01)) if animate else None

    _banner_demo(console, engagement_name, hosts)
    if animate:
        pause(1.0)

    for i, (st, tid, tlabel, ph, _ot, ok) in enumerate(chain):
        title, mitre, lines = narration[i] if i < len(narration) else (
            st.replace("_", " ").title(), tid, []
        )
        _phase_header(console, i + 1, len(chain), title, mitre)
        for line in lines:
            console.print(f"    {line}", style="dim")
            if animate:
                pause(0.6)
        sym, style = OUTCOME_STYLE[ok]
        verdict = "SUCCESS" if ok else "BLOCKED"
        console.print(f"  [{style}]{sym}[/{style}] Phase "
                      f"[{style}]{verdict}[/{style}]\n")
        if animate:
            pause(PHASE_OUTCOME_PAUSE)

    _score_panel(console, payload)
    return payload


def _banner_demo(console: Any, engagement_name: str, hosts) -> None:
    from rich.panel import Panel

    host_lines = "\n".join(
        f"  [cyan]{name}[/]  [dim]{ip} — {desc}[/]" for name, ip, desc in hosts
    )
    console.print(Panel(
        f"[bold yellow]DEMO MODE[/] — synthetic stage data (fictional hosts)\n"
        f"[dim]{engagement_name}[/]\n\n"
        f"{host_lines}\n\n"
        f"[dim]Zero network. Zero real targets. Deterministic narration\n"
        f"scored by the real R-2 CoverageScorer rubric.[/]",
        title="[bold red]THE VOID — Stage Demo[/]",
        border_style="yellow",
    ))


def _phase_header(console: Any, idx: int, total: int, title: str,
                  mitre: str) -> None:
    console.print(
        f"\n[bold cyan]PHASE {idx}/{total}[/bold cyan] "
        f"[bold]{title}[/bold]"
    )
    console.print(f"    [dim]MITRE: {mitre}[/dim]")


def _verdict_from_counts(counts) -> str:
    """Derive a human verdict string from R-2 verdict_counts.

    Dominance order: exploited > verified > unknown. Produces e.g.
    ``exploited×4 verified×1`` so the panel reads at a glance.
    """
    if not counts:
        return "—"
    # R-2 coverage classes, best → worst (see modules.coverage.WEIGHT_COVERAGE).
    order = ["verified", "exploited", "reachability", "unknown"]
    parts = [f"{cls}\u00d7{n}" for cls in order
             for n in [counts.get(cls, 0)] if n]
    return " ".join(parts) if parts else "—"


def _score_panel(console: Any, payload: Dict[str, Any]) -> None:
    from rich.panel import Panel

    p = payload["prevention"]
    score = p.get("score")
    score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "—"
    verdict = _verdict_from_counts(p.get("verdict_counts"))
    lines = [
        f"Engagements scored: [bold]{p.get('engagement_count')}[/]",
        f"Aggregated score:   [bold]{p.get('aggregated')}[/]",
        f"Primary target:     [bold]{score_str}[/]",
        f"Verdict:            [bold]{verdict}[/]",
        "",
        f"[dim]Computed by modules.coverage.CoverageScorer (the same code\n"
        f"path served at /api/coverage in Command Center).[/]",
    ]
    console.print(Panel(
        "\n".join(lines),
        title="[bold red]Prevention / Coverage Score[/]",
        border_style="red",
    ))
