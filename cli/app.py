#!/usr/bin/env python3
"""THE VOID — CLI Application.

A click-based command-line interface for THE VOID.

Subcommands:
    engage   Engage one or more targets with the ChaosEngine.
    recon    Run reconnaissance on a target without exploitation.
    report   Generate an engagement report (HTML/JSON/Markdown).
    targets  List, add, or remove targets from the active set.
    status   Show the current status of the agent/engine.
    version  Show version information.

Usage::

    thevoid engage 192.168.1.1 --mode full --stealth
    thevoid recon example.com
    thevoid report --format html -o report.html
    thevoid targets --add 10.0.0.5 --add 10.0.0.6
    thevoid status
    thevoid version
"""

import json
import logging
import os
import sys
import time
from contextlib import nullcontext as _nullcontext
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure project root is on sys.path so imports resolve whether or not
# the package was installed via pip.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from config.settings import Settings  # noqa: E402

console = Console()

logger = logging.getLogger("void.cli")

# ─── Version ───────────────────────────────────────────────────────────────────

try:
    from config.defaults import AGENT_VERSION as _VERSION  # noqa: E402
except Exception:  # pragma: no cover — fallback if defaults not importable
    _VERSION = "1.0.0"

VERSION = _VERSION

# ─── Constants ─────────────────────────────────────────────────────────────────

VALID_MODES = ("quick", "full", "aggressive", "stealth", "chaos")
VALID_REPORT_FORMATS = ("html", "json", "markdown", "md")

# Banner used by the top-level group for the --banner flag. Canonical
# source lives in config.defaults (W4-2.4a) — no local copy.
from config.defaults import VOID_BANNER as BANNER  # noqa: E402


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    """Print the VOID banner (client-safe messaging)."""
    console.print(BANNER, style="bold red")
    console.print(
        "  THE VOID — Operator-authorized AI red team",
        style="dim",
    )
    console.print(
        "  Local · Auditable · MCP-aware · Scope-gated\n",
        style="dim",
    )


def _make_engine(settings: Optional[Settings] = None, quiet: bool = False):
    """Create a ChaosEngine, handling import errors gracefully."""
    try:
        from orchestrator.chaos import ChaosEngine
    except Exception as e:  # pragma: no cover
        if not quiet:
            console.print(f"[red]Error:[/] Failed to import ChaosEngine: {e}")
        raise
    return ChaosEngine(settings)


def _make_target(value: str):
    """Create a Target object from a string."""
    from core.target import Target
    return Target(value=value, name=value)


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _settings_from_options(
    config: Optional[str] = None,
    profile: Optional[str] = None,
    authz: Optional[str] = None,
    strict: bool = False,
    dry_run: bool = False,
    client: bool = False,
) -> Settings:
    """Build a Settings instance from CLI options / profile files."""
    # Settings is a singleton — reload defaults then apply overlays so
    # repeated CLI invocations in-process (tests) stay predictable.
    settings = Settings()
    settings._load_defaults()

    if profile == "demo" or profile == "client":
        demo_cfg = os.path.join(
            _project_root(), "config", "examples", "demo_profile.json"
        )
        if os.path.isfile(demo_cfg):
            settings.load_file(demo_cfg)
        settings.set("CLIENT_MODE", True)
        settings.set("STRICT_DIFFICULTY", True)
        settings.set("REQUIRE_AUTHORIZATION", True)
        if not settings.get("AUTHORIZATION_FILE"):
            settings.set(
                "AUTHORIZATION_FILE",
                os.path.join(
                    "config", "examples", "authorization.demo.json"
                ),
            )

    if config:
        settings.load_file(config)
    if authz:
        settings.set("AUTHORIZATION_FILE", authz)
        settings.set("REQUIRE_AUTHORIZATION", True)
    if strict:
        settings.set("STRICT_DIFFICULTY", True)
    if dry_run:
        settings.set("DRY_RUN", True)
    if client:
        settings.set("CLIENT_MODE", True)
        settings.set("REQUIRE_AUTHORIZATION", True)
    return settings


# ─── Click Group ───────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--banner", "-b", is_flag=True, help="Print the VOID banner.")
@click.version_option(VERSION, prog_name="thevoid")
@click.pass_context
def cli(ctx: click.Context, banner: bool) -> None:
    """THE VOID — Operator-authorized AI red team (local, auditable, MCP-aware).

    Use subcommands to engage in-scope targets, run recon, generate reports,
    manage targets, and check status. Prefer --profile demo for client demos.
    """
    ctx.ensure_object(dict)
    if banner or ctx.invoked_subcommand is None:
        _print_banner()
    if ctx.invoked_subcommand is None:
        # No subcommand: show help-like overview.
        console.print("[dim]Run [bold]thevoid --help[/] to see available commands.[/]")
        console.print(
            "[dim]Client demo: [bold]thevoid recon 127.0.0.1 --profile demo --dry-run[/][/]")


def _scenario_catalog_names() -> List[str]:
    """Names of all curated scenarios (R-6 catalog). Never raises."""
    try:
        from scenarios import scenario_library
        names = scenario_library.names()
    except Exception:
        names = []
    return names


def _complete_scenario(ctx, param, incomplete):
    """Click shell-completion for --scenario: curated scenario catalog.

    Registered on engage / demo / continuity-start --scenario (W4-2.2c).
    """
    for n in _scenario_catalog_names():
        if incomplete is None or n.startswith(incomplete):
            yield n


# ─── engage ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--mode", "-m", default="full",
              type=click.Choice(VALID_MODES, case_sensitive=False),
              help="Engagement mode (quick=recon only).")
@click.option("--stealth", "-s", is_flag=True, help="Activate stealth mode (Tor).")
@click.option("--output", "-o", type=click.Path(),
              help="Save results to a JSON file.")
@click.option("--config", "-c", type=click.Path(), help="Config file path.")
@click.option(
    "--profile",
    type=click.Choice(["default", "demo", "client"], case_sensitive=False),
    default=None,
    help="Engagement profile (demo/client enable scope gate + strict difficulty).",
)
@click.option("--authz", type=click.Path(exists=True),
              help="Path to authorization/scope JSON (ROE).")
@click.option("--strict", is_flag=True,
              help="Enable strict difficulty gate (abort blocks engage).")
@click.option("--dry-run", is_flag=True,
              help="Plan phases and check scope without executing tools.")
@click.option("--client", is_flag=True,
              help="Client mode: require authorization file.")
@click.option("--json-output", "json_out", is_flag=True,
              help="Output results as JSON (no rich tables).")
@click.option("--scenario", "scenario_name", default=None,
              shell_complete=_complete_scenario,
              help="Use a curated attack scenario (see `thevoid scenarios list`). "
                   "Overrides the mode-derived phase list.")
def engage(targets, mode, stealth, output, config, profile, authz, strict,
           dry_run, client, json_out, scenario_name):
    """Engage one or more TARGETS (must be in authorized scope when gated).

    TARGETS is one or more IP addresses, domains, or URLs.
    """
    settings = _settings_from_options(
        config=config, profile=profile, authz=authz,
        strict=strict, dry_run=dry_run, client=client,
    )
    engine = _make_engine(settings)

    # Apply scenario override (R-6) — scenarios replace the mode-derived
    # phase list for the whole engagement.
    if scenario_name:
        try:
            engine.agent.set_scenario(scenario_name)
            if not json_out:
                console.print(
                    f"[cyan][*][/cyan] Scenario: [bold]{scenario_name}[/]"
                )
        except (KeyError, ImportError) as e:
            console.print(f"[bold red][!][/] {e}")
            raise SystemExit(2)

    if stealth:
        try:
            engine.activate_stealth()
            if not json_out:
                console.print("[yellow][*][/yellow] Stealth mode activated")
        except Exception as e:
            console.print(f"[red][!][/red] Stealth activation failed: {e}")

    target_objs = [_make_target(t) for t in targets]

    # W4-2.2a: live phase-by-phase table. Only attach the listener when we
    # are actually rendering (not JSON mode) and the engine exposes a real
    # ShadowAgent (engine.agent is None or a MagicMock in unit tests).
    from cli.render import PhaseTracker
    tracker = (PhaseTracker(console, target=target_objs[0].name, mode=mode)
               if not json_out else None)
    agent = getattr(engine, "agent", None) if tracker else None
    has_listener = agent is not None and callable(
        getattr(agent, "set_phase_listener", None))

    all_results = []
    try:
        if tracker and has_listener:
            agent.set_phase_listener(tracker.listener())
        with tracker.live() if tracker else _nullcontext():
            for target_obj in target_objs:
                if not json_out:
                    console.print(
                        f"\n[cyan][*][/cyan] Engaging [bold]{target_obj.name}[/] "
                        f"(mode={mode}{', dry-run' if dry_run else ''})"
                    )
                try:
                    result = engine.engage(target_obj, mode)
                    all_results.append(result)
                except KeyboardInterrupt:
                    console.print("\n[yellow][!][/yellow] Interrupted by user")
                    sys.exit(1)
                except Exception as e:
                    console.print(
                        f"[red][!][/red] Error engaging {target_obj.name}: {e}"
                    )
                    logger.error("Engagement error: %s", e, exc_info=True)
                    all_results.append({
                        "target": target_obj.name, "mode": mode,
                        "status": "error", "error": str(e),
                    })
    finally:
        if tracker and has_listener:
            try:
                agent.set_phase_listener(None)
            except Exception:
                pass

    if json_out:
        click.echo(json.dumps(all_results, indent=2, default=str))
    else:
        _render_engagement_results(all_results)

    if output:
        with open(output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        console.print(f"\n[green][+][/green] Results saved to {output}")


def _render_engagement_results(results: list) -> None:
    """Unified engagement-results renderer (W4-2.3a) for engage AND recon.

    - Gate verdicts (denied/aborted/dry_run/error) → first-class red panels
      via cli.render.render_gate_verdict (reason, authz, difficulty detail).
    - Summary table with status colouring.
    - Real prevention-strength panel (W4-2.2b) scored by CoverageScorer
      over the completed results in this run.
    """
    from cli import render as R

    if not results:
        console.print("[dim]No results.[/]")
        return

    table = Table(title="Engagement Results", show_header=True,
                  header_style="bold red")
    table.add_column("Target", style="cyan")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Difficulty", justify="right")
    table.add_column("Phases", justify="right")

    for r in results:
        if not isinstance(r, dict):
            continue
        findings = r.get("findings", {})
        planned = r.get("planned_phases") or (
            list(findings.keys()) if isinstance(findings, dict) else []
        )
        n_phases = len(planned) if planned else (
            len(findings) if isinstance(findings, dict) else 0
        )
        diff = r.get("difficulty")
        if isinstance(diff, dict):
            diff_str = f"{diff.get('score', 0):.2f}"
        elif diff is not None:
            diff_str = str(diff)
        else:
            diff_str = "—"
        status = r.get("status", "?")
        status_style = "green" if status in ("completed", "dry_run") else (
            "red" if status in ("error", "aborted", "denied") else "yellow"
        )
        table.add_row(
            str(r.get("target", "?")),
            str(r.get("mode", "?")),
            f"[{status_style}]{status}[/{status_style}]",
            diff_str,
            str(n_phases),
        )
        if status == "dry_run" and planned:
            console.print(f"  [dim]→ phases: {', '.join(planned)}[/]")

    console.print(table)

    # First-class gate-verdict panels for non-completed results (W4-2.3a).
    for r in results:
        if isinstance(r, dict) and r.get("status") in R.VERDICT_TITLE:
            R.render_gate_verdict(console, r)

    # Prevention-strength summary via the real CoverageScorer (W4-2.2b).
    completed = [r for r in results
                 if isinstance(r, dict) and r.get("status") == "completed"]
    if completed:
        R.render_prevention_summary(console, completed,
                                    title="Prevention Strength — this run")


# ─── demo ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--json-output", "json_out", is_flag=True,
              help="Emit the demo result as JSON (no narration).")
@click.option("--no-animate", "no_animate", is_flag=True,
              help="Disable phase pacing (no sleeps). CI/capture friendly.")
@click.option("--speed", "speed", type=float, default=1.0, show_default=True,
              help="Animation speed multiplier (>1 = faster).")
@click.option("--scenario", "scenario_name", default=None,
              shell_complete=_complete_scenario,
              help="Named stage scenario to narrate (see `thevoid scenarios list`; "
                   "default: stage-scenario-1).")
def demo(json_out, no_animate, speed, scenario_name):
    """Run a guided, deterministic, narrated stage demo (Black Hat / DEF CON).

    Zero network, zero real targets. Narrates the seeded fictional stage
    scenario and ends in a prevention/coverage score computed by the real
    R-2 CoverageScorer rubric — the same code path as /api/coverage.

    With --scenario, a curated scenario from `thevoid scenarios` is
    projected onto the fictional demo hosts and narrated deterministically.

    Examples:

        thevoid demo
        thevoid demo --scenario rdp-brute-force
        thevoid demo --no-animate
    """
    from cli.demo import run_demo

    try:
        run_demo(
            console,
            json_out=json_out,
            animate=not no_animate,
            speed=max(speed, 0.01),
            scenario_name=scenario_name,
        )
    except SystemExit:
        raise
    except Exception as exc:
        console.print(f"[bold red][!][/bold red] demo failed: {exc}")
        logger.error("demo failed: %s", exc, exc_info=True)
        raise SystemExit(1)


# ─── recon ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--output", "-o", type=click.Path(),
              help="Save recon results to a JSON file.")
@click.option("--config", "-c", type=click.Path(), help="Config file path.")
@click.option(
    "--profile",
    type=click.Choice(["default", "demo", "client"], case_sensitive=False),
    default=None,
    help="Engagement profile (demo/client enable scope gate).",
)
@click.option("--authz", type=click.Path(exists=True),
              help="Path to authorization/scope JSON (ROE).")
@click.option("--dry-run", is_flag=True,
              help="Plan recon without executing tools.")
@click.option("--json-output", "json_out", is_flag=True,
              help="Output results as JSON (no rich tables).")
def recon(targets, output, config, profile, authz, dry_run, json_out):
    """Run reconnaissance on TARGETS (quick mode — recon phase only).

    Equivalent to ``engage --mode quick``. Non-destructive by design:
    only the recon phase is scheduled.
    """
    settings = _settings_from_options(
        config=config, profile=profile, authz=authz, dry_run=dry_run,
    )
    engine = _make_engine(settings)

    target_objs = [_make_target(t) for t in targets]
    all_results = []

    # W4-2.2a: same live phase table as `engage` (unified surface).
    from cli.render import PhaseTracker
    tracker = (PhaseTracker(console, target=target_objs[0].name, mode="quick")
               if not json_out else None)
    agent = getattr(engine, "agent", None) if tracker else None
    has_listener = agent is not None and callable(
        getattr(agent, "set_phase_listener", None))

    try:
        if tracker and has_listener:
            agent.set_phase_listener(tracker.listener())
        with tracker.live() if tracker else _nullcontext():
            for target_obj in target_objs:
                if not json_out:
                    console.print(
                        f"\n[cyan][*][/cyan] Recon on [bold]{target_obj.name}[/]"
                    )
                try:
                    result = engine.engage(target_obj, "quick")
                    all_results.append(result)
                except Exception as e:
                    console.print(
                        f"[red][!][/red] Recon error on {target_obj.name}: {e}"
                    )
                    all_results.append({
                        "target": target_obj.name, "mode": "quick",
                        "status": "error", "error": str(e),
                    })
    finally:
        if tracker and has_listener:
            try:
                agent.set_phase_listener(None)
            except Exception:
                pass

    if json_out:
        click.echo(json.dumps(all_results, indent=2, default=str))
    else:
        _render_engagement_results(all_results)

    if output:
        with open(output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        console.print(f"\n[green][+][/green] Recon saved to {output}")


def _render_recon_results(results: list) -> None:
    """Back-compat shim: recon now shares the unified engagement renderer."""
    _render_engagement_results(results)


# ─── report ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--format", "-f", "fmt", default="json",
              type=click.Choice(VALID_REPORT_FORMATS, case_sensitive=False),
              help="Report format (html, json, markdown).")
@click.option("--output", "-o", type=click.Path(),
              help="Write report to this file.")
@click.option("--operator", default="THE VOID",
              help="Operator name for the report header.")
@click.option("--name", default="Engagement Report",
              help="Engagement name for the report header.")
@click.option("--verify-integrity", "verify_integrity", is_flag=True,
              help="Run cryptographic integrity verification on WarLog/Boneyard "
                   "(slow for large logs: O(n) PBKDF2 per row).")
@click.option("--export", "export_sinks", multiple=True,
              type=click.Choice(["syslog", "webhook", "file_jsonlines"]),
              help="Also export the report data to these SIEM sinks "
                   "(webhook requires THE_VOID_SIEM_TOKEN + THE_VOID_SIEM_URL env).")
@click.option("--export-url", "export_url", default=None,
              help="Override webhook URL (default from THE_VOID_SIEM_URL env).")
@click.option("--export-file", "export_file", type=click.Path(), default=None,
              help="File path for the file_jsonlines sink.")
@click.option("--config", "-c", type=click.Path(), help="Config file path.")
def report(fmt, output, operator, name, verify_integrity, export_sinks, export_url, export_file, config):
    """Generate an engagement report from current WarLog + Boneyard data.

    Pulls data from the active WarLog and Boneyard instances and renders
    a report in the specified format. If no --output is given, the report
    is printed to stdout.

    Integrity verification is OFF by default for speed. Use --verify-integrity
    to run cryptographic verification (slow for large logs).
    """
    settings = _settings_from_options(config=config)

    from modules.reporter import Reporter
    from core.warlog import WarLog
    from core.boneyard import Boneyard

    warlog = WarLog()
    boneyard = Boneyard()

    # W4-2.3c: integrity verification is O(n) PBKDF2 work — show a live
    # progress bar when verifying, unless the report itself is being
    # echoed as raw JSON to stdout (progress would corrupt the stream).
    progress_cb = None
    progress_ctx = _nullcontext()
    if verify_integrity and not (fmt == "json" and not output):
        from rich.progress import (
            BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
            TextColumn, TimeElapsedColumn,
        )
        _progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console, transient=True,
        )
        _task = {"id": None, "total": 0}

        def progress_cb(done, total, label):
            try:
                if _task["id"] is None or total != _task["total"]:
                    if _task["id"] is not None:
                        _progress.remove_task(_task["id"])
                    _task["id"] = _progress.add_task(label, total=total)
                    _task["total"] = total
                _progress.update(_task["id"], completed=done,
                                 description=label)
            except Exception:
                pass

        progress_ctx = _progress

    reporter = Reporter(
        warlog=warlog,
        boneyard=boneyard,
        attack_log=[],
        operator=operator,
        engagement_name=name,
        verify_integrity=verify_integrity,
        integrity_progress=progress_cb,
    )

    with progress_ctx:
        if output:
            reporter.generate(format=fmt, output_path=output)
        else:
            content = reporter.generate(format=fmt)

    if output:
        console.print(f"[green][+][/green] Report written to {output}")
    else:
        # For HTML/Markdown, print via console (rich rendering). For JSON,
        # echo raw so it's pipe-friendly.
        if fmt == "json":
            click.echo(content)
        else:
            console.print(content)

    # ─── SIEM / downstream export (R-5) ─────────────────────────────────
    if export_sinks:
        data = reporter.gather_data()
        sinks: List[Any] = []
        for sink in export_sinks:
            if sink == "syslog":
                from modules.exporters import SyslogExporter
                sinks.append(SyslogExporter())
            elif sink == "webhook":
                url = export_url or os.environ.get(
                    "THE_VOID_SIEM_URL", "http://127.0.0.1:8080/report")
                from modules.exporters import WebhookExporter
                sinks.append(WebhookExporter(url))
            elif sink == "file_jsonlines":
                fp = export_file or os.environ.get(
                    "THE_VOID_SIEM_FILE", "/tmp/void-siem.jsonl")
                from modules.exporters import FileJSONLinesExporter
                sinks.append(FileJSONLinesExporter(fp))

        sent = []
        for s in sinks:
            try:
                ok = s.export(data)
            except Exception as exc:
                logger.error("Export to %s failed: %s", s.name, exc)
                ok = False
            sent.append((s.name, ok))
        console.print(f"[green][+][/green] Export attempt: {sent}")


# ─── targets ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--add", "add_targets", multiple=True,
              help="Add a target (can be repeated).")
@click.option("--remove", "remove_targets", multiple=True,
              help="Remove a target by name (can be repeated).")
@click.option("--clear", is_flag=True, help="Remove all targets.")
@click.option("--list", "list_flag", is_flag=True, default=True,
              help="List all targets (default action).")
@click.option("--config", "-c", type=click.Path(), help="Config file path.")
def targets(add_targets, remove_targets, clear, list_flag, config):
    """Manage the target list.

    Add, remove, or list targets. Targets are stored in the active agent.
    """
    settings = _settings_from_options(config)
    engine = _make_engine(settings, quiet=True)

    if clear:
        engine.agent.targets.clear()
        console.print("[yellow][*][/yellow] Cleared all targets")

    for t in add_targets:
        engine.agent.add_target(_make_target(t))
        console.print(f"[green][+][/green] Added target: {t}")

    for t_name in remove_targets:
        target_obj = engine.agent.get_target(t_name)
        if target_obj:
            engine.agent.remove_target(target_obj)
            console.print(f"[yellow][-][/yellow] Removed target: {t_name}")
        else:
            console.print(f"[red][!][/red] Target not found: {t_name}")

    if list_flag or (not add_targets and not remove_targets and not clear):
        _render_targets(engine)


def _render_targets(engine) -> None:
    """Render the target list as a rich table."""
    target_list = engine.agent.targets
    if not target_list:
        console.print("[dim]No targets. Use --add to add one.[/]")
        return

    table = Table(title="Targets", show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Value")
    table.add_column("Type")

    for i, t in enumerate(target_list, 1):
        table.add_row(str(i), t.name, t.value,
                      getattr(t.target_type, "value", str(t.target_type)))

    console.print(table)


# ─── status ───────────────────────────────────────────────────────────────────

def _status_enrich(engine, st: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich engine status with R-2 prevention score, last drift finding,
    active scenario, and integrity state (W4-2.3b).

    Defensive by design: unit tests inject MagicMock engines whose attribute
    access returns MagicMocks, so every probe is guarded by ``isinstance``
    checks against the real types. Anything that isn't the real thing is
    treated as absent (None) rather than rendered.
    """
    extra: Dict[str, Any] = {
        "prevention": None,
        "last_drift": None,
        "scenario": None,
        "integrity": None,
    }

    agent = getattr(engine, "agent", None)
    if agent is None:
        return extra

    # ── Prevention score (R-2 CoverageScorer over completed attack_log) ──
    try:
        attack_log = getattr(agent, "attack_log", None)
        if isinstance(attack_log, list):
            completed = [e for e in attack_log
                         if isinstance(e, dict) and e.get("status") == "completed"]
            if completed:
                from modules.coverage import CoverageScorer
                scores = CoverageScorer().score_all(completed)
                extra["prevention"] = {
                    "score": scores.get("aggregated"),
                    "engagement_count": scores.get("count", len(completed)),
                }
    except Exception:
        pass

    # ── Active scenario ──
    try:
        sc = getattr(agent, "scenario", None)
        if isinstance(sc, str) and sc:
            extra["scenario"] = sc
    except Exception:
        pass

    # ── Last drift finding (R-3; continuity stores these in boneyard) ──
    try:
        boneyard = getattr(agent, "boneyard", None)
        search = getattr(boneyard, "search", None)
        if callable(search):
            rows = search(category="drift")
            # search() returns newest-first (ORDER BY epoch DESC).
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                last = rows[0]
                payload = last.get("data") if isinstance(
                    last.get("data"), dict) else {}
                extra["last_drift"] = {
                    "msg": payload.get("msg") or payload.get("message")
                    or last.get("note") or "drift detected",
                    "when": last.get("timestamp"),
                }
    except Exception:
        pass

    # ── Integrity state (warlog + boneyard WORM verification) ──
    try:
        integrity: Dict[str, Any] = {}
        for name, store in (("warlog", getattr(agent, "warlog", None)),
                            ("boneyard", getattr(agent, "boneyard", None))):
            fn = getattr(store, "verify_integrity", None)
            if not callable(fn):
                continue
            try:
                report = fn()
            except Exception:
                continue
            if report is True:
                integrity[name] = True
            elif report is False:
                integrity[name] = False
            else:
                # Real IntegrityReport (warlog dataclass / boneyard
                # dataclass) exposes a boolean `.verified`. Guard with an
                # isinstance(bool) check so a MagicMock is never treated as
                # a real report.
                verified = getattr(report, "verified", None)
                if isinstance(verified, bool):
                    integrity[name] = verified
        if integrity:
            extra["integrity"] = integrity
    except Exception:
        pass

    return extra


@cli.command()
@click.option("--config", "-c", type=click.Path(), help="Config file path.")
@click.option("--json-output", "json_out", is_flag=True,
              help="Output status as JSON.")
def status(config, json_out):
    """Show the current status of the agent/engine."""
    settings = _settings_from_options(config=config)
    engine = _make_engine(settings, quiet=True)

    try:
        st = engine.get_status()
    except Exception:
        st = engine.agent.get_status()

    extra = _status_enrich(engine, st)

    if json_out:
        merged = dict(st) if isinstance(st, dict) else {"status": st}
        merged.update({k: v for k, v in extra.items() if v is not None})
        click.echo(json.dumps(merged, indent=2, default=str))
        return

    panel_content = []
    engaged = st.get("engaged", False)
    panel_content.append(
        f"[{'green' if engaged else 'red'}]Engaged:[/] "
        f"{'YES' if engaged else 'NO'}"
    )

    targets = st.get("targets", [])
    panel_content.append(f"Targets: [bold]{len(targets)}[/]")
    if targets:
        panel_content.append("  " + ", ".join(targets))

    stealth = st.get("stealth_active", False)
    panel_content.append(
        f"[{'green' if stealth else 'dim'}]Stealth:[/] "
        f"{'ACTIVE' if stealth else 'inactive'}"
    )

    panel_content.append(f"WarLog entries: {st.get('warlog_entries', 0)}")
    panel_content.append(f"Attacks logged: {st.get('attack_log', 0)}")

    stolen = st.get("stolen_data", 0)
    panel_content.append(f"Stolen data items: {stolen}")

    sessions = st.get("active_sessions", [])
    panel_content.append(f"Active sessions: {len(sessions)}")

    beacons = st.get("beacons", [])
    panel_content.append(f"Beacons: {len(beacons)}")

    # ── W4-2.3b enrichment block ──
    prevention = extra.get("prevention")
    if prevention:
        panel_content.append(
            f"Prevention score: [bold red]{prevention.get('score')}[/] "
            f"({prevention.get('engagement_count')} engagements)"
        )

    scenario = extra.get("scenario")
    if scenario:
        panel_content.append(f"Scenario: [cyan]{scenario}[/]")

    drift = extra.get("last_drift")
    if drift:
        when = drift.get("when")
        panel_content.append(
            f"Last drift: [yellow]{drift.get('msg')}[/]"
            + (f" [dim]@ {when}[/]" if when else "")
        )

    integrity = extra.get("integrity")
    if integrity:
        parts = []
        for name, ok in integrity.items():
            parts.append(
                f"[green]{name} ✓[/]" if ok else f"[red]{name} ✗[/]"
            )
        panel_content.append("Integrity: " + "  ".join(parts))

    console.print(Panel(
        "\n".join(panel_content),
        title="[bold red]THE VOID — Status[/]",
        border_style="red",
    ))


# ─── version ──────────────────────────────────────────────────────────────────

def _collect_version_meta() -> Dict[str, Any]:
    """Assemble version/build metadata. Defensive: never raise on a missing
    subsystem — a version query must always succeed on stage."""
    import platform as _platform

    meta: Dict[str, Any] = {
        "version": VERSION,
        "name": "thevoid",
        "platform": {
            "agent_version": VERSION,
            "python": _platform.python_version(),
            "os": f"{_platform.system()} {_platform.release()}",
        },
        "command_center": {"version": "unknown"},
        "phases": 0,
        "scenarios": 0,
    }

    try:
        from commandcenter import __version__ as cc_ver
        meta["command_center"]["version"] = cc_ver
    except Exception:
        pass

    try:
        from agent.phase_registry import PhaseRegistry
        meta["phases"] = len(PhaseRegistry().phases)
    except Exception:
        pass

    try:
        from scenarios import scenario_library
        meta["scenarios"] = len(scenario_library.names())
    except Exception:
        pass

    return meta


@cli.command()
@click.option("--json-output", "json_out", is_flag=True,
              help="Output version as JSON.")
def version(json_out):
    """Show version + build metadata (platform, Command Center, agent)."""
    meta = _collect_version_meta()

    if json_out:
        click.echo(json.dumps(meta, indent=2, default=str))
        return

    plat = meta["platform"]
    cc = meta["command_center"]
    lines = [
        f"[bold red]THE VOID[/] — v{VERSION}",
        f"[dim]Operator-authorized AI red team — local, auditable, MCP-aware[/]",
        "",
        f"[bold]Agent[/]      v{plat['agent_version']}",
        f"[bold]Python[/]     {plat['python']}",
        f"[bold]OS[/]         {plat['os']}",
        f"[bold]Phases[/]     {meta['phases']} registered",
        f"[bold]Scenarios[/]  {meta['scenarios']} curated",
        "",
        f"[bold]Command Center[/]  v{cc['version']}  (binds 127.0.0.1 only)",
    ]
    console.print(Panel("\n".join(lines), border_style="red"))


# ─── scenarios ────────────────────────────────────────────────────────────────

@cli.group()
def scenarios():
    """Work with curated attack scenarios (planned phase lists)."""


@scenarios.command(name="list")
@click.option("--json-output", "json_out", is_flag=True)
def scenarios_list(json_out):
    """List the curated attack scenarios."""
    try:
        from scenarios import scenario_library
    except Exception:
        click.echo("[red][!][/red] scenarios package not available")
        return

    if json_out:
        click.echo(json.dumps(scenario_library.describe(), indent=2))
        return

    total = len(scenario_library.names())
    console.print(f"\n[bold]Curated Scenarios[/] ({total})")
    for s in scenario_library.list():
        console.print(
            f"  [bold cyan]{s.name}[/] v{s.version}"
        )
        console.print(f"    [dim]{s.description}[/]")
        console.print(
            f"    Phases: [dim]{', '.join(s.phases)}[/]  "
            f"MITRE: [dim]{', '.join(s.mitre_techniques[:3])}"
            f"{'...' if len(s.mitre_techniques) > 3 else ''}[/]"
        )
        console.print()


@scenarios.command(name="show")
@click.argument("name", required=True)
@click.option("--json-output", "json_out", is_flag=True)
def scenarios_show(name, json_out):
    """Show detailed information for one scenario."""
    try:
        from scenarios import scenario_library
    except Exception:
        click.echo("[red][!][/red] scenarios package not available")
        return

    try:
        sc = scenario_library.get(name)
    except KeyError as e:
        console.print(f"[bold red][!][/] {e}")
        raise SystemExit(2)

    if json_out:
        click.echo(json.dumps({
            "name": sc.name, "description": sc.description,
            "phases": list(sc.phases),
            "mitre": list(sc.mitre_techniques), "version": sc.version,
        }, indent=2))
        return

    console.print(f"\n[bold cyan]{sc.name}[/] v{sc.version}")
    console.print(f"\n{sc.description}\n")
    console.print(f"  [bold]Phases:[/] {', '.join(sc.phases)}")
    console.print(f"  [bold]MITRE:[/] {', '.join(sc.mitre_techniques)}")
    console.print()


# ─── continuity ─────────────────────────────────────────────────────────────────

@cli.group()
def continuity():
    """Continuity engagement scheduling (R-3)."""


@continuity.command(name="start")
@click.argument("targets", nargs=-1, required=True)
@click.option("--mode", "mode_", default="quick",
              type=click.Choice(VALID_MODES, case_sensitive=False),
              help="Engagement mode for each run.")
@click.option("--interval-hours", "interval_hours", type=int, default=24,
              help="Hours between full engagement runs (min 1).")
@click.option("--max-runs", "max_runs", type=int, default=None,
              help="Stop after N runs (omit to run indefinitely).")
@click.option("--scenario", "scenario_name", default=None,
              shell_complete=_complete_scenario,
              help="Use a curated scenario (overrides mode phases).")
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--quiet", is_flag=True, default=False,
              help="Suppress startup banner (scheduler only logs).")
def continuity_start(
    targets, mode_, interval_hours, max_runs, scenario_name, config_path, quiet
):
    """Start a background continuity scheduler.

    Each TARGET is engaged every INTERVAL_HOURS. Drift between runs
    (verdic class changes at any phase) is logged to warlog and boneyard
    as `category=drift`. Runs until --max-runs or Ctrl-C.
    """
    try:
        from orchestrator.chaos import ChaosEngine  # canonical engine location
    except Exception as exc:
        console.print(f"[bold red][!][/] orchestrator engine unavailable: {exc}")
        return

    try:
        s = _settings_from_options(config=config_path)
    except Exception as exc:
        console.print(f"[bold red][!][/] config error: {exc}")
        return

    engine = ChaosEngine(settings=s)
    target_objs = [_make_target(t) for t in targets]

    try:
        from modules.continuity import ContinuityScheduler
    except Exception as exc:
        console.print(f"[bold red][!][/] continuity module unavailable: {exc}")
        return

    try:
        score = scenario_name
        if score:
            engine.agent.set_scenario(score)
    except Exception as exc:
        console.print(f"[bold red][!][/] scenario error: {exc}")
        return

    if not quiet:
        _print_banner()

    console.print(
        f"[bold cyan][~][/] Continuity started: targets={[t.name for t in target_objs]} "
        f"mode={mode_} scenario={scenario_name or 'default'} "
        f"interval={interval_hours}h"
    )
    console.print("[dim]Press Ctrl-C to stop.[/]")

    scheduler = ContinuityScheduler(
        shadow_agent=engine.agent,
        targets=target_objs,
        mode=mode_,
        interval_seconds=int(interval_hours) * 3600,
        max_runs=max_runs,
        warlog=getattr(engine, "warlog", None),
        boneyard=getattr(engine, "boneyard", None),
    )
    scheduler.start()

    try:
        while scheduler.is_alive:
            if max_runs and scheduler._run_count >= max_runs:
                break
            # wake every 30s so Ctrl-C response is bounded without busy-waiting
            interruptible_sleep = 30
            for _ in range(interruptible_sleep):
                if not scheduler.is_alive:
                    break
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    scheduler.stop()
                    console.print("\n[bold red][!][/] Stopped by user.")
                    return
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.stop()

    console.print(f"[green][✓][/] Continuity finished ({scheduler._run_count} run(s))")


@continuity.command(name="drift")
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--output", "output", type=click.Path(), default=None)
@click.option("--json-output", "json_out", is_flag=True)
@click.option("--list", "list_flag", is_flag=True, default=True)
def continuity_drift(config_path, output, json_out, list_flag):
    """Show recorded drift events from the boneyard."""
    console.print("[bold cyan][~][/] Querying boneyard for drift findings…")
    try:
        from core.boneyard import Boneyard
    except Exception as exc:
        console.print(f"[bold red][!][/] boneyard unavailable: {exc}")
        return

    yard = Boneyard()
    result = yard.query_findings(filters={"category": "drift"})
    findings = getattr(result, "records", result if isinstance(result, list) else [])
    if not findings:
        console.print("[dim]No drift events recorded yet.[/]")
        return

    if json_out:
        click.echo(json.dumps(findings, indent=2))
        return

    console.print(f"\n[bold]Recorded drift events ({len(findings)})[/]\n")
    for f in findings:
        rid = f.get("id", "?")
        ts = f.get("timestamp", "?")
        target = f.get("host_id", "?")
        tags = ", ".join(t for t in f.get("tags", []) if t != "drift")
        console.print(f"  [bold cyan]{rid}[/]")
        console.print(f"    Time: {ts}  Host: {target}  "
                      f"Tags: [dim]{tags or '—'}[/]")
        # Truncate long data for terminal
        data = f.get("data", "")
        if isinstance(data, str) and len(data) > 200:
            data = data[:200] + "…"
        console.print(f"    Data: {data}\n")

    if output:
        try:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2, default=str)
            console.print(f"[green][✓][/] Written to {output}")
        except Exception as exc:
            console.print(f"[bold red][!][/] write failed: {exc}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    """Entry point for the thevoid console script."""
    cli(obj={})


if __name__ == "__main__":
    main()
