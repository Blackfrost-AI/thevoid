"""Rich-rendering helpers for the THE VOID CLI (W4).

Keeps cli/app.py focused on command wiring. Everything here is defensive:
a render helper must never raise, and must degrade gracefully when the
console is non-interactive or rich features are unavailable.

W4-2.2a  live phase-by-phase tracker (rich.Live table driven by the
         ShadowAgent phase-listener events)
W4-2.2b  post-engagement prevention-strength panel (real CoverageScorer)
W4-2.3a  unified engagement renderer + first-class gate-verdict panels
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Outcome/verdict styling shared across surfaces.
STATUS_STYLE = {
    "completed": "green",
    "dry_run": "cyan",
    "denied": "red",
    "aborted": "red",
    "error": "red",
}

VERDICT_TITLE = {
    "denied": "[bold red]ENGAGEMENT DENIED — scope gate[/bold red]",
    "aborted": "[bold red]ENGAGEMENT ABORTED — difficulty gate[/bold red]",
    "dry_run": "[bold cyan]DRY RUN — planned, nothing executed[/bold cyan]",
    "error": "[bold red]ENGAGEMENT ERROR[/bold red]",
}

PHASE_MARK = {
    "pending": ("·", "dim"),
    "running": ("→", "yellow"),
    "ok": ("✓", "green"),
    "fail": ("✗", "red"),
}


# ─── Phase tracker (W4-2.2a) ──────────────────────────────────────────────────

class PhaseTracker:
    """rich.Live phase table driven by ShadowAgent phase-listener events.

    Usage::

        tracker = PhaseTracker(console)
        with tracker.live():
            agent.set_phase_listener(tracker.listener())
            result = engine.engage(target, mode)
            agent.set_phase_listener(None)

    The tracker owns its Live object and re-renders on every event. All
    event handling is exception-safe — a render glitch can never abort an
    engagement. A single tracker can serve a multi-target engage loop; it
    re-binds its header on each ``engage_start``.
    """

    def __init__(self, console, target: Optional[str] = None,
                 mode: Optional[str] = None):
        self.console = console
        self.target = target
        self.mode = mode
        self._phases: List[Dict[str, Any]] = []
        self._status = "idle"
        self._live: Optional[Live] = None

    def listener(self) -> Callable[[Dict[str, Any]], None]:
        """The callable ShadowAgent invokes per phase event."""
        return self._on_event

    def live(self):
        """Context manager: start a rich.Live that renders this tracker."""
        self._live = Live(
            self._table(), console=self.console,
            refresh_per_second=10, transient=False,
        )
        return self

    def __enter__(self) -> "PhaseTracker":
        if self._live is not None:
            self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self._live is not None:
                self._live.update(self._table())
                self._live.__exit__(*exc)
        except Exception:  # noqa: BLE001
            pass
        self._live = None

    # ─── internals ────────────────────────────────────────────────────────

    def _on_event(self, ev: Dict[str, Any]) -> None:
        try:
            kind = ev.get("event")
            if kind == "engage_start":
                self.target = ev.get("target", self.target)
                self.mode = ev.get("mode", self.mode)
                self._status = "engaging"
                self._phases = [
                    {"name": p, "state": "pending", "error": None}
                    for p in (ev.get("phases") or [])
                ]
            elif kind == "phase_start":
                self._set(ev.get("phase"), "running")
                return  # _set() already refreshed
            elif kind == "phase_end":
                ok = bool(ev.get("ok", True))
                self._set(ev.get("phase"), "ok" if ok else "fail",
                          error=ev.get("error"))
                return
            elif kind == "engage_end":
                self._status = ev.get("status", "completed")
            self._push()
        except Exception:  # noqa: BLE001
            pass

    def _set(self, phase: Optional[str], state: str,
             error: Optional[str] = None) -> None:
        if phase is None:
            return
        for row in self._phases:
            if row["name"] == phase:
                row["state"] = state
                if error:
                    row["error"] = str(error)[:80]
                break
        self._push()

    def _push(self) -> None:
        try:
            if self._live is not None:
                self._live.update(self._table())
        except Exception:  # noqa: BLE001
            pass

    def _table(self) -> Table:
        header = Text.from_markup(
            f"[bold red]THE VOID[/bold red] — {self.target or 'target'}"
            + (f"  [dim]mode={self.mode}[/dim]" if self.mode else "")
        )
        table = Table(title=header, show_header=True, header_style="bold",
                      border_style="red")
        table.add_column("Phase", style="cyan", min_width=18)
        table.add_column("Status", justify="center", width=8)
        table.add_column("Detail", style="dim", max_width=44)
        if not self._phases:
            table.add_row("[dim]awaiting phases…[/dim]", "", "")
        for row in self._phases:
            mark, style = PHASE_MARK.get(row["state"], PHASE_MARK["pending"])
            table.add_row(
                row["name"],
                f"[{style}]{mark}[/{style}]",
                row.get("error") or "",
            )
        table.caption = Text.from_markup(f"[dim]{self._status}[/dim]")
        return table


# ─── Gate-verdict panels (W4-2.3a) ───────────────────────────────────────────

def render_gate_verdict(console, result: Dict[str, Any]) -> bool:
    """Render a denied/aborted/dry_run/error result as a first-class panel.

    The governance story is the point: an aborted or denied engagement is a
    *feature*, surfaced prominently rather than buried in a dim one-liner.
    Returns True if a verdict panel was rendered.
    """
    status = result.get("status", "")
    if status not in VERDICT_TITLE:
        return False

    lines = [f"[bold]Target:[/] {result.get('target', '?')}",
             f"[bold]Mode:[/]   {result.get('mode', '?')}"]
    reason = result.get("reason")
    if reason:
        lines.append(f"[bold]Reason:[/] {reason}")

    authz = result.get("authorization")
    if isinstance(authz, dict) and authz:
        allowed = authz.get("allowed", "?")
        a_reason = authz.get("reason") or ""
        lines.append(f"[dim]Authorization gate: allowed={allowed}"
                     f"{f' — {a_reason}' if a_reason else ''}[/dim]")

    diff = result.get("difficulty")
    if isinstance(diff, dict) and diff:
        score = diff.get("score")
        verdict = diff.get("verdict") or diff.get("mode")
        rationale = diff.get("rationale") or ""
        lines.append(f"[dim]Difficulty gate: score={score} verdict={verdict}"
                     f"{f' — {rationale}' if rationale else ''}[/dim]")

    planned = result.get("planned_phases")
    if planned:
        lines.append(f"[dim]Planned phases: {', '.join(map(str, planned))}[/dim]")

    console.print(Panel("\n".join(lines), title=VERDICT_TITLE[status],
                        border_style="red"))
    return True


# ─── Prevention-strength panel (W4-2.2b) ────────────────────────────────────

def render_prevention_summary(console, results: List[Dict[str, Any]],
                              title: str = "Prevention Strength") -> None:
    """Score the engagement(s) with the REAL CoverageScorer and render a panel.

    Reuses modules.coverage.CoverageScorer (identical code path to
    /api/coverage). Only ``completed`` engagements are scored; other
    statuses are skipped (they render via gate-verdict panels instead).
    Never raises.
    """
    try:
        from modules.coverage import CoverageScorer
    except Exception:
        return

    completed = [r for r in results
                 if isinstance(r, dict) and r.get("status") == "completed"]
    if not completed:
        console.print("[dim]No completed engagements to score.[/]")
        return

    try:
        scores = CoverageScorer().score_all(completed)
    except Exception:
        console.print("[dim]Prevention scoring unavailable.[/]")
        return

    aggregated = scores.get("aggregated")
    count = scores.get("count", 0)
    header = (
        f"[bold]Engagements scored:[/]       {count}\n"
        f"[bold]Aggregated prevention score:[/] "
        f"[bold red]{aggregated}[/bold red] / 100\n\n"
        f"[dim]Computed by modules.coverage.CoverageScorer — the same code\n"
        f"path served at /api/coverage in the Command Center.[/dim]"
    )
    console.print(Panel(header, title=f"[bold red]{title}[/bold red]",
                        border_style="red"))

    per = scores.get("engagement_scores") or []
    if per:
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Target", style="cyan")
        table.add_column("Mode")
        table.add_column("Score", justify="right")
        table.add_column("Verdict breakdown", style="dim")
        for e in per:
            vc = e.get("verdict_counts") or {}
            breakdown = " ".join(
                f"{cls}×{n}" for cls in
                ("verified", "exploited", "reachability", "unknown")
                for n in [vc.get(cls, 0)] if n
            ) or "—"
            score = e.get("score")
            table.add_row(
                str(e.get("target", "?")),
                str(e.get("mode", "?")),
                f"{score}" if isinstance(score, (int, float)) else "—",
                breakdown,
            )
        console.print(table)
