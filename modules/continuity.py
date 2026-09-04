"""Continuity scheduler for THE VOID (roadmap R-3).

Runs ShadowAgent engagements on a recurring interval (default: daily)
without third-party cron libraries. Own-rolled ``threading.Event`` loop
— stopping is an explicit ``stop()`` call, honouring the platform's
zero-telemetry guarantee (no external HTTP timers, no hidden OS-level
cron writes).

Architecture notes
------------------
- ``ContinuityScheduler`` owns a background ``threading.Thread``.
  The thread block-waits on a ``threading.Event`` for the configured
  interval; ``stop()`` signals the event, the loop sees it and exits.
- Every completed engagement is compared against the previous run for
  the same target to detect **drift** — a change in verdict class at
  any phase means the security posture shifted between runs.
- Drift events are persisted as specially-named findings in the
  boneyard (``category=="drift"``) so they survive encryption-at-rest
  and appear in the operator's normal report alongside real findings.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from modules.coverage import CoverageScorer, _PHASE_EVIDENCE

logger = logging.getLogger("void.modules.continuity")

# How long to wait between full engagement runs (seconds).
DEFAULT_INTERVAL_SECONDS = 86_400  # 24 hours


class ContinuityScheduler:
    """Recurring engagement runner with drift detection.

    Parameters
    ----------
    shadow_agent : ShadowAgent
        The agent to drive. Must expose ``.engage()`` and ``.warlog``
        attributes.
    targets : list[str]
        One engagement target per entry. Runs sequentially.
    mode : str
        ShadowAgent mode string passed to ``.engage()``.
    interval_seconds : int
        Polling interval between full engagement runs.
    max_runs : int | None
        Safety stop after this many runs (``None`` = run until ``stop()``
        or ``KeyboardInterrupt``).
    warlog : AuditWarLog, optional
        If provided, drift events are also mirrored there.
    boneyard : BoneYard, optional
        If provided, drift events are written as findings.
    """

    def __init__(
        self,
        shadow_agent,
        targets: List[str],
        mode: str = "quick",
        interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
        max_runs: Optional[int] = None,
        warlog=None,
        boneyard=None,
    ) -> None:
        self._agent = shadow_agent
        self._targets = list(targets)
        self._mode = mode
        self._interval = max(int(interval_seconds), 3600)  # min 1 hour
        self._max_runs = max_runs
        self._warlog = warlog
        self._boneyard = boneyard
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # per-target snapshot of the previous run's verdict class per phase
        self._previous: Dict[str, Dict[str, str]] = {}
        self._run_count = 0
        self._scorer = CoverageScorer()

    # ─── Lifecycle ────────────────────────────────────────────────────
    def start(self) -> None:
        """Start the scheduler thread. Returns immediately."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Continuity scheduler already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="void-continuity",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Continuity scheduler started: targets=%s mode=%s interval=%ds",
            self._targets, self._mode, self._interval,
        )

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the scheduler to stop and wait for the thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("Continuity scheduler stopped after %d runs", self._run_count)

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ─── Main loop ────────────────────────────────────────────────────
    def _loop(self) -> None:
        while not self._stop_event.is_set():
            for target in self._targets:
                if self._stop_event.is_set():
                    break
                try:
                    self._run_one(target)
                except Exception:
                    logger.exception(
                        "Continuity run failed for target=%r", target
                    )
            self._run_count += 1
            if self._max_runs is not None and self._run_count >= self._max_runs:
                break
            # Block-wait; wake up on stop_event OR interval expiry.
            self._stop_event.wait(self._interval)

    # ─── Engagement + drift detection ──────────────────────────────────
    def _run_one(self, target: str) -> None:
        logger.debug("Continuity: engaging target=%r", target)
        result = self._agent.engage(target, self._mode)
        ts = datetime.now(timezone.utc).isoformat()

        finding = {
            "timestamp": ts,
            "target": target,
            "mode": self._mode,
            "status": result.get("status", "unknown"),
            "score": (self._scorer.score_engagement(result).get("score")
                      if isinstance(result, dict) else 0.0),
            "elapsed_seconds": result.get("elapsed_seconds", 0.0),
            "errors": result.get("errors", []),
        }

        # ─── Drift detection ─────────────────────────────────────────
        drift = self._detect_drift(target, result, ts)
        if drift:
            self._persist_drift(target, drift, ts)
        # Snapshot AFTER drift detection so the NEXT run compares
        # against this run (not the previous one).
        self._update_snapshot(target, result)

        logger.info(
            "Continuity: target=%r status=%s score=%s drift=%s",
            target, result.get("status"), finding["score"],
            "YES" if drift else "no",
        )
        return finding

    def _detect_drift(
        self,
        target: str,
        result: Dict[str, Any],
        ts: str,
    ) -> Optional[Dict[str, Any]]:
        """Compare this run's verdict classes against the previous run."""
        if target not in self._previous:
            return None  # first run for this target — nothing to compare against

        findings = result.get("findings", {})
        if not isinstance(findings, dict):
            return None

        prev = self._previous[target]  # phase → verdict_class
        current: Dict[str, str] = {}
        for phase in findings:
            coverage, _ = _PHASE_EVIDENCE.get(phase, ("unknown", "passive"))
            current[phase] = coverage

        drift_rows: List[Dict[str, Any]] = []
        for phase, old in prev.items():
            new = current.get(phase, "unknown")
            if old != new:
                drift_rows.append({
                    "phase": phase,
                    "was": old,
                    "now": new,
                })

        # Also flag phases present now that were absent previously
        for phase in current:
            if phase not in prev:
                drift_rows.append({
                    "phase": phase,
                    "was": "absent",
                    "now": current[phase],
                })

        return {"phases": drift_rows} if drift_rows else None

    def _update_snapshot(self, target: str, result: Dict[str, Any]) -> None:
        findings = result.get("findings", {})
        self._previous[target] = {
            phase: _PHASE_EVIDENCE.get(phase, ("unknown", "passive"))[0]
            for phase in (findings if isinstance(findings, dict) else {})
        }

    def _persist_drift(
        self,
        target: str,
        drift: Dict[str, Any],
        ts: str,
    ) -> None:
        """Write drift events to warlog + boneyard, never block on errors.

        Uses the real engine signatures (W1 fix — previously this called
        ``boneyard.put()`` (nonexistent) and ``warlog.log()`` with kwargs
        that don't exist, so drift events were silently dropped).
        """
        from core.warlog import LogLevel

        msg = (
            f"Continuity drift: target={target} "
            f"phases={json.dumps(drift['phases'], default=str)}"
        )
        # WarLog — real signature: log(message, level, module, target, data).
        # NB: truthiness-test is unsafe — WarLog.__len__ returns entry count,
        # so an empty warlog is falsy. Use explicit None-check.
        if self._warlog is not None:
            try:
                self._warlog.log(
                    msg,
                    level=LogLevel.WARNING,
                    module="continuity",
                    target=target,
                    data={"ts": ts, **drift},
                )
            except Exception:
                logger.exception("continuity: warlog write failed")

        # Boneyard — real legacy signature: store(category, data, tags).
        # ShadowAgent persists engagements as store(f"attack_<t>_<ts>", payload);
        # drift is stored under the fixed category "drift" so /api/drift can
        # query it directly (search(category="drift")).
        # NB: same falsy-store trap — Boneyard.__len__ counts rows.
        if self._boneyard is not None:
            try:
                self._boneyard.store(
                    "drift",
                    {"kind": "drift", "target": target, "ts": ts, **drift},
                    tags=["continuity", "drift"],
                )
            except Exception:
                logger.exception("continuity: boneyard write failed")

        logger.warning("Continuity drift detected for %s: %s", target, drift)


# ─── Convenience factory ────────────────────────────────────────────────
def create_scheduler(
    shadow_agent,
    targets: List[str],
    mode: str = "quick",
    interval_hours: int = 24,
    **kwargs: Any,
) -> ContinuityScheduler:
    """Instantiate a ContinuityScheduler. ``interval_hours`` is more
    convenient than raw seconds for operators."""
    return ContinuityScheduler(
        shadow_agent=shadow_agent,
        targets=targets,
        mode=mode,
        interval_seconds=int(interval_hours * 3600),
        **kwargs,
    )
