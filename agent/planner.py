"""THE VOID — Agentic phase planner over the Boneyard attack-graph.

The planner turns observed attack-path evidence into an ordered plan of
phase invocations, and keeps every step inside hard structural limits:

* **Grounded in evidence.** Each planned step cites the Boneyard attack
  step it descends from (step id, host, step_type, technique) and the
  phase it proposes. Nothing is planned from model imagination alone —
  if the graph has no attack steps, the plan is empty.
* **Bounded.** ``max_steps`` caps plan length; ``max_branches`` caps
  alternatives retained per step; ``time_box_seconds`` caps total planned
  duration (phase risk times are the estimates). Hard limits are applied
  by code — the LLM cannot exceed them.
* **Operator-gated.** Every plan is Sentinel-reviewed and handed to an
  operator approval callback before it can be executed. Without an explicit
  approval, ``plan()`` returns the plan with ``approved=False`` and
  ``execute()`` refuses to run. Denied steps are dropped (fail closed);
  ambiguous approvals are refusals.

The LLM (FrostyBrain) proposes phase mappings for graph steps and ranks
alternatives; the structure — limits, ordering, evidence citation, gating —
is deterministic code. If the LLM is unavailable or returns garbage, the
planner degrades to a deterministic fallback mapper and says so in the
plan's provenance.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from agent.phase_registry import PhaseRegistry
from agent.sentinel import (
    Provenance,
    Sentinel,
    VERDICT_ALLOW,
    normalize_risk,
)
from core.boneyard import Boneyard
from core.warlog import LogLevel, WarLog

logger = logging.getLogger("void.agent.planner")

MODULE = "agent.planner"

# ─── Hard limits (defaults; overridable per instance, floored by code) ──────

DEFAULT_MAX_STEPS = 8
DEFAULT_MAX_BRANCHES = 3
DEFAULT_TIME_BOX_SECONDS = 3600.0
HARD_MAX_STEPS = 32        # absolute ceiling regardless of caller values
HARD_MAX_BRANCHES = 8
HARD_TIME_BOX_SECONDS = 24 * 3600.0

# ─── Deterministic fallback phase mapping (graph step_type -> phases) ───────

_FALLBACK_PHASES: Dict[str, Tuple[str, ...]] = {
    "initial_access": ("recon", "cve_exploit", "mcp_scan"),
    "recon": ("recon", "mcp_scan"),
    "privesc": ("cve_exploit", "exploit"),
    "lateral": ("exploit", "c2"),
    "persist": ("c2", "persistent_exfil"),
    "exfil": ("data_theft", "persistent_exfil"),
    "c2": ("c2",),
}

_STEP_TYPES = tuple(_FALLBACK_PHASES.keys())

# Map phase risk to estimated seconds for time-box calculations.
# Unknown/CRITICAL risk is treated as worst case (3600s) so an unmapped
# value exhausts the box instead of slipping through unmeasured.
_PHASE_SECONDS: Dict[str, float] = {
    "low": 60.0,
    "medium": 300.0,
    "high": 900.0,
    "critical": 3600.0,
}


def _phase_seconds(risk: str) -> float:
    return _PHASE_SECONDS.get(risk, 3600.0)


class PlanLimitExceeded(Exception):
    """Raised when the caller requests limits beyond the hard ceilings."""


class PlanNotApproved(Exception):
    """Raised when execute() is called on a plan the operator did not approve."""


@dataclass
class PlanStep:
    """One proposed phase invocation, grounded in attack-graph evidence."""

    step_id: str
    phase: str
    target: str
    risk: str
    reason: str
    graph_step_id: str
    graph_step_type: str
    technique: str
    host_id: str
    estimated_seconds: float
    source: str = "planner"
    source_confidence: float = 1.0
    alternatives: List[str] = field(default_factory=list)
    approved: Optional[bool] = None
    provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "phase": self.phase,
            "target": self.target,
            "risk": self.risk,
            "reason": self.reason,
            "graph_step_id": self.graph_step_id,
            "graph_step_type": self.graph_step_type,
            "technique": self.technique,
            "host_id": self.host_id,
            "estimated_seconds": self.estimated_seconds,
            "source": self.source,
            "source_confidence": self.source_confidence,
            "alternatives": list(self.alternatives),
            "approved": self.approved,
            "provenance": self.provenance,
        }


@dataclass
class Plan:
    """An ordered, bounded, operator-gated plan of phase invocations."""

    plan_id: str
    target: str
    mode: str
    steps: List[PlanStep]
    dropped: List[Dict[str, Any]]
    limits: Dict[str, Any]
    approved: bool = False
    approval_note: str = ""
    created_at: float = field(default_factory=time.time)
    estimated_seconds: float = 0.0
    time_box_exhausted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "mode": self.mode,
            "steps": [s.to_dict() for s in self.steps],
            "dropped": list(self.dropped),
            "limits": dict(self.limits),
            "approved": self.approved,
            "approval_note": self.approval_note,
            "created_at": self.created_at,
            "estimated_seconds": self.estimated_seconds,
            "time_box_exhausted": self.time_box_exhausted,
        }


class PhasePlanner:
    """Agentic phase planner over the Boneyard attack-graph.

    Args:
        boneyard: evidence store providing ``graph_attack_paths()``.
        registry: PhaseRegistry providing ``phases``, ``spec(name)`` and
            ``resolve(name)`` (dispatch bound to a ShadowAgent).
        sentinel: agent.sentinel.Sentinel for ROE + dual-LLM review of each
            proposed step. Missing sentinel fails closed (no step survives).
        brain: llm.frosty_brain.FrostyBrain used to propose phase mappings
            and rank alternatives. Optional — falls back to the deterministic
            mapper.
        agent: ShadowAgent (or compatible) whose phase runners execute plan
            steps. Required for :meth:`execute`; missing agent fails closed.
        warlog: WarLog evidence store.
        max_steps / max_branches / time_box_seconds: planning limits
            (floored to the HARD_* ceilings; raises if the caller asks
            for more than the ceiling).
    """

    def __init__(
        self,
        boneyard: Boneyard,
        registry: PhaseRegistry,
        sentinel: Optional[Sentinel] = None,
        brain: Any = None,
        agent: Any = None,
        warlog: Optional[WarLog] = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        max_branches: int = DEFAULT_MAX_BRANCHES,
        time_box_seconds: float = DEFAULT_TIME_BOX_SECONDS,
    ):
        if max_steps < 1 or max_steps > HARD_MAX_STEPS:
            raise PlanLimitExceeded(
                f"max_steps must be 1..{HARD_MAX_STEPS}, got {max_steps}"
            )
        if max_branches < 1 or max_branches > HARD_MAX_BRANCHES:
            raise PlanLimitExceeded(
                f"max_branches must be 1..{HARD_MAX_BRANCHES}, got {max_branches}"
            )
        if time_box_seconds <= 0 or time_box_seconds > HARD_TIME_BOX_SECONDS:
            raise PlanLimitExceeded(
                f"time_box_seconds must be in (0, {HARD_TIME_BOX_SECONDS}], "
                f"got {time_box_seconds}"
            )

        self.boneyard = boneyard
        self.registry = registry
        self.sentinel = sentinel
        self.brain = brain
        self.agent = agent
        self.warlog = warlog if warlog is not None else WarLog()
        self.max_steps = int(max_steps)
        self.max_branches = int(max_branches)
        self.time_box_seconds = float(time_box_seconds)

    # ─── Public API ──────────────────────────────────────────────────────────

    def plan(
        self,
        target: str,
        mode: str = "full",
        goal: str = "",
    ) -> Plan:
        """Build a bounded plan for ``target`` and return it unapproved.

        The plan is Sentinel-reviewed step by step (fail closed), then left
        for the operator: ``approved`` is always False here. Call
        :meth:`request_approval` (or pass the plan to an operator gate) to
        approve; only then may :meth:`execute` run.
        """
        plan_id = str(uuid.uuid4())
        graph = self._load_graph()
        candidates = self._extract_candidates(graph, target)

        steps: List[PlanStep] = []
        dropped: List[Dict[str, Any]] = []
        used_seconds = 0.0
        time_box_exhausted = False

        for candidate in candidates:
            # ── hard limit: plan length ────────────────────────────────
            if len(steps) >= self.max_steps:
                dropped.append({**candidate, "reason": "max_steps limit reached"})
                continue

            # ── hard limit: time box ───────────────────────────────────
            estimated = _phase_seconds(candidate["risk"])
            if used_seconds + estimated > self.time_box_seconds:
                time_box_exhausted = True
                dropped.append({**candidate, "reason": "time_box exhausted"})
                continue

            # ── Sentinel review (ROE + dual LLM), fail closed ──────────
            review = self._review(candidate, target, mode)
            if review is None or review.verdict != VERDICT_ALLOW:
                reason = "no sentinel configured (fail closed)" if review is None else review.reason
                dropped.append({**candidate, "reason": f"sentinel denied: {reason}"})
                continue

            step = PlanStep(
                step_id=str(uuid.uuid4()),
                phase=candidate["phase"],
                target=target,
                risk=candidate["risk"],
                reason=candidate["reason"],
                graph_step_id=candidate["graph_step_id"],
                graph_step_type=candidate["graph_step_type"],
                technique=candidate["technique"],
                host_id=candidate["host_id"],
                estimated_seconds=estimated,
                source=candidate["source"],
                source_confidence=candidate["source_confidence"],
                alternatives=candidate["alternatives"],
                approved=None,
                provenance=review.tag(),
            )
            steps.append(step)
            used_seconds += estimated

        plan = Plan(
            plan_id=plan_id,
            target=target,
            mode=mode,
            steps=steps,
            dropped=dropped,
            limits={
                "max_steps": self.max_steps,
                "max_branches": self.max_branches,
                "time_box_seconds": self.time_box_seconds,
            },
            approved=False,
            approval_note="awaiting operator approval",
            estimated_seconds=used_seconds,
            time_box_exhausted=time_box_exhausted,
        )
        self._evidence(
            "planner.plan_created",
            LogLevel.AGENT,
            target=target,
            data={
                "plan_id": plan_id,
                "mode": mode,
                "steps": len(steps),
                "dropped": len(dropped),
                "estimated_seconds": used_seconds,
                "time_box_exhausted": time_box_exhausted,
                "graph_candidates": len(candidates),
            },
        )
        return plan

    def request_approval(
        self,
        plan: Plan,
        approver: Callable[[Plan], Optional[bool]],
    ) -> Plan:
        """Hand the plan to an operator approval callback and gate it.

        The callback returns True (approve), False (deny), or None (ambiguous
        = denial). Only a clear True sets ``plan.approved``. Every outcome is
        WarLog-evidenced.
        """
        try:
            decision = approver(plan)
        except Exception as exc:
            logger.exception("operator approval callback raised")
            decision = None
            note = f"approval callback error: {exc}"
        else:
            if decision is True:
                note = "operator approved"
            elif decision is False:
                note = "operator denied"
            else:
                note = "operator decision ambiguous (treated as denial)"
                decision = None

        plan.approved = decision is True
        plan.approval_note = note
        self._evidence(
            "planner.approval",
            LogLevel.AGENT if plan.approved else LogLevel.ERROR,
            target=plan.target,
            data={"plan_id": plan.plan_id, "approved": plan.approved, "note": note},
        )
        return plan

    def execute(
        self,
        plan: Plan,
        ctx: Optional[Dict[str, Any]] = None,
        agent: Any = None,
    ) -> List[Dict[str, Any]]:
        """Execute an approved plan's steps in order. Refuses unapproved plans.

        Each step dispatches through ``registry.resolve(phase)(agent, target,
        mode, ctx)``. Failures are recorded and stop the plan (fail closed) —
        a failing step must not cascade into later phases.
        """
        if not plan.approved:
            raise PlanNotApproved(
                f"plan {plan.plan_id} is not approved "
                f"({plan.approval_note or 'no operator approval recorded'})"
            )

        runner_agent = agent if agent is not None else self.agent
        if runner_agent is None:
            raise PlanNotApproved(
                "no agent configured for plan execution (fail closed)"
            )

        context: Dict[str, Any] = dict(ctx or {})
        results: List[Dict[str, Any]] = []
        for step in plan.steps:
            try:
                self.registry.spec(step.phase)  # KeyError on unknown phase
            except KeyError:
                results.append({"step_id": step.step_id, "phase": step.phase,
                                "status": "error", "error": "unknown phase"})
                self._evidence("planner.step_error", LogLevel.ERROR, target=plan.target,
                               data={"plan_id": plan.plan_id, "phase": step.phase,
                                     "error": "unknown phase"})
                break
            try:
                runner = self.registry.resolve(step.phase)
                result = runner(runner_agent, plan.target, plan.mode, context)
                results.append({"step_id": step.step_id, "phase": step.phase,
                                "status": "ok", "result": result})
                self._evidence("planner.step_executed", LogLevel.AGENT, target=plan.target,
                               data={"plan_id": plan.plan_id, "phase": step.phase,
                                     "risk": step.risk})
            except Exception as exc:
                results.append({"step_id": step.step_id, "phase": step.phase,
                                "status": "error", "error": str(exc)[:300]})
                self._evidence("planner.step_error", LogLevel.ERROR, target=plan.target,
                               data={"plan_id": plan.plan_id, "phase": step.phase,
                                     "error": str(exc)[:300]})
                break  # fail closed: stop the plan on first error

        self._evidence(
            "planner.plan_executed",
            LogLevel.AGENT,
            target=plan.target,
            data={"plan_id": plan.plan_id, "steps_run": len(results),
                  "errors": sum(1 for r in results if r["status"] != "ok")},
        )
        return results

    # ─── Graph → candidates ──────────────────────────────────────────────────

    def _load_graph(self) -> Dict[str, Any]:
        try:
            graph = self.boneyard.graph_attack_paths()
        except Exception as exc:
            logger.exception("graph_attack_paths failed")
            return {"nodes": [], "edges": [], "outcomes": [], "error": str(exc)}
        return graph if isinstance(graph, dict) else {"nodes": [], "edges": [], "outcomes": []}

    def _extract_candidates(self, graph: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
        """Turn graph nodes into bounded planning candidates (evidence-first)."""
        nodes = graph.get("nodes", []) or []
        step_nodes = [n for n in nodes if isinstance(n, dict) and n.get("step_type")]
        # Oldest evidence first: initial access before later steps.
        step_nodes.sort(key=lambda n: str(n.get("created_at", "")))

        candidates: List[Dict[str, Any]] = []
        for node in step_nodes:
            step_type = str(node.get("step_type", ""))
            phases, source, confidence = self._propose_phases(node, step_type, target)
            phases = phases[: self.max_branches]
            if not phases:
                continue
            candidates.append({
                "phase": phases[0],
                "alternatives": phases[1:],
                "risk": normalize_risk(None, phases[0]),
                "reason": (
                    f"graph step {node.get('id', '?')} "
                    f"({step_type or 'unknown'}"
                    f"{', ' + node.get('technique', '') if node.get('technique') else ''}) "
                    f"on host {node.get('host_id', '?')}"
                ),
                "graph_step_id": str(node.get("id", "")),
                "graph_step_type": step_type,
                "technique": str(node.get("technique", "")),
                "host_id": str(node.get("host_id", "")),
                "source": source,
                "source_confidence": confidence,
            })
        return candidates

    def _propose_phases(self, node: Dict[str, Any], step_type: str, target: str) -> Tuple[List[str], str, float]:
        """LLM-backed phase proposal with deterministic fallback.

        Returns (phases, source, confidence). The LLM only ever proposes from
        the registry's known phases and the graph's known step types; anything
        else degrades to the fallback mapper.
        """
        known_phases = tuple(self.registry.phases)
        if self.brain is None:
            return list(_FALLBACK_PHASES.get(step_type, ("recon",))), "fallback", 1.0

        prompt = {
            "goal": "map one attack-graph step to follow-on phases",
            "graph_step": {
                "step_type": step_type,
                "technique": node.get("technique", ""),
                "status": node.get("outcome_status",
                                   node.get("status", node.get("step_status", ""))),
                "host_id": node.get("host_id", ""),
            },
            "known_phases": list(known_phases),
            "known_step_types": list(_STEP_TYPES),
            "constraints": {
                "max_branches": self.max_branches,
                "respond": "JSON list of phase names, ordered most-likely-first",
            },
        }
        try:
            response = self.brain.chat(
                [
                    {"role": "system", "content": (
                        "You map a single penetration-testing attack-graph step "
                        "to follow-on phases. Respond with a JSON list of phase "
                        "names chosen ONLY from the provided known_phases, "
                        "ordered most-likely-first. No prose."
                    )},
                    {"role": "user", "content": json.dumps(prompt, sort_keys=True)},
                ],
                temperature=0.0,
                max_tokens=128,
                purpose="planner-phase-mapping",
                target=target,
            )
        except Exception as exc:
            logger.warning("planner brain call failed, using fallback: %s", exc)
            return list(_FALLBACK_PHASES.get(step_type, ("recon",))), "fallback", 1.0

        phases = self._parse_phase_list(getattr(response, "text", "") or "", known_phases)
        if not phases:
            return list(_FALLBACK_PHASES.get(step_type, ("recon",))), "fallback", 1.0
        return phases, "llm", 0.9

    @staticmethod
    def _parse_phase_list(text: str, known_phases: Tuple[str, ...]) -> List[str]:
        """Parse a JSON list of phase names; keep only known phases, in order."""
        match = re.search(r"\[.*?\]", text, re.DOTALL)
        if not match:
            return []
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        known = set(known_phases)
        out: List[str] = []
        for item in data:
            name = str(item).strip().lower()
            if name in known and name not in out:
                out.append(name)
        return out

    def _review(self, candidate: Dict[str, Any], target: str, mode: str) -> Optional[Provenance]:
        if self.sentinel is None:
            return None
        return self.sentinel.review({
            "target": target,
            "phase": candidate["phase"],
            "mode": mode,
            "risk": candidate["risk"],
            "description": candidate["reason"],
            "source": candidate["source"],
            "source_confidence": candidate["source_confidence"],
        })

    def _evidence(self, message: str, level: LogLevel, target: str,
                  data: Optional[Dict[str, Any]] = None) -> None:
        try:
            self.warlog.log(message, level=level, module=MODULE, target=target, data=data)
        except Exception:
            logger.exception("WarLog write failed for planner event %s", message)


__all__ = [
    "DEFAULT_MAX_BRANCHES",
    "DEFAULT_MAX_STEPS",
    "DEFAULT_TIME_BOX_SECONDS",
    "HARD_MAX_BRANCHES",
    "HARD_MAX_STEPS",
    "HARD_TIME_BOX_SECONDS",
    "MODULE",
    "PhasePlanner",
    "Plan",
    "PlanLimitExceeded",
    "PlanNotApproved",
    "PlanStep",
]
