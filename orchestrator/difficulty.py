"""THE VOID — Difficulty Assessor (P1.2).

Assesses the difficulty/risk of an engagement action before committing to it,
producing a 4-axis score and a recommended mode (explore / exploit / abort).

Axes (each 0.0–1.0, higher = harder):
  horizon       — steps-to-evidence for this action (how far the agent must see)
  confidence    — quality/quantity of prior evidence about the target
  context_load  — token budget pressure this action creates
  history       — success rate on similar past actions (from boneyard feedback)

The composite score is a weighted sum; the mode is derived from thresholds:

    score < 0.40  → exploit   (we know enough; execute the attack)
    0.40 ≤ s < 0.70 → explore (gather more info before committing)
    score ≥ 0.70  → abort     (too hard/risky; skip or escalate)

Used by ChaosEngine (P1.2.3) as an advisory gate before each engagement,
and persists assessments to the boneyard (P1.2.4) so future assessments can
calibrate from observed outcomes.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("void.orchestrator.difficulty")

# ─── Constants ──────────────────────────────────────────────────────────────

EXPLOIT_THRESHOLD = 0.40   # score < this → exploit
ABORT_THRESHOLD = 0.70     # score >= this → abort
# between the two → explore

DEFAULT_WEIGHTS: Dict[str, float] = {
    'horizon': 0.35,
    'history': 0.30,
    'confidence': 0.20,
    'context_load': 0.15,
}

# Cap for past-assessment sample when computing history success rate. Below this
# count we apply an uncertainty discount (lack of calibration data = harder).
HISTORY_MIN_SAMPLES = 5


# ─── Data Types ─────────────────────────────────────────────────────────────

@dataclass
class Action:
    """An engagement action to be assessed."""

    name: str
    phase: str = ""
    estimated_steps: int = 1
    technique: str = ""
    target: str = ""
    expected_output_tokens: int = 1000


@dataclass
class Context:
    """Engagement context at the time of assessment."""

    findings_count: int = 0
    recon_depth: float = 0.0           # 0.0 (none) – 1.0 (thorough)
    known_vulns: int = 0
    known_creds: int = 0
    token_budget_remaining: int = 100_000
    token_budget_total: int = 100_000
    target_familiarity: float = 0.0    # 0.0 (unknown) – 1.0 (well-known)
    engagement_phase: int = 1


@dataclass
class DifficultyReport:
    """Result of a difficulty assessment."""

    action: Action
    axes: Dict[str, float]                    # horizon, confidence, context_load, history
    weights: Dict[str, float]
    score: float                              # composite 0.0–1.0
    mode: str                                 # explore | exploit | abort
    rationale: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Set by assess_and_store() / callers after persisting to boneyard.
    # None means the assessment has not been persisted yet.
    assessment_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict (for warlog/json consumers)."""
        return {
            'action': self.action.name,
            'phase': self.action.phase,
            'technique': self.action.technique,
            'target': self.action.target,
            'axes': dict(self.axes),
            'weights': dict(self.weights),
            'score': self.score,
            'mode': self.mode,
            'rationale': self.rationale,
            'timestamp': self.timestamp,
            'assessment_id': self.assessment_id,
        }


# ─── Assessor ───────────────────────────────────────────────────────────────

class DifficultyAssessor:
    """Assesses action difficulty and recommends an engagement mode.

    Optionally wired to a Boneyard instance so it can (a) persist assessments
    and (b) read past outcomes to calibrate the history axis.
    """

    def __init__(self, boneyard: Any = None,
                 weights: Optional[Dict[str, float]] = None,
                 exploit_threshold: float = EXPLOIT_THRESHOLD,
                 abort_threshold: float = ABORT_THRESHOLD) -> None:
        self.boneyard = boneyard
        self.weights = dict(weights) if weights else dict(DEFAULT_WEIGHTS)
        self.exploit_threshold = exploit_threshold
        self.abort_threshold = abort_threshold
        # Normalize weights to sum to 1.0 (defensive; keeps score in [0,1])
        total = sum(self.weights.values())
        if total > 0 and not math.isclose(total, 1.0, abs_tol=1e-9):
            self.weights = {k: v / total for k, v in self.weights.items()}
        logger.debug(
            "DifficultyAssessor init weights=%s thresholds=(exploit<%.2f, abort>=%.2f)",
            self.weights, self.exploit_threshold, self.abort_threshold,
        )

    # ─── Public API ───────────────────────────────────────────────────────

    def assess(self, action: Action, context: Optional[Context] = None,
               history: Optional[List[Dict[str, Any]]] = None) -> DifficultyReport:
        """Assess the difficulty of an action.

        Args:
            action: The action to assess.
            context: Current engagement context. Defaults to an empty Context.
            history: Optional list of past-assessment dicts (as produced by
                     Boneyard.query_difficulty). If None and a boneyard is
                     attached, the assessor queries it automatically.

        Returns:
            A DifficultyReport with axes, composite score, mode, and rationale.
        """
        context = context or Context()

        axes = {
            'horizon': self._score_horizon(action, context),
            'confidence': self._score_confidence(action, context),
            'context_load': self._score_context_load(action, context),
            'history': self._score_history(action, history),
        }

        score = self._composite(axes)
        mode = self._mode_for(score)
        rationale = self._explain(action, context, axes, score, mode)

        report = DifficultyReport(
            action=action,
            axes=axes,
            weights=dict(self.weights),
            score=score,
            mode=mode,
            rationale=rationale,
        )
        logger.info(
            "Assessed '%s' score=%.3f mode=%s (h=%.2f c=%.2f l=%.2f H=%.2f)",
            action.name, score, mode,
            axes['horizon'], axes['confidence'], axes['context_load'], axes['history'],
        )
        return report

    def assess_and_store(self, action: Action,
                         context: Optional[Context] = None,
                         history: Optional[List[Dict[str, Any]]] = None
                         ) -> DifficultyReport:
        """Assess and, if a boneyard is attached, persist the report.

        Returns the report regardless. On store failure, logs and continues
        (assessment is advisory; persistence is best-effort).
        """
        report = self.assess(action, context, history)
        if self.boneyard is not None:
            try:
                report.assessment_id = self.boneyard.store_difficulty(report)  # type: ignore[attr-defined]
            except Exception as e:  # noqa: BLE001 — persistence is best-effort
                logger.warning("store_difficulty failed (non-fatal): %s", e)
        return report

    # ─── Axis Scorers ─────────────────────────────────────────────────────

    def _score_horizon(self, action: Action, context: Context) -> float:
        """Steps-to-evidence: more steps → harder.

        Uses a sub-linear curve so the marginal hardness of each additional
        step diminishes (10 steps isn't 10x harder than 1 step).
        """
        steps = max(1, action.estimated_steps)
        # 1 - exp(-k*(steps-1)) gives a smooth 0→1 curve with diminishing return
        # k=0.18 → 1 step ≈ 0.0, 5 steps ≈ 0.51, 10 steps ≈ 0.82, 20 steps ≈ 0.97
        raw = 1.0 - math.exp(-0.18 * (steps - 1))

        # Late-phase actions (post-exploit, exfil) have a longer implicit horizon
        # because the evidence chain is deeper. Boost slightly for later phases.
        phase_boost = max(0.0, min(0.15, (context.engagement_phase - 1) * 0.05))
        score = min(1.0, raw + phase_boost)
        return round(score, 4)

    def _score_confidence(self, action: Action, context: Context) -> float:
        """Quality/quantity of prior evidence: less evidence → harder.

        Combines recon depth, known vulns/creds, and target familiarity into
        a single 'how blind are we?' score. Each signal reduces blindness.
        """
        # Start fully blind (1.0 = no evidence, hardest), reduce as we learn
        blindness = 1.0

        # Recon depth: thorough recon (1.0) removes up to 0.35 blindness
        blindness -= 0.35 * clamp01(context.recon_depth)

        # Target familiarity: well-known target (1.0) removes up to 0.25
        blindness -= 0.25 * clamp01(context.target_familiarity)

        # Known vulns/creds: each reduces blindness slightly (capped)
        intel = clamp01((context.known_vulns + context.known_creds) / 10.0)
        blindness -= 0.25 * intel

        # Findings count: more findings means more context, removes up to 0.15
        findings = clamp01(context.findings_count / 20.0)
        blindness -= 0.15 * findings

        return round(clamp01(blindness), 4)

    def _score_context_load(self, action: Action, context: Context) -> float:
        """Token budget pressure: less headroom / bigger output → harder.

        Score rises as remaining budget shrinks AND as expected output grows
        relative to remaining budget (a big operation when nearly empty is hard).
        """
        total = max(1, context.token_budget_total)
        remaining = max(0, context.token_budget_remaining)
        budget_fraction = remaining / total  # 1.0 = full, 0.0 = empty

        # Budget pressure: 1 - fraction (empty budget = 1.0 pressure)
        pressure = 1.0 - budget_fraction

        # Output fraction: how much of remaining budget this action eats
        if remaining > 0:
            output_fraction = clamp01(action.expected_output_tokens / remaining)
        else:
            output_fraction = 1.0

        # Weighted blend: pressure matters more than single-action size
        score = 0.65 * pressure + 0.35 * output_fraction
        return round(clamp01(score), 4)

    def _score_history(self, action: Action,
                       history: Optional[List[Dict[str, Any]]] = None) -> float:
        """Past success rate on similar actions: lower success → harder.

        If a boneyard is attached and no explicit history is passed, query it.
        With too few samples, apply an uncertainty discount (assume slightly
        harder than the raw rate suggests).
        """
        if history is None and self.boneyard is not None:
            try:
                history = self.boneyard.query_difficulty(action_name=action.name)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 — calibration is best-effort
                history = []

        history = history or []
        if not history:
            # No history at all: neutral, slight upward bias (unknown = somewhat hard)
            return 0.5

        # Count outcomes (only resolved assessments inform the rate).
        # 'partial' is treated as half a success: the agent found something, but
        # not everything worked. This keeps the calibration signal granular.
        resolved = [h for h in history
                    if h.get('outcome') in ('success', 'failure', 'partial')]
        if not resolved:
            return 0.5  # pending-only → no signal yet

        success_weight = {'success': 1.0, 'partial': 0.5, 'failure': 0.0}
        total_weight = sum(success_weight.get(h.get('outcome'), 0.0) for h in resolved)
        success_rate = total_weight / len(resolved)

        # Difficulty = 1 - success_rate (low success → high difficulty)
        raw_difficulty = 1.0 - success_rate

        # Uncertainty discount: with few samples, push toward 0.5 (neutral)
        if len(resolved) < HISTORY_MIN_SAMPLES:
            # Blend toward 0.5 by the fraction of samples missing
            certainty = len(resolved) / HISTORY_MIN_SAMPLES
            raw_difficulty = (raw_difficulty * certainty) + (0.5 * (1.0 - certainty))

        return round(clamp01(raw_difficulty), 4)

    # ─── Composite + Mode ─────────────────────────────────────────────────

    def _composite(self, axes: Dict[str, float]) -> float:
        """Weighted sum of axes → composite score in [0, 1]."""
        score = 0.0
        for axis_name, weight in self.weights.items():
            score += weight * axes.get(axis_name, 0.0)
        return round(clamp01(score), 4)

    def _mode_for(self, score: float) -> str:
        """Map composite score to a mode."""
        if score < self.exploit_threshold:
            return 'exploit'
        if score >= self.abort_threshold:
            return 'abort'
        return 'explore'

    # ─── Explanation ──────────────────────────────────────────────────────

    @staticmethod
    def _explain(action: Action, context: Context,
                 axes: Dict[str, float], score: float, mode: str) -> str:
        """Produce a human-readable rationale for the assessment."""
        # Identify the dominant axis (highest weighted contribution)
        contribs = {
            k: axes.get(k, 0.0) for k in DEFAULT_WEIGHTS
        }
        dominant = max(contribs, key=contribs.get)  # type: ignore[arg-type]
        dom_val = contribs[dominant]

        mode_desc = {
            'exploit': "sufficient evidence and capacity to execute",
            'explore': "partial uncertainty; gather more before committing",
            'abort': "too costly/risky at current capacity; skip or escalate",
        }.get(mode, "unknown")

        parts = [
            f"'{action.name}' assessed {mode} (score={score:.3f}): {mode_desc}.",
            f"Dominant factor: {dominant} ({dom_val:.2f}).",
        ]

        # Add axis-specific colour
        if axes.get('horizon', 0) > 0.6:
            parts.append(f"Long horizon ({action.estimated_steps} steps).")
        if axes.get('confidence', 0) > 0.6:
            parts.append("Low confidence (insufficient recon/intel).")
        if axes.get('context_load', 0) > 0.6:
            rem = context.token_budget_remaining
            tot = context.token_budget_total
            parts.append(f"Heavy context load ({rem}/{tot} tokens left).")
        if axes.get('history', 0) > 0.6:
            parts.append("Poor historical success on similar actions.")

        return " ".join(parts)


# ─── Helpers ────────────────────────────────────────────────────────────────

def clamp01(x: float) -> float:
    """Clamp a float to [0.0, 1.0]."""
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x
