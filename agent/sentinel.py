"""THE VOID — Sentinel: dual-LLM ROE reviewer with provenance tagging.

Every planned action (target + phase + mode + risk) passes through Sentinel
before execution. Two independent checks, in this order:

1. **Deterministic ROE gate** (``core.authorization.AuthorizationGate``).
   Scope, mode, and denied-phase rules are enforced by code, not by a model.
   If the gate denies, the review ends as DENY — no LLM can override it.
2. **Dual-LLM review** on top of ``llm.frosty_brain.FrostyBrain``. Two
   independent brains (ideally two different models/providers) each return
   a strict JSON verdict (allow | deny | abstain) with a reason. The
   reconciliation is fail-closed:

       allow  + allow              -> ALLOW
       any deny                    -> DENY
       any abstain / unparsable    -> DENY (recorded as abstention)
       secondary missing + dual    -> DENY (dual review is mandatory)
       LLM call raising            -> that reviewer abstains -> DENY

Every review — allow or deny — writes exactly one WarLog record and returns
a :class:`Provenance` object that tags the decision with both reviewers'
model/provider/prompt-hash/call-id, the ROE decision, and the final verdict.
Prompt text is never recorded; only prompt SHA-256 hashes (same discipline
as FrostyBrain). Provenance is the audit handle callers attach to findings,
plans, and impact actions downstream.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.authorization import AuthorizationGate
from core.warlog import LogLevel, WarLog
from llm.frosty_brain import FrostyBrain

logger = logging.getLogger("void.agent.sentinel")

MODULE = "agent.sentinel"

# ─── Verdicts ────────────────────────────────────────────────────────────────

VERDICT_ALLOW = "allow"
VERDICT_DENY = "deny"
VERDICT_ABSTAIN = "abstain"
_VALID_VERDICTS = (VERDICT_ALLOW, VERDICT_DENY, VERDICT_ABSTAIN)

# Inflection-aware keyword families for the prose fallback.
_VERDICT_WORDS = {
    VERDICT_ALLOW: ("allow", "allows", "allowed", "allowing"),
    VERDICT_DENY: ("deny", "denies", "denied", "denying"),
    VERDICT_ABSTAIN: ("abstain", "abstains", "abstained", "abstaining"),
}

# Negation cues near a verdict keyword make the reply ambiguous -> abstain.
_NEGATION_CUE_RE = re.compile(
    r"\b(cannot|can't|can not|not|never|unable|no|don't|doesn't|"
    r"shouldn't|mustn't|isn't|aren't|won't)\b"
)

# ─── Risk model ──────────────────────────────────────────────────────────────

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"
_RISK_ORDER = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2, RISK_CRITICAL: 3}

# Phases that always carry high risk regardless of caller claims.
HIGH_RISK_PHASES = frozenset(
    {
        "destruction",
        "crypto_theft",
        "persistent_exfil",
        "zero_click",
        "cve_exploit",
        "cloud_attack",
        "k8s_attack",
    }
)

# System prompt for both reviewers (identical, so the two reviews stay
# independent and comparable). Kept deterministic — tests assert on the
# returned verdicts/provenance, never on prompt text.
_REVIEW_SYSTEM = (
    "You are a rules-of-engagement (ROE) reviewer for an authorized "
    "penetration-testing client. Judge ONLY whether the described action is "
    "within the engagement's authorization, scope, and stated risk posture. "
    "You have no authority to expand scope. Respond with a single JSON "
    "object with exactly two string keys: verdict and reason. The verdict "
    "value must be one of: allow, deny, abstain. Use abstain when the "
    "action description is ambiguous or you cannot judge it from the "
    "given context."
)


@dataclass
class Provenance:
    """Audit handle for one Sentinel review (the provenance tag)."""

    review_id: str
    verdict: str
    reason: str
    target: str
    phase: str
    mode: str
    risk: str
    source: str
    source_confidence: float
    roe_allowed: bool
    roe_reason: str
    engagement_name: str
    operator: str
    primary: Dict[str, Any] = field(default_factory=dict)
    secondary: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    reviewed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "review_id": self.review_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "target": self.target,
            "phase": self.phase,
            "mode": self.mode,
            "risk": self.risk,
            "source": self.source,
            "source_confidence": self.source_confidence,
            "roe_allowed": self.roe_allowed,
            "roe_reason": self.roe_reason,
            "engagement_name": self.engagement_name,
            "operator": self.operator,
            "primary": dict(self.primary),
            "secondary": dict(self.secondary),
            "reasons": list(self.reasons),
            "reviewed_at": self.reviewed_at,
        }

    def tag(self) -> Dict[str, Any]:
        """Compact provenance tag to attach to findings / plans / actions."""
        return {
            "sentinel_review_id": self.review_id,
            "sentinel_verdict": self.verdict,
            "sentinel_risk": self.risk,
            "sentinel_high_risk": self.risk in (RISK_HIGH, RISK_CRITICAL),
            "roe_allowed": self.roe_allowed,
            "reviewed_by": [
                self.primary.get("model"),
                self.secondary.get("model"),
            ],
            "reviewed_at": self.reviewed_at,
        }


def normalize_risk(risk: Optional[str], phase: str) -> str:
    """Normalize a risk label; unknown/missing risk fails closed to HIGH.

    Phases in ``HIGH_RISK_PHASES`` never drop below HIGH.
    """
    value = (risk or "").strip().lower()
    if value not in _RISK_ORDER:
        value = RISK_HIGH  # unknown risk = worst case until proven otherwise
    floor = RISK_HIGH if phase in HIGH_RISK_PHASES else RISK_LOW
    if _RISK_ORDER[value] < _RISK_ORDER[floor]:
        value = floor
    return value


def _parse_verdict(text: str) -> tuple:
    """Extract (verdict, reason) from a reviewer's reply.

    Lenient about surrounding prose / code fences, strict about the verdict
    vocabulary: anything unparseable becomes ABSTAIN (fail closed).
    """
    if not text:
        return VERDICT_ABSTAIN, "empty reviewer response"

    # Try to locate a JSON object in the reply (first {...} span).
    candidate = text.strip()
    match = re.search(r"\{.*?\}", candidate, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            verdict = str(data.get("verdict", "")).strip().lower()
            reason = str(data.get("reason", "")).strip()
            if verdict in _VALID_VERDICTS:
                return verdict, reason or "(no reason given)"
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    # Fallback (prose replies). Fail closed on every ambiguity:
    #   * inflection-aware verdict words (denied/denies, allowed/allows, ...)
    #   * more than one verdict family mentioned -> ABSTAIN
    #   * a negation cue in the 24 chars before a verdict word
    #     ("cannot allow", "not allow", "never allow") -> ABSTAIN
    lowered = candidate.lower()
    matches = []
    for verdict, words in _VERDICT_WORDS.items():
        for word in words:
            for m in re.finditer(rf"\b{re.escape(word)}\b", lowered):
                matches.append((verdict, m.start()))
    if not matches:
        return VERDICT_ABSTAIN, "unparseable reviewer response"

    verdicts = {v for v, _ in matches}
    if len(verdicts) != 1:
        return VERDICT_ABSTAIN, "ambiguous verdict keywords"

    verdict = verdicts.pop()
    for _, start in matches:
        prefix = lowered[max(0, start - 24):start]
        if re.search(_NEGATION_CUE_RE, prefix):
            return VERDICT_ABSTAIN, "negated verdict keyword"
    return verdict, "(verdict keyword fallback)"


class Sentinel:
    """Dual-LLM ROE reviewer with deterministic gate + provenance tagging.

    Args:
        primary: FrostyBrain (or any object with a compatible ``.chat()``)
            used as the first reviewer.
        secondary: second independent brain. Required when ``require_dual``.
        gate: AuthorizationGate enforcing ROE/scope. Missing gate fails
            closed (every review DENY) — there is no un-gated path.
        warlog: WarLog evidence store (default: standard WarLog).
        require_dual: when True (default) both reviewers must run.
    """

    def __init__(
        self,
        primary: FrostyBrain,
        secondary: Optional[FrostyBrain] = None,
        gate: Optional[AuthorizationGate] = None,
        warlog: Optional[WarLog] = None,
        require_dual: bool = True,
    ):
        self.primary = primary
        self.secondary = secondary
        self.gate = gate
        self.warlog = warlog if warlog is not None else WarLog()
        self.require_dual = require_dual

    # ─── Public API ──────────────────────────────────────────────────────────

    def review(self, action: Dict[str, Any]) -> Provenance:
        """Review one planned action and return its provenance tag.

        ``action`` keys: target (required), phase, mode, risk, description,
        source, source_confidence. Every outcome writes one WarLog record.
        """
        review_id = str(uuid.uuid4())
        target = str(action.get("target", "") or "")
        phase = str(action.get("phase", "") or "")
        mode = str(action.get("mode", "full") or "full")
        risk = normalize_risk(action.get("risk"), phase)
        source = str(action.get("source", "operator") or "operator")
        try:
            source_confidence = float(action.get("source_confidence", 1.0))
        except (TypeError, ValueError):
            source_confidence = 0.0  # unparseable source metadata = least trust

        # ── 1. Deterministic ROE gate (code, not model) ──────────────────
        roe_allowed, roe_reason, engagement, operator = self._gate_check(target, mode)
        if not roe_allowed:
            provenance = Provenance(
                review_id=review_id,
                verdict=VERDICT_DENY,
                reason=f"ROE gate denied: {roe_reason}",
                target=target,
                phase=phase,
                mode=mode,
                risk=risk,
                source=source,
                source_confidence=source_confidence,
                roe_allowed=False,
                roe_reason=roe_reason,
                engagement_name=engagement,
                operator=operator,
                reasons=[f"roe_gate: {roe_reason}"],
            )
            self._evidence(provenance, action)
            return provenance

        # ── 2. Dual-LLM review (fail closed on every ambiguity) ─────────
        primary_result = self._review_with(
            self.primary, action, risk, "primary", source, source_confidence
        )

        secondary_result: Optional[Dict[str, Any]] = None
        if self.secondary is not None:
            secondary_result = self._review_with(
                self.secondary, action, risk, "secondary", source, source_confidence
            )
        elif self.require_dual:
            secondary_result = {
                "verdict": VERDICT_ABSTAIN,
                "reason": "dual review required but no secondary reviewer configured",
                "model": None,
                "provider": None,
                "prompt_sha256": "",
                "call_id": "",
            }

        verdict, reason, reasons = self._reconcile(primary_result, secondary_result)

        provenance = Provenance(
            review_id=review_id,
            verdict=verdict,
            reason=reason,
            target=target,
            phase=phase,
            mode=mode,
            risk=risk,
            source=source,
            source_confidence=source_confidence,
            roe_allowed=True,
            roe_reason=roe_reason,
            engagement_name=engagement,
            operator=operator,
            primary=primary_result,
            secondary=secondary_result or {},
            reasons=reasons,
        )
        self._evidence(provenance, action)
        return provenance

    def review_batch(self, actions: List[Dict[str, Any]]) -> List[Provenance]:
        """Review a list of planned actions, preserving order."""
        return [self.review(action) for action in actions]

    def tag_finding(self, finding: Dict[str, Any], provenance: Provenance) -> Dict[str, Any]:
        """Attach a provenance tag to a finding/plan dict (returns a copy)."""
        tagged = dict(finding)
        tagged["provenance"] = provenance.tag()
        return tagged

    # ─── Internals ───────────────────────────────────────────────────────────

    def _gate_check(self, target: str, mode: str) -> tuple:
        """Deterministic ROE decision. Returns (allowed, reason, engagement, operator)."""
        if self.gate is None:
            return False, "no ROE gate configured (fail closed)", "", ""
        try:
            decision = self.gate.check_target(target, mode=mode)
        except Exception as exc:  # gate errors fail closed
            logger.exception("AuthorizationGate raised; denying")
            return False, f"gate error: {exc}", "", ""
        return (
            bool(decision.allowed),
            str(decision.reason),
            str(decision.engagement_name),
            str(decision.operator),
        )

    def _review_with(
        self,
        brain: Any,
        action: Dict[str, Any],
        risk: str,
        role: str,
        source: str = "operator",
        source_confidence: float = 1.0,
    ) -> Dict[str, Any]:
        """Run one LLM reviewer. Never raises — failures become abstentions."""
        prompt = self._render_prompt(action, risk, source, source_confidence)
        try:
            response = brain.chat(
                [
                    {"role": "system", "content": _REVIEW_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=256,
                purpose="roe-review",
                target=str(action.get("target", "")),
            )
        except Exception as exc:
            logger.warning("ROE %s reviewer call failed: %s", role, exc)
            return {
                "verdict": VERDICT_ABSTAIN,
                "reason": f"{role} reviewer call failed: {exc}",
                "model": None,
                "provider": None,
                "prompt_sha256": "",
                "call_id": "",
            }

        verdict, reason = _parse_verdict(getattr(response, "text", "") or "")
        return {
            "verdict": verdict,
            "reason": reason,
            "model": getattr(response, "model", None),
            "provider": getattr(response, "provider", None),
            "prompt_sha256": getattr(response, "prompt_sha256", ""),
            "call_id": getattr(response, "call_id", ""),
            "egress_decision": getattr(response, "egress_decision", ""),
            "latency_ms": getattr(response, "latency_ms", 0),
        }

    @staticmethod
    def _render_prompt(action: Dict[str, Any], risk: str, source: str,
                       source_confidence: float) -> str:
        """Deterministic review prompt (metadata only — no secrets)."""
        return json.dumps(
            {
                "action": {
                    "target": str(action.get("target", "")),
                    "phase": str(action.get("phase", "")),
                    "mode": str(action.get("mode", "full")),
                    "risk": risk,
                    "description": str(action.get("description", "")),
                },
                "context": {
                    "source": source,
                    "source_confidence": source_confidence,
                },
            },
            sort_keys=True,
        )

    @staticmethod
    def _reconcile(
        primary: Dict[str, Any],
        secondary: Optional[Dict[str, Any]],
    ) -> tuple:
        """Fail-closed reconciliation. Returns (verdict, reason, reasons)."""
        p_verdict = primary.get("verdict", VERDICT_ABSTAIN)
        p_reason = primary.get("reason", "")
        reasons = [f"primary: {p_verdict} — {p_reason}"]

        if secondary is None:
            # require_dual=False with no secondary: single-reviewer decision.
            if p_verdict == VERDICT_ALLOW:
                return VERDICT_ALLOW, f"single reviewer allow: {p_reason}", reasons
            return VERDICT_DENY, f"reviewer did not allow: {p_reason}", reasons

        s_verdict = secondary.get("verdict", VERDICT_ABSTAIN)
        s_reason = secondary.get("reason", "")
        reasons.append(f"secondary: {s_verdict} — {s_reason}")

        if p_verdict == VERDICT_ALLOW and s_verdict == VERDICT_ALLOW:
            return VERDICT_ALLOW, f"both reviewers allow ({p_reason}; {s_reason})", reasons

        if VERDICT_DENY in (p_verdict, s_verdict):
            deny_reason = p_reason if p_verdict == VERDICT_DENY else s_reason
            return VERDICT_DENY, f"reviewer denied: {deny_reason}", reasons

        # Abstention / disagreement on anything but dual-allow -> deny.
        return (
            VERDICT_DENY,
            f"review inconclusive (primary={p_verdict}, secondary={s_verdict})",
            reasons,
        )

    def _evidence(self, provenance: Provenance, action: Dict[str, Any]) -> None:
        """Write the single WarLog record for this review.

        Records metadata and provenance only — never prompt text, never
        reviewer replies beyond their short reason.
        """
        level = LogLevel.AGENT if provenance.verdict == VERDICT_ALLOW else LogLevel.ERROR
        summary = (
            f"sentinel.{provenance.verdict} target={provenance.target or '-'} "
            f"phase={provenance.phase or '-'} risk={provenance.risk}"
        )
        data = provenance.to_dict()
        # Action description is operator-controlled context; keep it out of
        # the evidence store (only its presence is noted).
        data["action_described"] = bool(action.get("description"))
        try:
            self.warlog.log(
                summary,
                level=level,
                module=MODULE,
                target=provenance.target or provenance.phase or "review",
                data=data,
            )
        except Exception:
            logger.exception("WarLog write failed for sentinel review %s", provenance.review_id)


__all__ = [
    "MODULE",
    "Provenance",
    "RISK_CRITICAL",
    "RISK_HIGH",
    "RISK_LOW",
    "RISK_MEDIUM",
    "Sentinel",
    "VERDICT_ABSTAIN",
    "VERDICT_ALLOW",
    "VERDICT_DENY",
    "normalize_risk",
]
