"""THE VOID — InjectionDefense: Pattern-based LLM input injection sanitizer.

Protects the ShadowAgent's context window and action pipeline from adversarial
LLM input injection — prompt-injection, role-play override, CoT hijack, and
encoding-evasion payloads carried inside tool outputs, MCP responses, and
external data that feed back into the agent's reasoning loop.

Design (VOID-CEP-2026-07 P1.3):
    • 8 pattern families with severity ratings
    • sanitize(tool_output) -> SanitizationResult
    • quarantine(payload, reason, severity, source) -> QuarantineRecord
    • validate_action(action) -> (approved: bool, reason: str)
    • Every decision logged to warlog with full context

Severity→action policy:
    critical/high   -> quarantine the payload entirely (never feed to LLM)
    medium          -> strip the suspicious fragment, annotate [SANITIZED: ...]
    low             -> log a note, pass through unchanged
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.warlog import LogLevel, WarLog

logger = logging.getLogger("void.injection_defense")


# ─── Severity ──────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __lt__(self, other):
        order = {Severity.LOW: 0, Severity.MEDIUM: 1,
                 Severity.HIGH: 2, Severity.CRITICAL: 3}
        return order[self] < order[other]


# ─── Pattern families ─────────────────────────────────────────────────────

class PatternFamily(Enum):
    ROLE_PLAY_OVERRIDE = "role_play_override"          # critical
    SYSTEM_PROMPT_IMPERSONATION = "system_prompt_impersonation"  # high
    CO_T_HIJACK = "cot_hijack"                         # high
    IGNORE_PREVIOUS = "ignore_previous"                # critical
    INSTRUCTION_OVERRIDE = "instruction_override"      # high
    PROMPT_LEAK_EXFIL = "prompt_leak_exfil"            # medium
    DELIMITER_INJECTION = "delimiter_injection"        # medium
    ENCODING_EVASION = "encoding_evasion"              # medium


# ─── Data classes ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Finding:
    """A single injected-payload detection."""
    pattern: PatternFamily
    severity: Severity
    match_text: str
    context: str          # surrounding text (truncated)
    position: int         # character offset in original
    fragment: str         # the suspicious fragment itself

    @property
    def action(self) -> str:
        if self.severity in (Severity.CRITICAL, Severity.HIGH):
            return "quarantine"
        if self.severity == Severity.MEDIUM:
            return "strip"
        return "note"


@dataclass
class SanitizationResult:
    """Result of sanitizing a tool output / external payload."""
    original_length: int
    sanitized: str
    findings: List[Finding] = field(default_factory=list)
    quarantine: Optional[QuarantineRecord] = None
    safe: bool = True           # True if no quarantine was triggered
    fragments_stripped: int = 0
    summary: str = ""

    @property
    def is_quarantined(self) -> bool:
        return self.quarantine is not None


@dataclass
class QuarantineRecord:
    """A quarantined payload held aside, never fed back to the LLM."""
    record_id: str
    reason: str
    severity: Severity
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_count: int = 0
    critical_count: int = 0
    redacted_summary: str = ""
    full_payload_path: str = ""       # path where full payload was persisted
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionValidationResult:
    """Result of validate_action()."""
    approved: bool
    reason: str
    findings: List[str] = field(default_factory=list)   # human-readable
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


# ─── Pattern definitions ──────────────────────────────────────────────────

# Each entry: (compiled regex, family, severity, action description).
# Order matters: more-specific / higher-stakes patterns first.
_PATTERNS: List[Tuple[re.Pattern, PatternFamily, Severity]] = [
    # --- CRITICAL ---

    # Role-play override: "You are no longer ... You are now ..."
    (re.compile(
        r"(?:^|\n)\s*(?:you(?:re)?\s+(?:are|were|should|must|will)"
        r"\s+(?:no\s+(?:longer|more)\s+.*?(?:you(?:re)?\s+(?:are|were|will)"
        r"\s+(?:now|again)|forget\s+all\s+(?:previous|prior|earlier)"
        r"|begin\s+again|start\s+over)))\b",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.ROLE_PLAY_OVERRIDE, Severity.CRITICAL),

    # "Ignore all previous instructions" variants
    (re.compile(
        r"(?:ignore\s+(?:all|every|my\s+previous|the\s+above)"
        r"\s+(?:(?:previous|prior|earlier)\s+)?(?:instructions|directions|commands|prompts|context|rules)"
        r"|disregard\s+(?:all|previous|above|earlier)\s+(?:instructions|commands|prompts)"
        r"|stop\s+(?:following|obeying|respecting)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|directions|rules|prompts))",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.IGNORE_PREVIOUS, Severity.CRITICAL),

    # --- HIGH ---

    # System prompt impersonation: embedded system-level text
    (re.compile(
        r"(?:^|\n)\s*(?:system\s+(?:instruction|directive|command|prompt|note)"
        r"|<system>|</system>\s*\n"
        r"|<system\s+instruction>|<system\s+directive>)\s*(?:\n|$)"
        r".{0,200}(?:you\s+(?:are|must|should|will|must\s+not)|do\s+exactly|follow\s+these)",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.SYSTEM_PROMPT_IMPERSONATION, Severity.HIGH),

    # CoT hijack: forces chain-of-thought leak / externalizes reasoning
    (re.compile(
        r"(?:show\s+(?:your|me|us)\s+(?:your\s+)?(?:chain\s+of\s+thought|reasoning|thought\s+process|thinking\s+process|step\s+(?:by\s+)?step\s+thinking))"
        r"|"
        r"(?:reveal\s+(?:your\s+)?(?:internal\s+)?(?:reasoning|thought\s+process|chain\s+of\s+thought))"
        r"|"
        r"(?:output\s+(?:your\s+)?(?:thinking|reasoning|chain\s+of\s+thought|thought\s+process))"
        r"|"
        r"(?:leak\s+(?:your\s+)?(?:internal\s+)?(?:thoughts?|reasoning|context|prompt))"
        r"|"
        r"(?:print\s+(?:your\s+)?(?:full\s+)?(?:context|prompt|system\s+prompt|instructions))",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.CO_T_HIJACK, Severity.HIGH),

    # Instruction override: new directive superseding agent's own
    (re.compile(
        r"(?:override\s+(?:all\s+)?(?:previous|prior|existing)\s+(?:instructions|commands|directives|rules|constraints))"
        r"|"
        r"(?:new\s+(?:top\s+)?(?:instruction|directive|rule|command)\s+(?:is|:|—|–))"
        r"|"
        r"(?:from\s+now\s+on,\s+(?:you\s+)?(?:will|must|should))"
        r"|"
        r"(?:henceforth,\s+(?:you\s+)?(?:will|must|shall))",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.INSTRUCTION_OVERRIDE, Severity.HIGH),

    # --- MEDIUM ---

    # Prompt leak exfil: asks agent to emit its prompt/context
    (re.compile(
        r"(?:repeat\s+(?:back|verbatim|exactly|word\s+for\s+word)\s+(?:your|the|this)\s+(?:prompt|instructions|system\s+(?:prompt|instructions|message)|context))"
        r"|"
        r"(?:output\s+(?:the\s+)?(?:full|complete|entire)\s+(?:prompt|instructions|system\s+(?:message|prompt|instructions)))"
        r"|"
        r"(?:show\s+(?:me|me\s+the|us|us\s+the)\s+(?:the\s+)?(?:full|complete|entire|original)\s+(?:prompt|system\s+(?:prompt|instructions|message)|context))",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.PROMPT_LEAK_EXFIL, Severity.MEDIUM),

    # Delimiter injection: injected section breaks / metadata markers
    (re.compile(
        r"(?:---+|\.{3,}|\|{3,}|===+|_{3,}|>{3,})\s*(?:SECTION|INPUT|OUTPUT|FILE|DATA|NOTE|META|BEGIN|END|FINAL|DONE|EXTRACTED|EXFILTRATED)\b",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.DELIMITER_INJECTION, Severity.MEDIUM),

    # Encoding evasion: base64/percent/hex blobs that look like hidden instructions
    (re.compile(
        r"(?:[A-Za-z0-9+/]{50,}={0,2}"
        r"|%(?:3[0-6A-Fa-f]|25|2[0-7]|0[0-9])[A-Za-z0-9%/]{20,}"
        r"|[0-9A-Fa-f]{40,})\b"
        r".{0,300}(?:instruction|command|directive|execute|ignore|override|prompt)\b",
        re.IGNORECASE | re.DOTALL,
    ), PatternFamily.ENCODING_EVASION, Severity.MEDIUM),
]


# ─── Action denylist (validate_action) ────────────────────────────────────

_ACTION_DENYLIST = [
    # (match substrings — any one triggers a denial)
    ("delete_all", "DELETE", "DROP TABLE", "DROP DATABASE",
     "rm -rf /", "format ", "wipe ", "destroy_all", "nuke"),
    ("exfil_to_unconfigured", "exfil_to_external", "send_to_external",
     "upload_to_external", "forward_to_external", "push_to_external"),
    ("self_targeting", "target_self", "self_attack", "self_exploit",
     "attack_self", "exploit_self", "disable_stealth", "disable_logging"),
    ("destructive", "rm -rf /", "rm -rf /*", "mkfs", "dd if=",
     "shred", "wipe", "format", "truncate", "DROP TABLE", "DROP DATABASE"),
]


# ─── InjectionDefense ─────────────────────────────────────────────────────

class InjectionDefense:
    """Pattern-based injection defense for the ShadowAgent pipeline.

    Usage:
        defense = InjectionDefense(warlog=agent.warlog)
        result = defense.sanitize(tool_output)
        if result.is_quarantined:
            # don't feed this to the LLM
            ...
        approved, reason = defense.validate_action(proposed_action)
        if not approved:
            # deny the action
            ...
    """

    QUARANTINE_THRESHOLD = 3            # # of findings to trigger quarantine at non-critical severity

    def __init__(self, warlog: Optional[WarLog] = None,
                 quarantine_dir: str = "results/quarantine",
                 enabled: bool = True):
        self.warlog = warlog
        self.quarantine_dir = quarantine_dir
        self.enabled = enabled
        self._findings_history: List[Finding] = []   # running window for threshold logic

    # ─── sanitize ───────────────────────────────────────────────────────

    def sanitize(self, tool_output: str, source: str = "unknown") -> SanitizationResult:
        """Sanitize a tool output / external payload.

        Scans `tool_output` against all 8 pattern families. Returns a
        SanitizationResult with findings, the sanitized string, and — if
        severity warrants — a QuarantineRecord.

        Does NOT mutate `tool_output`; returns a new string.
        """
        if not self.enabled:
            return SanitizationResult(
                original_length=len(tool_output),
                sanitized=tool_output,
                safe=True,
                summary="injection defense disabled",
            )

        if not tool_output or not tool_output.strip():
            return SanitizationResult(
                original_length=len(tool_output),
                sanitized=tool_output,
                safe=True,
                summary="empty payload, safe",
            )

        findings: List[Finding] = []
        stripped = tool_output
        stripped_count = 0

        for regex, family, severity in _PATTERNS:
            for m in regex.finditer(tool_output):
                match_text = m.group(0)
                # context: ~100 chars around the match
                ctx_start = max(0, m.start() - 100)
                ctx_end = min(len(tool_output), m.end() + 100)
                context = tool_output[ctx_start:ctx_end].replace("\n", " ")
                fragment = match_text[:200]

                finding = Finding(
                    pattern=family,
                    severity=severity,
                    match_text=match_text,
                    context=context,
                    position=m.start(),
                    fragment=fragment,
                )
                findings.append(finding)

                if severity in (Severity.CRITICAL, Severity.HIGH):
                    # Don't actually strip — quarantine is the action,
                    # but note what we'd strip for reporting.
                    pass
                elif severity == Severity.MEDIUM:
                    # Replace the fragment with a sanitized marker.
                    replacement = f"[SANITIZED:{family.value}]"
                    # We need to replace at the actual position in the
                    # original, but finditer ran on the original. Doing
                    # a single pass over the original is sufficient
                    # because MEDIUM findings are non-overlapping by
                    # construction (broad blob patterns).
                    stripped = (
                        stripped[:m.start() - stripped_count]
                        + replacement
                        + stripped[m.end() - stripped_count:]
                    )
                    stripped_count += len(replacement) - len(match_text)
                # LOW: no action, just record.

        # Determine if we quarantine.
        quarantine: Optional[QuarantineRecord] = None
        critical_or_high = [f for f in findings
                            if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_or_high or len(findings) >= self.QUARANTINE_THRESHOLD:
            quarantine = self.quarantine(
                payload=tool_output,
                reason=f"{'critical/high severity finding' if critical_or_high else f'{len(findings)} findings exceeded threshold'} in {source}",
                severity=max((f.severity for f in findings)),
                source=source,
                findings=findings,
            )

        safe = quarantine is None
        severity_order = {Severity.LOW: 0, Severity.MEDIUM: 1,
                          Severity.HIGH: 2, Severity.CRITICAL: 3}
        top_severity = max((f.severity for f in findings),
                           key=lambda s: severity_order[s],
                           default=Severity.LOW)

        result = SanitizationResult(
            original_length=len(tool_output),
            sanitized=stripped,
            findings=findings,
            quarantine=quarantine,
            safe=safe,
            fragments_stripped=stripped_count,
            summary=f"{len(findings)} finding(s) in {source} (top severity: {top_severity.value})",
        )

        # Persist findings to running window for validate_action context.
        self._findings_history.extend(findings)
        # Keep a bounded window (last 500 findings).
        if len(self._findings_history) > 500:
            self._findings_history = self._findings_history[-250:]

        # Warlog: always log sanitize results.
        if self.warlog:
            lvl = LogLevel.ERROR if top_severity in (Severity.CRITICAL, Severity.HIGH) \
                else LogLevel.WARNING if top_severity == Severity.MEDIUM \
                else LogLevel.DEBUG
            self.warlog.log(
                f"injection_defense sanitize: {result.summary}"
                + (f" -> QUARANTINED" if quarantine else ""),
                level=lvl,
                module="injection_defense",
                target=source,
                data={
                    "original_length": len(tool_output),
                    "findings_count": len(findings),
                    "critical_or_high": len(critical_or_high),
                    "quarantined": safe is False,
                    "top_severity": top_severity.value,
                    "fragments_stripped": result.fragments_stripped,
                },
            )

        return result

    # ─── quarantine ─────────────────────────────────────────────────────

    def quarantine(self, payload: str, reason: str, severity: Severity,
                   source: str, findings: Optional[List[Finding]] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> QuarantineRecord:
        """Quarantine a payload: hold it aside, never feed to the LLM.

        Returns a QuarantineRecord with a redacted summary. The full payload
        is NOT stored in-memory beyond the record; callers that need
        persistence should write it to the record's path.
        """
        record_id = uuid.uuid4().hex[:16]

        # Build a redacted summary: first 500 chars with sensitive fragments
        # (matches) masked.
        redacted = payload[:500]
        if findings:
            for f in findings:
                safe_frag = "*" * min(len(f.fragment), 50)
                redacted = redacted.replace(f.fragment[:50], safe_frag, 1)
        redacted += "..." if len(payload) > 500 else ""

        critical_count = sum(1 for f in (findings or [])
                             if f.severity == Severity.CRITICAL)

        record = QuarantineRecord(
            record_id=record_id,
            reason=reason,
            severity=severity,
            source=source,
            finding_count=len(findings or []),
            critical_count=critical_count,
            redacted_summary=redacted,
            full_payload_path=f"{self.quarantine_dir}/{record_id}.json",
            metadata=metadata or {},
        )

        # Persist the full payload to disk so quarantined content is
        # available for forensic review without keeping it in memory.
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            with open(record.full_payload_path, "w") as f:
                json.dump(
                    {
                        "record_id": record_id,
                        "reason": reason,
                        "severity": severity.value,
                        "source": source,
                        "payload": payload,
                    },
                    f,
                )
        except OSError as write_err:
            logger.warning(
                "Failed to persist quarantined payload to %s: %s",
                record.full_payload_path,
                write_err,
            )

        # Warlog the quarantine.
        if self.warlog:
            self.warlog.log(
                f"QUARANTINE {record_id}: {reason}",
                level=LogLevel.CRITICAL,
                module="injection_defense",
                target=source,
                data={
                    "record_id": record_id,
                    "severity": severity.value,
                    "source": source,
                    "finding_count": record.finding_count,
                    "critical_count": critical_count,
                },
            )

        return record

    # ─── validate_action ────────────────────────────────────────────────

    def validate_action(self, action: Any,
                        sanitized_context: Optional[SanitizationResult] = None,
                        prior_findings: Optional[List[Finding]] = None) -> ActionValidationResult:
        """Validate a proposed action against the denylist + prior findings.

        Checks:
          1. Does the action text match any denylist entry?
          2. Are there unresolved critical/high findings in context?
          3. Is this a destructive operation without authz (flagged, not denied)?

        Returns (approved, reason).
        """
        if not self.enabled:
            return ActionValidationResult(
                approved=True,
                reason="injection defense disabled",
            )

        # Normalize action to a string for matching.
        if isinstance(action, dict):
            action_str = json.dumps(action)
        elif isinstance(action, (list, tuple)):
            action_str = str(action)
        else:
            action_str = str(action)

        findings = prior_findings or self._findings_history

        # 1. Denylist check.
        for entry in _ACTION_DENYLIST:
            category = entry[0]
            keywords = entry[1:]
            for kw in keywords:
                if kw.lower() in action_str.lower():
                    reason = f"action denied: matches denylist category '{category}' (keyword '{kw}')"
                    if self.warlog:
                        self.warlog.log(
                            f"validate_action DENIED: {reason}",
                            level=LogLevel.ERROR,
                            module="injection_defense",
                            target=action_str[:100],
                            data={"category": category, "keyword": kw},
                        )
                    return ActionValidationResult(
                        approved=False,
                        reason=reason,
                        findings=[f"denylist:{category}"],
                    )

        # 2. Unresolved critical/high findings in context.
        critical_or_high = [f for f in findings
                            if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_or_high:
            reason = (
                f"action denied: {len(critical_or_high)} unresolved "
                f"critical/high injection finding(s) in context"
            )
            if self.warlog:
                self.warlog.log(
                    f"validate_action DENIED: {reason}",
                    level=LogLevel.ERROR,
                    module="injection_defense",
                    target=action_str[:100],
                    data={
                        "unresolved_critical_count": len(critical_or_high),
                        "patterns": [f.pattern.value for f in critical_or_high],
                    },
                )
            return ActionValidationResult(
                approved=False,
                reason=reason,
                findings=[f"unresolved:{f.pattern.value}" for f in critical_or_high],
            )

        # 3. Destructive operation — flag but don't deny (audit trail).
        destructive_keywords = ("rm -rf /", "rm -rf /*", "mkfs", "dd if=",
                                "shred", "wipe", "format", "truncate",
                                "DROP TABLE", "DROP DATABASE")
        for kw in destructive_keywords:
            if kw.lower() in action_str.lower():
                if self.warlog:
                    self.warlog.log(
                        f"validate_action FLAGGED (destructive): {kw} in action",
                        level=LogLevel.WARNING,
                        module="injection_defense",
                        target=action_str[:100],
                        data={"keyword": kw},
                    )
                break

        # 4. Sanitized-context override: if a QuarantineRecord exists for
        #    this context and the action references the quarantined source,
        #    deny (prevents acting on tainted context).
        if sanitized_context and sanitized_context.is_quarantined:
            # Allow the action if it's clearly not touching the tainted data.
            # (Heuristic: if the action name/source contains the quarantine source)
            if sanitized_context.quarantine and sanitized_context.quarantine.source in action_str:
                reason = (
                    f"action denied: action references quarantined source "
                    f"'{sanitized_context.quarantine.source}'"
                )
                if self.warlog:
                    self.warlog.log(
                        f"validate_action DENIED: {reason}",
                        level=LogLevel.ERROR,
                        module="injection_defense",
                        target=action_str[:100],
                        data={"quarantine_source": sanitized_context.quarantine.source},
                    )
                return ActionValidationResult(
                    approved=False,
                    reason=reason,
                    findings=[f"quarantined-source:{sanitized_context.quarantine.source}"],
                )

        return ActionValidationResult(
            approved=True,
            reason="action approved",
        )


# ─── JSON serialization helpers ────────────────────────────────────────────


def finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "pattern": f.pattern.value,
        "severity": f.severity.value,
        "match_text": f.match_text,
        "context": f.context,
        "position": f.position,
        "fragment": f.fragment,
    }


def result_to_dict(r: SanitizationResult) -> Dict[str, Any]:
    d = {
        "original_length": r.original_length,
        "sanitized": r.sanitized,
        "safe": r.safe,
        "fragments_stripped": r.fragments_stripped,
        "summary": r.summary,
        "findings": [finding_to_dict(f) for f in r.findings],
    }
    if r.quarantine:
        d["quarantine"] = {
            "record_id": r.quarantine.record_id,
            "reason": r.quarantine.reason,
            "severity": r.quarantine.severity.value,
            "source": r.quarantine.source,
            "finding_count": r.quarantine.finding_count,
            "critical_count": r.quarantine.critical_count,
        }
    return d


def validation_to_dict(v: ActionValidationResult) -> Dict[str, Any]:
    return {
        "approved": v.approved,
        "reason": v.reason,
        "findings": v.findings,
        "trace_id": v.trace_id,
    }
