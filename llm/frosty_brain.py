"""THE VOID — FrostyBrain: the audited LLM entry point.

Every reasoning call Frosty makes goes through this module. It is the only
place where a prompt is handed to a provider, and it guarantees two things:

1. **Egress discipline.** The call is checked against the registry's egress
   policy *again* at the brain layer (defense in depth): a cloud provider is
   refused unless the operator opted in via VOID_LLM_EGRESS=cloud.
2. **Evidence.** Every call — success or failure — writes a WarLog record with
   model, provider, latency, prompt hash and the egress decision. Prompt *text*
   is never recorded: only the SHA-256 prompt hash, so evidence is stable and
   cross-referenceable without leaking operator input into the log store.

Frosty never talks to a provider directly; callers use FrostyBrain (or the
ProviderRegistry underneath it) so the audit trail cannot be bypassed.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.warlog import LogLevel, WarLog
from llm.providers import (
    EGRESS_CLOUD_ALLOWED,
    EGRESS_LOCAL_ONLY,
    EgressViolation,
    LLMProvider,
    LLMResponse,
    ProviderRegistry,
    default_registry,
    prompt_hash,
)

logger = logging.getLogger("void.llm.frosty_brain")

MODULE = "llm.frosty_brain"

# Agent-level telemetry for successful reasoning calls.
AUDIT_LEVEL = LogLevel.AGENT

# Egress decisions recorded in evidence.
EGRESS_DECISION_LOCAL = "local"                  # call stayed on-host
EGRESS_DECISION_CLOUD_PERMITTED = "cloud_ok"     # off-host, operator opted in
EGRESS_DECISION_CLOUD_BLOCKED = "cloud_blocked"  # refused before any data left


@dataclass
class BrainResponse(LLMResponse):
    """LLMResponse plus the audit/provenance fields Frosty carries around."""

    prompt_sha256: str = ""
    call_id: str = ""
    egress_decision: str = EGRESS_DECISION_LOCAL
    purpose: str = "chat"

    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        data.update(
            {
                "prompt_sha256": self.prompt_sha256,
                "call_id": self.call_id,
                "egress_decision": self.egress_decision,
                "purpose": self.purpose,
            }
        )
        return data


def _egress_decision(provider: LLMProvider, egress_policy: str) -> str:
    if provider.local:
        return EGRESS_DECISION_LOCAL
    return EGRESS_DECISION_CLOUD_PERMITTED if egress_policy == EGRESS_CLOUD_ALLOWED else EGRESS_DECISION_CLOUD_BLOCKED


class FrostyBrain:
    """Audited LLM gateway.

    Args:
        registry: ProviderRegistry to use (default: environment-built,
            local-first via ``default_registry()``).
        warlog: WarLog evidence store (default: the standard WarLog).
    """

    def __init__(
        self,
        registry: Optional[ProviderRegistry] = None,
        warlog: Optional[WarLog] = None,
    ):
        self.registry = registry if registry is not None else default_registry()
        self.warlog = warlog if warlog is not None else WarLog()
        self.egress_policy = self.registry.egress_policy

    # ─── Public API ──────────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        purpose: str = "chat",
        target: Optional[str] = None,
    ) -> BrainResponse:
        """Run one audited completion and return the response with provenance.

        Every call — success, provider failure, egress refusal, or
        'no provider available' — leaves exactly one WarLog record.
        """
        call_id = str(uuid.uuid4())
        p_hash = prompt_hash(messages)
        started = time.monotonic()

        # Pre-flight: which provider would serve this, and may it?
        try:
            provider = self.registry.pick()
        except Exception as exc:
            self._audit(
                call_id=call_id,
                status="error",
                prompt_sha256=p_hash,
                provider=None,
                model=None,
                egress_decision=EGRESS_DECISION_CLOUD_BLOCKED,
                latency_ms=int((time.monotonic() - started) * 1000),
                usage={},
                purpose=purpose,
                target=target,
                error=exc,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            raise

        decision = _egress_decision(provider, self.registry.egress_policy)
        if decision == EGRESS_DECISION_CLOUD_BLOCKED:
            self._audit(
                call_id=call_id,
                status="error",
                prompt_sha256=p_hash,
                provider=provider.name,
                model=provider.model,
                egress_decision=decision,
                latency_ms=int((time.monotonic() - started) * 1000),
                usage={},
                purpose=purpose,
                target=target,
                error=None,
                note="egress refused: cloud provider under local-only policy",
                temperature=temperature,
                max_tokens=max_tokens,
            )
            raise EgressViolation(
                f"Provider {provider.name} would send data off-host; "
                f"egress policy is {EGRESS_LOCAL_ONLY}"
            )

        # Execute the call against exactly the provider we audited above.
        # (Egress was already enforced here; a provider-level failure still
        # leaves evidence before propagating.)
        try:
            response = provider.chat(
                messages, temperature=temperature, max_tokens=max_tokens
            )
        except Exception as exc:
            self._audit(
                call_id=call_id,
                status="error",
                prompt_sha256=p_hash,
                provider=provider.name,
                model=provider.model,
                egress_decision=decision,
                latency_ms=int((time.monotonic() - started) * 1000),
                usage={},
                purpose=purpose,
                target=target,
                error=exc,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            raise

        self._audit(
            call_id=call_id,
            status="ok",
            prompt_sha256=p_hash,
            provider=response.provider,
            model=response.model,
            egress_decision=decision,
            latency_ms=response.latency_ms,
            usage=response.usage,
            purpose=purpose,
            target=target,
            error=None,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return BrainResponse(
            text=response.text,
            model=response.model,
            provider=response.provider,
            latency_ms=response.latency_ms,
            usage=dict(response.usage),
            local=response.local,
            prompt_sha256=p_hash,
            call_id=call_id,
            egress_decision=decision,
            purpose=purpose,
        )

    def ask(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        purpose: str = "chat",
        target: Optional[str] = None,
    ) -> BrainResponse:
        """Convenience wrapper: one user prompt with an optional system preamble."""
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.chat(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            purpose=purpose,
            target=target,
        )

    # ─── Evidence ────────────────────────────────────────────────────────────

    def _audit(
        self,
        *,
        call_id: str,
        status: str,
        prompt_sha256: str,
        provider: Optional[str],
        model: Optional[str],
        egress_decision: str,
        latency_ms: int,
        usage: Dict[str, int],
        purpose: str,
        target: Optional[str],
        error: Optional[BaseException],
        note: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> None:
        """Write the single evidence record for one brain call.

        Prompt text is never recorded — only its hash — so the evidence store
        stays free of operator input and model output content.
        """
        level = AUDIT_LEVEL if status == "ok" else LogLevel.ERROR
        summary = f"llm.{status} provider={provider or '-'} model={model or '-'} egress={egress_decision}"
        if note:
            summary = f"{summary} ({note})"
        data: Dict[str, Any] = {
            "call_id": call_id,
            "status": status,
            "prompt_sha256": prompt_sha256,
            "provider": provider,
            "model": model,
            "latency_ms": int(latency_ms),
            "usage": dict(usage or {}),
            "egress_decision": egress_decision,
            "egress_policy": self.registry.egress_policy,
            "purpose": purpose,
        }
        if temperature is not None:
            data["temperature"] = temperature
        if max_tokens is not None:
            data["max_tokens"] = max_tokens
        if note:
            data["note"] = note
        if error is not None:
            data["error_type"] = type(error).__name__
            data["error"] = str(error)[:500]
        try:
            self.warlog.log(
                summary,
                level=level,
                module=MODULE,
                target=target or model or purpose,
                data=data,
            )
        except Exception:  # evidence failure must never mask the call result
            logger.exception("WarLog write failed for brain call %s", call_id)


__all__ = [
    "AUDIT_LEVEL",
    "BrainResponse",
    "EGRESS_DECISION_CLOUD_BLOCKED",
    "EGRESS_DECISION_CLOUD_PERMITTED",
    "EGRESS_DECISION_LOCAL",
    "EgressViolation",
    "FrostyBrain",
    "MODULE",
]
