"""THE VOID — local-first LLM provider layer.

Frosty's reasoning runs on models the operator controls. The default policy
is **zero egress**: requests only ever leave the machine if the operator
explicitly opts into cloud providers via VOID_LLM_EGRESS=cloud.

Providers
    ollama        — local Ollama server (OpenAI-compatible /v1 endpoints)
    llama.cpp     — any OpenAI-compatible server (llama.cpp server, vLLM,
                    LM Studio, …) pointed at a local or lab base_url
    anthropic     — cloud, requires egress opt-in
    openai        — cloud, requires egress opt-in

Every call is WarLog-audited by FrostyBrain: model, provider, latency,
prompt hash, and the egress decision are recorded as evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("void.llm.providers")

# ─── Egress policy ───────────────────────────────────────────────────────────

EGRESS_LOCAL_ONLY = "local_only"     # default: local providers only
EGRESS_CLOUD_ALLOWED = "cloud_allowed"

def resolve_egress_policy(value: Optional[str] = None) -> str:
    raw = value if value is not None else os.environ.get("VOID_LLM_EGRESS", "")
    raw = (raw or "").strip().lower()
    if raw in ("", EGRESS_LOCAL_ONLY, "local", "off"):
        return EGRESS_LOCAL_ONLY
    if raw in (EGRESS_CLOUD_ALLOWED, "cloud", "on"):
        return EGRESS_CLOUD_ALLOWED
    raise ValueError(
        f"Invalid LLM egress policy {raw!r}; expected "
        f"'{EGRESS_LOCAL_ONLY}' or '{EGRESS_CLOUD_ALLOWED}'"
    )


class EgressViolation(RuntimeError):
    """Raised when a cloud provider is used under a local-only policy."""


# ─── Response / provider base ────────────────────────────────────────────────

@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str
    latency_ms: int
    usage: Dict[str, int] = field(default_factory=dict)
    local: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "model": self.model,
            "provider": self.provider,
            "latency_ms": self.latency_ms,
            "usage": self.usage,
            "local": self.local,
        }


class LLMProvider:
    """Base provider. Subclasses implement ``_chat`` and set ``local``."""

    name: str = "base"
    local: bool = False

    def __init__(self, model: str, base_url: str, api_key: str = ""):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    # -- public API ----------------------------------------------------------
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        start = time.monotonic()
        text, usage = self._chat(messages, temperature=temperature, max_tokens=max_tokens)
        latency = int((time.monotonic() - start) * 1000)
        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.name,
            latency_ms=latency,
            usage=usage,
            local=self.local,
        )

    def available(self) -> bool:
        try:
            return self._probe()
        except Exception:
            return False

    # -- subclass hooks ------------------------------------------------------
    def _chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> "tuple[str, Dict[str, int]]":
        raise NotImplementedError

    def _probe(self) -> bool:
        raise NotImplementedError


# ─── OpenAI-compatible providers (Ollama, llama.cpp/vLLM/LM Studio) ──────────

class OpenAICompatProvider(LLMProvider):
    """Works against any OpenAI-compatible /v1/chat/completions server.

    Default base_url is the local Ollama server; override via
    ``base_url`` for llama.cpp server, vLLM, LM Studio, etc.
    """

    name = "openai_compat"
    local = True

    def __init__(
        self,
        model: str,
        base_url: str = "http://127.0.0.1:11434/v1",
        api_key: str = "",
    ):
        super().__init__(model=model, base_url=base_url, api_key=api_key)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _chat(self, messages, temperature=0.2, max_tokens=1024):
        import requests

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=self._headers(),
            timeout=120,
        )
        resp.raise_for_status()
        body = resp.json()
        text = body["choices"][0]["message"]["content"]
        usage = dict(body.get("usage") or {})
        return text, usage

    def _probe(self) -> bool:
        import requests

        resp = requests.get(f"{self.base_url}/models", timeout=5)
        return resp.status_code == 200


class OllamaProvider(OpenAICompatProvider):
    name = "ollama"
    local = True

    def __init__(self, model: str, base_url: str = ""):
        super().__init__(
            model=model,
            base_url=base_url or os.environ.get(
                "OLLAMA_HOST", "http://127.0.0.1:11434/v1"
            ),
        )


# ─── Cloud providers (egress-gated) ─────────────────────────────────────────

class AnthropicProvider(LLMProvider):
    name = "anthropic"
    local = False

    def __init__(self, model: str, api_key: str = ""):
        super().__init__(
            model=model,
            base_url="https://api.anthropic.com/v1",
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
        )

    def _chat(self, messages, temperature=0.2, max_tokens=1024):
        import requests

        system = "\n".join(
            m["content"] for m in messages if m.get("role") == "system"
        )
        chat = [m for m in messages if m.get("role") != "system"]
        payload = {
            "model": self.model,
            "messages": chat,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        resp = requests.post(
            f"{self.base_url}/messages",
            json=payload,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            timeout=120,
        )
        resp.raise_for_status()
        body = resp.json()
        text = "".join(
            block.get("text", "") for block in body.get("content", [])
        )
        usage = dict(body.get("usage") or {})
        return text, usage

    def _probe(self) -> bool:
        return bool(self.api_key)


class OpenAIProvider(OpenAICompatProvider):
    name = "openai"
    local = False

    def __init__(self, model: str, api_key: str = ""):
        super().__init__(
            model=model,
            base_url="https://api.openai.com/v1",
            api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
        )

    def _probe(self) -> bool:
        return bool(self.api_key)


# ─── Registry ────────────────────────────────────────────────────────────────

class ProviderRegistry:
    """Ordered provider pool with egress policy enforcement.

    Priority order is local-first: the registry only falls through to a
    cloud provider when every local provider is unavailable *and* the
    egress policy allows cloud calls.
    """

    def __init__(self, egress_policy: Optional[str] = None):
        self.egress_policy = resolve_egress_policy(egress_policy)
        self._providers: List[LLMProvider] = []

    def register(self, provider: LLMProvider) -> None:
        if not provider.local and self.egress_policy == EGRESS_LOCAL_ONLY:
            logger.info(
                "Provider %s is cloud-based; refusing registration under "
                "local-only egress policy (set VOID_LLM_EGRESS=cloud to opt in)",
                provider.name,
            )
            return
        self._providers.append(provider)

    @property
    def providers(self) -> List[LLMProvider]:
        return list(self._providers)

    def pick(self) -> LLMProvider:
        """First *available* provider, local-first regardless of registration
        order. Cloud providers are only considered after every local provider
        is unavailable. Raises if none."""
        ordered = [p for p in self._providers if p.local] + [
            p for p in self._providers if not p.local
        ]
        for provider in ordered:
            if provider.available():
                return provider
        raise RuntimeError(
            "No LLM provider available. Local-first default: start Ollama "
            "(ollama serve) or point VOID_LLM_BASE_URL at an OpenAI-compatible "
            "server. Cloud providers require VOID_LLM_EGRESS=cloud."
        )

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        provider = self.pick()
        if not provider.local and self.egress_policy == EGRESS_LOCAL_ONLY:
            raise EgressViolation(
                f"Provider {provider.name} would send data off-host; "
                f"egress policy is {EGRESS_LOCAL_ONLY}"
            )
        return provider.chat(messages, temperature=temperature, max_tokens=max_tokens)


def default_registry(egress_policy: Optional[str] = None) -> ProviderRegistry:
    """Registry built from environment, local-first.

    VOID_LLM_BASE_URL + VOID_LLM_MODEL → OpenAI-compatible local server.
    OLLAMA_HOST / default Ollama       → OllamaProvider.
    Cloud providers are only registered when egress is allowed AND their
    API keys are present.
    """
    registry = ProviderRegistry(egress_policy=egress_policy)

    base_url = os.environ.get("VOID_LLM_BASE_URL", "")
    model = os.environ.get("VOID_LLM_MODEL", "")
    if base_url and model:
        registry.register(
            OpenAICompatProvider(
                model=model,
                base_url=base_url,
                api_key=os.environ.get("VOID_LLM_API_KEY", ""),
            )
        )

    ollama_model = os.environ.get("OLLAMA_MODEL", "")
    if ollama_model:
        registry.register(OllamaProvider(model=ollama_model))

    if registry.egress_policy == EGRESS_CLOUD_ALLOWED:
        if os.environ.get("ANTHROPIC_API_KEY"):
            registry.register(
                AnthropicProvider(model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"))
            )
        if os.environ.get("OPENAI_API_KEY"):
            registry.register(
                OpenAIProvider(model=os.environ.get("OPENAI_MODEL", "gpt-4.1"))
            )
    return registry


def prompt_hash(messages: List[Dict[str, str]]) -> str:
    """Stable SHA-256 over the canonical message payload (for evidence)."""
    canonical = json.dumps(messages, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()