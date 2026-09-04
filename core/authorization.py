"""THE VOID — Authorization & scope gate.

Enforces operator-authorized engagement scope before any recon or exploit
pipeline runs. Designed for client demos and enterprise ROE compliance.

Authorization file format (JSON or YAML)::

    {
      "engagement_name": "Authorized Local Lab",
      "operator": "shadow-operator",
      "authorized": true,
      "allow_out_of_scope": false,
      "in_scope": [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "stage.demo.void",
        "http://127.0.0.1:8080"
      ],
      "out_of_scope": [
        "0.0.0.0/0"
      ],
      "allowed_modes": ["quick", "full", "stealth"],
      "denied_phases": ["destruction", "crypto_theft", "persistent_exfil"],
      "notes": "Lab only — no production systems."
    }

Missing authorization always fails closed. Documents require explicit consent,
operator identity, scope, modes, and a timezone-aware validity window. The old
require_authorization argument is accepted only for source compatibility.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

logger = logging.getLogger("void.authorization")


@dataclass
class AuthzDecision:
    """Result of an authorization check."""

    allowed: bool
    reason: str
    engagement_name: str = ""
    operator: str = ""
    matched_scope: Optional[str] = None
    denied_phases: List[str] = field(default_factory=list)
    allowed_modes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "engagement_name": self.engagement_name,
            "operator": self.operator,
            "matched_scope": self.matched_scope,
            "denied_phases": list(self.denied_phases),
            "allowed_modes": list(self.allowed_modes),
        }


def _load_raw(path: str) -> Dict[str, Any]:
    """Load JSON or YAML authorization document."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    # Prefer JSON; fall back to YAML if available.
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Cannot parse authorization file {path}: {exc}") from exc
    raise ValueError(f"Authorization file {path} did not contain an object")


def _host_from_target(value: str) -> str:
    """Extract host/IP from a target string (URL, host:port, bare host)."""
    v = (value or "").strip()
    if not v:
        return ""
    if "://" in v:
        parsed = urlparse(v)
        host = parsed.hostname or ""
        return host
    # host:port
    if re.match(r"^\[[\da-fA-F:]+\]:\d+$", v):  # [ipv6]:port
        return v.split("]:", 1)[0].lstrip("[")
    if v.count(":") == 1 and not v.startswith("["):
        host, _, port = v.partition(":")
        if port.isdigit():
            return host
    return v


def _ip_in_networks(ip_str: str, networks: Sequence[str]) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net in networks:
        try:
            network = ipaddress.ip_network(net, strict=False)
            if ip in network:
                return net
        except ValueError:
            continue
    return None


def _hostname_matches(host: str, patterns: Sequence[str], *, deny_subdomains: bool = False) -> Optional[str]:
    host_l = host.lower().rstrip(".")
    for pat in patterns:
        p = pat.strip().lower()
        if not p or "/" in p:  # skip CIDR here
            continue
        if p.startswith("http://") or p.startswith("https://"):
            p = _host_from_target(p).lower()
        if host_l == p or (deny_subdomains and host_l.endswith("." + p)):
            return pat
        # simple glob: *.example.com
        if p.startswith("*."):
            suffix = p[1:]  # .example.com
            if host_l.endswith(suffix) or host_l == p[2:]:
                return pat
    return None


class AuthorizationGate:
    """Scope and ROE gate for engagements."""

    def __init__(
        self,
        authz_path: Optional[str] = None,
        require_authorization: bool = True,
        data: Optional[Dict[str, Any]] = None,
    ):
        self.authz_path = authz_path
        self.require_authorization = True
        self._data: Optional[Dict[str, Any]] = data
        if data is None and authz_path and os.path.isfile(authz_path):
            self._data = _load_raw(authz_path)
            logger.info("Authorization loaded from %s", authz_path)
        elif data is not None:
            logger.info("Authorization loaded from in-memory document")
        else:
            logger.debug(
                "No authorization file (require=%s)", require_authorization
            )

    @property
    def loaded(self) -> bool:
        return self._data is not None

    def check_target(self, target_value: str, mode: str = "full") -> AuthzDecision:
        """Return whether *target_value* may be engaged under *mode*."""
        data = self._data

        if data is None:
            return AuthzDecision(
                allowed=False,
                reason="A valid authorization file is required. Engagement denied.",
            )

        error = self._validation_error(data)
        if error:
            return AuthzDecision(allowed=False, reason=error)

        engagement = str(data.get("engagement_name", "") or "")
        operator = str(data.get("operator", "") or "")
        authorized_flag = data.get("authorized", True)
        if authorized_flag is False:
            return AuthzDecision(
                allowed=False,
                reason="authorization document marks authorized=false",
                engagement_name=engagement,
                operator=operator,
            )

        allowed_modes = [str(m).lower() for m in (data.get("allowed_modes") or [])]
        denied_phases = [str(p) for p in (data.get("denied_phases") or [])]

        if allowed_modes and mode.lower() not in allowed_modes:
            return AuthzDecision(
                allowed=False,
                reason=f"mode '{mode}' not in allowed_modes {allowed_modes}",
                engagement_name=engagement,
                operator=operator,
                denied_phases=denied_phases,
                allowed_modes=allowed_modes,
            )

        in_scope = list(data.get("in_scope") or [])
        out_of_scope = list(data.get("out_of_scope") or [])
        allow_oos = bool(data.get("allow_out_of_scope", False))

        host = _host_from_target(target_value)
        # Explicit out-of-scope first
        oos_ip = _ip_in_networks(host, out_of_scope) if host else None
        oos_host = _hostname_matches(host, out_of_scope, deny_subdomains=True) if host else None
        if oos_ip or oos_host:
            return AuthzDecision(
                allowed=False,
                reason=f"target explicitly out of scope ({oos_ip or oos_host})",
                engagement_name=engagement,
                operator=operator,
                matched_scope=oos_ip or oos_host,
                denied_phases=denied_phases,
                allowed_modes=allowed_modes,
            )

        if not in_scope:
            # Authorized doc with empty in_scope → deny if not allow_out_of_scope
            if allow_oos:
                return AuthzDecision(
                    allowed=True,
                    reason="authorized with empty in_scope and allow_out_of_scope",
                    engagement_name=engagement,
                    operator=operator,
                    denied_phases=denied_phases,
                    allowed_modes=allowed_modes,
                )
            return AuthzDecision(
                allowed=False,
                reason="authorization file has empty in_scope",
                engagement_name=engagement,
                operator=operator,
                denied_phases=denied_phases,
                allowed_modes=allowed_modes,
            )

        # Match in-scope
        matched = _ip_in_networks(host, in_scope) if host else None
        if not matched:
            matched = _hostname_matches(host, in_scope) if host else None
        if not matched:
            # Also allow exact string match on full target (URLs listed as-is)
            for entry in in_scope:
                if target_value.rstrip("/") == str(entry).rstrip("/"):
                    matched = entry
                    break
                if host and host == _host_from_target(str(entry)):
                    matched = entry
                    break

        if matched:
            return AuthzDecision(
                allowed=True,
                reason=f"target in scope ({matched})",
                engagement_name=engagement,
                operator=operator,
                matched_scope=str(matched),
                denied_phases=denied_phases,
                allowed_modes=allowed_modes,
            )

        if allow_oos:
            return AuthzDecision(
                allowed=True,
                reason="target not in in_scope but allow_out_of_scope=true",
                engagement_name=engagement,
                operator=operator,
                denied_phases=denied_phases,
                allowed_modes=allowed_modes,
            )

        return AuthzDecision(
            allowed=False,
            reason=f"target '{target_value}' is outside authorized scope",
            engagement_name=engagement,
            operator=operator,
            denied_phases=denied_phases,
            allowed_modes=allowed_modes,
        )

    @staticmethod
    def _validation_error(data: Any) -> Optional[str]:
        if not isinstance(data, dict):
            return "Authorization must be an object."
        if data.get("authorized") is not True:
            return "Authorization requires authorized=true (a JSON boolean)."
        for key in ("operator", "engagement_name"):
            if not isinstance(data.get(key), str) or not data[key].strip():
                return f"Authorization requires {key}."
        for key in ("in_scope", "allowed_modes", "out_of_scope", "denied_phases"):
            values = data.get(key, [])
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value.strip() for value in values
            ):
                return f"Authorization {key} must be a list of nonempty strings."
            if key in {"in_scope", "allowed_modes"} and not values:
                return f"Authorization requires nonempty {key}."
        if data.get("allow_out_of_scope", False) is not False:
            return "Out-of-scope authorization overrides are not permitted."
        try:
            start = datetime.fromisoformat(data["not_before"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            if start.tzinfo is None or end.tzinfo is None or start >= end:
                raise ValueError("invalid interval")
        except (KeyError, ValueError, TypeError, AttributeError):
            return "Authorization requires a valid timezone-aware not_before/expires_at window."
        if not start <= datetime.now(timezone.utc) < end:
            return "Authorization is expired or not yet valid."
        return None

    def filter_phases(self, phases: Sequence[str]) -> List[str]:
        """Remove denied phases from a planned phase list."""
        if self._validation_error(self._data):
            return []
        denied = {str(p) for p in (self._data.get("denied_phases") or [])}
        return [p for p in phases if p not in denied]
