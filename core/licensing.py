"""Offline Ed25519 entitlement verification for commercial distributions.

Verification is deliberately local: the application never calls a licensing
server and never transmits license contents.  Production wrappers enable the
gate with ``VOID_REQUIRE_LICENSE=1`` and point at the installed entitlement.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from config.paths import get_runtime_paths

LICENSE_SCHEMA = "blackfrost-license/v1"
PRODUCT_ID = "the-void"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


class LicenseError(RuntimeError):
    """Raised when a required commercial entitlement is unavailable."""


@dataclass(frozen=True)
class LicenseStatus:
    """Sanitized entitlement result safe to return through the local API."""

    state: str
    permitted: bool
    required: bool
    message: str
    customer_id: str | None = None
    license_id: str | None = None
    expires_at: str | None = None
    features: tuple[str, ...] = ()
    product_version: str | None = None

    def public_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "permitted": self.permitted,
            "required": self.required,
            "message": self.message,
            "customer_id": self.customer_id,
            "license_id": self.license_id,
            "expires_at": self.expires_at,
            "features": list(self.features),
            "product_version": self.product_version,
        }


def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    """Encode a payload exactly as the signer and verifier expect."""
    return json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an RFC 3339 timestamp")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _invalid(message: str, required: bool = True) -> LicenseStatus:
    return LicenseStatus(
        state="invalid",
        permitted=False,
        required=required,
        message=message,
    )


def verify_license_document(
    document: Mapping[str, Any],
    public_key_pem: bytes,
    *,
    now: datetime | None = None,
    required: bool = True,
    expected_version: str | None = None,
) -> LicenseStatus:
    """Verify signature, schema, product, validity window, and basic fields."""
    try:
        if document.get("schema") != LICENSE_SCHEMA:
            return _invalid("Unsupported license schema.", required)
        payload = document.get("payload")
        signature_text = document.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature_text, str):
            return _invalid("License payload or signature is missing.", required)

        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            return _invalid("License public key is not Ed25519.", required)
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except (binascii.Error, ValueError):
            return _invalid("License signature encoding is invalid.", required)
        key.verify(signature, canonical_payload(payload))

        if payload.get("product") != PRODUCT_ID:
            return _invalid("License is for a different product.", required)

        license_id = payload.get("license_id")
        customer_id = payload.get("customer_id")
        features = payload.get("features", [])
        product_version = payload.get("product_version")
        if not isinstance(license_id, str) or not license_id.strip():
            return _invalid("License ID is missing.", required)
        if not isinstance(customer_id, str) or not customer_id.strip():
            return _invalid("Customer ID is missing.", required)
        if not isinstance(features, list) or not all(
            isinstance(item, str) and item.strip() for item in features
        ):
            return _invalid("License features are invalid.", required)
        if product_version is not None and not isinstance(product_version, str):
            return _invalid("Product version is invalid.", required)

        _parse_timestamp(payload.get("issued_at"), "issued_at")
        not_before = _parse_timestamp(payload.get("not_before"), "not_before")
        expires_raw = payload.get("expires_at")
        expires_at = (
            _parse_timestamp(expires_raw, "expires_at")
            if expires_raw is not None
            else None
        )
        if expires_at is not None and expires_at <= not_before:
            return _invalid("License expiry is earlier than its start time.", required)

        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        common = {
            "required": required,
            "customer_id": customer_id,
            "license_id": license_id,
            "expires_at": expires_raw,
            "features": tuple(sorted(set(features))),
            "product_version": product_version,
        }
        if expected_version is not None and product_version != expected_version:
            return LicenseStatus(
                state="version_mismatch",
                permitted=False,
                message="License is for a different product version.",
                **common,
            )
        if current < not_before:
            return LicenseStatus(
                state="not_yet_valid",
                permitted=False,
                message="License is not valid yet.",
                **common,
            )
        if expires_at is not None and current >= expires_at:
            return LicenseStatus(
                state="expired",
                permitted=False,
                message="License has expired.",
                **common,
            )
        return LicenseStatus(
            state="valid",
            permitted=True,
            message="License signature and validity window are verified.",
            **common,
        )
    except InvalidSignature:
        return _invalid("License signature is invalid.", required)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _invalid("License contents are malformed.", required)
    except Exception:
        # Do not leak parser/library details into browser responses.
        return _invalid("License could not be verified.", required)


def license_required(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get("VOID_REQUIRE_LICENSE", "").strip().lower() in _TRUE_VALUES


def configured_license_status(
    environ: Mapping[str, str] | None = None,
    *,
    now: datetime | None = None,
    required_feature: str | None = "core",
) -> LicenseStatus:
    """Load and verify the configured entitlement, returning safe status."""
    env = os.environ if environ is None else environ
    required = license_required(env)
    paths = get_runtime_paths(env)
    license_path = Path(env.get("VOID_LICENSE_FILE") or paths.license_file).expanduser()
    key_path = Path(
        env.get("VOID_LICENSE_PUBLIC_KEY") or paths.license_public_key
    ).expanduser()

    if not license_path.is_file() or not key_path.is_file():
        if not required:
            return LicenseStatus(
                state="not_required",
                permitted=True,
                required=False,
                message="License enforcement is disabled for this source build.",
            )
        return LicenseStatus(
            state="missing",
            permitted=False,
            required=True,
            message="A signed license and public key are required.",
        )

    try:
        document = json.loads(license_path.read_text(encoding="utf-8"))
        public_key_pem = key_path.read_bytes()
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _invalid("Configured license files could not be read.", required)
    if not isinstance(document, dict):
        return _invalid("License document must be a JSON object.", required)
    from config.defaults import AGENT_VERSION

    status = verify_license_document(
        document,
        public_key_pem,
        now=now,
        required=required,
        expected_version=AGENT_VERSION,
    )
    if (
        status.state == "valid"
        and required_feature
        and required_feature not in status.features
    ):
        return LicenseStatus(
            state="feature_missing",
            permitted=False,
            required=status.required,
            message=f"License does not include the {required_feature} feature.",
            customer_id=status.customer_id,
            license_id=status.license_id,
            expires_at=status.expires_at,
            features=status.features,
            product_version=status.product_version,
        )
    return status


def enforce_license_if_required(
    environ: Mapping[str, str] | None = None,
    *,
    required_feature: str | None = "core",
) -> LicenseStatus:
    """Fail closed only when the commercial wrapper enables enforcement."""
    status = configured_license_status(environ, required_feature=required_feature)
    if status.required and not status.permitted:
        raise LicenseError(
            f"{status.message} Run `thevoid license status` for details."
        )
    return status
