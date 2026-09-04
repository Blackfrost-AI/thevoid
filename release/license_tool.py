#!/usr/bin/env python3
"""Create and inspect offline THE VOID commercial entitlements.

The signing key is an operator/release-system asset and must never be placed in
the source repository or customer bundle.  Production automation should keep
it in a KMS/HSM-backed secret system; this utility also supports an encrypted
PEM for controlled offline release work.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from config.defaults import AGENT_VERSION
from core.licensing import (
    LICENSE_SCHEMA,
    PRODUCT_ID,
    canonical_payload,
    verify_license_document,
)

PASSPHRASE_ENV = "VOID_LICENSE_KEY_PASSPHRASE"  # noqa: S105 - environment variable name
OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _write_new(path: Path, data: bytes, mode: int, force: bool) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise RuntimeError(f"refusing to overwrite {path}; pass --force")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if force:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise RuntimeError(
                    f"refusing to overwrite {path}; pass --force"
                ) from exc
            temporary.unlink()
        os.chmod(path, mode)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _password() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode("utf-8") if value else None


def keygen(args: argparse.Namespace) -> int:
    password = _password()
    if not password and not args.unencrypted:
        raise RuntimeError(
            f"set {PASSPHRASE_ENV} or explicitly pass --unencrypted"
        )
    if password and args.unencrypted:
        raise RuntimeError(
            f"--unencrypted conflicts with the configured {PASSPHRASE_ENV}"
        )
    private_path = Path(args.private_key).expanduser().absolute()
    public_path = Path(args.public_key).expanduser().absolute()
    if private_path == public_path:
        raise RuntimeError("private and public key paths must be different")
    if not args.force:
        existing = [str(path) for path in (private_path, public_path) if path.exists()]
        if existing:
            raise RuntimeError(
                "refusing to replace an existing key-pair member: "
                + ", ".join(existing)
            )

    private_key = Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new(private_path, private_pem, 0o600, args.force)
    _write_new(public_path, public_pem, 0o644, args.force)
    print(f"Created signing key: {private_path}")
    print(f"Created verification key: {public_path}")
    return 0


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        value = serialization.load_pem_private_key(
            path.expanduser().read_bytes(),
            password=_password(),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError("could not load the Ed25519 signing key") from exc
    if not isinstance(value, Ed25519PrivateKey):
        raise RuntimeError("signing key is not Ed25519")
    return value


def issue(args: argparse.Namespace) -> int:
    key = _load_private_key(Path(args.private_key))
    if not OPAQUE_ID_RE.fullmatch(args.customer_id):
        raise RuntimeError("customer ID must be an opaque 1-128 character identifier")
    license_id = args.license_id or str(uuid.uuid4())
    if not OPAQUE_ID_RE.fullmatch(license_id):
        raise RuntimeError("license ID must be an opaque 1-128 character identifier")
    now = _utc_now()
    not_before = _parse_timestamp(args.not_before) if args.not_before else now
    if args.expires_at and args.days is not None:
        raise RuntimeError("choose either --expires-at or --days")
    if args.expires_at:
        expires_at: str | None = _timestamp(_parse_timestamp(args.expires_at))
    elif args.days is not None:
        if args.days <= 0:
            raise RuntimeError("--days must be positive")
        expires_at = _timestamp(not_before + timedelta(days=args.days))
    else:
        expires_at = None

    features = sorted(set(args.feature or ["core", "command-center", "snowblind"]))
    payload: dict[str, Any] = {
        "product": PRODUCT_ID,
        "product_version": args.product_version,
        "customer_id": args.customer_id,
        "license_id": license_id,
        "issued_at": _timestamp(now),
        "not_before": _timestamp(not_before),
        "expires_at": expires_at,
        "features": features,
    }
    signature = base64.b64encode(key.sign(canonical_payload(payload))).decode("ascii")
    document = {
        "schema": LICENSE_SCHEMA,
        "payload": payload,
        "signature": signature,
    }
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_new(Path(args.output), encoded, 0o644, args.force)
    print(f"Issued license {payload['license_id']} for customer {payload['customer_id']}")
    print(f"Wrote: {Path(args.output).expanduser().absolute()}")
    return 0


def verify(args: argparse.Namespace) -> int:
    try:
        document = json.loads(Path(args.license).expanduser().read_text(encoding="utf-8"))
        public_key = Path(args.public_key).expanduser().read_bytes()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("could not read license or public key") from exc
    if not isinstance(document, dict):
        raise RuntimeError("license document must be a JSON object")
    status = verify_license_document(document, public_key)
    print(json.dumps(status.public_dict(), indent=2, sort_keys=True))
    return 0 if status.permitted else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="THE VOID offline license utility")
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("keygen", help="generate an Ed25519 signing key pair")
    generate.add_argument("--private-key", required=True)
    generate.add_argument("--public-key", required=True)
    generate.add_argument("--unencrypted", action="store_true")
    generate.add_argument("--force", action="store_true")
    generate.set_defaults(handler=keygen)

    create = sub.add_parser("issue", help="issue a signed customer entitlement")
    create.add_argument("--private-key", required=True)
    create.add_argument("--customer-id", required=True, help="opaque store/customer ID")
    create.add_argument("--license-id")
    create.add_argument("--product-version", default=AGENT_VERSION)
    create.add_argument("--not-before", help="RFC 3339 timestamp; defaults to now")
    create.add_argument("--expires-at", help="RFC 3339 timestamp")
    create.add_argument("--days", type=int, help="validity in days from not-before")
    create.add_argument("--feature", action="append")
    create.add_argument("--output", required=True)
    create.add_argument("--force", action="store_true")
    create.set_defaults(handler=issue)

    inspect = sub.add_parser("verify", help="verify a signed entitlement")
    inspect.add_argument("--license", required=True)
    inspect.add_argument("--public-key", required=True)
    inspect.set_defaults(handler=verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
