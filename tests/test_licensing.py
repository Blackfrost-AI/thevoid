"""Offline entitlement signing boundaries and application gates."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cli.app import cli
from core.licensing import (
    LICENSE_SCHEMA,
    canonical_payload,
    configured_license_status,
    verify_license_document,
)


def _signed_document(*, expired: bool = False):
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "product": "the-void",
        "product_version": "1.1.0",
        "customer_id": "customer-test-001",
        "license_id": "license-test-001",
        "issued_at": (now - timedelta(days=2)).isoformat(),
        "not_before": (now - timedelta(days=1)).isoformat(),
        "expires_at": (now - timedelta(hours=1) if expired else now + timedelta(days=30)).isoformat(),
        "features": ["core", "command-center", "snowblind"],
    }
    document = {
        "schema": LICENSE_SCHEMA,
        "payload": payload,
        "signature": base64.b64encode(key.sign(canonical_payload(payload))).decode("ascii"),
    }
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return document, public


def test_valid_signed_license_is_permitted():
    document, public = _signed_document()
    status = verify_license_document(document, public)
    assert status.state == "valid"
    assert status.permitted is True
    assert status.customer_id == "customer-test-001"


def test_tampered_license_fails_signature():
    document, public = _signed_document()
    document["payload"]["customer_id"] = "changed"
    status = verify_license_document(document, public)
    assert status.state == "invalid"
    assert status.permitted is False


def test_expired_license_is_rejected():
    document, public = _signed_document(expired=True)
    status = verify_license_document(document, public)
    assert status.state == "expired"
    assert status.permitted is False


def test_configured_license_loads_from_files(tmp_path):
    document, public = _signed_document()
    license_path = tmp_path / "license.json"
    key_path = tmp_path / "public.pem"
    license_path.write_text(json.dumps(document), encoding="utf-8")
    key_path.write_bytes(public)
    status = configured_license_status(
        {
            "VOID_REQUIRE_LICENSE": "1",
            "VOID_LICENSE_FILE": str(license_path),
            "VOID_LICENSE_PUBLIC_KEY": str(key_path),
        }
    )
    assert status.permitted is True


def test_required_license_blocks_operational_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VOID_REQUIRE_LICENSE", "1")
    monkeypatch.setenv("VOID_LICENSE_FILE", str(tmp_path / "missing.json"))
    monkeypatch.setenv("VOID_LICENSE_PUBLIC_KEY", str(tmp_path / "missing.pem"))
    result = CliRunner().invoke(cli, ["status"])
    assert result.exit_code == 1
    assert "signed license" in result.output


def test_license_status_and_version_remain_available(monkeypatch, tmp_path):
    monkeypatch.setenv("VOID_REQUIRE_LICENSE", "1")
    monkeypatch.setenv("VOID_LICENSE_FILE", str(tmp_path / "missing.json"))
    monkeypatch.setenv("VOID_LICENSE_PUBLIC_KEY", str(tmp_path / "missing.pem"))
    runner = CliRunner()
    status = runner.invoke(cli, ["license", "status", "--json-output"])
    version = runner.invoke(cli, ["version", "--json-output"])
    assert status.exit_code == 1
    assert json.loads(status.output)["state"] == "missing"
    assert version.exit_code == 0


def test_required_feature_is_enforced(tmp_path):
    document, _ = _signed_document()
    document["payload"]["features"] = ["core"]
    # Re-sign after changing the authorized feature set.
    key = Ed25519PrivateKey.generate()
    document["signature"] = base64.b64encode(
        key.sign(canonical_payload(document["payload"]))
    ).decode("ascii")
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    license_path = tmp_path / "license.json"
    key_path = tmp_path / "public.pem"
    license_path.write_text(json.dumps(document), encoding="utf-8")
    key_path.write_bytes(public)
    status = configured_license_status(
        {
            "VOID_REQUIRE_LICENSE": "1",
            "VOID_LICENSE_FILE": str(license_path),
            "VOID_LICENSE_PUBLIC_KEY": str(key_path),
        },
        required_feature="command-center",
    )
    assert status.state == "feature_missing"
    assert status.permitted is False


def test_license_tool_round_trip(tmp_path, monkeypatch):
    from release.license_tool import main

    private = tmp_path / "license-signing.pem"
    public = tmp_path / "license-public.pem"
    issued = tmp_path / "issued.json"
    monkeypatch.setenv("VOID_LICENSE_KEY_PASSPHRASE", "test-only-passphrase")
    assert main([
        "keygen",
        "--private-key", str(private),
        "--public-key", str(public),
    ]) == 0
    assert private.stat().st_mode & 0o777 == 0o600
    assert main([
        "issue",
        "--private-key", str(private),
        "--customer-id", "cust_test_01",
        "--license-id", "lic_test_01",
        "--days", "30",
        "--output", str(issued),
    ]) == 0
    assert main([
        "verify",
        "--license", str(issued),
        "--public-key", str(public),
    ]) == 0


def test_license_keygen_preflights_both_outputs(tmp_path, monkeypatch):
    from release.license_tool import main

    private = tmp_path / "existing-private.pem"
    public = tmp_path / "new-public.pem"
    private.write_text("retain-me\n", encoding="utf-8")
    monkeypatch.setenv("VOID_LICENSE_KEY_PASSPHRASE", "test-only-passphrase")

    result = main(
        [
            "keygen",
            "--private-key",
            str(private),
            "--public-key",
            str(public),
        ]
    )

    assert result == 2
    assert private.read_text(encoding="utf-8") == "retain-me\n"
    assert not public.exists()
