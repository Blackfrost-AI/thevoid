"""Security invariants for commercial release payload verification."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from release.build_release import (
    _install_script,
    _sign_hashes,
    _validate_release_signing_pair,
)
from release.prepare_wheelhouse import _safe_replace_directory
from release.verify_release import (
    RELEASE_SCHEMA,
    _verify_release_signature,
    verify_hashes,
    verify_release,
)


def _write_sums(root: Path, entries: list[Path]) -> None:
    lines = []
    for path in entries:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(root)}\n")
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def _write_release_key_pair(root: Path, password: bytes) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    private_path = root / "release-signing.key"
    public_path = root / "release-signing.pub"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o644)
    return private_path, public_path


def test_hash_verification_accepts_complete_payload(tmp_path: Path) -> None:
    payload = tmp_path / "RELEASE.json"
    payload.write_text("{}\n", encoding="utf-8")
    _write_sums(tmp_path, [payload])

    assert verify_hashes(tmp_path) == 1


def test_hash_verification_rejects_uncovered_file(tmp_path: Path) -> None:
    payload = tmp_path / "RELEASE.json"
    payload.write_text("{}\n", encoding="utf-8")
    _write_sums(tmp_path, [payload])
    (tmp_path / "unexpected.bin").write_bytes(b"not signed")

    with pytest.raises(RuntimeError, match="not covered"):
        verify_hashes(tmp_path)


def test_hash_verification_rejects_path_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-release-test.bin"
    outside.write_bytes(b"outside")
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(
        f"{digest}  ../{outside.name}\n",
        encoding="utf-8",
    )
    try:
        with pytest.raises(RuntimeError, match="unsafe path"):
            verify_hashes(tmp_path)
    finally:
        outside.unlink(missing_ok=True)


def test_hash_verification_rejects_symlink(tmp_path: Path) -> None:
    payload = tmp_path / "RELEASE.json"
    payload.write_text("{}\n", encoding="utf-8")
    (tmp_path / "linked-release.json").symlink_to(payload)
    _write_sums(tmp_path, [payload])

    with pytest.raises(RuntimeError, match="unsupported filesystem entries"):
        verify_hashes(tmp_path)


def test_development_release_requires_explicit_opt_in(tmp_path: Path) -> None:
    manifest = tmp_path / "RELEASE.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": RELEASE_SCHEMA,
                "version": "1.1.0",
                "architecture": "amd64",
                "development": True,
                "packages": [],
            }
        ),
        encoding="utf-8",
    )
    _write_sums(tmp_path, [manifest])

    with pytest.raises(RuntimeError, match="explicit --development"):
        verify_release(tmp_path)


def test_production_release_requires_external_trust_key(tmp_path: Path) -> None:
    manifest = tmp_path / "RELEASE.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": RELEASE_SCHEMA,
                "version": "1.1.0",
                "architecture": "amd64",
                "development": False,
                "packages": [],
            }
        ),
        encoding="utf-8",
    )
    _write_sums(tmp_path, [manifest])
    (tmp_path / "SHA256SUMS.sig").write_bytes(b"x" * 64)

    with pytest.raises(RuntimeError, match="out-of-band release public key"):
        verify_release(tmp_path)


def test_production_installer_uses_external_key_before_hashes() -> None:
    script = _install_script(development=False)

    assert '-inkey "$TRUST_KEY"' in script
    assert "trust/release-signing.pub" not in script
    assert "Refusing a release key carried inside" in script
    assert script.index("openssl pkeyutl -verify") < script.index(
        "sha256sum --check SHA256SUMS"
    )


def test_detached_release_signature_verifies_and_detects_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = b"ephemeral-release-test-password"
    private_key, public_key = _write_release_key_pair(tmp_path, password)
    release_root = tmp_path / "payload"
    release_root.mkdir()
    sums = release_root / "SHA256SUMS"
    sums.write_text(f"{'0' * 64}  payload.bin\n", encoding="utf-8")
    monkeypatch.setenv("VOID_RELEASE_SIGNING_KEY_PASSWORD", password.decode())

    _validate_release_signing_pair(private_key, public_key)
    signature = _sign_hashes(sums, private_key, public_key)

    assert signature.stat().st_size == 64
    assert _verify_release_signature(
        release_root,
        public_key,
        required=True,
        expected_key_sha256=hashlib.sha256(public_key.read_bytes()).hexdigest(),
    )

    sums.write_text(f"{'1' * 64}  payload.bin\n", encoding="utf-8")
    with pytest.raises(subprocess.CalledProcessError):
        _verify_release_signature(
            release_root,
            public_key,
            required=True,
            expected_key_sha256=hashlib.sha256(public_key.read_bytes()).hexdigest(),
        )


def test_release_verifier_rejects_trust_key_inside_payload(tmp_path: Path) -> None:
    key = tmp_path / "untrusted-release-key.pub"
    key.write_text("not-a-trust-anchor\n", encoding="utf-8")
    (tmp_path / "SHA256SUMS").write_text("placeholder\n", encoding="utf-8")
    (tmp_path / "SHA256SUMS.sig").write_bytes(b"x" * 64)

    with pytest.raises(RuntimeError, match="inside the payload"):
        _verify_release_signature(
            tmp_path,
            key,
            required=True,
            expected_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
        )


def test_wheelhouse_force_refuses_unmarked_directory(tmp_path: Path) -> None:
    destination = tmp_path / "existing-directory"
    destination.mkdir()
    retained = destination / "retain.txt"
    retained.write_text("keep\n", encoding="utf-8")
    staged = tmp_path / "staged-wheelhouse"
    staged.mkdir()

    with pytest.raises(RuntimeError, match="not created as a wheelhouse"):
        _safe_replace_directory(staged, destination, force=True)

    assert retained.read_text(encoding="utf-8") == "keep\n"
    assert staged.is_dir()
