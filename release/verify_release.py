#!/usr/bin/env python3
"""Verify THE VOID release payloads without installing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from core.licensing import verify_license_document

RELEASE_SCHEMA = "blackfrost-release/v1"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_UNHASHED_FILES = {
    "BUNDLE.json",
    "SHA256SUMS",
    "SHA256SUMS.sig",
    "license/license.json",
}


def _tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required verification tool is missing: {name}")
    return path


def _verification_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("VOID_LICENSE_KEY_PASSPHRASE", None)
    env.pop("VOID_RELEASE_SIGNING_KEY_PASSWORD", None)
    return env


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"checksum contains an unsafe path: {relative}") from exc
    return candidate


def verify_hashes(root: Path) -> int:
    unsupported = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_symlink() or not (path.is_file() or path.is_dir())
    )
    if unsupported:
        raise RuntimeError(
            "release contains unsupported filesystem entries: "
            + ", ".join(unsupported)
        )
    sums = root / "SHA256SUMS"
    try:
        lines = sums.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError("SHA256SUMS is missing") from exc
    checked = 0
    seen: set[str] = set()
    for line in lines:
        digest, separator, relative = line.partition("  ")
        if not separator or not HASH_RE.fullmatch(digest) or not relative:
            raise RuntimeError("SHA256SUMS contains an invalid line")
        if relative in seen:
            raise RuntimeError(f"duplicate checksum entry: {relative}")
        seen.add(relative)
        path = _safe_member(root, relative)
        if not path.is_file() or sha256(path) != digest:
            raise RuntimeError(f"checksum failed: {relative}")
        checked += 1
    if not checked:
        raise RuntimeError("SHA256SUMS contains no files")
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
    }
    unexpected = sorted(actual - seen - ALLOWED_UNHASHED_FILES)
    if unexpected:
        raise RuntimeError(
            "release contains files not covered by its signed checksums: "
            + ", ".join(unexpected)
        )
    return checked


def _verify_release_signature(
    root: Path,
    public_key: Path | None,
    required: bool,
    expected_key_sha256: str | None,
) -> bool:
    signature = root / "SHA256SUMS.sig"
    if not signature.is_file():
        if required:
            raise RuntimeError("production release signature is missing")
        return False
    if signature.stat().st_size != 64:
        raise RuntimeError("release signature is not a valid Ed25519 signature size")
    if required and public_key is None:
        raise RuntimeError(
            "production verification requires an out-of-band release public key"
        )
    if public_key is None:
        return False
    key = public_key
    if not key.is_file():
        raise RuntimeError("release public key is missing")
    try:
        key.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError(
            "refusing a release public key located inside the payload"
        )
    if not isinstance(expected_key_sha256, str) or not HASH_RE.fullmatch(
        expected_key_sha256
    ):
        raise RuntimeError("release manifest has an invalid release key fingerprint")
    if sha256(key) != expected_key_sha256:
        raise RuntimeError("release public key fingerprint does not match manifest")
    subprocess.run(  # noqa: S603 - resolved executable and fixed flags
        [
            _tool("openssl"),
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(key),
            "-rawin",
            "-in",
            str(root / "SHA256SUMS"),
            "-sigfile",
            str(signature),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        env=_verification_env(),
    )
    return True


def _deb_field(package: Path, field: str) -> str:
    return subprocess.run(  # noqa: S603 - resolved executable and fixed flags
        [_tool("dpkg-deb"), "--field", str(package), field],
        check=True,
        capture_output=True,
        text=True,
        env=_verification_env(),
    ).stdout.strip()


def _verify_debs(root: Path, release: dict[str, Any]) -> list[dict[str, str]]:
    expected = release.get("packages")
    if not isinstance(expected, list) or len(expected) != 2:
        raise RuntimeError("release manifest must name the two packages")
    packages: list[dict[str, str]] = []
    expected_names = {"blackfrost-the-void", "blackfrost-the-void-snowblind"}
    for filename in expected:
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise RuntimeError("release manifest contains an unsafe package name")
        package = root / "packages" / filename
        if not package.is_file():
            raise RuntimeError(f"package is missing: {filename}")
        name = _deb_field(package, "Package")
        version = _deb_field(package, "Version")
        architecture = _deb_field(package, "Architecture")
        if name not in expected_names:
            raise RuntimeError(f"unexpected Debian package identity: {name}")
        if not version.startswith(f"{release['version']}-"):
            raise RuntimeError(f"package version mismatch: {filename}")
        if architecture != release.get("architecture"):
            raise RuntimeError(f"package architecture mismatch: {filename}")
        listing = subprocess.run(  # noqa: S603 - resolved executable and fixed flags
            [_tool("dpkg-deb"), "--contents", str(package)],
            check=True,
            capture_output=True,
            text=True,
            env=_verification_env(),
        ).stdout
        if name == "blackfrost-the-void":
            required_paths = (
                "./usr/bin/thevoid",
                "./usr/bin/thevoid-command-center",
                "commandcenter/frontend/dist/index.html",
                "license-public.pem",
            )
        else:
            required_paths = ("./usr/bin/snowblind", "snowblind/snow.py")
        if any(item not in listing for item in required_paths):
            raise RuntimeError(f"package is missing required files: {filename}")
        packages.append({"file": filename, "package": name, "version": version})
    if {item["package"] for item in packages} != expected_names:
        raise RuntimeError("release does not contain both expected package identities")
    return packages


def _verify_optional_license(root: Path, release: dict[str, Any]) -> dict[str, Any] | None:
    license_file = root / "license" / "license.json"
    if not license_file.is_file():
        return None
    key = root / "trust" / "license-public.pem"
    try:
        document = json.loads(license_file.read_text(encoding="utf-8"))
        key_bytes = key.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("customer license or verification key is unreadable") from exc
    if not isinstance(document, dict):
        raise RuntimeError("customer license is not a JSON object")
    status = verify_license_document(document, key_bytes)
    if not status.permitted:
        raise RuntimeError(f"customer license failed verification: {status.state}")
    if status.product_version != release.get("version"):
        raise RuntimeError("customer license version does not match the release")
    return status.public_dict()


def verify_release(
    root: Path,
    *,
    release_public_key: Path | None = None,
    allow_development: bool = False,
) -> dict[str, Any]:
    root = root.expanduser().absolute()
    try:
        release = json.loads((root / "RELEASE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("RELEASE.json is missing or invalid") from exc
    if not isinstance(release, dict) or release.get("schema") != RELEASE_SCHEMA:
        raise RuntimeError("unsupported release manifest")
    for field in ("version", "architecture"):
        if not isinstance(release.get(field), str) or not release[field]:
            raise RuntimeError(f"release manifest has an invalid {field}")
    checked = verify_hashes(root)
    development = release.get("development") is True
    if development and not allow_development:
        raise RuntimeError(
            "development releases require explicit --development verification"
        )
    signed = _verify_release_signature(
        root,
        release_public_key,
        required=not development,
        expected_key_sha256=release.get("release_verifier_sha256"),
    )
    packages = _verify_debs(root, release)
    license_status = _verify_optional_license(root, release)
    return {
        "ok": True,
        "root": str(root),
        "version": release.get("version"),
        "architecture": release.get("architecture"),
        "development": development,
        "signed": signed,
        "files_verified": checked,
        "packages": packages,
        "license": license_status,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_dir")
    parser.add_argument(
        "--release-public-key",
        help="trusted out-of-band Ed25519 public key (required for production)",
    )
    parser.add_argument(
        "--development",
        action="store_true",
        help="explicitly allow verification of a development payload",
    )
    args = parser.parse_args(argv)
    key = (
        Path(args.release_public_key).expanduser().absolute()
        if args.release_public_key
        else None
    )
    try:
        result = verify_release(
            Path(args.release_dir),
            release_public_key=key,
            allow_development=args.development,
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
