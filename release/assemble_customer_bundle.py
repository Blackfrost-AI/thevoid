#!/usr/bin/env python3
"""Assemble one store-ready customer archive from a verified generic release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.licensing import verify_license_document
from release.verify_release import sha256, verify_release

BUNDLE_SCHEMA = "blackfrost-customer-bundle/v1"


def _load_license(path: Path, public_key: Path, release_version: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        public_key_bytes = public_key.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("license or license public key is unreadable") from exc
    if not isinstance(document, dict):
        raise RuntimeError("license must be a JSON object")
    status = verify_license_document(document, public_key_bytes)
    if not status.permitted:
        raise RuntimeError(f"license verification failed: {status.state}")
    if status.product_version != release_version:
        raise RuntimeError("license product version does not match release")
    required_features = {"core", "command-center", "snowblind"}
    if not required_features.issubset(status.features):
        missing = sorted(required_features - set(status.features))
        raise RuntimeError(f"license is missing bundle features: {', '.join(missing)}")
    return status.public_dict()


def assemble(args: argparse.Namespace) -> Path:
    release_dir = Path(args.release_dir).expanduser().absolute()
    trusted_release_key = Path(args.release_public_key).expanduser().absolute()
    release_result = verify_release(
        release_dir,
        release_public_key=trusted_release_key,
        allow_development=args.development,
    )
    if release_result["development"] and not args.development:
        raise RuntimeError("refusing to distribute a development release")
    if not release_result["signed"] and not args.development:
        raise RuntimeError("refusing to distribute an unsigned release")

    release_doc = json.loads((release_dir / "RELEASE.json").read_text(encoding="utf-8"))
    license_file = Path(args.license).expanduser().absolute()
    license_key = release_dir / "trust" / "license-public.pem"
    license_status = _load_license(license_file, license_key, release_doc["version"])

    output = Path(args.output).expanduser().absolute()
    output.mkdir(parents=True, exist_ok=True)
    token = hashlib.sha256(str(license_status["license_id"]).encode("utf-8")).hexdigest()[:12]
    stem = (
        f"the-void-{release_doc['version']}-linux-"
        f"{release_doc['architecture']}-{token}"
    )
    archive = output / f"{stem}.tar.zst"
    metadata_path = output / f"{stem}.metadata.json"
    checksum_path = output / f"{stem}.sha256"
    for target in (archive, metadata_path, checksum_path):
        if target.exists():
            raise RuntimeError(f"refusing to overwrite existing bundle output: {target}")

    work = Path(tempfile.mkdtemp(prefix=".customer-bundle-", dir=output))
    try:
        bundle_root = work / stem
        shutil.copytree(release_dir, bundle_root)
        license_destination = bundle_root / "license" / "license.json"
        license_destination.parent.mkdir(parents=True)
        license_destination.parent.chmod(0o755)
        shutil.copy2(license_file, license_destination)
        license_destination.chmod(0o644)

        bundle_doc = {
            "schema": BUNDLE_SCHEMA,
            "product": "the-void",
            "version": release_doc["version"],
            "architecture": release_doc["architecture"],
            "source_commit": release_doc["source_commit"],
            "customer_id": license_status["customer_id"],
            "license_id": license_status["license_id"],
            "expires_at": license_status["expires_at"],
            "assembled_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "release_signature": "SHA256SUMS.sig",
            "license_signature": "license/license.json",
        }
        (bundle_root / "BUNDLE.json").write_text(
            json.dumps(bundle_doc, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (bundle_root / "BUNDLE.json").chmod(0o644)

        epoch = int(release_doc["source_date_epoch"])
        staged_archive = work / archive.name
        env = os.environ.copy()
        env.pop("VOID_LICENSE_KEY_PASSPHRASE", None)
        env.pop("VOID_RELEASE_SIGNING_KEY_PASSWORD", None)
        env["ZSTD_CLEVEL"] = "19"
        tar_binary = shutil.which("tar")
        if not tar_binary:
            raise RuntimeError("GNU tar is required to create the customer bundle")
        subprocess.run(  # noqa: S603 - resolved tool, fixed flags, validated paths
            [
                tar_binary,
                "--create",
                "--zstd",
                "--file",
                str(staged_archive),
                "--sort=name",
                f"--mtime=@{epoch}",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "--directory",
                str(work),
                stem,
            ],
            check=True,
            env=env,
        )
        staged_archive.replace(archive)
        archive.chmod(0o644)
        archive_hash = sha256(archive)
        checksum_path.write_text(f"{archive_hash}  {archive.name}\n", encoding="utf-8")
        checksum_path.chmod(0o644)
        metadata = {
            **bundle_doc,
            "archive": archive.name,
            "sha256": archive_hash,
            "bytes": archive.stat().st_size,
        }
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        metadata_path.chmod(0o644)
        print(f"Customer bundle: {archive}")
        print(f"SHA-256: {archive_hash}")
        return archive
    finally:
        if work.exists():
            shutil.rmtree(work)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--license", required=True)
    parser.add_argument(
        "--release-public-key",
        required=True,
        help="trusted release key from outside the payload",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--development", action="store_true")
    args = parser.parse_args(argv)
    try:
        assemble(args)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
