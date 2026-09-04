#!/usr/bin/env python3
"""Resolve a binary-only, hashed wheelhouse on the intended Kali builder."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "blackfrost-wheelhouse/v1"
HERE = Path(__file__).resolve().parent


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_replace_directory(staged: Path, destination: Path, force: bool) -> None:
    destination = destination.absolute()
    if destination.exists() and not force:
        raise RuntimeError(f"refusing to replace {destination}; pass --force")
    if destination in {Path("/"), HERE, HERE.parent}:
        raise RuntimeError(f"unsafe wheelhouse destination: {destination}")
    if destination.exists():
        marker = destination / "wheelhouse-manifest.json"
        try:
            prior = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"refusing to replace a directory not created as a wheelhouse: {destination}"
            ) from exc
        if not isinstance(prior, dict) or prior.get("schema") != SCHEMA:
            raise RuntimeError(
                f"refusing to replace a directory with an invalid marker: {destination}"
            )
        shutil.rmtree(destination)
    staged.replace(destination)


def prepare(requirements: Path, destination: Path, force: bool) -> Path:
    requirements = requirements.expanduser().absolute()
    destination = destination.expanduser().absolute()
    if not requirements.is_file():
        raise RuntimeError(f"requirements file not found: {requirements}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".wheelhouse-", dir=destination.parent))
    try:
        subprocess.run(  # noqa: S603 - fixed interpreter/pip subcommand
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--disable-pip-version-check",
                "--only-binary=:all:",
                "--require-hashes",
                "--dest",
                str(staged),
                "--requirement",
                str(requirements),
            ],
            check=True,
        )
        wheels = sorted(staged.glob("*.whl"), key=lambda path: path.name.lower())
        unexpected = [path.name for path in staged.iterdir() if path.suffix != ".whl"]
        if not wheels or unexpected:
            raise RuntimeError(
                "wheelhouse preparation did not produce only wheels"
                + (f" (unexpected: {', '.join(unexpected)})" if unexpected else "")
            )
        shutil.copy2(requirements, staged / "requirements-runtime.txt")
        manifest = {
            "schema": SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "architecture": platform.machine(),
            "platform": sysconfig.get_platform(),
            "requirements_sha256": _sha256(requirements),
            "files": [
                {
                    "name": wheel.name,
                    "sha256": _sha256(wheel),
                    "size": wheel.stat().st_size,
                }
                for wheel in wheels
            ],
        }
        (staged / "wheelhouse-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _safe_replace_directory(staged, destination, force)
        print(f"Prepared {len(wheels)} verified wheels at {destination}")
        return destination
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--requirements",
        default=str(HERE / "requirements-runtime.txt"),
    )
    parser.add_argument("--output", default=str(HERE / "wheelhouse"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        prepare(Path(args.requirements), Path(args.output), args.force)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
