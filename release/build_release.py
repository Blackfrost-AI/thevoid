#!/usr/bin/env python3
"""Build reproducible Kali ``.deb`` release payloads from tracked sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from config.defaults import AGENT_VERSION

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
PACKAGE_REVISION = "1"
WHEELHOUSE_SCHEMA = "blackfrost-wheelhouse/v1"
RELEASE_SCHEMA = "blackfrost-release/v1"
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+~][A-Za-z0-9.]+)?$")

APP_PREFIXES = (
    "agent/",
    "c2/",
    "cli/",
    "config/",
    "core/",
    "exploit/",
    "llm/",
    "modules/",
    "orchestrator/",
    "recon/",
    "scenarios/",
    "snowblind/",
    "Frosty/",
    "mcp-tools/mcp-scanner/",
    "commandcenter/backend/",
    "commandcenter/frontend/dist/",
)
APP_FILES = {
    "run.py",
    "commandcenter/__init__.py",
    "commandcenter/launcher.py",
}
SOURCE_EXCLUDES = (
    "/__pycache__/",
    ".pyc",
    ".pyo",
    ".db",
    ".log",
)


def _run(
    argv: list[str],
    *,
    expose_release_password: bool = False,
    **kwargs,
) -> subprocess.CompletedProcess:
    # All callers construct argument vectors from fixed tools and validated
    # paths; shell execution is never enabled.
    supplied_env = kwargs.pop("env", None)
    child_env = (os.environ if supplied_env is None else supplied_env).copy()
    child_env.pop("VOID_LICENSE_KEY_PASSPHRASE", None)
    if not expose_release_password:
        child_env.pop("VOID_RELEASE_SIGNING_KEY_PASSWORD", None)
    return subprocess.run(  # noqa: S603
        argv,
        check=True,
        text=True,
        env=child_env,
        **kwargs,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_output(*args: str) -> str:
    return _run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
    ).stdout.strip()


def _git_clean() -> bool:
    return not _git_output("status", "--porcelain", "--untracked-files=normal")


def _source_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if value:
        return int(value)
    return int(_git_output("show", "-s", "--format=%ct", "HEAD"))


def _architecture() -> str:
    return _run(
        ["dpkg", "--print-architecture"],
        capture_output=True,
    ).stdout.strip()


def _load_ed25519_public_key(path: Path, purpose: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"could not load {purpose} public key: {path}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError(f"{purpose} public key must be Ed25519")
    return key


def _validate_release_signing_pair(private_path: Path, public_path: Path) -> None:
    if private_path.is_symlink() or not private_path.is_file():
        raise RuntimeError("release signing key must be a regular file")
    if private_path.stat().st_mode & 0o077:
        raise RuntimeError("release signing key permissions must be owner-only")
    password = os.environ.get("VOID_RELEASE_SIGNING_KEY_PASSWORD", "")
    if not password:
        raise RuntimeError("VOID_RELEASE_SIGNING_KEY_PASSWORD is required")
    try:
        private_bytes = private_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"release signing key is unreadable: {private_path}") from exc
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" not in private_bytes:
        raise RuntimeError("production release signing key must be encrypted")
    try:
        private_key = serialization.load_pem_private_key(
            private_bytes,
            password=password.encode("utf-8"),
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("release signing key or password is invalid") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("release signing key must be Ed25519")
    public_key = _load_ed25519_public_key(public_path, "release verification")
    private_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if private_raw != public_raw:
        raise RuntimeError("release signing and public keys do not match")


def verify_wheelhouse(wheelhouse: Path, requirements: Path) -> dict:
    manifest_path = wheelhouse / "wheelhouse-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid wheelhouse manifest: {manifest_path}") from exc
    if manifest.get("schema") != WHEELHOUSE_SCHEMA:
        raise RuntimeError("unsupported wheelhouse manifest schema")
    if manifest.get("requirements_sha256") != _sha256(requirements):
        raise RuntimeError("wheelhouse was prepared from a different requirements file")
    expected_python = ".".join(platform.python_version().split(".")[:2])
    manifest_python = ".".join(str(manifest.get("python", "")).split(".")[:2])
    if manifest_python != expected_python:
        raise RuntimeError(
            f"wheelhouse targets Python {manifest_python}, builder is {expected_python}"
        )
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("wheelhouse manifest has no files")
    expected_names: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise RuntimeError("wheelhouse manifest contains an invalid entry")
        name = item["name"]
        if Path(name).name != name or not name.endswith(".whl"):
            raise RuntimeError(f"unsafe wheelhouse filename: {name}")
        wheel = wheelhouse / name
        if not wheel.is_file() or _sha256(wheel) != item.get("sha256"):
            raise RuntimeError(f"wheel is missing or has changed: {name}")
        expected_names.add(name)
    actual_names = {path.name for path in wheelhouse.glob("*.whl")}
    if actual_names != expected_names:
        raise RuntimeError("wheelhouse contents do not exactly match its manifest")
    return manifest


def _is_app_source(relative: str) -> bool:
    if relative in APP_FILES:
        return True
    if not relative.startswith(APP_PREFIXES):
        return False
    if any(marker in f"/{relative}" for marker in SOURCE_EXCLUDES):
        return False
    return True


def _source_files(development: bool) -> list[Path]:
    args = ["ls-files", "-z"]
    if development:
        args.extend(["--cached", "--others", "--exclude-standard"])
    raw = _run(["git", *args], cwd=ROOT, capture_output=True).stdout
    files: list[Path] = []
    for relative in raw.split("\0"):
        if not relative or not _is_app_source(relative):
            continue
        source = ROOT / relative
        if source.is_symlink():
            raise RuntimeError(f"application source may not be a symlink: {relative}")
        if source.is_file():
            files.append(source)
    required = {
        "core/boneyard_schema.sql",
        "core/warlog_schema.sql",
        "commandcenter/frontend/dist/index.html",
        "Frosty/AGENTS.md",
        "mcp-tools/mcp-scanner/src/scanner.py",
    }
    present = {str(path.relative_to(ROOT)) for path in files}
    missing = sorted(required - present)
    if missing:
        raise RuntimeError(f"required application sources are missing: {', '.join(missing)}")
    return sorted(files)


def _copy_sources(destination: Path, development: bool) -> None:
    for source in _source_files(development):
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o644)


def _build_frontend(development: bool, skip: bool) -> None:
    frontend = ROOT / "commandcenter" / "frontend"
    if not skip:
        _run(["npm", "ci", "--no-audit", "--no-fund"], cwd=frontend)
        _run(["npm", "run", "build"], cwd=frontend)
    if not (frontend / "dist" / "index.html").is_file():
        raise RuntimeError("Command Center frontend build is missing")
    if not development:
        changed = _run(
            ["git", "status", "--porcelain", "--", "commandcenter/frontend/dist"],
            cwd=ROOT,
            capture_output=True,
        ).stdout.strip()
        if changed:
            raise RuntimeError("frontend build differs from committed dist; commit it first")


def _install_venv(stage: Path, wheelhouse: Path, requirements: Path) -> None:
    venv = stage / "opt" / "blackfrost" / "the-void" / "venv"
    _run([sys.executable, "-m", "venv", str(venv)])
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    _run(
        [
            str(venv / "bin" / "python"),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-compile",
            "--require-hashes",
            "--find-links",
            str(wheelhouse),
            "--requirement",
            str(requirements),
        ],
        env=env,
    )
    result = _run(
        [str(venv / "bin" / "python"), "-m", "pip", "check"],
        capture_output=True,
    )
    if result.stdout.strip() not in {"", "No broken requirements found."}:
        print(result.stdout.strip())
    site_packages = next((venv / "lib").glob("python*/site-packages"), None)
    if site_packages is None:
        raise RuntimeError("could not locate staged venv site-packages")
    (site_packages / "blackfrost_the_void.pth").write_text(
        "/opt/blackfrost/the-void/app\n",
        encoding="utf-8",
    )


def _wrapper(module: str, development: bool) -> str:
    required = "0" if development else "1"
    return f"""#!/bin/sh
set -eu
export PYTHONNOUSERSITE=1
export VOID_REQUIRE_LICENSE={required}
export VOID_LICENSE_FILE=/etc/blackfrost/the-void/license.json
export VOID_LICENSE_PUBLIC_KEY=/usr/share/blackfrost/the-void/license-public.pem
exec /opt/blackfrost/the-void/venv/bin/python -I -m {module} "$@"
"""


def _snowblind_wrapper(development: bool) -> str:
    required = "0" if development else "1"
    return f"""#!/bin/sh
set -eu
export PYTHONNOUSERSITE=1
export VOID_REQUIRE_LICENSE={required}
export VOID_LICENSE_FILE=/etc/blackfrost/the-void/license.json
export VOID_LICENSE_PUBLIC_KEY=/usr/share/blackfrost/the-void/license-public.pem
export SNOW_STATE_DIR=/var/lib/blackfrost/the-void/snowblind
if ! /opt/blackfrost/the-void/venv/bin/python -I -m core.recovery_guard "$@" && \\
   ! /usr/bin/thevoid license status --feature snowblind --json-output >/dev/null; then
    echo "Snowblind requires a valid THE VOID license." >&2
    exit 78
fi
exec /opt/blackfrost/the-void/venv/bin/python -I /opt/blackfrost/the-void/app/snowblind/snow.py "$@"
"""


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _package_size_kib(stage: Path) -> int:
    total = sum(path.stat().st_size for path in stage.rglob("*") if path.is_file())
    return max(1, (total + 1023) // 1024)


def _write_control(
    stage: Path,
    *,
    package: str,
    version: str,
    architecture: str,
    depends: str,
    description: str,
) -> None:
    support_email = os.environ.get("VOID_SUPPORT_EMAIL", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", support_email):
        raise RuntimeError("Set VOID_SUPPORT_EMAIL to an approved, monitored support address before packaging.")
    debian = stage / "DEBIAN"
    debian.mkdir(parents=True, exist_ok=True)
    control = (
        f"Package: {package}\n"
        f"Version: {version}-{PACKAGE_REVISION}\n"
        "Section: admin\n"
        "Priority: optional\n"
        f"Architecture: {architecture}\n"
        f"Depends: {depends}\n"
        f"Maintainer: Blackfrost AI <{support_email}>\n"
        "Homepage: https://blackfrostai.com/void\n"
        f"Installed-Size: {_package_size_kib(stage)}\n"
        f"Description: {description}\n"
    )
    (debian / "control").write_text(control, encoding="utf-8")
    md5_lines: list[str] = []
    for path in sorted(stage.rglob("*")):
        if path.is_file() and debian not in path.parents:
            digest = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
            md5_lines.append(f"{digest}  {path.relative_to(stage)}")
    (debian / "md5sums").write_text("\n".join(md5_lines) + "\n", encoding="utf-8")


def _normalize_mtimes(root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_symlink():
            os.utime(path, (epoch, epoch))
    os.utime(root, (epoch, epoch))


def _normalize_permissions(root: Path) -> None:
    """Remove builder umask/group-write variance from package metadata."""
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            executable = bool(path.stat().st_mode & 0o111)
            path.chmod(0o755 if executable else 0o644)


def _build_deb(stage: Path, output: Path, epoch: int) -> None:
    _normalize_permissions(stage)
    _normalize_mtimes(stage, epoch)
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = str(epoch)
    _run(
        ["dpkg-deb", "--root-owner-group", "--build", str(stage), str(output)],
        env=env,
    )


def _stage_core(
    stage: Path,
    wheelhouse: Path,
    requirements: Path,
    license_public_key: Path | None,
    development: bool,
    version: str,
    architecture: str,
) -> None:
    app = stage / "opt" / "blackfrost" / "the-void" / "app"
    _copy_sources(app, development)
    # The companion owns this subtree so the core can be upgraded separately.
    shutil.rmtree(app / "snowblind", ignore_errors=True)
    _install_venv(stage, wheelhouse, requirements)

    bin_dir = stage / "usr" / "bin"
    _write_executable(bin_dir / "thevoid", _wrapper("cli.app", development))
    _write_executable(bin_dir / "void", _wrapper("run", development))
    _write_executable(
        bin_dir / "thevoid-command-center",
        _wrapper("commandcenter.launcher", development),
    )

    desktop = stage / "usr" / "share" / "applications" / "blackfrost-the-void.desktop"
    desktop.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HERE / "assets" / "blackfrost-the-void.desktop", desktop)
    desktop.chmod(0o644)
    icon = (
        stage
        / "usr"
        / "share"
        / "icons"
        / "hicolor"
        / "scalable"
        / "apps"
        / "blackfrost-the-void.svg"
    )
    icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "commandcenter" / "frontend" / "dist" / "favicon.svg", icon)
    icon.chmod(0o644)

    doc = stage / "usr" / "share" / "doc" / "blackfrost-the-void"
    doc.mkdir(parents=True, exist_ok=True)
    for source, name in (
        (ROOT / "README.md", "README.md"),
        (ROOT / "LICENSE", "LICENSE"),
        (ROOT / "docs" / "OPERATOR_GUIDE.md", "OPERATOR_GUIDE.md"),
    ):
        shutil.copy2(source, doc / name)
        (doc / name).chmod(0o644)

    (stage / "etc" / "blackfrost" / "the-void").mkdir(parents=True, exist_ok=True)
    key_destination = (
        stage / "usr" / "share" / "blackfrost" / "the-void" / "license-public.pem"
    )
    key_destination.parent.mkdir(parents=True, exist_ok=True)
    if license_public_key:
        shutil.copy2(license_public_key, key_destination)
    else:
        key_destination.write_text(
            "DEVELOPMENT BUILD - LICENSE ENFORCEMENT DISABLED\n",
            encoding="utf-8",
        )
    key_destination.chmod(0o644)

    py_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    next_minor = f"{sys.version_info.major}.{sys.version_info.minor + 1}"
    _write_control(
        stage,
        package="blackfrost-the-void",
        version=version,
        architecture=architecture,
        depends=f"python3 (>= {py_minor}), python3 (<< {next_minor}), ca-certificates",
        description="Visual-first, localhost security validation platform.",
    )


def _stage_snowblind(
    stage: Path,
    development: bool,
    version: str,
    architecture: str,
) -> None:
    app = stage / "opt" / "blackfrost" / "the-void" / "app" / "snowblind"
    for source in _source_files(development):
        relative = source.relative_to(ROOT)
        if not str(relative).startswith("snowblind/"):
            continue
        if relative in {Path("snowblind/install.sh"), Path("snowblind/.gitignore")}:
            continue
        target = app / relative.relative_to("snowblind")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o644)
    if not (app / "snow.py").is_file():
        raise RuntimeError("Snowblind sources are missing")

    wrapper = _snowblind_wrapper(development)
    _write_executable(stage / "usr" / "bin" / "snowblind", wrapper)
    _write_executable(stage / "usr" / "bin" / "snow", wrapper)
    tmpfiles = stage / "usr" / "lib" / "tmpfiles.d" / "blackfrost-snowblind.conf"
    tmpfiles.parent.mkdir(parents=True, exist_ok=True)
    tmpfiles.write_text("d /run/tor 0750 debian-tor debian-tor -\n", encoding="utf-8")
    tmpfiles.chmod(0o644)

    doc = stage / "usr" / "share" / "doc" / "blackfrost-the-void-snowblind"
    doc.mkdir(parents=True, exist_ok=True)
    for name in ("README.md", "ACCEPTABLE_USE.md", "LICENSE"):
        shutil.copy2(ROOT / "snowblind" / name, doc / name)
        (doc / name).chmod(0o644)

    _write_control(
        stage,
        package="blackfrost-the-void-snowblind",
        version=version,
        architecture=architecture,
        depends=(
            f"blackfrost-the-void (= {version}-{PACKAGE_REVISION}), tor, torsocks, "
            "macchanger, iptables, iproute2, curl, jq, conntrack, dnsutils"
        ),
        description="Privileged Snowblind companion for authorized Kali operations.",
    )


def _generate_sbom(stage: Path, output: Path, name: str, version: str) -> None:
    if not shutil.which("syft"):
        raise RuntimeError("syft is required to generate release SBOMs")
    _run(
        [
            "syft",
            "scan",
            f"dir:{stage}",
            "--source-name",
            name,
            "--source-version",
            version,
            "--output",
            f"spdx-json={output}",
            "--quiet",
        ]
    )
    output.chmod(0o644)


def _write_hashes(directory: Path) -> Path:
    excluded = {"SHA256SUMS", "SHA256SUMS.sig"}
    paths = [
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name not in excluded
    ]
    sums = directory / "SHA256SUMS"
    sums.write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(directory)}\n"
            for path in sorted(paths)
        ),
        encoding="utf-8",
    )
    sums.chmod(0o644)
    return sums


def _sign_hashes(sums: Path, key: Path, public_key: Path) -> Path:
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL is required to sign a production release")
    signature = sums.with_name("SHA256SUMS.sig")
    _run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key),
            "-passin",
            "env:VOID_RELEASE_SIGNING_KEY_PASSWORD",
            "-rawin",
            "-in",
            str(sums),
            "-out",
            str(signature),
        ],
        expose_release_password=True,
        capture_output=True,
    )
    if not signature.is_file() or signature.stat().st_size != 64:
        raise RuntimeError("OpenSSL did not produce an Ed25519 release signature")
    signature.chmod(0o644)
    _run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key),
            "-rawin",
            "-in",
            str(sums),
            "-sigfile",
            str(signature),
        ],
        capture_output=True,
    )
    return signature


def _install_script(development: bool) -> str:
    trust_setup = (
        ""
        if development
        else """if [ "$#" -ne 1 ]; then
  echo "Usage: sudo ./install.sh /path/to/independently-downloaded-release-signing.pub" >&2
  exit 1
fi
TRUST_KEY_INPUT=$1
case "$TRUST_KEY_INPUT" in
  /*) ;;
  *) TRUST_KEY_INPUT="$(pwd)/$TRUST_KEY_INPUT" ;;
esac
TRUST_KEY=$(readlink -f -- "$TRUST_KEY_INPUT")
DIR_REAL=$(readlink -f -- "$DIR")
test -f "$TRUST_KEY" || {
  echo "The independently downloaded Blackfrost release key was not found." >&2
  exit 1
}
case "$TRUST_KEY" in
  "$DIR_REAL"|"$DIR_REAL"/*)
    echo "Refusing a release key carried inside the download being verified." >&2
    exit 1
    ;;
esac"""
    )
    signature_check = (
        "echo 'Development payload: release signature is intentionally absent.'"
        if development
        else """command -v openssl >/dev/null 2>&1 || {
  echo "OpenSSL is required to verify this commercial release." >&2
  exit 1
}
openssl pkeyutl -verify \\
  -pubin \\
  -inkey "$TRUST_KEY" \\
  -rawin \\
  -in "$DIR/SHA256SUMS" \\
  -sigfile "$DIR/SHA256SUMS.sig" >/dev/null"""
    )
    return f"""#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi
{trust_setup}
cd "$DIR"
{signature_check}
sha256sum --check SHA256SUMS
test -f "$DIR/license/license.json" || {{
  echo "Customer license is missing from this bundle." >&2
  exit 1
}}
apt-get install -y \\
  "$DIR/packages/blackfrost-the-void_{AGENT_VERSION}-{PACKAGE_REVISION}_$(dpkg --print-architecture).deb" \\
  "$DIR/packages/blackfrost-the-void-snowblind_{AGENT_VERSION}-{PACKAGE_REVISION}_$(dpkg --print-architecture).deb"
install -d -m 0755 /etc/blackfrost/the-void
install -m 0644 "$DIR/license/license.json" /etc/blackfrost/the-void/license.json
/usr/bin/thevoid license status
echo "Installation complete. Open THE VOID Command Center from the application menu."
"""


def build(args: argparse.Namespace) -> Path:
    development = bool(args.development)
    if not VERSION_RE.fullmatch(args.version):
        raise RuntimeError(f"invalid release version: {args.version}")
    if args.version != AGENT_VERSION:
        raise RuntimeError(
            f"release version {args.version} does not match AGENT_VERSION {AGENT_VERSION}"
        )
    if args.allow_dirty and not development:
        raise RuntimeError("--allow-dirty is limited to --development builds")
    if not args.allow_dirty and not _git_clean():
        raise RuntimeError("git worktree is not clean")

    architecture = _architecture()
    if not development and architecture != "amd64":
        raise RuntimeError(f"production target must be Kali amd64, got {architecture}")
    if platform.system() != "Linux":
        raise RuntimeError("release packages must be built on Linux")

    requirements = Path(args.requirements).expanduser().absolute()
    wheelhouse = Path(args.wheelhouse).expanduser().absolute()
    verify_wheelhouse(wheelhouse, requirements)
    _build_frontend(development, args.skip_frontend)

    license_public_key: Path | None = None
    if args.license_public_key:
        license_public_key = Path(args.license_public_key).expanduser().absolute()
        _load_ed25519_public_key(license_public_key, "license")
    elif not development:
        raise RuntimeError("production builds require --license-public-key")

    release_signing_key: Path | None = None
    release_public_key: Path | None = None
    if args.release_signing_key:
        release_signing_key = Path(args.release_signing_key).expanduser().absolute()
    if args.release_public_key:
        release_public_key = Path(args.release_public_key).expanduser().absolute()
        _load_ed25519_public_key(release_public_key, "release verification")
    if not development and (release_signing_key is None or release_public_key is None):
        raise RuntimeError(
            "production builds require --release-signing-key and --release-public-key"
        )
    if release_signing_key and release_public_key:
        _validate_release_signing_pair(release_signing_key, release_public_key)

    output_parent = Path(args.output).expanduser().absolute()
    output_parent.mkdir(parents=True, exist_ok=True)
    destination = output_parent / f"the-void-{args.version}-{architecture}"
    if destination.exists():
        raise RuntimeError(f"release destination already exists: {destination}")

    epoch = _source_epoch()
    commit = _git_output("rev-parse", "HEAD")
    if not _git_clean():
        commit += "+dirty"

    work = Path(tempfile.mkdtemp(prefix=".the-void-release-", dir=output_parent))
    try:
        payload = work / destination.name
        packages = payload / "packages"
        trust = payload / "trust"
        packages.mkdir(parents=True)
        trust.mkdir(parents=True)

        core_stage = work / "stage-core"
        snow_stage = work / "stage-snowblind"
        core_stage.mkdir()
        snow_stage.mkdir()
        _stage_core(
            core_stage,
            wheelhouse,
            requirements,
            license_public_key,
            development,
            args.version,
            architecture,
        )
        _stage_snowblind(
            snow_stage,
            development,
            args.version,
            architecture,
        )

        core_name = f"blackfrost-the-void_{args.version}-{PACKAGE_REVISION}_{architecture}.deb"
        snow_name = (
            f"blackfrost-the-void-snowblind_{args.version}-{PACKAGE_REVISION}_{architecture}.deb"
        )
        _generate_sbom(
            core_stage,
            payload / "SBOM.core.spdx.json",
            "blackfrost-the-void",
            args.version,
        )
        _generate_sbom(
            snow_stage,
            payload / "SBOM.snowblind.spdx.json",
            "blackfrost-the-void-snowblind",
            args.version,
        )
        _build_deb(core_stage, packages / core_name, epoch)
        _build_deb(snow_stage, packages / snow_name, epoch)

        if license_public_key:
            shutil.copy2(license_public_key, trust / "license-public.pem")
            (trust / "license-public.pem").chmod(0o644)

        shutil.copy2(HERE / "assets" / "README.customer.txt", payload / "README.txt")
        (payload / "README.txt").chmod(0o644)
        _write_executable(payload / "install.sh", _install_script(development))

        release_document = {
            "schema": RELEASE_SCHEMA,
            "product": "the-void",
            "version": args.version,
            "package_revision": PACKAGE_REVISION,
            "architecture": architecture,
            "python": platform.python_version(),
            "source_commit": commit,
            "source_date_epoch": epoch,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "development": development,
            "license_required": not development,
            "release_verifier_sha256": (
                _sha256(release_public_key) if release_public_key else None
            ),
            "packages": [core_name, snow_name],
        }
        (payload / "RELEASE.json").write_text(
            json.dumps(release_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        _normalize_permissions(payload)
        sums = _write_hashes(payload)
        if release_signing_key and release_public_key:
            _sign_hashes(sums, release_signing_key, release_public_key)
        elif not development:
            raise RuntimeError("production release was not signed")

        payload.replace(destination)
        print(f"Release payload built at {destination}")
        return destination
    finally:
        if work.exists():
            shutil.rmtree(work)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=AGENT_VERSION)
    parser.add_argument("--output", default=str(HERE / "out"))
    parser.add_argument("--requirements", default=str(HERE / "requirements-runtime.txt"))
    parser.add_argument("--wheelhouse", default=str(HERE / "wheelhouse"))
    parser.add_argument("--license-public-key")
    parser.add_argument(
        "--release-signing-key",
        help="encrypted Ed25519 private key used by OpenSSL",
    )
    parser.add_argument(
        "--release-public-key",
        help="out-of-band Ed25519 release verification key",
    )
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--skip-frontend", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        build(args)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
