"""Private local files and per-store keys; never silently re-key existing data.

The key files protect database-only copies, not a compromised operator account
or an unencrypted disk image. Full-disk encryption is a separate requirement.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import stat
from pathlib import Path

from config.paths import get_runtime_paths


def private_directory(path: str | Path) -> Path:
    """Create an owner-only directory; reject unsafe existing directories."""
    directory = Path(path)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError(
            f"Storage directory must be owned by this user and not a symlink: {directory}"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(
            f"Storage directory requires owner-only permissions (0700): {directory}"
        )
    return directory


def private_file(path: str | Path, *, create: bool = True) -> int:
    """Open a private regular file without following a final symlink.

    The caller owns the returned descriptor. Existing bytes and permissions
    are never silently changed. Hard links are rejected as well.
    """
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise PermissionError(
            f"Storage file must be a private, owner-held regular file (0600): {path}"
        )
    return fd


def prepare_database(path: str | Path) -> None:
    """Pre-create SQLite files privately and reject unsafe existing sidecars."""
    database = Path(path)
    for candidate in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
        if candidate == database or candidate.exists() or candidate.is_symlink():
            os.close(private_file(candidate))


def store_passphrase(database: str | Path) -> str:
    """Load a distinct random per-store key, or create it for a new store only."""
    database = Path(database).absolute()
    key_dir = private_directory(get_runtime_paths().config / "evidence-keys")
    identifier = hashlib.sha256(os.fsencode(database)).hexdigest()
    key_path = key_dir / f"{identifier}.key"
    lock_fd = private_file(key_dir / ".lock")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if not key_path.exists():
            if database.exists() and database.stat().st_size:
                raise RuntimeError(
                    "Existing evidence has no managed key. Preserve the database and keys; "
                    "a reviewed legacy migration or key restore is required. No re-key was attempted."
                )
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(secrets.token_hex(32) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            directory_fd = os.open(key_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        with os.fdopen(private_file(key_path, create=False), "r", encoding="ascii") as handle:
            value = handle.read(66).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise RuntimeError(
                "Evidence key is invalid; restore the original key. No re-key was attempted."
            )
        return value
    finally:
        os.close(lock_fd)
