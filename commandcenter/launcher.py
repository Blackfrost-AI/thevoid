"""Safe desktop/terminal launcher for the localhost Command Center."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from config.paths import get_runtime_paths
from commandcenter.session import browser_bootstrap

PROCESS_MARKER = "commandcenter.backend.main"


def _server_path() -> Path:
    return Path(__file__).resolve().parent / "backend" / "main.py"


def _ensure_unprivileged() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise RuntimeError(
            "The Command Center must run as the desktop operator, not root."
        )


def _runtime_files() -> tuple[Path, Path, Path]:
    paths = get_runtime_paths()
    return (
        paths.runtime / "command-center.json",
        paths.runtime / "command-center.lock",
        paths.logs / "command-center.log",
    )


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


@contextmanager
def _launcher_lock() -> Iterator[None]:
    pid_file, lock_file, _ = _runtime_files()
    _secure_directory(pid_file.parent)
    with lock_file.open("a+", encoding="utf-8") as handle:
        try:
            os.chmod(lock_file, 0o600)
        except OSError:
            pass
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def _read_record() -> dict[str, object] | None:
    pid_file, _, _ = _runtime_files()
    try:
        record = json.loads(pid_file.read_text(encoding="utf-8"))
        pid = int(record["pid"])
        if pid <= 1:
            return None
        record["pid"] = pid
        return record
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def _write_record(pid: int, port: int) -> None:
    pid_file, _, _ = _runtime_files()
    _secure_directory(pid_file.parent)
    record = {
        "pid": pid,
        "port": port,
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "process": PROCESS_MARKER,
    }
    fd = os.open(pid_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(pid_file, 0o600)


def _remove_record(expected_pid: int | None = None) -> None:
    pid_file, _, _ = _runtime_files()
    if expected_pid is not None:
        current = _read_record()
        if current is not None and int(current["pid"]) != expected_pid:
            return
    try:
        pid_file.unlink()
    except FileNotFoundError:
        pass


def _process_matches(pid: int) -> bool:
    """Confirm a PID belongs to this user and the expected Python module."""
    proc = Path("/proc") / str(pid)
    try:
        if proc.stat().st_uid != os.geteuid():
            return False
        command = (proc / "cmdline").read_bytes().split(b"\0")
        return os.fsencode(_server_path()) in command
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return False


def _health_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/api/health"


def _health_ok(port: int, timeout: float = 0.75) -> bool:
    request = urllib.request.Request(  # noqa: S310 - fixed localhost HTTP URL
        _health_url(port),
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - request URL is fixed above
            request, timeout=timeout
        ) as response:
            body = json.loads(response.read().decode("utf-8"))
            return (
                response.status == 200
                and body.get("ok") is True
                and body.get("service") == "the-void-command-center"
                and body.get("port") == port
                and not body.get("degraded")
            )
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
        return False


def _port() -> int:
    try:
        value = int(os.environ.get("VOID_CC_PORT", "7070"))
    except ValueError as exc:
        raise RuntimeError("VOID_CC_PORT must be an integer.") from exc
    if not 1 <= value <= 65535:
        raise RuntimeError("VOID_CC_PORT must be between 1 and 65535.")
    return value


def start(*, open_browser: bool = True, wait_seconds: float = 15.0) -> int:
    """Start one background instance and optionally open its browser UI."""
    _ensure_unprivileged()
    port = _port()
    _, _, log_file = _runtime_files()
    _secure_directory(log_file.parent)

    with _launcher_lock():
        current = _read_record()
        if current and _process_matches(int(current["pid"])):
            pid = int(current["pid"])
            port = int(current.get("port", port))
        else:
            _remove_record()
            with log_file.open("ab", buffering=0) as output:
                process = subprocess.Popen(  # noqa: S603 - fixed interpreter and script
                    [sys.executable, "-I", str(_server_path())],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    start_new_session=True,
                )
            pid = process.pid
            _write_record(pid, port)

    deadline = time.monotonic() + max(0.0, wait_seconds)
    while time.monotonic() < deadline:
        if _health_ok(port):
            url = f"http://127.0.0.1:{port}/"
            print(f"THE VOID Command Center is ready at {url}")
            if open_browser:
                webbrowser.open(browser_bootstrap(port), new=2)
            return 0
        if not _process_matches(pid):
            with _launcher_lock():
                _remove_record(expected_pid=pid)
            print(f"Command Center exited during startup. Review {log_file}", file=sys.stderr)
            return 1
        time.sleep(0.2)

    print(f"Command Center did not become healthy. Review {log_file}", file=sys.stderr)
    return 1


def foreground() -> int:
    """Run the localhost server in the current terminal."""
    _ensure_unprivileged()
    from commandcenter.backend.main import main as server_main

    server_main()
    return 0


def stop(*, wait_seconds: float = 10.0) -> int:
    """Gracefully stop the recorded instance without signaling foreign PIDs."""
    _ensure_unprivileged()
    with _launcher_lock():
        record = _read_record()
        if not record:
            _remove_record()
            print("Command Center is not running.")
            return 0
        pid = int(record["pid"])
        if not _process_matches(pid):
            _remove_record(expected_pid=pid)
            print("Removed a stale Command Center PID record.")
            return 0
        os.kill(pid, signal.SIGTERM)

    deadline = time.monotonic() + max(0.0, wait_seconds)
    while time.monotonic() < deadline:
        if not _process_matches(pid):
            with _launcher_lock():
                _remove_record(expected_pid=pid)
            print("Command Center stopped.")
            return 0
        time.sleep(0.2)
    print(
        "Command Center did not stop after SIGTERM; no forced kill was sent.",
        file=sys.stderr,
    )
    return 1


def status() -> int:
    """Report process ownership and HTTP health."""
    record = _read_record()
    if not record or not _process_matches(int(record["pid"])):
        print("Command Center: stopped")
        return 1
    port = int(record.get("port", _port()))
    healthy = _health_ok(port)
    state = "healthy" if healthy else "starting or degraded"
    print(f"Command Center: {state} (pid {record['pid']}, {_health_url(port)})")
    return 0 if healthy else 1


def open_ui() -> int:
    """Open an already-running Command Center in the default browser."""
    _ensure_unprivileged()
    record = _read_record()
    if not record or not _process_matches(int(record["pid"])):
        print("Command Center is not running. Start it first.", file=sys.stderr)
        return 1
    port = int(record.get("port", _port()))
    if not _health_ok(port):
        print("Command Center is not healthy yet.", file=sys.stderr)
        return 1
    webbrowser.open(browser_bootstrap(port), new=2)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thevoid-command-center",
        description="Start and manage THE VOID's localhost visual console.",
    )
    subcommands = parser.add_subparsers(dest="command")
    start_parser = subcommands.add_parser("start", help="start in the background")
    start_parser.add_argument("--no-open", action="store_true", help="do not open a browser")
    subcommands.add_parser("foreground", help="run in the current terminal")
    subcommands.add_parser("stop", help="stop the background instance")
    subcommands.add_parser("status", help="show process and health status")
    subcommands.add_parser("open", help="open the running console in a browser")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "start"
    try:
        if command == "start":
            return start(open_browser=not getattr(args, "no_open", False))
        if command == "foreground":
            return foreground()
        if command == "stop":
            return stop()
        if command == "status":
            return status()
        if command == "open":
            return open_ui()
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
