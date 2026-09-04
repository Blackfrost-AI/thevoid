"""Owner-only local API access token shared by the launcher and web server.

HTTP uses an explicit Bearer header and WebSockets use a subprotocol token.
Cookies are deliberately avoided: cookies are not isolated between local ports.
"""

from __future__ import annotations

import fcntl
import hmac
import html
import os
import re
import secrets

from config.paths import get_runtime_paths
from core.private_storage import private_directory, private_file


def access_token(port: int, *, create: bool = False) -> str:
    root = get_runtime_paths().runtime
    if create:
        private_directory(root)
    path = root / f"command-center-{port}.token"
    with os.fdopen(private_file(path, create=create), "r+", encoding="ascii") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        value = handle.read(128)
        if not value and create:
            value = secrets.token_hex(32)
            handle.write(value + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        value = value.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise RuntimeError(
                "Invalid local access token; restore it or rotate it with the server stopped."
            )
        return value


def token_matches(expected: str, supplied: str | None) -> bool:
    return isinstance(supplied, str) and hmac.compare_digest(expected.encode(), supplied.encode())


def browser_url(port: int) -> str:
    # A fragment is not transmitted in HTTP requests or normal access logs.
    return f"http://127.0.0.1:{port}/#access_token={access_token(port)}"


def browser_bootstrap(port: int) -> str:
    """Pass a private file URI to the browser, never a secret-bearing argv URL."""
    root = private_directory(get_runtime_paths().runtime)
    path = root / f"command-center-{port}-open.html"
    destination = html.escape(browser_url(port), quote=True)
    content = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer">'
        f'<meta http-equiv="refresh" content="0;url={destination}">'
        "<title>Open THE VOID</title>"
        f'<a href="{destination}">Open the local operator console</a></html>'
    )
    with os.fdopen(private_file(path), "r+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        handle.write(content)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
    return path.as_uri()
