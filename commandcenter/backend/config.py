"""Command center configuration — localhost-only binding."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Project root: commandcenter/backend/config.py → ../../../
_BACKEND_DIR = Path(__file__).resolve().parent
_COMMANDCENTER_DIR = _BACKEND_DIR.parent
PROJECT_ROOT = _COMMANDCENTER_DIR.parent


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the command center backend."""

    host: str = "127.0.0.1"
    port: int = 7070
    # Polling intervals (seconds)
    warlog_poll_interval: float = 1.0
    c2_poll_interval: float = 2.0
    engagement_poll_interval: float = 2.0
    integrity_poll_interval: float = 30.0
    # Frontend static assets (production)
    static_dir: Path = _COMMANDCENTER_DIR / "frontend" / "dist"
    # Session state DB (UI preferences only)
    session_state_db: Path = _COMMANDCENTER_DIR / "session_state.db"
    # Export temp dir for warlog/report downloads
    export_dir: Path = _COMMANDCENTER_DIR / "exports"
    # DEMO MODE runtime — isolated stores for the seeded stage scenario.
    # Wiped and rebuilt deterministically on every enable; never touches the
    # live boneyard/warlog.
    demo_dir: Path = _COMMANDCENTER_DIR / "demo_runtime"
    # CORS for Vite dev server
    cors_origins: tuple[str, ...] = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:7070",
        "http://localhost:7070",
    )

    def assert_localhost(self) -> None:
        """Reject non-localhost bindings. Security hard-stop."""
        forbidden = {"0.0.0.0", "::", "[::]", "*"}
        if self.host in forbidden:
            raise RuntimeError(
                f"Refusing to bind to {self.host!r}. "
                "Command center is localhost-only (127.0.0.1)."
            )
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(
                f"Refusing to bind to {self.host!r}. "
                "Only 127.0.0.1 / localhost / ::1 are permitted."
            )


def load_settings() -> Settings:
    """Load settings from environment with safe defaults."""
    host = os.environ.get("VOID_CC_HOST", "127.0.0.1")
    port = int(os.environ.get("VOID_CC_PORT", "7070"))
    settings = Settings(host=host, port=port)
    settings.assert_localhost()
    return settings
