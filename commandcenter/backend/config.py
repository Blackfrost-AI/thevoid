"""Command center configuration — localhost-only binding."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from config.paths import get_runtime_paths

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
    session_state_db: Path = field(
        default_factory=lambda: get_runtime_paths().commandcenter_session_db
    )
    # Export temp dir for warlog/report downloads
    export_dir: Path = field(default_factory=lambda: get_runtime_paths().exports)
    # DEMO MODE runtime — isolated stores for the seeded stage scenario.
    # Wiped and rebuilt deterministically on every enable; never touches the
    # live boneyard/warlog.
    demo_dir: Path = field(default_factory=lambda: get_runtime_paths().commandcenter_demo)
    # CORS for Vite dev server
    cors_origins: tuple[str, ...] = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )

    def assert_localhost(self) -> None:
        """Reject non-localhost bindings. Security hard-stop."""
        forbidden = {
            "0.0.0.0",  # noqa: S104 - denylist value, never a bind target
            "::",
            "[::]",
            "*",
        }
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


def allowed_browser_origins(settings: Settings) -> frozenset[str]:
    """Return development origins plus the configured same-origin UI."""
    return frozenset(
        (
            *settings.cors_origins,
            f"http://127.0.0.1:{settings.port}",
            f"http://localhost:{settings.port}",
        )
    )


def load_settings() -> Settings:
    """Load settings from environment with safe defaults."""
    host = os.environ.get("VOID_CC_HOST", "127.0.0.1")
    port = int(os.environ.get("VOID_CC_PORT", "7070"))
    paths = get_runtime_paths()
    session_state_db = Path(
        os.environ.get("VOID_CC_SESSION_DB", str(paths.commandcenter_session_db))
    ).expanduser().absolute()
    export_dir = Path(
        os.environ.get("VOID_CC_EXPORT_DIR", str(paths.exports))
    ).expanduser().absolute()
    demo_dir = Path(
        os.environ.get("VOID_CC_DEMO_DIR", str(paths.commandcenter_demo))
    ).expanduser().absolute()
    settings = Settings(
        host=host,
        port=port,
        session_state_db=session_state_db,
        export_dir=export_dir,
        demo_dir=demo_dir,
    )
    settings.assert_localhost()
    return settings
