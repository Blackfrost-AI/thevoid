"""Per-user runtime paths for THE VOID.

Application code may be installed read-only (for example below ``/opt``).
All mutable files therefore live in operator-owned XDG directories unless an
explicit ``VOID_*_DIR`` override is supplied.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_VENDOR = "blackfrost"
_APPLICATION = "the-void"


def _absolute(path: str | Path) -> Path:
    """Return a normalized absolute path without requiring it to exist."""
    return Path(path).expanduser().absolute()


def _xdg_root(
    environ: Mapping[str, str],
    variable: str,
    fallback: Path,
) -> Path:
    value = environ.get(variable, "").strip()
    if not value:
        return fallback
    candidate = Path(value).expanduser()
    # The XDG specification says these values must be absolute. Treat an
    # invalid relative value as unset rather than writing relative to an
    # unpredictable process working directory.
    return candidate if candidate.is_absolute() else fallback


@dataclass(frozen=True)
class RuntimePaths:
    """Resolved roots and derived application runtime locations."""

    config: Path
    state: Path
    data: Path
    cache: Path
    runtime: Path

    @property
    def boneyard(self) -> Path:
        return self.state / "boneyard"

    @property
    def warlog(self) -> Path:
        return self.state / "warlog"

    @property
    def c2(self) -> Path:
        return self.state / "c2"

    @property
    def logs(self) -> Path:
        return self.state / "logs"

    @property
    def quarantine(self) -> Path:
        return self.state / "quarantine"

    @property
    def loot(self) -> Path:
        return self.data / "loot"

    @property
    def exports(self) -> Path:
        return self.data / "exports"

    @property
    def commandcenter(self) -> Path:
        return self.state / "commandcenter"

    @property
    def commandcenter_session_db(self) -> Path:
        return self.commandcenter / "session-state.db"

    @property
    def commandcenter_demo(self) -> Path:
        return self.commandcenter / "demo"

    @property
    def license_file(self) -> Path:
        return self.config / "license.json"

    @property
    def license_public_key(self) -> Path:
        return self.config / "license-public.pem"


def get_runtime_paths(
    environ: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> RuntimePaths:
    """Resolve application paths from overrides and the XDG environment.

    ``VOID_CONFIG_DIR``, ``VOID_STATE_DIR``, ``VOID_DATA_DIR``,
    ``VOID_CACHE_DIR``, and ``VOID_RUNTIME_DIR`` take precedence over XDG.
    The function is intentionally side-effect free; consumers create only the
    directories they actually need.
    """

    env = os.environ if environ is None else environ
    home_dir = _absolute(home if home is not None else Path.home())

    xdg_config = _xdg_root(env, "XDG_CONFIG_HOME", home_dir / ".config")
    xdg_state = _xdg_root(env, "XDG_STATE_HOME", home_dir / ".local" / "state")
    xdg_data = _xdg_root(env, "XDG_DATA_HOME", home_dir / ".local" / "share")
    xdg_cache = _xdg_root(env, "XDG_CACHE_HOME", home_dir / ".cache")

    config = _absolute(env.get("VOID_CONFIG_DIR") or xdg_config / _VENDOR / _APPLICATION)
    state = _absolute(env.get("VOID_STATE_DIR") or xdg_state / _VENDOR / _APPLICATION)
    data = _absolute(env.get("VOID_DATA_DIR") or xdg_data / _VENDOR / _APPLICATION)
    cache = _absolute(env.get("VOID_CACHE_DIR") or xdg_cache / _VENDOR / _APPLICATION)

    runtime_override = env.get("VOID_RUNTIME_DIR", "").strip()
    if runtime_override:
        runtime = _absolute(runtime_override)
    else:
        xdg_runtime = env.get("XDG_RUNTIME_DIR", "").strip()
        candidate = Path(xdg_runtime).expanduser() if xdg_runtime else None
        runtime = (
            candidate / "blackfrost-the-void"
            if candidate is not None and candidate.is_absolute()
            else state / "run"
        )

    return RuntimePaths(
        config=config,
        state=state,
        data=data,
        cache=cache,
        runtime=_absolute(runtime),
    )
