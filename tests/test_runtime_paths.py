"""Runtime path isolation for source, package, and test execution."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from config.paths import get_runtime_paths


def test_xdg_defaults_are_application_scoped(tmp_path):
    env = {
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "XDG_RUNTIME_DIR": str(tmp_path / "run"),
    }
    paths = get_runtime_paths(env, home=tmp_path / "home")
    assert paths.config == tmp_path / "cfg" / "blackfrost" / "the-void"
    assert paths.boneyard == tmp_path / "state" / "blackfrost" / "the-void" / "boneyard"
    assert paths.exports == tmp_path / "data" / "blackfrost" / "the-void" / "exports"
    assert paths.runtime == tmp_path / "run" / "blackfrost-the-void"


def test_void_overrides_take_precedence(tmp_path):
    env = {
        "VOID_CONFIG_DIR": str(tmp_path / "a"),
        "VOID_STATE_DIR": str(tmp_path / "b"),
        "VOID_DATA_DIR": str(tmp_path / "c"),
        "VOID_CACHE_DIR": str(tmp_path / "d"),
        "VOID_RUNTIME_DIR": str(tmp_path / "e"),
    }
    paths = get_runtime_paths(env, home=tmp_path / "ignored")
    assert (paths.config, paths.state, paths.data, paths.cache, paths.runtime) == tuple(
        tmp_path / leaf for leaf in ("a", "b", "c", "d", "e")
    )


def test_relative_xdg_value_is_ignored(tmp_path):
    paths = get_runtime_paths({"XDG_STATE_HOME": "relative"}, home=tmp_path)
    assert paths.state == tmp_path / ".local" / "state" / "blackfrost" / "the-void"


def test_snowblind_state_uses_explicit_external_root(tmp_path):
    env = os.environ.copy()
    env["SNOW_STATE_DIR"] = str(tmp_path / "snow-state")
    code = (
        "import json; from snowblind.modules.util import STATE_DIR, STATE_ROOT; "
        "print(json.dumps([str(STATE_ROOT), str(STATE_DIR)]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout) == [str(tmp_path / "snow-state")] * 2
