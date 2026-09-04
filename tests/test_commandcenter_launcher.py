"""Process-safety tests for the visual Command Center launcher."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import commandcenter.launcher as launcher


def test_pid_record_is_private(tmp_path, monkeypatch):
    monkeypatch.setenv("VOID_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("VOID_STATE_DIR", str(tmp_path / "state"))
    launcher._write_record(1234, 7070)
    pid_file, _, _ = launcher._runtime_files()
    assert pid_file.stat().st_mode & 0o777 == 0o600
    assert json.loads(pid_file.read_text())["process"] == launcher.PROCESS_MARKER


def test_process_match_requires_expected_cmdline(tmp_path):
    with patch.object(Path, "stat") as stat_call, patch.object(Path, "read_bytes") as read_call:
        stat_call.return_value.st_uid = launcher.os.geteuid()
        read_call.return_value = b"python\0-m\0something.else\0"
        assert launcher._process_matches(1234) is False


def test_stop_never_signals_unrelated_pid(tmp_path, monkeypatch):
    monkeypatch.setenv("VOID_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("VOID_STATE_DIR", str(tmp_path / "state"))
    launcher._write_record(4321, 7070)
    with patch.object(launcher, "_ensure_unprivileged"), patch.object(
        launcher, "_process_matches", return_value=False
    ), patch.object(launcher.os, "kill") as kill:
        assert launcher.stop() == 0
    kill.assert_not_called()


def test_launcher_rejects_root():
    with patch.object(launcher.os, "geteuid", return_value=0):
        try:
            launcher._ensure_unprivileged()
        except RuntimeError as exc:
            assert "not root" in str(exc)
        else:
            raise AssertionError("root launch was not rejected")


def test_health_check_requires_command_center_identity():
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.read.return_value = b'{"ok": true, "service": "other", "port": 7070}'

    with patch.object(launcher.urllib.request, "urlopen", return_value=response):
        assert launcher._health_ok(7070) is False

    response.read.return_value = (
        b'{"ok": true, "service": "the-void-command-center", "port": 7070}'
    )
    with patch.object(launcher.urllib.request, "urlopen", return_value=response):
        assert launcher._health_ok(7070) is True
