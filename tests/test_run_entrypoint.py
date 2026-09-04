"""Compatibility tests for the ``void`` / ``run.py`` entrypoint."""

from unittest.mock import patch

import run


def test_explicit_demo_routes_to_click(monkeypatch):
    monkeypatch.setattr(run.sys, "argv", ["run.py", "demo", "--no-animate"])
    with patch("cli.app.cli") as cli:
        run.main()
    cli.assert_called_once_with(prog_name="thevoid")


def test_explicit_group_routes_to_click(monkeypatch):
    monkeypatch.setattr(run.sys, "argv", ["run.py", "scenarios", "list"])
    with patch("cli.app.cli") as cli:
        run.main()
    cli.assert_called_once_with(prog_name="thevoid")


def test_legacy_target_and_mode_translate(monkeypatch):
    monkeypatch.setattr(
        run.sys,
        "argv",
        ["run.py", "192.0.2.10", "quick", "--dry-run", "--profile", "demo"],
    )
    with patch("cli.app.cli") as cli:
        run.main()
    cli.assert_called_once_with(
        args=[
            "engage",
            "192.0.2.10",
            "--mode",
            "quick",
            "--dry-run",
            "--profile",
            "demo",
        ],
        prog_name="thevoid",
        obj={},
    )
