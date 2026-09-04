"""THE VOID — Tests for the CLI application (cli.app).

Covers all seven subcommands:
    - version       (--json-output, default panel)
    - status        (--json-output, default panel, get_status exception fallback)
    - targets       (--add, --remove, --clear, --list, not-found, empty list)
    - report        (json/markdown/html to stdout, --output file, --verify-integrity)
    - engage        (single/multiple targets, --mode, --stealth, --output,
                     --json-output, engine error handling)
    - recon         (single/multiple, --output, --json-output, error handling)
    - demo          (W4: narrated stage walkthrough, --json-output, --no-animate,
                     determinism, real-rubric scoring)

Strategy:
    _make_engine is patched to return a MagicMock engine so no real
    ChaosEngine / ShadowAgent / WarLog / Boneyard is constructed.
    For ``report``, the Reporter class is patched so no real WarLog/
    Boneyard is instantiated.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli.app import cli
from config.defaults import AGENT_VERSION


# ═══════════════════════════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def runner():
    """A Click CliRunner that captures stdout without colour codes."""
    return CliRunner()


def _mock_engine(status=None, engage_result=None):
    """Build a MagicMock engine suitable for all commands.

    Args:
        status: dict returned by engine.get_status().
        engage_result: value returned by engine.engage(); if a list is given,
            successive calls pop from it.
    """
    engine = MagicMock(name="ChaosEngine")
    engine.agent.targets = []
    engine.agent.get_target.return_value = None
    engine.agent.get_status.return_value = status or {
        "engaged": False,
        "targets": [],
        "stealth_active": False,
        "warlog_entries": 0,
        "attack_log": 0,
        "stolen_data": 0,
        "active_sessions": [],
        "beacons": [],
    }
    engine.get_status.return_value = engine.agent.get_status.return_value

    # engage returns a dict by default.
    if engage_result is None:
        engage_result = {
            "target": "default",
            "mode": "full",
            "status": "completed",
            "difficulty": {"score": 3.5},
            "findings": {"recon": {"open_ports": [22, 80]}},
        }
    if isinstance(engage_result, list):
        engine.engage.side_effect = engage_result
    else:
        engine.engage.return_value = engage_result
    return engine


# ═══════════════════════════════════════════════════════════════════════════════
#  GROUP / BANNER
# ═══════════════════════════════════════════════════════════════════════════════

class TestCliGroup:
    """Tests for the top-level ``cli`` group and banner."""

    def test_no_subcommand_prints_banner(self, runner):
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        assert "THE VOID" in result.output or "VOID" in result.output

    def test_banner_flag(self, runner):
        result = runner.invoke(cli, ["--banner"])
        assert result.exit_code == 0
        assert "VOID" in result.output

    def test_banner_short_flag(self, runner):
        result = runner.invoke(cli, ["-b"])
        assert result.exit_code == 0
        assert "VOID" in result.output

    def test_version_option_on_group(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert AGENT_VERSION in result.output


# ═══════════════════════════════════════════════════════════════════════════════
#  version
# ═══════════════════════════════════════════════════════════════════════════════

class TestVersionCommand:
    """Tests for ``thevoid version``."""

    def test_version_default(self, runner):
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert AGENT_VERSION in result.output

    def test_version_json(self, runner):
        result = runner.invoke(cli, ["version", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert data["version"] == AGENT_VERSION
        assert data["name"] == "thevoid"


# ═══════════════════════════════════════════════════════════════════════════════
#  status
# ═══════════════════════════════════════════════════════════════════════════════

class TestStatusCommand:
    """Status reports persisted evidence without implying a live attachment."""

    def test_status_default_panel(self, runner):
        observer = MagicMock()
        observer.degraded = []
        observer.get_status.return_value = {"warlog_entries": 42, "attack_log": 7}
        with patch("cli.app._make_evidence_bridge", return_value=observer), patch("cli.app._make_engine") as engine:
            result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "current activity is unknown" in result.output
        assert "42" in result.output
        engine.assert_not_called()

    def test_status_json_output(self, runner):
        observer = MagicMock()
        observer.degraded = []
        observer.get_status.return_value = {"warlog_entries": 5, "attack_log": 2}
        with patch("cli.app._make_evidence_bridge", return_value=observer):
            result = runner.invoke(cli, ["status", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["state_source"] == "recorded_evidence"
        assert data["runtime_state"] == "not_attached"
        assert data["recorded_engagements"] == 2
        assert data["warlog_entries"] == 5

    def test_degraded_status_is_nonzero(self, runner):
        observer = MagicMock()
        observer.degraded = ["boneyard"]
        observer.get_status.return_value = {}
        with patch("cli.app._make_evidence_bridge", return_value=observer):
            result = runner.invoke(cli, ["status"])
        assert result.exit_code == 1
        assert "degraded" in result.output


class TestTargetsCommand:
    """Recorded hosts are an evidence view, not an in-memory edit interface."""

    def test_targets_empty_list(self, runner):
        observer = MagicMock()
        observer.degraded = []
        observer.query_hosts.return_value = []
        with patch("cli.app._make_evidence_bridge", return_value=observer):
            result = runner.invoke(cli, ["targets"])
        assert result.exit_code == 0
        assert "Recorded hosts" in result.output

    def test_targets_list_existing(self, runner):
        observer = MagicMock()
        observer.degraded = []
        observer.query_hosts.return_value = [
            {"hostname": "fixture.invalid", "ip_address": "192.0.2.1"},
        ]
        with patch("cli.app._make_evidence_bridge", return_value=observer), patch("cli.app._make_engine") as engine:
            result = runner.invoke(cli, ["targets"])
        assert result.exit_code == 0
        assert "fixture.invalid" in result.output
        engine.assert_not_called()

    @pytest.mark.parametrize("arguments", [
        ["--add", "fixture.invalid"], ["--remove", "fixture.invalid"], ["--clear"],
    ])
    def test_target_edits_are_explicitly_rejected(self, runner, arguments):
        with patch("cli.app._make_engine") as engine, patch("cli.app._make_evidence_bridge") as observer:
            result = runner.invoke(cli, ["targets", *arguments])
        assert result.exit_code == 2
        assert "did not persist" in result.output
        engine.assert_not_called()
        observer.assert_not_called()

class TestReportCommand:
    """Tests for ``thevoid report``."""

    def _reporter_patch(self, content=None, captured=None):
        """Patch modules.reporter.Reporter with a fake.

        Args:
            content: string returned by generate() when no output_path.
            captured: dict to fill with the kwargs passed to __init__/generate.
        """
        if content is None:
            content = '{"mock": "report"}'
        capt = captured if captured is not None else {}

        class FakeReporter:
            def __init__(self, **kwargs):
                capt["init"] = kwargs

            def generate(self, format=None, output_path=None, **kw):
                capt["generate"] = {
                    "format": format, "output_path": output_path,
                }
                if output_path:
                    with open(output_path, "w") as f:
                        f.write(content)
                return content

        return patch("modules.reporter.Reporter", FakeReporter)

    def test_report_json_to_stdout(self, runner):
        captured = {}
        with self._reporter_patch(content='{"k": "v"}', captured=captured):
            result = runner.invoke(cli, ["report", "--format", "json"])
        assert result.exit_code == 0
        assert '"k"' in result.output
        assert captured["init"]["verify_integrity"] is False

    def test_report_markdown_to_stdout(self, runner):
        captured = {}
        with self._reporter_patch(content="# Report\n", captured=captured):
            result = runner.invoke(cli, ["report", "--format", "markdown"])
        assert result.exit_code == 0
        assert "# Report" in result.output

    def test_report_html_to_stdout(self, runner):
        captured = {}
        with self._reporter_patch(content="<html>hi</html>", captured=captured):
            result = runner.invoke(cli, ["report", "--format", "html"])
        assert result.exit_code == 0
        assert "<html>" in result.output

    def test_report_md_alias(self, runner):
        captured = {}
        with self._reporter_patch(content="# MD", captured=captured):
            result = runner.invoke(cli, ["report", "-f", "md"])
        assert result.exit_code == 0
        assert "# MD" in result.output

    def test_report_output_file(self, runner, tmp_path):
        captured = {}
        out = tmp_path / "rep.json"
        with self._reporter_patch(content='{"x": 1}', captured=captured):
            result = runner.invoke(cli, [
                "report", "--format", "json", "-o", str(out),
            ])
        assert result.exit_code == 0
        assert out.read_text() == '{"x": 1}'
        assert "written" in result.output.lower()

    def test_report_verify_integrity_flag(self, runner):
        captured = {}
        with self._reporter_patch(captured=captured):
            result = runner.invoke(cli, [
                "report", "--format", "json", "--verify-integrity",
            ])
        assert result.exit_code == 0
        assert captured["init"]["verify_integrity"] is True

    def test_report_default_format_is_json(self, runner):
        captured = {}
        with self._reporter_patch(captured=captured):
            result = runner.invoke(cli, ["report"])
        assert result.exit_code == 0
        assert captured["generate"]["format"] == "json"

    def test_report_operator_and_name(self, runner):
        captured = {}
        with self._reporter_patch(captured=captured):
            result = runner.invoke(cli, [
                "report", "--operator", "Alice", "--name", "Op Nightfall",
            ])
        assert result.exit_code == 0
        assert captured["init"]["operator"] == "Alice"
        assert captured["init"]["engagement_name"] == "Op Nightfall"

    def test_report_invalid_format_rejected(self, runner):
        result = runner.invoke(cli, ["report", "-f", "pdf"])
        assert result.exit_code != 0
        # click prints usage + error for invalid choice.


# ═══════════════════════════════════════════════════════════════════════════════
#  engage
# ═══════════════════════════════════════════════════════════════════════════════

class TestEngageCommand:
    """Tests for ``thevoid engage``."""

    def test_engage_single_target(self, runner):
        engine = _mock_engine(engage_result={
            "target": "10.0.0.1", "mode": "full", "status": "completed",
            "difficulty": {"score": 4.2},
            "findings": {"recon": {"ports": [22]}},
        })
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "10.0.0.1"])
        assert result.exit_code == 0
        assert engine.engage.call_count == 1
        args = engine.engage.call_args[0]
        assert args[0].value == "10.0.0.1"
        assert args[1] == "full"

    def test_engage_multiple_targets(self, runner):
        engine = _mock_engine(engage_result={
            "target": "x", "mode": "full", "status": "completed",
            "findings": {},
        })
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "10.0.0.1", "10.0.0.2"])
        assert result.exit_code == 0
        assert engine.engage.call_count == 2

    def test_engage_with_mode(self, runner):
        engine = _mock_engine()
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "example.com", "-m", "quick"])
        assert result.exit_code == 0
        assert engine.engage.call_args[0][1] == "quick"

    def test_engage_stealth_flag(self, runner):
        engine = _mock_engine()
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "10.0.0.1", "--stealth"])
        assert result.exit_code == 0
        engine.activate_stealth.assert_called_once()
        assert "Stealth" in result.output

    def test_engage_stealth_activation_fails(self, runner):
        engine = _mock_engine()
        engine.activate_stealth.side_effect = RuntimeError("tor unavailable")
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "10.0.0.1", "-s"])
        assert result.exit_code == 0
        assert "Stealth activation failed" in result.output

    def test_engage_engine_error_records_error(self, runner):
        engine = _mock_engine()
        engine.engage.side_effect = RuntimeError("connection refused")
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "10.0.0.1"])
        assert result.exit_code == 0
        assert "Error engaging" in result.output

    def test_engage_json_output(self, runner):
        engine = _mock_engine(engage_result={
            "target": "10.0.0.1", "mode": "full", "status": "completed",
            "findings": {"a": 1},
        })
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["engage", "10.0.0.1", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert isinstance(data, list)
        assert data[0]["target"] == "10.0.0.1"

    def test_engage_output_file(self, runner, tmp_path):
        engine = _mock_engine(engage_result={
            "target": "10.0.0.1", "mode": "full", "status": "completed",
            "findings": {},
        })
        out = tmp_path / "results.json"
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, [
                "engage", "10.0.0.1", "-o", str(out),
            ])
        assert result.exit_code == 0
        saved = json.loads(out.read_text())
        assert isinstance(saved, list)
        assert saved[0]["target"] == "10.0.0.1"

    def test_engage_requires_at_least_one_target(self, runner):
        result = runner.invoke(cli, ["engage"])
        assert result.exit_code != 0

    def test_engage_invalid_mode_rejected(self, runner):
        result = runner.invoke(cli, ["engage", "10.0.0.1", "-m", "invalid"])
        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════════════════════
#  recon
# ═══════════════════════════════════════════════════════════════════════════════

class TestReconCommand:
    """Tests for ``thevoid recon``."""

    def test_recon_single_target(self, runner):
        engine = _mock_engine(engage_result={
            "target": "example.com", "mode": "quick", "status": "completed",
            "findings": {"dns": {"records": 3}},
        })
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["recon", "example.com"])
        assert result.exit_code == 0
        engine.engage.assert_called_once()
        assert engine.engage.call_args[0][1] == "quick"

    def test_recon_multiple_targets(self, runner):
        engine = _mock_engine(engage_result={
            "target": "x", "mode": "quick", "status": "completed",
            "findings": {},
        })
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["recon", "a.com", "b.com"])
        assert result.exit_code == 0
        assert engine.engage.call_count == 2

    def test_recon_uses_quick_mode(self, runner):
        """recon always engages in quick mode."""
        engine = _mock_engine()
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["recon", "10.0.0.1"])
        assert result.exit_code == 0
        assert engine.engage.call_args[0][1] == "quick"

    def test_recon_error_handling(self, runner):
        engine = _mock_engine()
        engine.engage.side_effect = RuntimeError("timeout")
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["recon", "10.0.0.1"])
        assert result.exit_code == 0
        assert "Recon error" in result.output

    def test_recon_json_output(self, runner):
        engine = _mock_engine(engage_result={
            "target": "example.com", "mode": "quick", "status": "completed",
            "findings": {"x": 1},
        })
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["recon", "example.com", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert isinstance(data, list)
        assert data[0]["mode"] == "quick"

    def test_recon_output_file(self, runner, tmp_path):
        engine = _mock_engine(engage_result={
            "target": "example.com", "mode": "quick", "status": "completed",
            "findings": {},
        })
        out = tmp_path / "recon.json"
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["recon", "example.com", "-o", str(out)])
        assert result.exit_code == 0
        saved = json.loads(out.read_text())
        assert saved[0]["target"] == "example.com"

    def test_recon_requires_at_least_one_target(self, runner):
        result = runner.invoke(cli, ["recon"])
        assert result.exit_code != 0


# ═══════════════════════════Reporter════════════════════════════════════════════
#  Integration: real Reporter + report command (no mock on Reporter)
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportIntegration:
    """End-to-end: ``report`` command with the REAL Reporter class.

    Uses MagicMock sources so no files are touched.
    """

    def test_report_real_reporter_json(self, runner):
        warlog = MagicMock()
        warlog.iter_entries.return_value = []
        warlog.__len__ = lambda self: 0
        warlog.verify_integrity = MagicMock(return_value=True)
        boneyard = MagicMock()
        boneyard.iter_records.return_value = []
        boneyard.__len__ = lambda self: 0
        boneyard.verify_integrity = MagicMock(return_value=True)

        with patch("core.warlog.WarLog", return_value=warlog), \
             patch("core.boneyard.Boneyard", return_value=boneyard):
            result = runner.invoke(cli, ["report", "--format", "json"])
        assert result.exit_code == 0
        # Real JSON output should be parseable.
        data = json.loads(result.output.strip())
        assert isinstance(data, dict)

    def test_report_real_reporter_markdown(self, runner):
        warlog = MagicMock()
        warlog.iter_entries.return_value = []
        warlog.verify_integrity = MagicMock(return_value=True)
        boneyard = MagicMock()
        boneyard.iter_records.return_value = []
        boneyard.verify_integrity = MagicMock(return_value=True)

        with patch("core.warlog.WarLog", return_value=warlog), \
             patch("core.boneyard.Boneyard", return_value=boneyard):
            result = runner.invoke(cli, ["report", "--format", "markdown"])
        assert result.exit_code == 0
        assert len(result.output) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  DEMO COMMAND (W4) — deterministic, zero-network, scored by the real rubric
# ═══════════════════════════════════════════════════════════════════════════════

class TestDemo:
    """``demo`` — guided, narrated, deterministic stage walkthrough.

    The demo must:
      * require no engine / no network / no real targets,
      * be deterministic across runs,
      * be scored by the REAL CoverageScorer (not fabricated),
      * emit valid JSON in --json-output mode.
    """

    def test_demo_json_output(self, runner):
        result = runner.invoke(cli, ["demo", "--json-output"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data.get("demo") is True
        assert data.get("scenario") == "stage-scenario-1"
        assert len(data.get("hosts") or []) == 3
        assert len(data.get("phases") or []) == 6
        prev = data.get("prevention") or {}
        assert prev.get("engagement_count") == 2
        assert isinstance(prev.get("score"), (int, float))
        assert prev.get("verdict_counts") is not None

    def test_demo_deterministic_score(self, runner):
        r1 = runner.invoke(cli, ["demo", "--json-output"])
        r2 = runner.invoke(cli, ["demo", "--json-output"])
        assert r1.exit_code == 0 and r2.exit_code == 0
        s1 = json.loads(r1.output.strip())["prevention"]["score"]
        s2 = json.loads(r2.output.strip())["prevention"]["score"]
        assert s1 == s2

    def test_demo_narrated_no_animate(self, runner):
        result = runner.invoke(cli, ["demo", "--no-animate"])
        assert result.exit_code == 0, result.output
        # Narrative + score panel must appear in the rendered output.
        assert "DEMO" in result.output
        assert "Initial access" in result.output
        assert "Command & control" in result.output
        assert "Prevention" in result.output or "Coverage" in result.output

    def test_demo_speed_clamped(self, runner):
        result = runner.invoke(cli, ["demo", "--no-animate", "--speed", "0"])
        assert result.exit_code == 0, result.output
