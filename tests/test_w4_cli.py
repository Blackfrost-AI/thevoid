"""W4 — CLI polish test suite (thevoid demo-era operator experience).

Covers:
- 2.4a canonical banner (config.defaults.VOID_BANNER single source of truth)
- 2.4b version meta (platform, Command Center, agent build metadata)
- 2.2a phase-listener events emitted by ShadowAgent.engage()
- 2.2c --scenario shell completion against the curated catalog
- 2.3a gate-verdict panels + unified engagement renderer
- 2.2b prevention-strength panel (real CoverageScorer)
- 2.3b status enrichment (prevention/scenario/drift/integrity)
- 2.3c verify-integrity progress callback threading (WORM + Reporter)

All CLI tests use CliRunner and patch _make_engine so no real engine/store
is touched. WORM progress tests use isolated tmp stores.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli.app import cli


@pytest.fixture()
def runner():
    return CliRunner()


def _mock_engine(status=None, engage_result=None):
    """MagicMock engine with sane defaults (mirrors tests/test_cli.py)."""
    engine = MagicMock()
    engine.get_status.return_value = status or {
        "engaged": False, "targets": [], "stealth_active": False,
        "warlog_entries": 0, "attack_log": 0, "stolen_data": 0,
        "active_sessions": [], "beacons": [],
    }
    if engage_result is None:
        engage_result = {
            "target": "demo", "mode": "full", "status": "completed",
            "difficulty": {"score": 0.42}, "elapsed": 1.0,
            "findings": {},
        }
    engine.engage.return_value = engage_result
    return engine


# ═══════════════════════════════════════════════════════════════════════════════
#  2.4a — canonical banner
# ═══════════════════════════════════════════════════════════════════════════════

class TestCanonicalBanner:
    def test_banner_defined_in_defaults(self):
        from config.defaults import VOID_BANNER
        assert VOID_BANNER, "VOID_BANNER must be non-empty"
        # Block-art banner: contains box-drawing characters.
        assert "█" in VOID_BANNER

    def test_cli_banner_is_canonical_source(self):
        import cli.app as app
        from config.defaults import VOID_BANNER
        assert app.BANNER is VOID_BANNER, \
            "cli.app.BANNER must alias the canonical banner"

    def test_run_py_print_banner_uses_canonical(self):
        import io
        import contextlib
        import run
        from config.defaults import VOID_BANNER
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run.print_banner()
        # render output contains the canonical block art (allowing for the
        # leading indent run.py historically used — assert a core row).
        assert "███╗   ██╗" in buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
#  2.4b — version meta
# ═══════════════════════════════════════════════════════════════════════════════

class TestVersionMeta:
    def test_version_json_keys(self, runner):
        result = runner.invoke(cli, ["version", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Back-compat keys.
        assert "version" in data
        assert data.get("name") == "thevoid"
        # New platform metadata.
        assert "platform" in data
        assert "python" in data["platform"]
        assert "os" in data["platform"]
        assert "agent_version" in data["platform"]
        assert "command_center" in data
        assert "phases" in data
        assert "scenarios" in data

    def test_version_meta_populated(self, runner):
        result = runner.invoke(cli, ["version", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data["phases"], int) and data["phases"] > 0
        assert isinstance(data["scenarios"], int) and data["scenarios"] > 0
        assert data["command_center"].get("version") != "unknown"

    def test_version_panel_renders(self, runner):
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        # Panel should mention agent version and command center.
        assert "THE VOID" in result.output


# ═══════════════════════════════════════════════════════════════════════════════
#  2.2a — phase-listener events
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhaseListener:
    @staticmethod
    def _make_agent(phase_names):
        """Build a ShadowAgent via __new__ with a minimal engage() surface."""
        from agent import shadow_agent as sa

        class FakeRegistry:
            def __init__(self):
                self.phases = list(phase_names)

            def resolve(self, name):
                def _stub(agent, target, mode, ctx):
                    return {"ok": True, "phase": name}
                return _stub

        shadow = sa.ShadowAgent.__new__(sa.ShadowAgent)
        shadow._phase_registry = FakeRegistry()
        shadow.warlog = MagicMock()
        shadow.boneyard = MagicMock()
        shadow.engaged = False
        shadow.extra_denied_phases = set()
        shadow.authz = None
        shadow.attack_log = []
        shadow._validate_action = lambda plan: True
        shadow._sanitize_output = lambda x, source="": x
        shadow.MODE_PHASES = {"full": list(phase_names)}
        shadow.phases_for_mode = lambda mode: list(phase_names)
        return shadow

    @staticmethod
    def _target():
        t = MagicMock()
        t.value = "demo"
        t.name = "demo"
        return t

    def test_listener_receives_full_event_sequence(self):
        shadow = self._make_agent(["recon", "exploit"])
        events = []
        shadow.set_phase_listener(events.append)

        out = shadow.engage(self._target(), mode="full")

        kinds = [e["event"] for e in events]
        assert kinds[0] == "engage_start"
        assert kinds[-1] == "engage_end"
        # Per-phase start/end pairs, in order.
        assert "phase_start" in kinds and "phase_end" in kinds
        assert out["status"] == "completed"

    def test_listener_phase_events_have_required_fields(self):
        shadow = self._make_agent(["recon"])
        events = []
        shadow.set_phase_listener(events.append)
        shadow.engage(self._target(), mode="full")

        start = next(e for e in events if e["event"] == "phase_start")
        assert start["phase"] == "recon"
        assert start["index"] == 1
        assert start["total"] == 1
        assert start["mode"] == "full"

        end = next(e for e in events if e["event"] == "phase_end")
        assert end["ok"] is True
        assert end["error"] is None

    def test_listener_errors_do_not_break_engagement(self):
        shadow = self._make_agent(["recon"])

        def bad_listener(ev):
            raise RuntimeError("listener exploded")

        shadow.set_phase_listener(bad_listener)
        out = shadow.engage(self._target(), mode="full")
        assert out["status"] == "completed", \
            "listener exceptions must never abort the engagement"

    def test_clear_listener_with_none(self):
        shadow = self._make_agent(["recon"])
        events = []
        shadow.set_phase_listener(events.append)
        shadow.set_phase_listener(None)
        shadow.engage(self._target(), mode="full")
        assert events == [], "cleared listener must receive nothing"

    def test_engage_end_reports_status(self):
        shadow = self._make_agent(["recon"])
        events = []
        shadow.set_phase_listener(events.append)
        shadow.engage(self._target(), mode="full")
        end = events[-1]
        assert end["event"] == "engage_end"
        assert end["status"] == "completed"


# ═══════════════════════════════════════════════════════════════════════════════
#  2.2c — scenario completion
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenarioCompletion:
    def test_catalog_names_from_library(self):
        from cli.app import _scenario_catalog_names
        names = _scenario_catalog_names()
        assert isinstance(names, list)
        assert len(names) > 0

    def test_completion_returns_catalog(self):
        from cli.app import _complete_scenario, _scenario_catalog_names
        all_names = set(_scenario_catalog_names())
        completions = set(_complete_scenario(None, None, ""))
        assert completions == all_names

    def test_completion_prefix_filtering(self):
        from cli.app import _complete_scenario, _scenario_catalog_names
        names = _scenario_catalog_names()
        assert names, "need at least one scenario to test filtering"
        # Pick a real name and match on its first char.
        sample = names[0]
        prefix = sample[0]
        out = list(_complete_scenario(None, None, prefix))
        assert sample in out
        for n in out:
            assert n.startswith(prefix)

    def test_completion_no_match_returns_empty(self):
        from cli.app import _complete_scenario
        out = list(_complete_scenario(None, None, "zzz-no-such-scenario"))
        assert out == []


# ═══════════════════════════════════════════════════════════════════════════════
#  2.3a — gate-verdict panels + unified renderer
# ═══════════════════════════════════════════════════════════════════════════════

class TestGateVerdictPanels:
    def test_denied_renders_panel(self):
        from rich.console import Console
        from cli.render import render_gate_verdict
        import io
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        result = {"target": "demo", "mode": "full", "status": "denied",
                  "reason": "scope gate blocked"}
        assert render_gate_verdict(console, result) is True
        out = buf.getvalue()
        assert "DENIED" in out.upper()
        assert "scope gate blocked" in out

    def test_aborted_renders_panel(self):
        from rich.console import Console
        from cli.render import render_gate_verdict
        import io
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        result = {"target": "demo", "mode": "full", "status": "aborted",
                  "reason": "difficulty too high"}
        assert render_gate_verdict(console, result) is True
        assert "ABORTED" in buf.getvalue().upper()

    def test_completed_returns_false_no_panel(self):
        from rich.console import Console
        from cli.render import render_gate_verdict
        import io
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        result = {"target": "demo", "mode": "full", "status": "completed"}
        assert render_gate_verdict(console, result) is False

    def test_unified_renderer_handles_completed(self):
        """engage results for a completed run render without error."""
        import cli.app as app
        result = {"target": "demo", "mode": "full", "status": "completed",
                  "difficulty": {"score": 0.42}, "elapsed": 1.0,
                  "findings": {"recon": {"ok": True}}}
        with patch.object(app.console, "print"):
            app._render_engagement_results([result])
        # No exception is the assertion; presence handled by panel tests.


# ═══════════════════════════════════════════════════════════════════════════════
#  2.2b — prevention-strength panel
# ═══════════════════════════════════════════════════════════════════════════════

class TestPreventionPanel:
    def test_prevention_summary_uses_real_scorer(self):
        from rich.console import Console
        from cli.render import render_prevention_summary
        import io
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)

        # A completed engagement with a finding. CoverageScorer is real.
        results = [{
            "target": "demo", "mode": "full", "status": "completed",
            "findings": {"recon": {"ok": True}},
        }]
        render_prevention_summary(console, results)
        out = buf.getvalue()
        assert "Prevention" in out
        assert "CoverageScorer" in out

    def test_no_completed_shows_dim_message(self):
        from rich.console import Console
        from cli.render import render_prevention_summary
        import io
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        render_prevention_summary(console, [
            {"target": "demo", "status": "aborted"},
        ])
        assert "No completed engagements" in buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
#  2.3b — status enrichment
# ═══════════════════════════════════════════════════════════════════════════════

class TestStatusEnrichment:
    @staticmethod
    def _fake_agent(**attrs):
        """A minimal, real-ish agent object for _status_enrich."""
        agent = MagicMock()
        # Default everything to None/absent so only explicit attrs surface.
        for k in ("attack_log", "scenario", "boneyard", "warlog"):
            setattr(agent, k, None)
        for k, v in attrs.items():
            setattr(agent, k, v)
        return agent

    def test_magicmock_engine_does_not_crash(self, runner):
        """Regression: MagicMock engine must render status without error."""
        engine = _mock_engine()
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0

    def test_status_json_includes_enrichment(self, runner):
        engine = MagicMock()
        engine.get_status.return_value = {"engaged": False}
        # A real agent with a completed attack log + scenario.
        agent = self._fake_agent(
            attack_log=[{"target": "demo", "mode": "full",
                         "status": "completed", "findings": {}}],
            scenario="rdp-brute-cascade",
        )
        engine.agent = agent
        with patch("cli.app._make_engine", return_value=engine):
            result = runner.invoke(cli, ["status", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data.get("scenario") == "rdp-brute-cascade"
        # Prevention should be present (real CoverageScorer over attack_log).
        assert "prevention" in data

    def test_prevention_score_computed(self):
        import cli.app as app
        engine = MagicMock()
        agent = self._fake_agent(
            attack_log=[{"target": "demo", "mode": "full",
                         "status": "completed",
                         "findings": {"recon": {"ok": True, "exploits": []}}}],
        )
        engine.agent = agent
        extra = app._status_enrich(engine, {})
        assert extra.get("prevention") is not None
        assert "score" in extra["prevention"]
        assert extra["prevention"]["engagement_count"] >= 1

    def test_integrity_state_from_reports(self):
        import cli.app as app

        class Report:
            verified = True

        agent = self._fake_agent()
        agent.warlog = MagicMock()
        agent.warlog.verify_integrity.return_value = Report()
        agent.boneyard = None
        engine = MagicMock()
        engine.agent = agent
        extra = app._status_enrich(engine, {})
        assert extra.get("integrity") == {"warlog": True}

    def test_integrity_bool_report(self):
        import cli.app as app
        agent = self._fake_agent()
        agent.warlog = MagicMock()
        agent.warlog.verify_integrity.return_value = True
        agent.boneyard = None
        engine = MagicMock()
        engine.agent = agent
        extra = app._status_enrich(engine, {})
        assert extra.get("integrity") == {"warlog": True}

    def test_last_drift_from_boneyard_search(self):
        import cli.app as app
        agent = self._fake_agent()
        boneyard = MagicMock()
        boneyard.search.return_value = [
            {"data": {"msg": "phase drift: mcp_chain"}, "timestamp": 1000},
        ]
        agent.boneyard = boneyard
        engine = MagicMock()
        engine.agent = agent
        extra = app._status_enrich(engine, {})
        assert extra.get("last_drift") is not None
        assert extra["last_drift"]["msg"] == "phase drift: mcp_chain"

    def test_agent_none_safe(self):
        import cli.app as app
        engine = MagicMock()
        engine.agent = None
        extra = app._status_enrich(engine, {})
        assert extra["prevention"] is None
        assert extra["scenario"] is None
        assert extra["integrity"] is None
        assert extra["last_drift"] is None


# ═══════════════════════════════════════════════════════════════════════════════
#  2.3c — verify-integrity progress threading
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegrityProgress:
    @pytest.fixture
    def warlog(self, tmp_path):
        from core.warlog import WarLog
        return WarLog(
            log_dir=str(tmp_path / "warlog"),
            log_file=str(tmp_path / "warlog" / "test.log"),
        )

    @pytest.fixture
    def boneyard(self, tmp_path):
        from core.boneyard import Boneyard
        return Boneyard(storage_dir=str(tmp_path / "boneyard"))

    def test_warlog_verify_accepts_progress(self, warlog):
        warlog.log("e1")
        warlog.log("e2")
        calls = []
        report = warlog.verify_integrity(
            progress=lambda d, t, l: calls.append((d, t, l)))
        assert report.verified is True
        assert len(calls) >= 2, "progress must fire per event"
        # Total consistent and monotonic.
        totals = {c[1] for c in calls}
        assert len(totals) == 1, "total must be constant within one verify"

    def test_warlog_verify_no_progress_still_works(self, warlog):
        warlog.log("e1")
        report = warlog.verify_integrity()
        assert report.verified is True

    def test_warlog_progress_exception_swallowed(self, warlog):
        warlog.log("e1")

        def bad(d, t, l):
            raise RuntimeError("boom")

        report = warlog.verify_integrity(progress=bad)
        assert report.verified is True, \
            "progress exceptions must not break verification"

    def test_boneyard_verify_accepts_progress(self, boneyard):
        boneyard.store("host", {"ip": "1.2.3.4"})
        calls = []
        report = boneyard.verify_integrity(
            progress=lambda d, t, l: calls.append((d, t, l)))
        assert report.verified is True
        assert len(calls) >= 1, "progress must fire for stored rows"

    def test_boneyard_verify_no_progress_still_works(self, boneyard):
        boneyard.store("host", {"ip": "1.2.3.4"})
        report = boneyard.verify_integrity()
        assert report.verified is True

    def test_reporter_threads_progress_to_stores(self):
        from modules.reporter import Reporter
        warlog = MagicMock()
        warlog.verify_integrity.return_value = MagicMock(verified=True)
        boneyard = MagicMock()
        boneyard.verify_integrity.return_value = MagicMock(verified=True)

        seen = []

        def cb(d, t, l):
            seen.append((d, t, l))

        reporter = Reporter(
            warlog=warlog, boneyard=boneyard, attack_log=[],
            verify_integrity=True, integrity_progress=cb,
        )
        report = reporter.generate(format="json")
        # Reporter must forward the progress callback to the stores.
        assert warlog.verify_integrity.called
        # The callback was forwarded (store received progress= kwarg).
        args, kwargs = warlog.verify_integrity.call_args
        assert kwargs.get("progress") is cb or (
            args and callable(args[0]))


# ═══════════════════════════════════════════════════════════════════════════════
#  PhaseTracker (rich.Live) state machine — 2.2a
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhaseTrackerState:
    def _tracker(self):
        from rich.console import Console
        from cli.render import PhaseTracker
        import io
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        return PhaseTracker(console, target="demo", mode="full")

    def test_engage_start_builds_phase_rows(self):
        t = self._tracker()
        t.listener()({"event": "engage_start", "target": "demo",
                     "mode": "full", "phases": ["recon", "exploit"],
                     "total": 2})
        assert [p["name"] for p in t._phases] == ["recon", "exploit"]
        assert all(p["state"] == "pending" for p in t._phases)

    def test_phase_start_marks_running(self):
        t = self._tracker()
        t.listener()({"event": "engage_start", "target": "demo",
                      "phases": ["recon"], "total": 1})
        t.listener()({"event": "phase_start", "phase": "recon"})
        assert t._phases[0]["state"] == "running"

    def test_phase_end_ok_and_fail(self):
        t = self._tracker()
        t.listener()({"event": "engage_start", "target": "demo",
                      "phases": ["recon", "exploit"], "total": 2})
        t.listener()({"event": "phase_end", "phase": "recon", "ok": True})
        t.listener()({"event": "phase_end", "phase": "exploit",
                      "ok": False, "error": "boom"})
        assert t._phases[0]["state"] == "ok"
        assert t._phases[1]["state"] == "fail"
        assert t._phases[1]["error"] == "boom"

    def test_engage_end_sets_status(self):
        t = self._tracker()
        t.listener()({"event": "engage_end", "target": "demo",
                      "status": "completed"})
        assert t._status == "completed"

    def test_listener_never_raises(self):
        t = self._tracker()
        # Malformed / missing fields must not raise.
        t.listener()({"event": "phase_end"})
        t.listener()({"event": "unknown"})
        t.listener()({})
        assert True
