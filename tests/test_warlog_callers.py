"""THE VOID — WarLog caller signature regression tests.

Locks down the bug class where callers invoked ``WarLog.log()`` with the
WRONG signature — ``log(target, message, level=...)`` — which crashed with
``TypeError: log() got multiple values for argument 'level'`` because the
real signature is ``log(message, level=, module=, target=, ...)``.

Also locks down the secondary bug: callers passed ``level="ENGINE"`` (and
``"RECON"``/``"EXPLOIT"``/``"EXFIL"``/``"STEALTH"`` as strings), but
``"ENGINE"`` is not a valid ``LogLevel`` enum member.  All callers must now
pass ``LogLevel`` enum members.

These tests execute every previously-broken call site in both
``modules/shadow.py`` (8 sites) and ``orchestrator/chaos.py`` (7 sites) and
assert:

    1.  No ``TypeError`` is raised (signature is correct).
    2.  An entry is actually written to the warlog (level matches).
    3.  The ``target`` field is the target's string value, not a ``Target``
        object.
    4.  No level field is the string ``"ENGINE"`` (invalid enum member).
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.target import Target
from core.warlog import WarLog, LogLevel


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def warlog(tmp_path):
    """Fresh WarLog with rotation disabled, isolated to tmp_path."""
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "test.log"),
        max_db_size=10 * 1024 * 1024,
        max_age_days=365,
        rotate_on_init=False,
    )


@pytest.fixture
def target():
    return Target("10.0.0.5", name="victim-01")


# ═══════════════════════════════════════════════════════════════════════════════
#  modules/shadow.py  —  Shadow agent (8 call sites)
# ═══════════════════════════════════════════════════════════════════════════════

class TestShadowWarLogSignatures:
    """Every warlog.log() call in modules/shadow.py must use the right
    signature and pass LogLevel enum members."""

    def _make_shadow(self, warlog):
        from modules.shadow import Shadow
        s = Shadow()
        s.warlog = warlog
        # Neutralize the executor so recon/exploit helpers no-op cleanly.
        s.executor = MagicMock()
        s.executor.run.return_value = MagicMock(
            success=False, stdout="", stderr="mocked", returncode=1
        )
        # Neutralize boneyard.store so it doesn't write/findings spew.
        s.boneyard.store = MagicMock(return_value="mock-id")
        return s

    def test_recon_log(self, warlog, target):
        s = self._make_shadow(warlog)
        with patch.object(s, "_quick_recon", return_value={"ok": True}):
            s.recon(target, scan_type="quick")
        entries = warlog.get_entries(level=LogLevel.RECON)
        assert len(entries) == 1
        assert "quick recon" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_exploit_log(self, warlog, target):
        s = self._make_shadow(warlog)
        with patch.object(s, "_cred_exploit", return_value={"ok": True}):
            s.exploit(target, exploit_type="cred")
        entries = warlog.get_entries(level=LogLevel.EXPLOIT)
        assert len(entries) == 1
        assert "cred exploitation" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_steal_data_log(self, warlog, target):
        s = self._make_shadow(warlog)
        with patch("modules.datatheft.DataTheft") as DT:
            DT.return_value.exfil_file.return_value = {"ok": True}
            s.steal_data(target, data_type="files")
        entries = warlog.get_entries(level=LogLevel.EXFIL)
        assert len(entries) == 1
        assert "Stealing files" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_jailbreak_llm_log(self, warlog, target):
        s = self._make_shadow(warlog)
        with patch("modules.llm_jailbreak.LLMJailbreak") as JB:
            JB.return_value.full_jailbreak_test.return_value = {"ok": True}
            s.jailbreak_llm(target)
        entries = warlog.get_entries(level=LogLevel.EXPLOIT)
        assert len(entries) == 1
        assert "LLM jailbreak" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_bypass_network_log(self, warlog, target):
        s = self._make_shadow(warlog)
        with patch("modules.network_bypass.NetworkBypass") as NB:
            NB.return_value.full_bypass.return_value = {"ok": True}
            s.bypass_network(target)
        entries = warlog.get_entries(level=LogLevel.EXPLOIT)
        assert len(entries) == 1
        assert "network bypass" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_stealth_activate_log(self, warlog):
        s = self._make_shadow(warlog)
        with patch.object(s.stealth, "activate_tor"):
            s.activate_stealth()
        entries = warlog.get_entries(level=LogLevel.STEALTH)
        assert len(entries) == 1
        assert "activated" in entries[0]["message"]
        # Stealth events have no target.
        assert entries[0].get("target") in (None, "")

    def test_stealth_deactivate_log(self, warlog):
        s = self._make_shadow(warlog)
        with patch.object(s.stealth, "deactivate_tor"):
            s.deactivate_stealth()
        entries = warlog.get_entries(level=LogLevel.STEALTH)
        assert len(entries) == 1
        assert "deactivated" in entries[0]["message"]

    def test_full_attack_log(self, warlog, target):
        s = self._make_shadow(warlog)
        # full_attack calls recon/exploit/steal internally; patch the helpers.
        with patch.object(s, "recon", return_value={}), \
             patch.object(s, "exploit", return_value={}), \
             patch.object(s, "steal_data", return_value={}):
            s.full_attack(target)
        entries = warlog.get_entries(level=LogLevel.EXPLOIT)
        assert any("full attack" in e["message"] for e in entries)
        full = [e for e in entries if "full attack" in e["message"]]
        assert full[0]["target"] == "10.0.0.5"


# ═══════════════════════════════════════════════════════════════════════════════
#  orchestrator/chaos.py  —  ChaosEngine (7 call sites)
# ═══════════════════════════════════════════════════════════════════════════════

class TestChaosWarLogSignatures:
    """Every warlog.log() call in orchestrator/chaos.py must use the right
    signature, pass ``LogLevel.AGENT`` (not the invalid ``"ENGINE"``), and
    pass a string target."""

    def _make_engine(self, warlog):
        from orchestrator.chaos import ChaosEngine
        eng = ChaosEngine()
        eng.warlog = warlog
        # The engine delegates to a ShadowAgent; stub it out.
        eng.agent = MagicMock()
        eng.agent.targets = []
        return eng

    def test_add_target_log(self, warlog, target):
        eng = self._make_engine(warlog)
        eng.add_target(target)
        entries = warlog.get_entries(level=LogLevel.AGENT)
        assert len(entries) == 1
        assert "Target added" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_engage_log(self, warlog, target):
        eng = self._make_engine(warlog)
        eng.agent.engage.return_value = {"phase": "done"}
        eng.engage(target, mode="full")
        entries = warlog.get_entries(level=LogLevel.AGENT)
        assert len(entries) == 1
        assert "full mode" in entries[0]["message"]
        assert entries[0]["target"] == "10.0.0.5"

    def test_stealth_activate_log(self, warlog):
        eng = self._make_engine(warlog)
        eng.activate_stealth()
        entries = warlog.get_entries(level=LogLevel.AGENT)
        assert len(entries) == 1
        assert "activated" in entries[0]["message"]

    def test_stealth_deactivate_log(self, warlog):
        eng = self._make_engine(warlog)
        eng.deactivate_stealth()
        entries = warlog.get_entries(level=LogLevel.AGENT)
        assert len(entries) == 1
        assert "deactivated" in entries[0]["message"]

    def test_start_log(self, warlog):
        eng = self._make_engine(warlog)
        eng.start()
        entries = warlog.get_entries(level=LogLevel.AGENT)
        assert len(entries) == 1
        assert "started" in entries[0]["message"]

    def test_stop_log(self, warlog):
        eng = self._make_engine(warlog)
        eng.stop()
        entries = warlog.get_entries(level=LogLevel.AGENT)
        assert len(entries) == 1
        assert "stopped" in entries[0]["message"]

    def test_run_interruption_log(self, warlog, target):
        """The KeyboardInterrupt handler in run() must log correctly."""
        eng = self._make_engine(warlog)
        eng.agent.engage.side_effect = KeyboardInterrupt
        eng.run([target], mode="full")
        entries = warlog.get_entries(level=LogLevel.AGENT)
        msgs = [e["message"] for e in entries]
        assert any("Interrupted" in m for m in msgs)


# ═══════════════════════════════════════════════════════════════════════════════
#  No invalid "ENGINE" level anywhere in the DB
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoInvalidEngineLevel:
    """Sanity: no entry in the warlog DB should carry the invalid 'ENGINE'
    or upper-case string levels that the old buggy callers produced."""

    def test_no_engine_level_anywhere(self, warlog, target):
        from modules.shadow import Shadow
        from orchestrator.chaos import ChaosEngine

        s = Shadow()
        s.warlog = warlog
        s.executor = MagicMock()
        s.boneyard.store = MagicMock(return_value="mock-id")
        with patch.object(s, "_quick_recon", return_value={}):
            s.recon(target)
        with patch.object(s.stealth, "activate_tor"):
            s.activate_stealth()

        eng = ChaosEngine()
        eng.warlog = warlog
        eng.agent = MagicMock()
        eng.start()
        eng.add_target(target)

        # Every stored level must be a lowercase value from the LogLevel enum.
        all_levels = {e["level"] for e in warlog.get_entries()}
        valid = {lv.value for lv in LogLevel}
        invalid = all_levels - valid
        assert not invalid, f"Invalid levels found in DB: {invalid}"
        assert "engine" not in all_levels
        assert "ENGINE" not in all_levels
