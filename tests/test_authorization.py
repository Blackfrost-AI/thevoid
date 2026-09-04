"""Tests for scope / authorization gate and mode phase selection."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from core.authorization import AuthorizationGate, AuthzDecision
from core.target import Target


class TestAuthorizationGate:
    def test_open_when_no_file(self):
        gate = AuthorizationGate(require_authorization=False)
        d = gate.check_target("8.8.8.8", mode="full")
        assert d.allowed is True
        assert "legacy" in d.reason or "no authorization" in d.reason

    def test_require_authz_denies_without_file(self):
        gate = AuthorizationGate(require_authorization=True)
        d = gate.check_target("127.0.0.1", mode="quick")
        assert d.allowed is False

    def test_in_scope_cidr(self):
        gate = AuthorizationGate(
            data={
                "authorized": True,
                "in_scope": ["10.0.0.0/8"],
                "allowed_modes": ["quick", "full"],
            }
        )
        assert gate.check_target("10.1.2.3", "quick").allowed is True
        assert gate.check_target("11.0.0.1", "quick").allowed is False

    def test_mode_not_allowed(self):
        gate = AuthorizationGate(
            data={
                "authorized": True,
                "in_scope": ["127.0.0.1"],
                "allowed_modes": ["quick"],
            }
        )
        d = gate.check_target("127.0.0.1", mode="chaos")
        assert d.allowed is False
        assert "allowed_modes" in d.reason

    def test_filter_phases(self):
        gate = AuthorizationGate(
            data={
                "authorized": True,
                "in_scope": ["127.0.0.1"],
                "denied_phases": ["destruction", "crypto_theft"],
            }
        )
        out = gate.filter_phases(
            ["recon", "destruction", "exploit", "crypto_theft"]
        )
        assert out == ["recon", "exploit"]

    def test_load_json_file(self):
        doc = {
            "authorized": True,
            "engagement_name": "unit-test",
            "in_scope": ["192.168.1.0/24"],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
            path = f.name
        try:
            gate = AuthorizationGate(authz_path=path)
            assert gate.loaded is True
            assert gate.check_target("192.168.1.50", "full").allowed is True
            assert gate.check_target("10.0.0.1", "full").allowed is False
        finally:
            os.unlink(path)

    def test_hostname_scope(self):
        gate = AuthorizationGate(
            data={
                "authorized": True,
                "in_scope": ["lab.local", "*.lab.local"],
            }
        )
        assert gate.check_target("lab.local", "quick").allowed is True
        assert gate.check_target("app.lab.local", "quick").allowed is True
        assert gate.check_target("evil.com", "quick").allowed is False


class TestModePhases:
    def test_quick_is_recon_only(self):
        from agent.shadow_agent import ShadowAgent

        agent = ShadowAgent()
        phases = agent.phases_for_mode("quick")
        assert phases == ["recon"]

    def test_chaos_includes_destruction_by_default(self):
        from agent.shadow_agent import ShadowAgent

        agent = ShadowAgent()
        phases = agent.phases_for_mode("chaos")
        assert "destruction" in phases
        assert "recon" in phases

    def test_extra_denied_phases(self):
        from agent.shadow_agent import ShadowAgent

        agent = ShadowAgent()
        agent.extra_denied_phases = {"destruction", "crypto_theft"}
        phases = agent.phases_for_mode("chaos")
        assert "destruction" not in phases
        assert "crypto_theft" not in phases


class TestChaosAuthzIntegration:
    def test_dry_run_no_tools(self):
        from config.settings import Settings
        from orchestrator.chaos import ChaosEngine

        s = Settings()
        s._load_defaults()
        s.set("DRY_RUN", True)
        s.set("REQUIRE_AUTHORIZATION", False)
        s.set("CLIENT_MODE", False)
        s.set("STRICT_DIFFICULTY", False)
        eng = ChaosEngine(s)
        result = eng.engage(Target(value="127.0.0.1", name="loopback"), mode="quick")
        assert result["status"] == "dry_run"
        assert "recon" in result.get("planned_phases", [])

    def test_out_of_scope_denied_with_authz(self):
        from config.settings import Settings
        from orchestrator.chaos import ChaosEngine

        s = Settings()
        s._load_defaults()
        s.set("CLIENT_MODE", False)
        s.set("REQUIRE_AUTHORIZATION", False)
        s.set("STRICT_DIFFICULTY", False)
        s.set("DRY_RUN", False)
        eng = ChaosEngine(s)
        eng.authz = AuthorizationGate(
            data={
                "authorized": True,
                "in_scope": ["10.0.0.0/8"],
                "allowed_modes": ["quick", "full"],
            }
        )
        eng.agent.authz = eng.authz
        result = eng.engage(Target(value="8.8.8.8", name="dns"), mode="quick")
        assert result["status"] == "denied"
