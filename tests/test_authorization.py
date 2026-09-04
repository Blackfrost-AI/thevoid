"""Tests for scope / authorization gate and mode phase selection."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from core.authorization import AuthorizationGate, AuthzDecision
from core.target import Target


class TestAuthorizationGate:
    @staticmethod
    def document(**overrides):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        return {
            "authorized": True, "operator": "fixture", "engagement_name": "offline-test",
            "in_scope": ["fixture.invalid"], "allowed_modes": ["quick", "full"],
            "not_before": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=1)).isoformat(),
            **overrides,
        }

    def test_no_legacy_open_gate(self):
        gate = AuthorizationGate(require_authorization=False)
        assert gate.check_target("fixture.invalid").allowed is False

    def test_require_authz_denies_without_file(self):
        assert not AuthorizationGate().check_target("fixture.invalid").allowed

    def test_in_scope_cidr(self):
        gate = AuthorizationGate(data=self.document(in_scope=["192.0.2.0/24"]))
        assert gate.check_target("192.0.2.1", "quick").allowed
        assert not gate.check_target("198.51.100.1", "quick").allowed

    def test_mode_not_allowed(self):
        gate = AuthorizationGate(data=self.document(allowed_modes=["quick"]))
        decision = gate.check_target("fixture.invalid", "full")
        assert not decision.allowed
        assert "allowed_modes" in decision.reason

    def test_filter_phases(self):
        gate = AuthorizationGate(data=self.document(denied_phases=["destruction", "crypto_theft"]))
        assert gate.filter_phases(["recon", "destruction", "crypto_theft"]) == ["recon"]

    def test_load_json_file(self, tmp_path):
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(self.document()))
        gate = AuthorizationGate(authz_path=str(path))
        assert gate.loaded
        assert gate.check_target("fixture.invalid", "quick").allowed

    def test_hostname_scope(self):
        gate = AuthorizationGate(data=self.document(in_scope=["*.fixture.invalid"]))
        assert gate.check_target("app.fixture.invalid", "quick").allowed
        assert not gate.check_target("elsewhere.invalid", "quick").allowed

    def test_exclusions_still_cover_subdomains(self):
        gate = AuthorizationGate(data=self.document(
            in_scope=["*.fixture.invalid"], out_of_scope=["restricted.fixture.invalid"],
        ))
        assert not gate.check_target("child.restricted.fixture.invalid", "quick").allowed


class TestModePhases:
    def test_quick_is_recon_only(self):
        from agent.shadow_agent import ShadowAgent

        agent = ShadowAgent()
        phases = agent.phases_for_mode("quick")
        assert phases == ["recon"]

    def test_high_risk_phases_denied_by_default(self):
        from agent.shadow_agent import ShadowAgent

        agent = ShadowAgent()
        phases = agent.phases_for_mode("chaos")
        assert "destruction" not in phases
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
        assert result["status"] == "denied"

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
