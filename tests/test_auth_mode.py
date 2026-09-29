"""THE VOID — auth mode (dev | strict) contract tests.

The hardened gate fails closed with no authorization document. The single
sanctioned bypass is an explicit dev mode, which must:

  1. Never activate by default (strict unless explicitly requested).
  2. Be resolved from VOID_AUTH_MODE env or the AUTH_MODE setting only.
  3. Keep explicitly out-of-scope targets denied even in dev mode.
  4. Reject garbage mode values loudly instead of silently defaulting.
"""

import pytest

from core.authorization import (
    AUTH_MODE_DEV,
    AUTH_MODE_STRICT,
    AuthorizationGate,
    resolve_auth_mode,
)


class TestResolveAuthMode:
    def test_default_is_strict(self, monkeypatch):
        monkeypatch.delenv("VOID_AUTH_MODE", raising=False)
        assert resolve_auth_mode() == AUTH_MODE_STRICT

    def test_env_dev(self, monkeypatch):
        monkeypatch.setenv("VOID_AUTH_MODE", "dev")
        assert resolve_auth_mode() == AUTH_MODE_DEV

    def test_legacy_vocabulary(self, monkeypatch):
        monkeypatch.delenv("VOID_AUTH_MODE", raising=False)
        assert resolve_auth_mode("on") == AUTH_MODE_STRICT
        assert resolve_auth_mode("off") == AUTH_MODE_DEV

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            resolve_auth_mode("yolo")


class TestStrictMode:
    def test_no_document_denied(self, monkeypatch):
        monkeypatch.delenv("VOID_AUTH_MODE", raising=False)
        gate = AuthorizationGate()
        decision = gate.check_target("10.0.0.1", mode="quick")
        assert not decision.allowed

    def test_legacy_flag_cannot_weaken_gate(self):
        # require_authorization=False is accepted for source compatibility
        # but must NOT open the gate in strict mode.
        gate = AuthorizationGate(require_authorization=False)
        assert gate.auth_mode == AUTH_MODE_STRICT
        assert not gate.check_target("10.0.0.1").allowed


class TestDevMode:
    def test_dev_allows_without_document(self):
        gate = AuthorizationGate(auth_mode=AUTH_MODE_DEV)
        decision = gate.check_target("10.0.0.1", mode="quick")
        assert decision.allowed
        assert "dev auth mode" in decision.reason

    def test_dev_bypass_is_loud(self, caplog):
        import logging

        gate = AuthorizationGate(auth_mode=AUTH_MODE_DEV)
        with caplog.at_level(logging.WARNING, logger="void.authorization"):
            gate.check_target("10.0.0.1")
        assert any("DEV AUTH BYPASS" in r.getMessage() for r in caplog.records)

    def test_dev_still_denies_explicit_out_of_scope(self):
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        gate = AuthorizationGate(
            auth_mode=AUTH_MODE_DEV,
            data={
                "authorized": True,
                "operator": "op",
                "engagement_name": "lab",
                "in_scope": ["10.0.0.0/8"],
                "allowed_modes": ["quick"],
                "out_of_scope": ["10.9.9.9"],
                "not_before": (now - timedelta(hours=1)).isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
            },
        )
        assert gate.check_target("10.1.1.1", mode="quick").allowed
        assert not gate.check_target("10.9.9.9", mode="quick").allowed

    def test_dev_invalid_document_bypasses_loudly(self):
        gate = AuthorizationGate(auth_mode=AUTH_MODE_DEV, data={"nope": 1})
        decision = gate.check_target("10.0.0.1")
        assert decision.allowed
        assert "invalid authorization document" in decision.reason

    def test_invalid_auth_mode_rejected_at_gate(self):
        with pytest.raises(ValueError):
            AuthorizationGate(auth_mode="maybe")