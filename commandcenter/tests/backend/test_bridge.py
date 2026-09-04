"""Unit tests for ServiceBridge — mocks VOID modules."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from commandcenter.backend.services import bridge as bridge_mod
from commandcenter.backend.services.bridge import ServiceBridge, reset_bridge


@pytest.fixture(autouse=True)
def _reset():
    reset_bridge()
    yield
    reset_bridge()


def _make_bridge_with_mocks():
    """Construct a ServiceBridge with mocked modules injected."""
    b = object.__new__(ServiceBridge)
    b.degraded = []
    b._boneyard = MagicMock()
    b._warlog = MagicMock()
    b._chaos = MagicMock()
    b._mcp_c2 = MagicMock()
    b._reporter = MagicMock()
    b._demo_active = False
    b._live_boneyard = None
    b._live_warlog = None
    b._demo_summary = {}
    b._state_listeners = []
    return b


def test_get_status_aggregates():
    b = _make_bridge_with_mocks()
    b._chaos.get_status.return_value = {
        "engaged": True,
        "targets": ["10.0.0.1"],
        "active_sessions": ["s1"],
        "stolen_data": 3,
        "stealth_active": True,
        "warlog_entries": 10,
        "attack_log": 2,
        "beacons": ["b1"],
        "c2_status": {"running": True},
    }
    b._mcp_c2.get_active_channel_count.return_value = 1
    b._mcp_c2.get_total_beacons.return_value = 5
    b._mcp_c2.get_total_tasks.return_value = 2
    b._boneyard.summary.return_value = {"total_items": 42}

    status = b.get_status()
    assert status["engaged"] is True
    assert status["target_count"] == 1
    assert status["c2_channels"] == 1
    assert status["boneyard_items"] == 42
    assert status["degraded"] == []


def test_sanitize_strips_secrets():
    b = _make_bridge_with_mocks()
    dirty = {
        "channel_id": "x",
        "auth": {"token": "secret"},
        "password": "p",
        "nested": {"api_key": "k", "ok": 1},
    }
    clean = b._sanitize(dirty)
    assert "auth" not in clean
    assert "password" not in clean
    assert "api_key" not in clean["nested"]
    assert clean["nested"]["ok"] == 1
    assert clean["channel_id"] == "x"


def test_query_hosts_returns_list():
    b = _make_bridge_with_mocks()

    class QR:
        def __iter__(self):
            return iter([{"id": "h1", "ip_address": "10.0.0.1", "row_hmac": "x"}])

    b._boneyard.query_hosts.return_value = QR()
    hosts = b.query_hosts()
    assert len(hosts) == 1
    assert hosts[0]["id"] == "h1"
    assert "row_hmac" not in hosts[0]


def test_boneyard_unavailable():
    b = _make_bridge_with_mocks()
    b._boneyard = None
    assert b.query_hosts() == []
    assert b.query_findings() == []
    summary = b.boneyard_summary()
    assert summary.get("error")


def test_warlog_entries_normalize():
    b = _make_bridge_with_mocks()
    b._warlog.get_entries.return_value = [
        {"epoch": 1000.0, "level": "agent", "operation": "engage", "module": "chaos"},
        {"epoch": 1001.0, "level": "c2", "message": "beacon", "module": "mcp_c2"},
    ]
    entries = b.get_warlog_entries(limit=10)
    assert len(entries) == 2
    # newest first
    assert entries[0]["level"] == "c2"
    assert entries[1]["message"] == "engage"


def test_graph_attack_paths():
    b = _make_bridge_with_mocks()
    b._boneyard.graph_attack_paths.return_value = {
        "nodes": [{"id": "n1"}],
        "edges": [{"from": "n1", "to": "n2"}],
        "outcomes": [],
    }
    g = b.graph_attack_paths("host1")
    assert len(g["nodes"]) == 1
    assert len(g["edges"]) == 1


def test_list_channels_strips_auth():
    b = _make_bridge_with_mocks()
    b._mcp_c2.list_channels.return_value = [
        {"channel_id": "c1", "status": "active", "auth": {"token": "x"}}
    ]
    b._mcp_c2.channels = {}
    channels = b.list_channels()
    assert channels[0]["channel_id"] == "c1"
    assert "auth" not in channels[0]
