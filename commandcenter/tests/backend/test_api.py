"""Integration tests for REST endpoints with mocked bridge."""

from __future__ import annotations

import sys
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def mock_bridge():
    b = MagicMock()
    b.degraded = []
    b.get_status.return_value = {
        "engaged": False,
        "targets": [],
        "target_count": 0,
        "active_sessions": [],
        "stolen_data": 0,
        "stealth_active": False,
        "warlog_entries": 10,
        "attack_log": 0,
        "beacons": [],
        "beacon_count": 0,
        "c2_status": {},
        "c2_channels": 0,
        "c2_beacons": 0,
        "c2_tasks": 0,
        "boneyard_items": 5,
        "degraded": [],
    }
    b.query_hosts.return_value = [
        {"id": "h1", "ip_address": "10.0.0.1", "hostname": "web01"}
    ]
    b.get_target.return_value = {
        "host": {"id": "h1", "ip_address": "10.0.0.1"},
        "findings": [],
        "attack_paths": {"nodes": [], "edges": [], "outcomes": []},
    }
    b.query_findings.return_value = [
        {"id": "f1", "category": "recon", "tags": [], "risk_score": 0.5}
    ]
    b.search_findings.return_value = []
    b.boneyard_summary.return_value = {"total_items": 5, "categories": {"recon": 5}}
    b.boneyard_categories.return_value = ["recon"]
    b.verify_integrity.return_value = {
        "verified": True,
        "total_rows_checked": 10,
        "broken_hmacs": [],
        "broken_chain_links": [],
        "orphaned_audit_entries": [],
        "table_counts": {},
        "audit_chain_length": 0,
    }
    b.graph_attack_paths.return_value = {"nodes": [], "edges": [], "outcomes": []}
    b.list_channels.return_value = []
    b.get_channel_status.return_value = {"channel_id": "c1", "status": "active"}
    b.check_channel_health.return_value = {"healthy": True, "channel_id": "c1"}
    b.get_tasks.return_value = []
    b.get_warlog_entries.return_value = [
        {"id": "e1", "level": "agent", "message": "hello", "module": "chaos"}
    ]
    b.get_warlog_summary.return_value = {
        "session_id": "sess",
        "total_entries": 10,
        "level_counts": {"agent": 10},
    }
    b.query_spans.return_value = []
    b.gather_report_data.return_value = {"exec_summary": {"findings_count": 0}}
    b.generate_report.return_value = {
        "format": "json",
        "content": "{}",
        "path": None,
    }
    return b


@pytest.fixture
def client(mock_bridge):
    with patch(
        "commandcenter.backend.services.bridge.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.main.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.status.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.targets.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.boneyard.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.attack_graph.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.c2.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.warlog.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.routers.report.get_bridge", return_value=mock_bridge
    ), patch(
        "commandcenter.backend.services.poller.EventPoller.start", return_value=None
    ), patch(
        "commandcenter.backend.services.poller.EventPoller.stop", return_value=None
    ):
        # Rebuild app so lifespan is manageable
        from commandcenter.backend.main import create_app

        app = create_app()
        with TestClient(app) as c:
            yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_bundled_frontend_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert '<div id="root"></div>' in r.text


def test_bundled_frontend_asset(client):
    index = client.get("/").text
    asset_path = re.search(r'src="(/assets/[^"]+\.js)"', index)
    assert asset_path is not None
    asset = client.get(asset_path.group(1))
    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"]


def test_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert "warlog_entries" in body
    assert body["boneyard_items"] == 5


def test_targets(client):
    r = client.get("/api/targets")
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_target_detail(client):
    r = client.get("/api/targets/h1")
    assert r.status_code == 200
    assert r.json()["host"]["id"] == "h1"


def test_findings(client):
    r = client.get("/api/findings")
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_boneyard_summary(client):
    r = client.get("/api/boneyard/summary")
    assert r.status_code == 200
    assert r.json()["total_items"] == 5


def test_integrity(client):
    r = client.get("/api/boneyard/integrity")
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_attack_graph(client):
    r = client.get("/api/attack-graph")
    assert r.status_code == 200
    assert "nodes" in r.json()


def test_c2_channels(client):
    r = client.get("/api/c2/channels")
    assert r.status_code == 200
    assert r.json()["count"] == 0


def test_warlog_entries(client):
    r = client.get("/api/warlog/entries?limit=10")
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_warlog_summary(client):
    r = client.get("/api/warlog/summary")
    assert r.status_code == 200
    assert r.json()["session_id"] == "sess"


def test_report_preview(client):
    r = client.get("/api/report/preview")
    assert r.status_code == 200
    assert "exec_summary" in r.json()


def test_report_generate(client):
    r = client.post(
        "/api/report/generate",
        json={"format": "json", "operator": "ops", "engagement_name": "demo"},
    )
    assert r.status_code == 200
    assert r.json()["format"] == "json"


def test_localhost_assertion():
    from commandcenter.backend.config import Settings

    with pytest.raises(RuntimeError):
        Settings(host="0.0.0.0").assert_localhost()
    Settings(host="127.0.0.1").assert_localhost()
