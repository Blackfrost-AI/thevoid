"""DEMO MODE (W3 item 5) — deterministic seeded stage scenario.

Guarantees under test:
  1. ``enable_demo_mode`` swaps onto ISOLATED stores — the live boneyard /
     warlog are never touched (row counts unchanged, no demo rows appear).
  2. The seeded demo data is complete: hosts, chained attack steps with
     parent edges, outcomes, attack_* payloads reconstructable by
     CoverageBridge.attack_log().
  3. The demo timeline is DETERMINISTIC: two enables produce identical
     graph topology, ordering, and coverage scores.
  4. CoverageScorer scores the demo attack log through the real rubric
     (nonzero, completed status).
  5. Demo rows are flagged: tags contain ``demo`` and data carries
     ``demo: true``.
  6. ``disable_demo_mode`` restores the live stores and removes the demo
     runtime dir; integrity of the demo DB verifies while active.
  7. The demo router endpoints return the expected shapes; toggling is
     idempotent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Point the default store dirs + demo dir at tmp_path so nothing
    touches real workspace data."""
    import config.defaults as defaults

    live_dir = tmp_path / "live"
    monkeypatch.setattr(defaults, "BONEYARD_DIR", str(live_dir / "boneyard"), raising=False)
    monkeypatch.setattr(defaults, "WARLOG_DIR", str(live_dir / "warlog"), raising=False)

    demo_dir = tmp_path / "demo_runtime"
    monkeypatch.setattr(
        "commandcenter.backend.config.Settings.demo_dir", demo_dir
    )

    import commandcenter.backend.services.bridge as bridge_mod
    import commandcenter.backend.services.coverage_bridge as cb_mod

    bridge_mod.reset_bridge()
    cb_mod.reset_coverage_bridge()
    yield tmp_path
    bridge_mod.reset_bridge()
    cb_mod.reset_coverage_bridge()


def _bridge():
    from commandcenter.backend.services.bridge import get_bridge

    return get_bridge()


def test_enable_swaps_to_isolated_stores(tmp_path):
    bridge = _bridge()
    live_boneyard = bridge._boneyard
    live_warlog = bridge._warlog
    live_items_before = live_boneyard.summary().get("total_items", 0)
    live_entries_before = live_warlog.get_summary().get("total_entries", 0)

    status = bridge.enable_demo_mode()
    assert bridge.is_demo_mode() is True
    assert status["demo_mode"] is True
    assert status["hosts"] == 3
    assert status["steps"] >= 6
    assert status["outcomes"] == status["steps"]

    # Swapped refs are different objects
    assert bridge._boneyard is not live_boneyard
    assert bridge._warlog is not live_warlog

    # Live stores untouched
    assert live_boneyard.summary().get("total_items", 0) == live_items_before
    assert live_warlog.get_summary().get("total_entries", 0) == live_entries_before

    # No demo rows leaked into live stores
    for row in live_boneyard.search(limit=200):
        tags = row.get("tags") or []
        if isinstance(tags, str):
            tags = json.loads(tags)
        assert "demo" not in tags


def test_demo_data_complete_and_flagged():
    bridge = _bridge()
    bridge.enable_demo_mode()
    status = bridge.get_status()
    assert status["c2_channels"] == 1
    assert status["c2_active_channels"] == 0
    assert status["c2_recorded_channels"] == 1
    channels = bridge.list_channels()
    assert len(channels) == 1
    assert channels[0]["status"] == "recorded"
    assert channels[0]["live"] is False
    graph = bridge.graph_attack_paths(None)
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    outcomes = graph.get("outcomes") or []
    assert len(nodes) >= 9  # 6 + 3 phases across two engagements
    assert len(edges) >= 7  # every non-root step chained to a parent
    assert len(outcomes) == len(nodes)

    # Graph outcomes carry type/success; the full evidence rows (flagged
    # demo) live in the outcomes table — verify via direct DB read.
    for o in outcomes:
        assert o.get("type")
        assert isinstance(o.get("success"), bool)

    demo_db = Path(bridge._boneyard._db_path)
    import sqlite3

    conn = sqlite3.connect(demo_db)
    rows = conn.execute("SELECT evidence FROM outcomes").fetchall()
    conn.close()
    assert rows
    for (ev_json,) in rows:
        ev = json.loads(ev_json or "{}")
        assert ev.get("demo") is True

    # Attack payloads reconstructible via CoverageBridge
    from commandcenter.backend.services.coverage_bridge import get_coverage_bridge

    cb = get_coverage_bridge()
    payloads = cb.attack_log()
    assert len(payloads) == 2
    for p in payloads:
        assert p.get("demo") is True
        assert p.get("status") == "completed"
        assert p.get("target", "").endswith(".demo.void")


def test_demo_timeline_deterministic():
    bridge = _bridge()
    bridge.enable_demo_mode()
    g1 = bridge.graph_attack_paths(None)
    cb = None
    from commandcenter.backend.services.coverage_bridge import get_coverage_bridge
    cb = get_coverage_bridge()
    cov1 = cb.coverage()

    bridge.disable_demo_mode()
    assert bridge.is_demo_mode() is False
    bridge.enable_demo_mode()
    g2 = bridge.graph_attack_paths(None)
    cb.invalidate_cache()
    cov2 = cb.coverage()

    # Topology identical (ids differ — uuids — compare ordered structure).
    # Node list is ORDER BY epoch ASC, so order == deterministic timeline.
    def topo(g):
        return [
            (n.get("step_type"), n.get("technique"), n.get("outcome_status"),
             bool(n.get("parent_step_id")))
            for n in g.get("nodes") or []
        ]

    assert topo(g1) == topo(g2)
    assert len(g1["edges"]) == len(g2["edges"])
    # Scores identical
    assert cov1["aggregated"] == cov2["aggregated"]
    assert cov1["count"] == cov2["count"] == 2


def test_coverage_scorer_scores_demo():
    from commandcenter.backend.services.coverage_bridge import get_coverage_bridge

    bridge = _bridge()
    bridge.enable_demo_mode()
    cb = get_coverage_bridge()
    cov = cb.coverage()
    assert cov.get("count") == 2
    assert cov.get("aggregated", 0.0) > 0.0
    for eng in cov.get("engagement_scores") or []:
        assert eng.get("score", 0.0) > 0.0
        assert eng.get("target", "").endswith(".demo.void")


def test_demo_integrity_verifies():
    bridge = _bridge()
    bridge.enable_demo_mode()
    report = bridge.verify_integrity()
    assert report.get("verified") is True


def test_curated_scenario_projects_into_demo_chain():
    from cli.demo import _resolve_scenario

    chain, narration, engagement_name = _resolve_scenario("baseline-network")
    assert len(chain) == len(narration) == 4
    assert "baseline-network" in engagement_name
    assert all(step[-1] in (True, False) for step in chain)


def test_unknown_curated_scenario_is_a_cli_error():
    import click
    from cli.demo import _resolve_scenario

    with pytest.raises(click.ClickException):
        _resolve_scenario("not-a-scenario")


def test_disable_restores_live_and_cleans_dir():
    bridge = _bridge()
    live_boneyard = bridge._boneyard
    live_warlog = bridge._warlog

    bridge.enable_demo_mode()
    status = bridge.disable_demo_mode()
    assert bridge.is_demo_mode() is False
    assert status["demo_mode"] is False
    assert bridge._boneyard is live_boneyard
    assert bridge._warlog is live_warlog

    from commandcenter.backend.config import load_settings

    demo_dir = load_settings().demo_dir
    assert not Path(demo_dir).exists()

    # Idempotent
    assert bridge.disable_demo_mode()["demo_mode"] is False


def test_demo_router_endpoints():
    from fastapi.testclient import TestClient

    from commandcenter.backend.main import create_app
    from commandcenter.backend.services import poller as poller_mod
    from commandcenter.backend.ws import hub as hub_mod

    app = create_app()

    # Keep the poller out of the test path (it binds real async loops).
    original_poller = poller_mod.EventPoller

    class _StubPoller:
        def __init__(self, *a, **k):
            pass

        async def start(self):
            pass

        async def stop(self):
            pass

    poller_mod.EventPoller = _StubPoller
    try:
        client = TestClient(app, base_url="http://127.0.0.1:7070")
        r = client.get("/api/demo")
        assert r.status_code == 200
        assert r.json()["demo_mode"] is False

        r = client.post("/api/demo/enable")
        assert r.status_code == 200
        body = r.json()
        assert body["demo_mode"] is True
        assert body["hosts"] == 3

        # status echoes demo_mode
        r = client.get("/api/status")
        assert r.status_code == 200
        assert r.json().get("demo_mode") is True

        # enable is idempotent
        r = client.post("/api/demo/enable")
        assert r.status_code == 200 and r.json()["demo_mode"] is True

        # attack-graph serves demo nodes
        r = client.get("/api/attack-graph")
        assert r.status_code == 200
        assert len(r.json().get("nodes") or []) >= 9

        r = client.post("/api/demo/disable")
        assert r.status_code == 200 and r.json()["demo_mode"] is False
        r = client.get("/api/demo")
        assert r.json()["demo_mode"] is False
    finally:
        poller_mod.EventPoller = original_poller


def test_demo_status_fields():
    bridge = _bridge()
    s = bridge.demo_status()
    assert s["demo_mode"] is False
    assert s["scenario"] is None
    bridge.enable_demo_mode()
    s = bridge.demo_status()
    assert s["demo_mode"] is True
    assert s["scenario"] == "stage-scenario-1"
    assert s["engagements"] == 2
    assert "DEMO" in s["note"]
