"""THE VOID — Command Center Attack-Graph API + live poller tests (W3).

Covers the live attack-graph plumbing that feeds the Command Center graph
with REAL engagement data:

    * GET /api/attack-graph returns nodes/edges/outcomes from the Boneyard.
    * EventPoller._poll_attack_graph seeds seen-node state when there are no
      WS clients (so a viewer doesn't get flooded on connect) and only
      broadcasts when new nodes appear AND clients are connected.
    * Poller emits ``attack_node`` per new step plus an ``attack_graph_full``
      rebuild, and does not broadcast when nothing changed.
"""

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from core.boneyard import Boneyard
from commandcenter.backend.services import bridge as bridge_mod
from commandcenter.backend.services.poller import EventPoller
from commandcenter.backend.main import create_app


@pytest.fixture(autouse=True)
def isolated_bridge(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    import core.boneyard as cb
    import core.warlog as cw

    monkeypatch.setattr(cb, "_instance", None, raising=False)
    monkeypatch.setattr(cb, "boneyard", None, raising=False)
    monkeypatch.setattr(cw, "_instance", None, raising=False)
    monkeypatch.setattr(cw, "warlog", None, raising=False)
    bridge_mod.reset_bridge()
    yield
    bridge_mod.reset_bridge()


@pytest.fixture
def seeded_boneyard(tmp_path):
    return Boneyard(storage_dir=str(tmp_path / "boneyard"))


def _seed(by):
    host = by.ensure_host(ip="10.9.9.9", hostname="web1")
    s1 = by.record_attack_step(host, "initial_access", outcome_status="attempted")
    s2 = by.record_attack_step(host, "exfil", outcome_status="success",
                               parent_step_id=s1)
    by.record_outcome(s2, "data", success=True)
    return host, s1, s2


# ─── REST endpoint ───────────────────────────────────────────────────────────

class TestAttackGraphEndpoint:
    def test_empty_boneyard(self):
        # W3 exit criterion: empty graph, not an error. Use an ISOLATED
        # empty boneyard so this stays deterministic even after real
        # engagements have populated the operator's live store (the default
        # Boneyard() storage dir is a fixed, shared location).
        import tempfile
        from core.boneyard import Boneyard

        empty = Boneyard(storage_dir=tempfile.mkdtemp(prefix="void_ag_empty_"))
        b = bridge_mod.get_bridge()
        b._boneyard = empty
        app = create_app()
        with TestClient(app, base_url="http://127.0.0.1:7070") as c:
            from commandcenter.session import access_token
            c.headers["Authorization"] = "Bearer " + access_token(7070)
            r = c.get("/api/attack-graph")
            assert r.status_code == 200
            j = r.json()
            assert j["nodes"] == []
            assert j["edges"] == []
            assert j["outcomes"] == []

    def test_seeded_returns_real_graph(self, seeded_boneyard):
        host, s1, s2 = _seed(seeded_boneyard)
        b = bridge_mod.get_bridge()
        b._boneyard = seeded_boneyard
        app = create_app()
        with TestClient(app, base_url="http://127.0.0.1:7070") as c:
            from commandcenter.session import access_token
            c.headers["Authorization"] = "Bearer " + access_token(7070)
            r = c.get("/api/attack-graph")
            assert r.status_code == 200
            j = r.json()
            assert len(j["nodes"]) == 2
            ids = {n["id"] for n in j["nodes"]}
            assert {s1, s2} == ids
            assert j["edges"] == [{"from": s1, "to": s2}]
            assert len(j["outcomes"]) == 1
            assert j["outcomes"][0]["attack_path_id"] == s2

    def test_filter_by_host(self, seeded_boneyard):
        host, s1, s2 = _seed(seeded_boneyard)
        other = seeded_boneyard.ensure_host(ip="10.9.9.10")
        seeded_boneyard.record_attack_step(other, "persist", outcome_status="attempted")
        b = bridge_mod.get_bridge()
        b._boneyard = seeded_boneyard
        app = create_app()
        with TestClient(app, base_url="http://127.0.0.1:7070") as c:
            from commandcenter.session import access_token
            c.headers["Authorization"] = "Bearer " + access_token(7070)
            r = c.get(f"/api/attack-graph?host_id={host}")
            assert r.status_code == 200
            assert len(r.json()["nodes"]) == 2
            r2 = c.get(f"/api/attack-graph?host_id={other}")
            assert len(r2.json()["nodes"]) == 1


# ─── Poller diff behavior ────────────────────────────────────────────────────

class FakeHub:
    """Captures broadcasts so we can assert what the poller emitted."""

    def __init__(self):
        self.messages = []
        self.client_count = 0

    async def broadcast(self, channel, payload):
        self.messages.append((channel, payload))


def _make_poller(boneyard, monkeypatch):
    bridge = MagicMock()
    bridge.graph_attack_paths.return_value = boneyard.graph_attack_paths(None)
    fake_hub = FakeHub()
    # The poller broadcasts through the module-level hub in services.poller.
    import commandcenter.backend.services.poller as poller_mod
    monkeypatch.setattr(poller_mod, "hub", fake_hub)
    return EventPoller(bridge), bridge, fake_hub


class TestAttackGraphPoller:
    def test_seeds_state_without_clients(self, seeded_boneyard, monkeypatch):
        _seed(seeded_boneyard)
        poller, bridge, hub = _make_poller(seeded_boneyard, monkeypatch)
        asyncio.run(poller._poll_attack_graph())
        # State seeded even though no clients connected.
        assert poller._seen_attack_nodes  # non-empty
        assert hub.messages == []  # no broadcast without clients

    def test_broadcasts_new_nodes_with_clients(self, seeded_boneyard, monkeypatch):
        _seed(seeded_boneyard)
        poller, bridge, hub = _make_poller(seeded_boneyard, monkeypatch)
        hub.client_count = 1
        asyncio.run(poller._poll_attack_graph())
        channels = [m[0] for m in hub.messages]
        types = [m[1]["type"] for m in hub.messages]
        assert channels.count("attack_graph") >= 1
        assert "attack_node" in types
        assert "attack_graph_full" in types

    def test_no_broadcast_when_no_change(self, seeded_boneyard, monkeypatch):
        _seed(seeded_boneyard)
        poller, bridge, hub = _make_poller(seeded_boneyard, monkeypatch)
        hub.client_count = 1
        # First poll seeds + broadcasts.
        asyncio.run(poller._poll_attack_graph())
        hub.messages.clear()
        # Bridge returns the same graph → no new nodes → no broadcast.
        asyncio.run(poller._poll_attack_graph())
        assert hub.messages == []

    def test_broadcasts_only_new_node_on_change(self, seeded_boneyard, monkeypatch):
        _seed(seeded_boneyard)
        poller, bridge, hub = _make_poller(seeded_boneyard, monkeypatch)
        hub.client_count = 1
        asyncio.run(poller._poll_attack_graph())  # seed + full
        hub.messages.clear()

        # Add a genuinely new step and refresh the bridge snapshot.
        host = seeded_boneyard.ensure_host(ip="10.9.9.9")
        new_step = seeded_boneyard.record_attack_step(
            host, "c2", outcome_status="attempted")
        bridge.graph_attack_paths.return_value = \
            seeded_boneyard.graph_attack_paths(None)
        asyncio.run(poller._poll_attack_graph())

        node_msgs = [m[1] for m in hub.messages if m[1]["type"] == "attack_node"]
        assert len(node_msgs) == 1
        assert node_msgs[0]["data"]["id"] == new_step
        assert any(m[1]["type"] == "attack_graph_full" for m in hub.messages)

    def test_empty_graph_noop(self, monkeypatch, tmp_path):
        empty = Boneyard(storage_dir=str(tmp_path / "ag_empty"))
        poller, bridge, hub = _make_poller(empty, monkeypatch)
        hub.client_count = 1
        asyncio.run(poller._poll_attack_graph())
        assert hub.messages == []
