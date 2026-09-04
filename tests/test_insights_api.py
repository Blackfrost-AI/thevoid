"""Tests for the Command Center insights API (W1).

Verifies the new endpoints serve REAL engine data — prevention-strength
scoring (R-2), MITRE mapping (R-1), compliance overlay (R-4), drift events
(R-3), and the scenario catalog (R-6) — and behave honestly on empty stores.

Stores are isolated per-test in tmp_path; the ServiceBridge and
CoverageBridge singletons are reset around every test.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.boneyard import Boneyard
from core.warlog import WarLog


# ─── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture()
def stores(tmp_path):
    """Isolated warlog + boneyard wired into fresh singletons."""
    from commandcenter.backend.services import bridge as bridge_mod
    from commandcenter.backend.services import coverage_bridge as cb_mod

    warlog = WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "void.log"),
        rotate_on_init=False,
    )
    boneyard = Boneyard(storage_dir=str(tmp_path / "boneyard"))

    bridge_mod.reset_bridge()
    cb_mod.reset_coverage_bridge()
    sb = bridge_mod.get_bridge()
    sb._warlog = warlog
    sb._boneyard = boneyard

    yield warlog, boneyard

    bridge_mod.reset_bridge()
    cb_mod.reset_coverage_bridge()


@pytest.fixture()
def client(stores):
    from commandcenter.backend.main import create_app

    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:7070") as c:
        from commandcenter.session import access_token
        c.headers["Authorization"] = "Bearer " + access_token(7070)
        yield c


# ─── Helpers ───────────────────────────────────────────────────────────────

def _payload(target="web1", phases=("recon", "vuln"), status="completed"):
    return {
        "status": status,
        "target": target,
        "mode": "recon",
        "findings": {p: {"services": ["http"], "note": f"{p} ran"} for p in phases},
        "elapsed": 1.23,
    }


def _seed_attack(boneyard, target="web1", ts=1723900000):
    boneyard.store(f"attack_{target}_{ts}", _payload(target))


def _seed_drift(boneyard, target="web1", phases=None):
    boneyard.store("drift", {
        "kind": "drift",
        "target": target,
        "phases": phases or {"recon": "verified -> unknown"},
        "ts": "2026-08-17T00:00:00+00:00",
    }, tags=["continuity", "drift"])


# ─── /api/coverage (R-2) ───────────────────────────────────────────────────

class TestCoverageEndpoint:
    def test_scores_persisted_attack(self, client, stores):
        _seed_attack(stores[1])
        r = client.get("/api/coverage")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert isinstance(body["aggregated"], (int, float))
        assert len(body["engagement_scores"]) == 1
        assert body["engagement_scores"][0]["target"] == "web1"

    def test_empty_store_honest_zero(self, client):
        r = client.get("/api/coverage")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 0
        assert body["aggregated"] == 0.0
        assert body["engagement_scores"] == []

    def test_incomplete_engagement_scores_zero(self, client, stores):
        stores[1].store("attack_halted_1", _payload(status="failed"))
        body = client.get("/api/coverage").json()
        assert body["count"] == 1
        assert body["aggregated"] == 0.0


# ─── /api/mitre (R-1) ──────────────────────────────────────────────────────

class TestMitreEndpoint:
    def test_real_technique_mapping(self, client, stores):
        _seed_attack(stores[1])
        r = client.get("/api/mitre")
        assert r.status_code == 200
        body = r.json()
        ids = [t["id"] for t in body["techniques_used"]]
        assert "T1046" in ids
        assert body["coverage_pct"] > 0
        assert body["mapped_phases"]  # recon/vuln phases present
        assert "mapped_findings" not in body  # excluded for payload size

    def test_empty_store_no_techniques(self, client):
        body = client.get("/api/mitre").json()
        assert body["techniques_used"] == []
        assert body["coverage_pct"] == 0

    def test_alias_honesty_carries_through(self, client, stores):
        """LLM/MCP phases must surface as ALIAS: ids, never invented T-ids."""
        stores[1].store("attack_llm_2", _payload(target="llm1", phases=("llm_jailbreak",)))
        body = client.get("/api/mitre").json()
        ids = [t["id"] for t in body["techniques_used"]]
        aliases = [t for t in ids if t.startswith("ALIAS:")]
        assert aliases, "expected ALIAS: technique for llm_jailbreak"


# ─── /api/compliance (R-4) ─────────────────────────────────────────────────

class TestComplianceEndpoint:
    def test_cross_reference_for_native_techniques(self, client, stores):
        _seed_attack(stores[1])
        r = client.get("/api/compliance")
        assert r.status_code == 200
        body = r.json()
        assert "T1046" in body["compliance"]
        ref = body["compliance"]["T1046"]
        assert ref.get("nist") and ref.get("pci") and ref.get("iso")
        assert "advisory" in body["note"].lower()

    def test_empty_store(self, client):
        body = client.get("/api/compliance").json()
        assert body["compliance"] == {}
        assert body["techniques_used"] == []


# ─── /api/drift (R-3) ──────────────────────────────────────────────────────

class TestDriftEndpoint:
    def test_returns_persisted_drift(self, client, stores):
        _seed_drift(stores[1], target="web1")
        r = client.get("/api/drift")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        ev = body["events"][0]
        assert ev["category"] == "drift"
        assert ev["data"]["kind"] == "drift"
        assert ev["data"]["target"] == "web1"

    def test_most_recent_first(self, client, stores):
        import time
        _seed_drift(stores[1], target="old", phases={"recon": "a"})
        time.sleep(0.01)
        _seed_drift(stores[1], target="new", phases={"recon": "b"})
        body = client.get("/api/drift").json()
        assert body["count"] == 2
        assert body["events"][0]["data"]["target"] == "new"

    def test_empty_store(self, client):
        body = client.get("/api/drift").json()
        assert body == {"events": [], "count": 0}


# ─── /api/scenarios (R-6) ──────────────────────────────────────────────────

class TestScenariosEndpoint:
    def test_catalog(self, client):
        r = client.get("/api/scenarios")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] >= 5  # built-in catalog
        assert body["count"] == len(body["scenarios"])
        names = {s["name"] for s in body["scenarios"]}
        assert "mcp-critical" in names


# ─── Continuity persistence regression (W1 drift bug fix) ─────────────────

class TestDriftPersistenceFix:
    """_persist_drift previously called nonexistent boneyard.put() and
    warlog.log(**kwargs) — drift was silently dropped. The fixed engine
    calls must actually persist."""

    def test_persist_drift_writes_to_real_stores(self, stores):
        warlog, boneyard = stores
        from modules.continuity import ContinuityScheduler

        sched = ContinuityScheduler(
            shadow_agent=None,
            targets=[],
            warlog=warlog,
            boneyard=boneyard,
        )
        sched._persist_drift("web1", {"phases": {"recon": "verified -> unknown"}},
                             "2026-08-17T00:00:00+00:00")

        rows = boneyard.search(category="drift")
        assert len(rows) == 1
        assert rows[0]["data"]["kind"] == "drift"
        assert rows[0]["data"]["target"] == "web1"

        entries = warlog.get_entries(module="continuity")
        assert any("Continuity drift" in str(e.get("message", "")) for e in entries)
