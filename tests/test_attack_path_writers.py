"""THE VOID — W3 attack-path persistence tests.

Verifies the Boneyard attack-path writers (``ensure_host``,
``record_attack_step``, ``record_outcome``) that feed the Command Center
Attack Graph and kill-chain timeline with REAL engagement data.

Key behaviors under test:

    1.  ``ensure_host`` creates a host when absent and is idempotent when a
        matching ip/hostname already exists.
    2.  ``record_attack_step`` inserts a step whose fields round-trip through
        ``graph_attack_paths``.
    3.  Parent/child chaining: a step with ``parent_step_id`` produces a graph
        edge ``parent -> child``.
    4.  ``record_outcome`` attaches an outcome whose ``attack_path_id`` links
        back to the step and appears in ``graph_attack_paths`` outcomes.
    5.  All written rows carry a valid ``row_hmac`` + ``chain_hmac`` and the
        boneyard ``verify_integrity`` passes afterwards.
    6.  Honest semantics: ``outcome_status`` defaults to ``attempted``; a
        failed phase maps to ``failed`` (never invented ``success``).
"""

import pytest

from core.boneyard import Boneyard


@pytest.fixture
def boneyard(tmp_path):
    """Fresh Boneyard with no encryption, no warlog."""
    return Boneyard(storage_dir=str(tmp_path / "boneyard"))


# ─── ensure_host ─────────────────────────────────────────────────────────────

class TestEnsureHost:
    def test_creates_host_when_absent(self, boneyard):
        host_id = boneyard.ensure_host(ip="10.9.9.9", hostname="demo.example")
        assert host_id
        assert isinstance(host_id, str)

    def test_idempotent_on_ip_match(self, boneyard):
        h1 = boneyard.ensure_host(ip="10.9.9.9")
        h2 = boneyard.ensure_host(ip="10.9.9.9")
        assert h1 == h2

    def test_idempotent_on_hostname_match(self, boneyard):
        h1 = boneyard.ensure_host(hostname="web01.local")
        h2 = boneyard.ensure_host(hostname="web01.local")
        assert h1 == h2

    def test_distinct_hosts_get_distinct_ids(self, boneyard):
        a = boneyard.ensure_host(ip="10.0.0.1")
        b = boneyard.ensure_host(ip="10.0.0.2")
        assert a != b


# ─── record_attack_step ──────────────────────────────────────────────────────

class TestRecordAttackStep:
    def test_insert_and_graph_roundtrip(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        step = boneyard.record_attack_step(
            host, "initial_access", technique="T1078",
            description="phase=recon status=attempted",
            outcome_status="attempted",
        )
        g = boneyard.graph_attack_paths(host)
        assert len(g["nodes"]) == 1
        node = g["nodes"][0]
        assert node["id"] == step
        assert node["step_type"] == "initial_access"
        assert node["technique"] == "T1078"

    def test_parent_child_edge(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        s1 = boneyard.record_attack_step(
            host, "initial_access", outcome_status="attempted")
        s2 = boneyard.record_attack_step(
            host, "exfil", outcome_status="attempted", parent_step_id=s1)
        g = boneyard.graph_attack_paths(host)
        assert len(g["nodes"]) == 2
        assert len(g["edges"]) == 1
        e = g["edges"][0]
        assert e["from"] == s1 and e["to"] == s2

    def test_default_outcome_status_attempted(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        step = boneyard.record_attack_step(host, "persist")
        g = boneyard.graph_attack_paths(host)
        assert g["nodes"][0]["outcome_status"] == "attempted"

    def test_failed_status_honored(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        step = boneyard.record_attack_step(
            host, "exploit", outcome_status="failed",
            description="phase=exploit status=failed error=timeout")
        g = boneyard.graph_attack_paths(host)
        assert g["nodes"][0]["outcome_status"] == "failed"


# ─── record_outcome ──────────────────────────────────────────────────────────

class TestRecordOutcome:
    def test_outcome_links_to_step(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        step = boneyard.record_attack_step(host, "exfil", outcome_status="attempted")
        out = boneyard.record_outcome(step, "data", success=True,
                                      evidence={"phase": "datatheft"})
        assert out
        g = boneyard.graph_attack_paths(host)
        assert len(g["outcomes"]) == 1
        o = g["outcomes"][0]
        assert o["attack_path_id"] == step
        assert o["type"] == "data"
        assert o["success"] is True

    def test_success_flag_roundtrips(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        step = boneyard.record_attack_step(host, "exfil", outcome_status="attempted")
        boneyard.record_outcome(step, "data", success=False)
        g = boneyard.graph_attack_paths(host)
        assert g["outcomes"][0]["success"] is False


# ─── integrity ───────────────────────────────────────────────────────────────

class TestIntegrity:
    def test_verify_integrity_passes_after_writes(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        s1 = boneyard.record_attack_step(host, "initial_access", outcome_status="attempted")
        s2 = boneyard.record_attack_step(
            host, "exfil", outcome_status="attempted", parent_step_id=s1)
        boneyard.record_outcome(s2, "data", success=True)

        report = boneyard.verify_integrity()
        assert report.verified is True
        assert report.broken_hmacs == []
        assert report.broken_chain_links == []

    def test_attack_paths_table_counted(self, boneyard):
        host = boneyard.ensure_host(ip="10.9.9.9")
        boneyard.record_attack_step(host, "initial_access", outcome_status="attempted")
        report = boneyard.verify_integrity()
        assert report.table_counts.get("attack_paths", 0) >= 1
