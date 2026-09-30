"""THE VOID — WarLog Merkle anchoring tests (P2, offline).

Covers:
  * anchor_events(): builds a Merkle root over row_hmac values, persists
    the anchor row, and is deterministic for identical logs.
  * verify_anchor(): passes for a clean log; fails after any row tamper
    inside the anchored range.
  * get_merkle_proof()/verify_merkle_proof(): anchored proofs verify
    against the frozen root; tampering any row (the leaf itself or any
    sibling in range) fails verification of every proof in the anchor.
  * Padding math: non-power-of-two leaf counts duplicate the last leaf
    consistently between root and proof paths.
  * Fail-closed: unknown anchor, empty range, unknown seq, forged anchor
    HMAC all verify False / raise.
  * mark_anchor_published(): publish stub, unknown id returns False.
"""

import sqlite3

import pytest

from core.warlog import LogLevel, WarLog


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


def seed(warlog, n=5):
    for i in range(n):
        warlog.log(f"e{i}", module="test", target="t1", data={"i": i})


# ─── Anchor construction ───────────────────────────────────────────────────

class TestAnchorConstruction:
    def test_anchor_persists_and_verifies(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 5)
        anchor = wl.anchor_events(1, 5)
        assert anchor["count"] == 5
        assert wl.verify_anchor(anchor["anchor_id"])
        assert len(wl.get_anchors()) == 1

    def test_deterministic_root(self, tmp_path):
        a = make_warlog(tmp_path / "a")
        b = make_warlog(tmp_path / "b")
        seed(a, 4)
        seed(b, 4)
        # Same content, independent chains — roots differ because row_hmac
        # covers seq/timestamp/..., but padding math is identical.
        ra = a.anchor_events(1, 4)["merkle_root"]
        rb = b.anchor_events(1, 4)["merkle_root"]
        assert len(ra) == len(rb) == 64

    def test_empty_range_raises(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        with pytest.raises(ValueError):
            wl.anchor_events(99, 100)

    def test_anchor_evidenced(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        wl.anchor_events(1, 3)
        entries = wl.get_entries(module="core.warlog")
        assert any("merkle anchor" in e["message"] for e in entries)


# ─── Inclusion proofs ──────────────────────────────────────────────────────

class TestMerkleProofs:
    @pytest.fixture()
    def anchored(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 5)
        anchor = wl.anchor_events(1, 5)
        return wl, anchor

    @pytest.mark.parametrize("seq", [1, 3, 5])
    def test_anchored_proof_verifies(self, anchored, seq):
        wl, anchor = anchored
        proof = wl.get_merkle_proof(seq, anchor_id=anchor["anchor_id"])
        assert wl.verify_merkle_proof(proof, anchor_id=anchor["anchor_id"])

    @pytest.mark.parametrize("seq", [1, 3, 5])
    def test_live_proof_verifies(self, anchored, seq):
        wl, anchor = anchored
        proof = wl.get_merkle_proof(seq)
        assert wl.verify_merkle_proof(proof)

    def test_tamper_leaf_fails(self, anchored):
        wl, anchor = anchored
        c = wl._get_conn()
        c.execute("UPDATE events SET row_hmac = ? WHERE seq = ?",
                  ("0" * 64, 3))
        c.commit()
        c.close()
        proof = wl.get_merkle_proof(3, anchor_id=anchor["anchor_id"])
        assert wl.verify_merkle_proof(proof, anchor_id=anchor["anchor_id"]) is False

    def test_tamper_somewhere_else_fails_every_proof(self, anchored):
        # Tamper-proofing: any row inside the anchored range whose
        # row_hmac changes (e.g. a swapped sibling) invalidates the
        # frozen root, so *no* proof in that anchor passes.
        wl, anchor = anchored
        c = wl._get_conn()
        c.execute("UPDATE events SET row_hmac = ? WHERE seq = ?",
                  ("0" * 64, 2))
        c.commit()
        c.close()
        assert wl.verify_anchor(anchor["anchor_id"]) is False
        for seq in (1, 2, 3):
            proof = wl.get_merkle_proof(seq, anchor_id=anchor["anchor_id"])
            assert wl.verify_merkle_proof(proof, anchor_id=anchor["anchor_id"]) is False

    def test_proof_outside_anchor_raises(self, anchored):
        wl, anchor = anchored
        wl.log("e5", module="test", target="t1")  # seq 6 now
        with pytest.raises(ValueError):
            wl.get_merkle_proof(6, anchor_id=anchor["anchor_id"])

    def test_unknown_seq_raises(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        with pytest.raises(ValueError):
            wl.get_merkle_proof(99)

    @pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 9])
    def test_padding_math(self, tmp_path, n):
        wl = make_warlog(tmp_path)
        seed(wl, n)
        anchor = wl.anchor_events(1, n)
        for seq in range(1, n + 1):
            proof = wl.get_merkle_proof(seq, anchor_id=anchor["anchor_id"])
            padded = proof["padded_leaves"]
            assert padded >= n and padded & (padded - 1) == 0
            assert len(proof["sibling_path"]) == (padded.bit_length() - 1)
            assert wl.verify_merkle_proof(
                proof, anchor_id=anchor["anchor_id"])

    def test_single_leaf(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 1)
        anchor = wl.anchor_events(1, 1)
        proof = wl.get_merkle_proof(1, anchor_id=anchor["anchor_id"])
        assert proof["sibling_path"] == []
        assert wl.verify_merkle_proof(proof, anchor_id=anchor["anchor_id"])


# ─── Fail-closed edge cases ────────────────────────────────────────────────

class TestFailClosed:
    def test_unknown_anchor_id_fails(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        anchor = wl.anchor_events(1, 2)
        proof = wl.get_merkle_proof(1, anchor_id=anchor["anchor_id"])
        assert wl.verify_merkle_proof(proof, anchor_id="nope") is False

    def test_forged_anchor_hmac_fails(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        anchor = wl.anchor_events(1, 2)
        c = wl._get_conn()
        c.execute("UPDATE merkle_anchors SET anchor_hmac = ? WHERE anchor_id = ?",
                  ("f" * 64, anchor["anchor_id"]))
        c.commit()
        c.close()
        assert wl.verify_anchor(anchor["anchor_id"]) is False
        proof = wl.get_merkle_proof(1, anchor_id=anchor["anchor_id"])
        assert wl.verify_merkle_proof(proof, anchor_id=anchor["anchor_id"]) is False

    def test_forged_merkle_root_fails(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        anchor = wl.anchor_events(1, 3)
        c = wl._get_conn()
        c.execute("UPDATE merkle_anchors SET merkle_root = ? WHERE anchor_id = ?",
                  ("e" * 64, anchor["anchor_id"]))
        c.commit()
        c.close()
        assert wl.verify_anchor(anchor["anchor_id"]) is False

    def test_self_signed_proof_fail(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 4)
        wl.anchor_events(1, 4)
        proof = wl.get_merkle_proof(1)
        proof["sibling_path"] = ["a" * 64] * 2   # too short for padded=4
        assert wl.verify_merkle_proof(proof) is False

    def test_empty_leaf_fails(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        assert wl.verify_merkle_proof(
            {"padded_leaves": 2, "sibling_path": ["x"]}) is False

    def test_get_anchors_lists(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        a1 = wl.anchor_events(1, 2)
        a2 = wl.anchor_events(2, 3)
        anchors = wl.get_anchors()
        assert [a["seq_from"] for a in anchors] == [1, 2]
        assert anchors[0]["anchor_id"] == a1["anchor_id"]
        assert anchors[1]["anchor_id"] == a2["anchor_id"]

    def test_mark_anchor_published(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        anchor = wl.anchor_events(1, 2)
        assert wl.mark_anchor_published(anchor["anchor_id"]) is True
        assert wl.get_anchors()[0]["published"] == 1
        assert wl.mark_anchor_published("nope") is False

    def test_legacy_logs_unaffected(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        assert len(wl.get_entries(module="test")) == 3
        # Anchoring does not alter event rows.
        c = wl._get_conn()
        row = c.execute("SELECT row_hmac FROM events WHERE seq = 1").fetchone()
        c.close()
        assert row["row_hmac"]


# ─── Row-level verification (P2) ───────────────────────────────────────────

class TestRowVerification:
    def test_max_seq(self, tmp_path):
        wl = make_warlog(tmp_path)
        assert wl.max_seq() == 0                  # empty log
        seed(wl, 3)
        assert wl.max_seq() == 3
        wl.log("e3", module="test", target="t1")
        assert wl.max_seq() == 4                  # monotonic with appends

    def test_verify_row_clean(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        anchor = wl.anchor_events(1, 3)
        for seq in (1, 2, 3):
            assert wl.verify_row(seq, anchor_id=anchor["anchor_id"])
        assert wl.verify_row(1)                   # live-log mode too

    def test_verify_row_catches_message_tamper(self, tmp_path):
        # row_hmac-level tampering (e.g. sibling swap) fails the anchor, but
        # a raw content edit fails verify_row *before* the Merkle check,
        # because the leaf is recomputed over the current row content.
        wl = make_warlog(tmp_path)
        seed(wl, 3)
        anchor = wl.anchor_events(1, 3)
        assert wl.verify_row(2, anchor_id=anchor["anchor_id"])
        c = wl._get_conn()
        c.execute("UPDATE events SET message = ? WHERE seq = ?",
                  ("surgery", 2))
        c.commit()
        c.close()
        assert wl.verify_row(2, anchor_id=anchor["anchor_id"]) is False
        assert wl.verify_row(1, anchor_id=anchor["anchor_id"])  # others pass

    def test_verify_row_catches_data_json_tamper(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        anchor = wl.anchor_events(1, 2)
        c = wl._get_conn()
        c.execute("UPDATE events SET data_json = ? WHERE seq = 1",
                  ('{"i": 999}',))
        c.commit()
        c.close()
        assert wl.verify_row(1, anchor_id=anchor["anchor_id"]) is False

    def test_verify_row_unknown_seq(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 2)
        wl.anchor_events(1, 2)
        assert wl.verify_row(99) is False         # outside any anchor

    def test_verify_row_anchored_range_bound(self, tmp_path):
        wl = make_warlog(tmp_path)
        seed(wl, 4)
        anchor = wl.anchor_events(1, 2)            # covers 1..2 only
        assert wl.verify_row(1, anchor_id=anchor["anchor_id"])
        assert wl.verify_row(3, anchor_id=anchor["anchor_id"]) is False

    def test_row_level_classification(self):
        assert WarLog.row_level(
            {"message": "stolen api_key=..."}
        )["sensitive"] is True
        assert WarLog.row_level(
            {"message": "c2 beacon established"}
        )["risky"] is True
        benign = WarLog.row_level(
            {"message": "port 443 open", "module": "recon"})
        assert benign == {"sensitive": False, "risky": False}