"""THE VOID — P1.4.5 Boneyard ↔ WarLog integration tests.

Verifies that attaching a WarLog to a Boneyard correctly emits structured
spans for every state-changing operation, with proper parent/child linkage
and cross-referencing by item_id.

Key behaviors under test:

    1.  store() emits a parent ``boneyard.store`` span, plus one child
        ``boneyard.audit.insert`` span per relational table written
        (findings + hosts/creds/vulns/services).
    2.  delete() emits a ``boneyard.delete`` span + ``boneyard.audit.delete``
        child span.
    3.  Child audit spans share the parent's trace_id (parent/child linkage
        via the warlog span stack).
    4.  Audit spans carry ``item_id`` cross-referencing the boneyard row_id.
    5.  Operations with no warlog attached are fully backward-compatible
        (no spans, no errors).
    6.  WarLog failures are non-fatal — the boneyard operation still completes.
    7.  Both the boneyard's own integrity chain AND the warlog's HMAC chain
        verify intact after integrated operations.
    8.  The ``__len__``/``__bool__`` falsy-warlog regression is locked down:
        a freshly-attached warlog with zero in-memory entries must still be
        treated as "attached" (not short-circuited by ``if not self._warlog``).
"""

import time
from typing import Any, Dict, List

import pytest

from core.boneyard import Boneyard
from core.warlog import WarLog


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def boneyard(tmp_path):
    """Fresh Boneyard with no encryption, no warlog."""
    return Boneyard(storage_dir=str(tmp_path / "boneyard"))


@pytest.fixture
def warlog(tmp_path):
    """Fresh WarLog, rotation disabled."""
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "test.log"),
        max_db_size=10 * 1024 * 1024,
        max_age_days=365,
        rotate_on_init=False,
    )


@pytest.fixture
def attached(tmp_path):
    """Boneyard + WarLog, warlog already attached. Returns (boneyard, warlog)."""
    b = Boneyard(storage_dir=str(tmp_path / "boneyard"))
    w = WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "test.log"),
        max_db_size=10 * 1024 * 1024,
        max_age_days=365,
        rotate_on_init=False,
    )
    b.attach_warlog(w)
    return b, w


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _span_starts(spans: List[Dict[str, Any]], operation: str) -> List[Dict]:
    """Filter to span_start events for a given operation."""
    return [s for s in spans
            if s['operation'] == operation and s['event_type'] == 'span_start']


def _span_ends(spans: List[Dict[str, Any]], operation: str) -> List[Dict]:
    """Filter to span_end events for a given operation."""
    return [s for s in spans
            if s['operation'] == operation and s['event_type'] == 'span_end']


# ═══════════════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY — no warlog attached
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoWarlogBackwardCompat:
    """A Boneyard with no warlog must behave exactly as before P1.4.5."""

    def test_store_without_warlog(self, boneyard):
        """store() returns a valid item_id and persists the finding."""
        fid = boneyard.store('cred', {'title': 'test', 'ip': '10.0.0.1'})
        assert fid is not None
        assert len(fid) == 36  # UUID4 format

    def test_store_does_not_error_without_warlog(self, boneyard):
        """No warlog means no span instrumentation — but no crash either."""
        # This is the core of the falsy-warlog fix: even though Boneyard
        # defines __len__, a missing warlog (None) must not be confused
        # with an empty-but-attached warlog.
        fid = boneyard.store('intel', {'title': 'no warlog'})
        item = boneyard.get(fid)
        assert item is not None

    def test_delete_without_warlog(self, boneyard):
        """delete() works normally without a warlog."""
        fid = boneyard.store('recon', {'title': 'to delete'})
        assert boneyard.delete(fid) is True
        # Soft-delete: get() should return None for deleted
        assert boneyard.get(fid) is None


# ═══════════════════════════════════════════════════════════════════════════════
# FALSY-WARLOG REGRESSION GUARD
# ═══════════════════════════════════════════════════════════════════════════════

class TestFalsyWarlogRegression:
    """Lock down the __len__/__bool__ bug that was fixed in P1.4.5.

    WarLog defines __len__ (returns len of in-memory _entries). A freshly
    attached warlog has 0 entries → bool(warlog) is False → the old
    ``if not self._warlog`` / ``if self._warlog`` checks misbehaved:

      • ``if not self._warlog`` returned True (wrongly treated as "no warlog")
      • ``if self._warlog`` returned False (wrongly skipped span emission)

    The fix uses explicit ``is None`` / ``is not None`` checks.
    """

    def test_fresh_warlog_is_falsy_but_attached(self, attached):
        """The root cause: a fresh warlog is falsy, yet it IS attached.

        This test documents the trap so the regression never returns: if a
        future refactor switches back to truthiness checks, this fails first.
        """
        b, w = attached
        # The trap: warlog is attached AND falsy at the same time
        assert b._warlog is w
        assert bool(w) is False, \
            "WarLog with 0 in-memory entries must be falsy (the trap)"

    def test_begin_span_returns_real_span_when_warlog_empty(self, attached):
        """_begin_span must return a Span even when warlog has 0 entries."""
        b, w = attached
        assert len(w) == 0  # empty → falsy
        span = b._begin_span("regression.test", data={"x": 1})
        assert span is not None
        assert span.operation == "regression.test"
        b._finish_span(span)

    def test_store_emits_spans_with_empty_warlog(self, attached):
        """store() must emit spans even though bool(warlog) is False."""
        b, w = attached
        fid = b.store('intel', {'title': 'regression guard'})
        spans = w.query_spans()
        # At minimum: boneyard.store start + end + at least one audit span
        assert len(spans) >= 2, \
            "Spans must be emitted even when warlog is falsy"


# ═══════════════════════════════════════════════════════════════════════════════
# STORE — parent + child span emission
# ═══════════════════════════════════════════════════════════════════════════════

class TestStoreSpanEmission:
    """store() emits a parent boneyard.store span + child audit spans."""

    def test_store_emits_parent_span(self, attached):
        """store() produces exactly one boneyard.store start + end."""
        b, w = attached
        b.store('intel', {'title': 'simple finding'})

        starts = _span_starts(w.query_spans(), "boneyard.store")
        ends = _span_ends(w.query_spans(), "boneyard.store")
        assert len(starts) == 1
        assert len(ends) == 1

    def test_store_parent_span_status_ok(self, attached):
        """Normal store() → parent span ends with status='ok'."""
        b, w = attached
        b.store('intel', {'title': 'ok finding'})
        end = _span_ends(w.query_spans(), "boneyard.store")[0]
        assert end['status'] == 'ok'

    def test_store_carries_item_id_in_end_data(self, attached):
        """The boneyard.store span_end data includes the item_id."""
        b, w = attached
        fid = b.store('intel', {'title': 'item check'})
        end = _span_ends(w.query_spans(), "boneyard.store")[0]
        data = end.get('data') or {}
        assert data.get('item_id') == fid

    def test_store_emits_audit_child_spans(self, attached):
        """store() emits at least one boneyard.audit.insert child span."""
        b, w = attached
        b.store('cred', {
            'title': 'creds', 'ip': '10.0.0.1',
            'username': 'root', 'password': 'hunter2'
        })

        audit_inserts = [s for s in w.query_spans()
                         if s['operation'] == 'boneyard.audit.insert']
        assert len(audit_inserts) >= 2, \
            "expected at least 2 audit spans (findings + relational table)"

    def test_audit_span_cross_references_item_id(self, attached):
        """Audit child span data carries item_id matching the finding."""
        b, w = attached
        fid = b.store('intel', {'title': 'cross-ref'})

        audit_spans = [s for s in w.query_spans()
                       if s['operation'] == 'boneyard.audit.insert'
                       and s['event_type'] == 'span_start']
        # The findings-table audit span should carry the item_id
        item_ids = [
            (s.get('data') or {}).get('item_id') for s in audit_spans
        ]
        assert fid in item_ids, \
            f"item_id {fid} must appear in audit span data, got {item_ids}"

    def test_store_parent_child_share_trace_id(self, attached):
        """Parent store span and child audit spans share one trace_id."""
        b, w = attached
        b.store('cred', {
            'title': 'trace check', 'ip': '10.0.0.2',
            'username': 'admin', 'password': 'secret'
        })

        spans = w.query_spans()
        store_trace_ids = {s['trace_id'] for s in spans
                           if s['operation'] == 'boneyard.store'}
        audit_trace_ids = {s['trace_id'] for s in spans
                           if s['operation'] == 'boneyard.audit.insert'}

        # Parent and children must share exactly one trace_id
        assert len(store_trace_ids) == 1
        assert len(audit_trace_ids) == 1
        assert store_trace_ids == audit_trace_ids, \
            "parent and child spans must share trace_id"

    def test_audit_child_has_parent_span_id(self, attached):
        """Audit child spans link to the store parent via parent_span_id."""
        b, w = attached
        b.store('intel', {'title': 'linkage'})

        spans = w.query_spans()
        parent_start = _span_starts(spans, "boneyard.store")[0]
        parent_span_id = parent_start['span_id']

        audit_starts = [s for s in spans
                        if s['operation'] == 'boneyard.audit.insert'
                        and s['event_type'] == 'span_start']
        for child in audit_starts:
            assert child.get('parent_span_id') == parent_span_id, \
                "audit child must link to store parent span_id"


# ═══════════════════════════════════════════════════════════════════════════════
# DELETE — span emission + audit
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeleteSpanEmission:
    """delete() emits boneyard.delete + boneyard.audit.delete spans."""

    def test_delete_emits_span(self, attached):
        b, w = attached
        fid = b.store('intel', {'title': 'to delete'})
        # Clear the query window — only look at delete's spans
        before = len(w.query_spans())
        b.delete(fid)
        new_spans = w.query_spans()[before:] if hasattr(w, '__getitem__') else []

        delete_starts = _span_starts(w.query_spans(), "boneyard.delete")
        assert len(delete_starts) == 1

    def test_delete_audit_span(self, attached):
        """delete() emits a boneyard.audit.delete child span."""
        b, w = attached
        fid = b.store('intel', {'title': 'audit delete'})
        b.delete(fid)

        audit_deletes = [s for s in w.query_spans()
                         if s['operation'] == 'boneyard.audit.delete']
        assert len(audit_deletes) >= 1

    def test_delete_nonexistent_finding(self, attached):
        """Deleting a non-existent finding returns False, still emits a span."""
        b, w = attached
        result = b.delete("nonexistent-uuid")
        assert result is False
        # Should still emit the delete span (with found=False)
        ends = _span_ends(w.query_spans(), "boneyard.delete")
        assert len(ends) == 1
        data = ends[0].get('data') or {}
        assert data.get('found') is False


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACH / DETACH
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttachDetach:
    """attach_warlog / detach_warlog lifecycle."""

    def test_attach_enables_span_emission(self, boneyard, warlog):
        """Before attach: no spans. After attach: spans emitted."""
        boneyard.store('intel', {'title': 'before attach'})
        assert len(warlog.query_spans()) == 0

        boneyard.attach_warlog(warlog)
        boneyard.store('intel', {'title': 'after attach'})
        assert len(warlog.query_spans()) > 0

    def test_detach_disables_span_emission(self, attached):
        """After detach, operations emit no new spans."""
        b, w = attached
        b.store('intel', {'title': 'while attached'})
        span_count = len(w.query_spans())

        b.detach_warlog()
        b.store('intel', {'title': 'after detach'})
        assert len(w.query_spans()) == span_count, \
            "detach must stop span emission"

    def test_detach_sets_warlog_none(self, attached):
        """detach_warlog sets _warlog to None (not just any falsy value)."""
        b, _ = attached
        b.detach_warlog()
        assert b._warlog is None

    def test_reattach_works(self, attached):
        """detach then attach again restores span emission."""
        b, w = attached
        b.store('intel', {'title': 'first'})
        b.detach_warlog()
        b.store('intel', {'title': 'second (no spans)'})
        b.attach_warlog(w)
        b.store('intel', {'title': 'third'})

        store_starts = _span_starts(w.query_spans(), "boneyard.store")
        assert len(store_starts) == 2, \
            "only first and third stores should emit spans"


# ═══════════════════════════════════════════════════════════════════════════════
# NON-FATAL WARLOG FAILURES
# ═══════════════════════════════════════════════════════════════════════════════

class TestWarlogFailuresNonFatal:
    """If the warlog raises, the boneyard operation must still succeed."""

    def test_store_with_broken_warlog(self, attached, monkeypatch):
        """A warlog that raises on start_span must not break store()."""
        b, w = attached

        def boom(*args, **kwargs):
            raise RuntimeError("warlog is broken")

        monkeypatch.setattr(w, 'start_span', boom)

        # store() should complete successfully despite the warlog failure
        fid = b.store('intel', {'title': 'survives warlog failure'})
        assert fid is not None
        assert len(fid) == 36

    def test_store_with_broken_warlog_persists(self, attached, monkeypatch):
        """Data is persisted even when warlog span emission fails."""
        b, w = attached

        def boom(*args, **kwargs):
            raise RuntimeError("broken")

        monkeypatch.setattr(w, 'start_span', boom)

        fid = b.store('cred', {'title': 'persisted', 'ip': '10.0.0.99'})
        item = b.get(fid)
        assert item is not None
        assert item['category'] == 'cred'


# ═══════════════════════════════════════════════════════════════════════════════
# DUAL INTEGRITY — both chains verify after integrated operations
# ═══════════════════════════════════════════════════════════════════════════════

class TestDualIntegrity:
    """After integrated operations, both the boneyard AND warlog chains verify."""

    def test_both_chains_verify_after_store(self, attached):
        b, w = attached
        b.store('intel', {'title': 'integrity test', 'ip': '10.0.0.1'})

        brep = b.verify_integrity()
        wrep = w.verify_integrity()

        assert brep.verified is True
        assert wrep.verified is True

    def test_both_chains_verify_after_multiple_ops(self, attached):
        b, w = attached
        f1 = b.store('cred', {'title': 'c1', 'ip': '10.0.0.1', 'password': 'p1'})
        f2 = b.store('vuln', {'title': 'v1', 'ip': '10.0.0.2'})
        b.delete(f1)
        f3 = b.store('intel', {'title': 'i1'})

        brep = b.verify_integrity()
        wrep = w.verify_integrity()

        assert brep.verified is True, "boneyard chain must remain intact"
        assert wrep.verified is True, "warlog chain must remain intact"
        assert wrep.total_events > 0

    def test_boneyard_integrity_independent_of_warlog(self, attached):
        """Boneyard integrity doesn't depend on warlog being attached."""
        b, w = attached
        b.store('intel', {'title': 'x'})
        b.detach_warlog()

        rep = b.verify_integrity()
        assert rep.verified is True


# ═══════════════════════════════════════════════════════════════════════════════
# SPAN STATUS ON ERROR
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpanStatusOnError:
    """Span end status reflects operation success/failure."""

    def test_store_error_marks_span_error(self, attached, monkeypatch):
        """If store() fails (DB error), the parent span ends with status='error'."""
        b, w = attached

        # Corrupt the boneyard DB connection to force a sqlite3.Error on store
        import sqlite3
        orig_get_conn = b._get_conn

        def broken_conn():
            conn = orig_get_conn()
            # Close it so subsequent execute() fails
            conn.close()
            return sqlite3.connect("/dev/null/broken")  # will fail

        monkeypatch.setattr(b, '_get_conn', broken_conn)

        with pytest.raises(Exception):
            b.store('intel', {'title': 'will fail'})

        ends = _span_ends(w.query_spans(), "boneyard.store")
        assert len(ends) == 1
        assert ends[0]['status'] == 'error'
