"""THE VOID — P1.4 WarLog Span/Trace/Integrity/Rotation tests.

Verifies the new structured-telemetry capabilities added in Phase 1.4:

    P1.4.1  Span / Trace model (context manager, parent/child linkage)
    P1.4.2  HMAC chain integrity + WORM storage (tamper detection)
    P1.4.3  Rotation (size + time, gzipped archives, retention pruning)
    P1.4.4  Query API (query_spans, trace_summary)
"""

import os
import gzip
import json
import time
import sqlite3
import tempfile
from pathlib import Path

import pytest

from core.warlog import WarLog, Span, LogLevel


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def warlog(tmp_path):
    """Fresh WarLog in a temp directory, rotation disabled for simplicity."""
    w = WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "test.log"),
        max_db_size=10 * 1024 * 1024,    # 10 MB — no accidental rotation
        max_age_days=365,                 # 1 year — no accidental rotation
        rotate_on_init=False,
    )
    yield w


@pytest.fixture
def small_warlog(tmp_path):
    """WarLog configured to rotate on a tiny size threshold."""
    w = WarLog(
        log_dir=str(tmp_path / "warlog_small"),
        log_file=str(tmp_path / "warlog_small" / "test.log"),
        max_db_size=1024,     # 1 KB — rotate almost immediately
        max_age_days=365,
        keep_archives=3,
        rotate_on_init=False,
    )
    yield w


# ═══════════════════════════════════════════════════════════════════════════════
# P1.4.1  SPAN / TRACE MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpanModel:
    """P1.4.1 — Span creation, context manager, parent/child linkage."""

    def test_span_context_manager(self, warlog):
        """Span via context manager writes span_start + span_end events."""
        with warlog.span("recon.port_scan", target="10.0.0.1") as s:
            s.set_attr("ports", [22, 80, 443])
            assert s.status == "active"
            assert s.start_time is not None

        # After exit: 2 events (start + end)
        spans = warlog.query_spans(operation="recon.port_scan")
        assert len(spans) == 2
        event_types = {e['event_type'] for e in spans}
        assert event_types == {"span_start", "span_end"}

    def test_span_end_records_duration(self, warlog):
        """Span end event must have a duration_ms > 0."""
        with warlog.span("op.test") as s:
            time.sleep(0.05)

        end_events = [e for e in warlog.query_spans()
                      if e['event_type'] == 'span_end']
        assert len(end_events) == 1
        assert end_events[0]['duration_ms'] is not None
        assert end_events[0]['duration_ms'] >= 40  # >= ~40ms

    def test_span_status_ok_on_normal_exit(self, warlog):
        """Normal exit → status='ok'."""
        with warlog.span("op.normal"):
            pass
        end = [e for e in warlog.query_spans() if e['event_type'] == 'span_end']
        assert end[0]['status'] == 'ok'

    def test_span_status_error_on_exception(self, warlog):
        """Exception inside span → status='error' with error data."""
        with pytest.raises(ValueError, match="boom"):
            with warlog.span("op.failing"):
                raise ValueError("boom")

        end = [e for e in warlog.query_spans() if e['event_type'] == 'span_end']
        assert end[0]['status'] == 'error'
        # Error info should be in data_json
        end_data = end[0].get('data') or {}
        assert 'error' in end_data or 'error_type' in end_data

    def test_span_parent_child_linkage(self, warlog):
        """Child span links to parent via parent_span_id + shared trace_id."""
        with warlog.span("parent.op", target="target1") as parent:
            with warlog.span("child.op") as child:
                pass

        # Both spans should share the same trace_id
        trace_ids = {e['trace_id'] for e in warlog.query_spans()}
        assert len(trace_ids) == 1, "parent and child should share trace_id"

        # Child span should have parent_span_id set to parent's span_id
        all_spans = warlog.query_spans()
        child_starts = [e for e in all_spans
                        if e['operation'] == 'child.op'
                        and e['event_type'] == 'span_start']
        parent_starts = [e for e in all_spans
                         if e['operation'] == 'parent.op'
                         and e['event_type'] == 'span_start']
        assert len(child_starts) == 1
        assert len(parent_starts) == 1
        assert child_starts[0]['parent_span_id'] == parent_starts[0]['span_id']

    def test_span_set_attr_persisted(self, warlog):
        """set_attr values appear in span_end data."""
        with warlog.span("op.attrs") as s:
            s.set_attr("key1", "value1")
            s.set_attr("count", 42)

        end = [e for e in warlog.query_spans() if e['event_type'] == 'span_end']
        data = end[0].get('data') or {}
        assert data.get('key1') == 'value1'
        assert data.get('count') == 42

    def test_span_log_within_span(self, warlog):
        """Span.log() attaches message to the span context."""
        with warlog.span("op.with_logs", module="testmod") as s:
            s.log("checkpoint reached", level=LogLevel.DEBUG)

        # Should have: span_start, 1 log, span_end = 3 entries total
        assert len(warlog._entries) == 3
        log_entry = warlog._entries[1]
        assert log_entry['event_type'] == 'log'
        assert log_entry['message'] == 'checkpoint reached'
        # log should carry the span_id
        assert log_entry['span_id'] is not None

    def test_span_idempotent_end(self, warlog):
        """Calling end() twice doesn't write a second span_end."""
        s = warlog.start_span("op.idem")
        s.end(status="ok")
        s.end(status="ok")  # second end — should be no-op

        end_count = sum(1 for e in warlog.query_spans()
                        if e['event_type'] == 'span_end')
        assert end_count == 1

    def test_trace_summary(self, warlog):
        """trace_summary aggregates spans in a trace."""
        with warlog.span("parent.op", target="host1") as p:
            with warlog.span("child1.op"):
                time.sleep(0.02)
            with warlog.span("child2.op"):
                time.sleep(0.02)

        trace_id = p.trace_id
        summary = warlog.trace_summary(trace_id)

        assert summary['trace_id'] == trace_id
        assert summary['span_count'] == 3  # parent + 2 children
        assert summary['status'] == 'ok'
        assert 'parent.op' in summary['operations']
        assert 'child1.op' in summary['operations']
        assert summary['total_duration_ms'] > 0
        # Each span dict should have a duration
        for span in summary['spans']:
            assert 'duration_ms' in span
            assert 'operation' in span

    def test_trace_summary_nonexistent(self, warlog):
        """trace_summary for unknown trace returns empty structure."""
        summary = warlog.trace_summary("nonexistent-trace-id")
        assert summary['span_count'] == 0
        assert summary['status'] == 'unknown'
        assert summary['spans'] == []


# ═══════════════════════════════════════════════════════════════════════════════
# P1.4.2  HMAC CHAIN INTEGRITY + WORM STORAGE
# ═══════════════════════════════════════════════════════════════════════════════

class TestHMACIntegrity:
    """P1.4.2 — Chain-of-custody HMAC, WORM append-only, tamper detection."""

    def test_fresh_chain_verifies(self, warlog):
        """A freshly written chain should verify as intact."""
        warlog.log("entry 1", level=LogLevel.INFO)
        warlog.log("entry 2", level=LogLevel.RECON)
        warlog.log("entry 3", level=LogLevel.EXPLOIT)

        report = warlog.verify_integrity()
        assert report.verified is True
        assert report.total_events == 3
        assert len(report.broken_hmacs) == 0
        assert len(report.broken_chain_links) == 0

    def test_chain_after_spans_verifies(self, warlog):
        """Span events also form a valid chain."""
        with warlog.span("op.a"):
            warlog.log("mid-span log")
        warlog.log("post-span log")

        report = warlog.verify_integrity()
        assert report.verified is True

    def test_tamper_detection_row_modification(self, warlog):
        """Modifying a row's content breaks row_hmac — detected."""
        warlog.log("original message")
        warlog.log("second entry")

        # Tamper: directly UPDATE the message column
        conn = warlog._get_conn()
        try:
            conn.execute(
                "UPDATE events SET message = 'tampered' WHERE seq = 1"
            )
            conn.commit()
        finally:
            conn.close()

        report = warlog.verify_integrity()
        assert report.verified is False
        assert len(report.broken_hmacs) >= 1
        assert report.broken_hmacs[0]['seq'] == 1

    def test_tamper_detection_row_deletion(self, warlog):
        """Deleting a row from the middle breaks the chain — detected."""
        warlog.log("entry A")
        warlog.log("entry B")  # this one gets deleted
        warlog.log("entry C")

        # Delete the middle row
        conn = warlog._get_conn()
        try:
            conn.execute("DELETE FROM events WHERE seq = 2")
            conn.commit()
        finally:
            conn.close()

        report = warlog.verify_integrity()
        assert report.verified is False
        # Chain link breakage detected (either seq gap or chain_hmac mismatch)
        assert len(report.broken_chain_links) >= 1

    def test_tamper_detection_row_insertion(self, warlog):
        """Inserting a fake row with wrong HMAC breaks the chain."""
        warlog.log("real entry 1")
        warlog.log("real entry 2")

        # Insert a fake row directly (with garbage HMAC)
        conn = warlog._get_conn()
        try:
            conn.execute(
                """INSERT INTO events
                   (span_id, trace_id, parent_span_id, event_type, operation,
                    level, message, module, target, status, duration_ms,
                    data_json, timestamp, epoch, session_id,
                    row_hmac, chain_hmac, prev_chain_hmac)
                   VALUES ('fake', 'fake', NULL, 'log', 'fake',
                           'info', 'injected', 'attacker', 'fake', 'ok', NULL,
                           NULL, '2025-01-01T00:00:00Z', 1000.0, 'fake',
                           'garbage', 'garbage', NULL)"""
            )
            conn.commit()
        finally:
            conn.close()

        report = warlog.verify_integrity()
        assert report.verified is False

    def test_worm_no_update_api(self, warlog):
        """The WarLog public API never UPDATEs or DELETEs — only INSERTs.

        We verify this structurally: after clear(), the DB should still
        hold all events (clear only empties the in-memory mirror).
        """
        warlog.log("persistent entry 1")
        warlog.log("persistent entry 2")

        assert len(warlog._entries) == 2

        warlog.clear()

        # In-memory mirror cleared
        assert len(warlog._entries) == 0
        assert len(warlog) == 0

        # But DB still has the rows (WORM)
        conn = warlog._get_conn()
        try:
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            conn.close()
        assert count == 2, "clear() must not delete from WORM DB"

    def test_chain_genesis_first_entry(self, warlog):
        """First entry's prev_chain_hmac should be NULL (genesis)."""
        warlog.log("genesis entry")

        conn = warlog._get_conn()
        try:
            row = conn.execute(
                "SELECT prev_chain_hmac FROM events WHERE seq = 1"
            ).fetchone()
        finally:
            conn.close()
        assert row[0] is None


# ═══════════════════════════════════════════════════════════════════════════════
# P1.4.3  ROTATION (size + time, gzipped archives, retention)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRotation:
    """P1.4.3 — DB rotation, gzip compression, archive retention."""

    def test_size_based_rotation(self, small_warlog, tmp_path):
        """Writing enough data triggers size-based rotation."""
        w = small_warlog

        # Write a lot of entries to exceed the 1KB threshold
        for i in range(50):
            w.log(f"entry number {i} with some padding text " * 10,
                  data={"index": i, "extra": "x" * 100})

        archives = w.list_archives()
        assert len(archives) >= 1, "at least one archive should exist after rotation"

    def test_archive_is_gzipped(self, small_warlog):
        """Rotated archive must be a valid gzip file."""
        w = small_warlog
        for i in range(50):
            w.log(f"rotating entry {i} " * 20)

        archives = w.list_archives()
        assert len(archives) >= 1

        # Verify the archive is valid gzip
        archive_path = archives[0]
        assert archive_path.endswith(".db.gz")
        with gzip.open(archive_path, 'rb') as f:
            # Should be a valid SQLite DB inside
            data = f.read()
            assert data[:16] == b'SQLite format 3\x00', \
                "archive should contain a valid SQLite DB"

    def test_archive_contains_prior_events(self, small_warlog):
        """Archived DB should contain the events that were rotated out."""
        w = small_warlog
        # Write entries that will be rotated
        for i in range(30):
            w.log(f"pre-rotation entry {i}")

        archives = w.list_archives()
        assert len(archives) >= 1

        # Decompress and read the archive
        with gzip.open(archives[0], 'rb') as f:
            db_data = f.read()

        # Write to temp file and query
        tmp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp_db.write(db_data)
        tmp_db.close()
        try:
            conn = sqlite3.connect(tmp_db.name)
            conn.row_factory = sqlite3.Row
            try:
                count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            finally:
                conn.close()
            assert count > 0, "archived DB should contain events"
        finally:
            os.unlink(tmp_db.name)

    def test_rotation_retention_pruning(self, tmp_path):
        """Old archives beyond keep_archives are pruned."""
        w = WarLog(
            log_dir=str(tmp_path / "warlog_retain"),
            log_file=str(tmp_path / "warlog_retain" / "test.log"),
            max_db_size=512,          # rotate very fast
            max_age_days=365,
            keep_archives=2,          # keep only 2 archives
            rotate_on_init=False,
        )
        # Write enough to trigger multiple rotations
        for i in range(200):
            w.log(f"retention test entry {i} " * 15)

        archives = w.list_archives()
        assert len(archives) <= 2, \
            f"should keep at most 2 archives, got {len(archives)}"

    def test_post_rotation_fresh_db(self, small_warlog):
        """After rotation, the active DB is fresh and chain is reset."""
        w = small_warlog
        for i in range(50):
            w.log(f"pre-rotation {i}")

        # After rotation, the fresh DB should verify cleanly
        report = w.verify_integrity()
        assert report.verified is True

    def test_manual_rotation(self, warlog):
        """Manual _rotate() creates an archive and resets."""
        w = warlog
        w.log("entry before manual rotation")
        w.log("another entry")

        archive = w._rotate(reason="manual_test")
        assert os.path.exists(archive)
        assert archive.endswith(".db.gz")

        # Fresh DB should verify
        report = w.verify_integrity()
        assert report.verified is True
        # Rotation event should be logged
        assert len(w._entries) >= 1

    def test_time_based_rotation(self, tmp_path):
        """Rotation triggered by max_age_days when oldest event is too old."""
        w = WarLog(
            log_dir=str(tmp_path / "warlog_time"),
            log_file=str(tmp_path / "warlog_time" / "test.log"),
            max_db_size=100 * 1024 * 1024,  # 100 MB — never size-rotate
            max_age_days=1,                  # 1 day threshold
            keep_archives=3,
            rotate_on_init=False,
        )
        # Insert an event, then backdate it past the age threshold
        w.log("old event")
        old_epoch = time.time() - (2 * 86400)  # 2 days ago
        conn = w._get_conn()
        try:
            conn.execute("UPDATE events SET epoch = ? WHERE seq = 1", (old_epoch,))
            conn.commit()
        finally:
            conn.close()

        # Next write should trigger time-based rotation
        w.log("trigger event")
        archives = w.list_archives()
        assert len(archives) >= 1, "time-based rotation should have occurred"


# ═══════════════════════════════════════════════════════════════════════════════
# P1.4.4  QUERY API
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryAPI:
    """P1.4.4 — Structured query API for spans and traces."""

    def test_query_spans_by_operation(self, warlog):
        """Filter spans by operation name."""
        with warlog.span("recon.scan"):
            pass
        with warlog.span("exploit.run"):
            pass

        recon = warlog.query_spans(operation="recon.scan")
        assert len(recon) == 2  # start + end
        assert all(e['operation'] == 'recon.scan' for e in recon)

    def test_query_spans_by_trace_id(self, warlog):
        """Filter spans by trace_id."""
        with warlog.span("op1") as s1:
            trace1 = s1.trace_id
        with warlog.span("op2") as s2:
            trace2 = s2.trace_id

        results = warlog.query_spans(trace_id=trace1)
        assert len(results) == 2
        assert all(e['trace_id'] == trace1 for e in results)

    def test_query_spans_by_status(self, warlog):
        """Filter spans by status."""
        with warlog.span("ok.op"):
            pass
        with pytest.raises(RuntimeError):
            with warlog.span("err.op"):
                raise RuntimeError("fail")

        ok_ends = warlog.query_spans(status="ok")
        ok_end_count = sum(1 for e in ok_ends if e['event_type'] == 'span_end')
        assert ok_end_count >= 1

        err_ends = warlog.query_spans(status="error")
        assert any(e['operation'] == 'err.op' for e in err_ends)

    def test_query_spans_by_target(self, warlog):
        """Filter spans by target."""
        with warlog.span("op", target="10.0.0.1"):
            pass
        with warlog.span("op", target="10.0.0.2"):
            pass

        results = warlog.query_spans(target="10.0.0.1")
        assert all(e['target'] == '10.0.0.1' for e in results)
        assert len(results) == 2

    def test_query_spans_by_level(self, warlog):
        """Filter spans by log level."""
        with warlog.span("op", level=LogLevel.RECON):
            pass

        recon = warlog.query_spans(level=LogLevel.RECON)
        assert len(recon) == 2
        assert all(e['level'] == 'recon' for e in recon)

    def test_query_spans_time_range(self, warlog):
        """Filter spans by time range (epoch)."""
        t0 = time.time()
        with warlog.span("timeframe.op"):
            pass
        t1 = time.time() + 1

        results = warlog.query_spans(time_range=(t0, t1))
        assert len(results) == 2  # start + end within range

        # Outside range
        results_empty = warlog.query_spans(time_range=(t1, t1 + 10))
        assert len(results_empty) == 0

    def test_query_spans_limit(self, warlog):
        """Limit caps the number of results."""
        for i in range(10):
            with warlog.span(f"op.{i}"):
                pass

        results = warlog.query_spans(limit=5)
        assert len(results) == 5

    def test_query_spans_excludes_logs(self, warlog):
        """query_spans only returns span events, not log events."""
        warlog.log("a plain log entry")
        with warlog.span("a.span"):
            pass

        spans = warlog.query_spans()
        types = {e['event_type'] for e in spans}
        assert 'log' not in types
        assert types <= {'span_start', 'span_end'}

    def test_query_spans_returns_empty_for_no_match(self, warlog):
        """No matching spans → empty list."""
        results = warlog.query_spans(operation="nonexistent")
        assert results == []

    def test_trace_summary_aggregation(self, warlog):
        """trace_summary correctly aggregates a multi-span trace."""
        with warlog.span("root.op", target="host") as root:
            with warlog.span("child1.op"):
                time.sleep(0.01)
            with warlog.span("child2.op"):
                time.sleep(0.01)

        summary = warlog.trace_summary(root.trace_id)
        assert summary['span_count'] == 3
        assert summary['status'] == 'ok'
        assert len(summary['operations']) == 3
        # Total duration should be at least the sum of sleeps
        assert summary['total_duration_ms'] >= 15
