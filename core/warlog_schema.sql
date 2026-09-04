-- ═══════════════════════════════════════════════════════════════════════════════
-- THE VOID — WarLog Relational Schema (SQLite)
-- Phase 1.4 — VOID-CEP-2026-07
--
-- Structured, tamper-evident, OpenTelemetry-style telemetry with spans, traces,
-- chain-of-custody HMAC integrity, and append-only (WORM) storage.
--
-- Design principles:
--   1. Single append-only events table — every log, span boundary, or state
--      change is one immutable row (INSERT only; no UPDATE/DELETE in operation)
--   2. Span lifecycle: two events (span_start / span_end) linked by span_id;
--      standalone log() calls are event_type='log' rows
--   3. Traces: all spans sharing a trace_id form a trace; root span has
--      parent_span_id = NULL
--   4. HMAC chain-of-custody: each row's chain_hmac depends on its own
--      row_hmac + the previous row's chain_hmac (WORM — deletion breaks chain)
--   5. seq AUTOINCREMENT provides ordering + gap detection for tamper evidence
--   6. Sensitive data payloads stored in data_json (JSON), optionally encrypted
--      at the application layer
--
-- SQLite pragmas applied at runtime by WarLog class:
--   PRAGMA journal_mode = WAL;
--   PRAGMA synchronous = FULL;
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    span_id         TEXT    NOT NULL,       -- UUID v4: groups span_start+span_end
    trace_id        TEXT    NOT NULL,       -- UUID v4: all spans in one trace
    parent_span_id  TEXT,                   -- parent span UUID (NULL = root)
    event_type      TEXT    NOT NULL,       -- span_start | span_end | log
    operation       TEXT,                   -- e.g. "recon.port_scan", "exploit.ssh"
    level           TEXT    DEFAULT 'info', -- info, warning, error, exploit, recon, ...
    message         TEXT,                   -- human-readable message
    module          TEXT,                   -- source module
    target          TEXT,                   -- operation target (host, service, etc.)
    status          TEXT    DEFAULT 'active', -- active | ok | error | timeout
    duration_ms     REAL,                   -- span duration (on span_end events)
    data_json       TEXT,                   -- JSON blob: arbitrary structured data
    timestamp       TEXT    NOT NULL,       -- UTC ISO8601
    epoch           REAL    NOT NULL,       -- Unix float for ordering
    session_id      TEXT    NOT NULL,       -- WarLog session identifier
    -- ── Integrity columns (chain-of-custody) ──
    row_hmac        TEXT    NOT NULL,       -- HMAC-SHA256 of this row's content
    chain_hmac      TEXT    NOT NULL,       -- HMAC(row_hmac || prev_chain_hmac)
    prev_chain_hmac TEXT                     -- previous row's chain_hmac (NULL for first)
);

-- Indexes for query performance (do not affect WORM property)
CREATE INDEX IF NOT EXISTS idx_events_trace    ON events(trace_id);
CREATE INDEX IF NOT EXISTS idx_events_span     ON events(span_id);
CREATE INDEX IF NOT EXISTS idx_events_epoch    ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_events_operation ON events(operation);
CREATE INDEX IF NOT EXISTS idx_events_level    ON events(level);
CREATE INDEX IF NOT EXISTS idx_events_session  ON events(session_id);
