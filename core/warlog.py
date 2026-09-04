"""THE VOID — WarLog: Structured, tamper-evident telemetry for all operations.

Every command, every discovery, every exploit — it all goes into the war log.
The war log is the memory of the agent. It never forgets. And it can prove it.

Phase 1.4 rewrite (VOID-CEP-2026-07):
    • OpenTelemetry-style Span / Trace model with parent/child linkage
    • Append-only WORM SQLite storage (INSERT only; no UPDATE/DELETE)
    • Chain-of-custody HMAC-SHA256 integrity — deletion breaks the chain
    • Size-based + time-based rotation with gzipped archives + retention
    • Structured query API: query_spans(), trace_summary(), get_entries()
    • Full backward compatibility with the original in-memory + JSONL API

Backward-compat contract (existing callers must not break):
    • WarLog(log_dir=, log_file=)  — both optional
    • log(message, level=, module=, target=, data=)
    • log_recon / log_exploit / log_stealth / log_exfil / log_c2
    • get_entries(level=, module=, target=) -> List[dict]
    • get_summary() -> dict
    • export(filepath)
    • clear()  — clears the in-memory mirror only (DB is WORM)
    • __len__  — returns in-memory entry count
    • LogLevel enum with all original values
    • _entries, _session_id attributes (tests access these)
"""

import os
import sys
import json
import time
import gzip
import uuid
import hmac
import sqlite3
import hashlib
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterator, Union
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger("void.warlog")

# ─── Constants ───────────────────────────────────────────────────────────────

_CHAIN_GENESIS = b"GENESIS"

_SCHEMA_PATH = Path(__file__).parent / "warlog_schema.sql"

# Rotation defaults
_DEFAULT_MAX_DB_SIZE = 50 * 1024 * 1024      # 50 MB
_DEFAULT_MAX_AGE_DAYS = 7                      # 7 days
_DEFAULT_KEEP_ARCHIVES = 5                     # keep last 5 archives


class LogLevel(Enum):
    """Log levels for the war log."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    EXPLOIT = "exploit"
    RECON = "recon"
    STEALTH = "stealth"
    EXFIL = "exfil"
    C2 = "c2"
    AGENT = "agent"


# ─── Span Model ──────────────────────────────────────────────────────────────

class Span:
    """A structured span — a unit of work within a trace.

    A span is started, runs for some duration, and ends. It has:
        • span_id, trace_id, parent_span_id (for tree structure)
        • operation (what was done), level, status
        • start/end timestamps and computed duration

    Spans are created via WarLog.span() context manager or start_span().
    On enter, a span_start event is written; on exit, a span_end event.
    """

    def __init__(self, warlog: 'WarLog', span_id: str, trace_id: str,
                 operation: str, parent_span_id: Optional[str] = None,
                 level: Union[LogLevel, str] = LogLevel.INFO,
                 module: Optional[str] = None,
                 target: Optional[str] = None,
                 data: Optional[Dict[str, Any]] = None):
        self._warlog = warlog
        self.span_id = span_id
        self.trace_id = trace_id
        self.parent_span_id = parent_span_id
        self.operation = operation
        self.level = level if isinstance(level, LogLevel) else LogLevel(level)
        self.module = module
        self.target = target
        self.status = "active"
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self._data = dict(data) if data else {}

    def start(self) -> 'Span':
        """Record span_start event."""
        self.start_time = time.time()
        self._warlog._write_event(
            event_type="span_start",
            span_id=self.span_id,
            trace_id=self.trace_id,
            parent_span_id=self.parent_span_id,
            operation=self.operation,
            level=self.level,
            module=self.module,
            target=self.target,
            status="active",
            data=dict(self._data),
        )
        return self

    def end(self, status: str = "ok", data: Optional[Dict[str, Any]] = None) -> None:
        """Record span_end event with duration."""
        if self.end_time is not None:
            return  # already ended (idempotent)
        self.end_time = time.time()
        self.status = status
        end_data = dict(self._data)
        if data:
            end_data.update(data)
        duration_ms = round((self.end_time - (self.start_time or self.end_time)) * 1000.0, 3)
        self._warlog._write_event(
            event_type="span_end",
            span_id=self.span_id,
            trace_id=self.trace_id,
            parent_span_id=self.parent_span_id,
            operation=self.operation,
            level=self.level,
            module=self.module,
            target=self.target,
            status=status,
            duration_ms=duration_ms,
            data=end_data,
        )

    def set_attr(self, key: str, value: Any) -> None:
        """Set a span attribute (stored in data, written on end)."""
        self._data[key] = value

    def log(self, message: str, level: Optional[LogLevel] = None,
            data: Optional[Dict[str, Any]] = None) -> None:
        """Log a message within this span context."""
        self._warlog.log(
            message,
            level=level or self.level,
            module=self.module,
            target=self.target,
            data=data,
            span_id=self.span_id,
            trace_id=self.trace_id,
        )

    def __enter__(self) -> 'Span':
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self.end_time is None:
            if exc_type is not None:
                self.end(status="error",
                         data={"error_type": exc_type.__name__,
                               "error": str(exc_val)})
            else:
                self.end(status="ok")
        # Don't suppress exceptions
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "parent_span_id": self.parent_span_id,
            "operation": self.operation,
            "level": self.level.value,
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round((self.end_time - self.start_time) * 1000, 3)
                           if self.start_time and self.end_time else None,
        }


class Trace:
    """A trace — a tree of spans sharing a trace_id.

    The root span has parent_span_id = None. Child spans reference their parent.
    """

    def __init__(self, trace_id: str, root_span: Optional[Span] = None):
        self.trace_id = trace_id
        self.root_span = root_span
        self.spans: List[Span] = []
        if root_span:
            self.spans.append(root_span)

    def add_span(self, span: Span) -> None:
        self.spans.append(span)

    @property
    def duration_ms(self) -> Optional[float]:
        """Total trace wall-clock duration (root span duration)."""
        if self.root_span and self.root_span.start_time and self.root_span.end_time:
            return round((self.root_span.end_time - self.root_span.start_time) * 1000, 3)
        return None


# ─── Integrity Report ────────────────────────────────────────────────────────

class IntegrityReport:
    """Result of WarLog integrity verification."""

    def __init__(self, verified: bool = True, total_events: int = 0,
                 broken_hmacs: Optional[List] = None,
                 broken_chain_links: Optional[List] = None):
        self.verified = verified
        self.total_events = total_events
        self.broken_hmacs = broken_hmacs or []
        self.broken_chain_links = broken_chain_links or []

    def __bool__(self) -> bool:
        return self.verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "total_events": self.total_events,
            "broken_hmacs": len(self.broken_hmacs),
            "broken_chain_links": len(self.broken_chain_links),
            "details": {
                "broken_hmacs": self.broken_hmacs,
                "broken_chain_links": self.broken_chain_links,
            },
        }

    def __repr__(self) -> str:
        status = "VERIFIED" if self.verified else "TAMPERED"
        return (f"IntegrityReport({status}, events={self.total_events}, "
                f"broken_hmacs={len(self.broken_hmacs)}, "
                f"broken_chain_links={len(self.broken_chain_links)})")


# ═══════════════════════════════════════════════════════════════════════════════
#  WarLog — the main class
# ═══════════════════════════════════════════════════════════════════════════════

class WarLog:
    """Structured, tamper-evident telemetry for all operations.

    Storage: append-only (WORM) SQLite database with HMAC chain-of-custody.
    Model: OpenTelemetry-style spans/traces, plus legacy log() entries.
    Rotation: size + time based, gzipped archives with retention policy.

    Backward compatibility: the original in-memory _entries list and JSONL
    file write are maintained so existing callers and tests continue to work.
    The SQLite store is the source of truth for persistence + integrity.
    """

    def __init__(self, log_dir: Optional[str] = None,
                 log_file: Optional[str] = None,
                 passphrase: Optional[str] = None,
                 max_db_size: int = _DEFAULT_MAX_DB_SIZE,
                 max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
                 keep_archives: int = _DEFAULT_KEEP_ARCHIVES,
                 rotate_on_init: bool = True):
        """Initialize the war log.

        Args:
            log_dir: Directory for log DB + files. If None, uses default.
            log_file: Legacy JSONL file path (kept for backward compat).
                      If None, uses default.
            passphrase: Passphrase for HMAC integrity key derivation.
                        If None, derives a dev-mode key from DB path + user.
            max_db_size: Max DB size in bytes before rotation (default 50 MB).
            max_age_days: Max age of oldest event in days before rotation (default 7).
            keep_archives: Number of gzipped archives to retain (default 5).
            rotate_on_init: If True, check rotation on init (default True).
        """
        if log_dir is None:
            from config.defaults import WARLOG_DIR
            log_dir = WARLOG_DIR
        if log_file is None:
            from config.defaults import LOG_FILE
            log_file = LOG_FILE

        self.log_dir = log_dir
        self.log_file = log_file
        self.max_db_size = max_db_size
        self.max_age_days = max_age_days
        self.keep_archives = keep_archives

        os.makedirs(self.log_dir, exist_ok=True)
        log_parent = os.path.dirname(os.path.abspath(self.log_file))
        os.makedirs(log_parent, exist_ok=True)

        # DB path: warlog.db in the log_dir
        self._db_path = os.path.join(self.log_dir, "warlog.db")
        self._passphrase = passphrase

        # Session ID — preserved on original for backward compat
        self._session_id = str(uuid.uuid4())
        self._start_time = time.time()

        # In-memory mirror of entries (for backward compat: get_entries, __len__)
        self._entries: List[Dict[str, Any]] = []

        # Active span stack for nested span tracking.
        # Each entry is a tuple (span_id, trace_id) so children inherit trace_id.
        self._span_stack: List[tuple] = []

        # Guard against rotation recursion (rotation writes an event, which
        # would re-trigger rotation on the fresh DB).
        self._rotating = False

        # Initialize DB schema
        self._init_db()

        # Check rotation
        if rotate_on_init:
            self._maybe_rotate()

        logger.info(f"WarLog initialized (session={self._session_id}, "
                    f"db={self._db_path})")

    # ─── Database Setup ──────────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Initialize SQLite database with schema."""
        conn = self._get_conn()
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = FULL;")
            # Apply schema
            schema_sql = _SCHEMA_PATH.read_text()
            conn.executescript(schema_sql)
            conn.commit()
        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a SQLite connection with Row factory."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    # ─── HMAC Integrity ────────────────────────────────────────────────────────

    def _integrity_key(self) -> bytes:
        """Derive the HMAC key from the passphrase."""
        if self._passphrase:
            return hashlib.pbkdf2_hmac('sha256', self._passphrase.encode(),
                                       b'warlog-integrity-v1', 200000, dklen=32)
        # Dev mode: stable key from DB path + user
        import getpass
        seed = f"{self._db_path}:{getpass.getuser()}".encode()
        return hashlib.pbkdf2_hmac('sha256', seed, b'dev-integrity-v1', 100000, dklen=32)

    def _compute_row_hmac(self, row: Dict[str, Any]) -> str:
        """Compute HMAC-SHA256 of a row's canonical representation."""
        _excluded = ('row_hmac', 'chain_hmac', 'prev_chain_hmac', 'seq')
        parts = ["events"]
        for key in sorted(row.keys()):
            if key in _excluded:
                continue
            val = row[key]
            if val is None:
                parts.append(f"{key}:NULL")
            else:
                parts.append(f"{key}:{str(val)}")
        canonical = "|".join(parts).encode('utf-8')
        return hmac.new(self._integrity_key(), canonical, hashlib.sha256).hexdigest()

    def _compute_chain_hmac(self, row_hmac: str, prev_chain_hmac: Optional[str]) -> str:
        """Compute chain HMAC linking this entry to the previous one."""
        prev = prev_chain_hmac.encode('utf-8') if prev_chain_hmac else _CHAIN_GENESIS
        payload = row_hmac.encode('utf-8') + b"||" + prev
        return hmac.new(self._integrity_key(), payload, hashlib.sha256).hexdigest()

    def _get_last_chain_hmac(self, conn: sqlite3.Connection) -> Optional[str]:
        """Get the last chain_hmac from events table for chaining."""
        row = conn.execute(
            "SELECT chain_hmac FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    # ─── Event Writing (WORM) ──────────────────────────────────────────────────

    def _write_event(self, event_type: str,
                     span_id: Optional[str] = None,
                     trace_id: Optional[str] = None,
                     parent_span_id: Optional[str] = None,
                     operation: Optional[str] = None,
                     level: Union[LogLevel, str] = LogLevel.INFO,
                     module: Optional[str] = None,
                     target: Optional[str] = None,
                     status: str = "active",
                     duration_ms: Optional[float] = None,
                     data: Optional[Dict[str, Any]] = None,
                     message: Optional[str] = None,
                     timestamp: Optional[str] = None,
                     epoch: Optional[float] = None) -> Dict[str, Any]:
        """Write an append-only event row with HMAC chain. Returns the event dict.

        This is the single INSERT path for all events (logs, span_start, span_end).
        Computes HMAC over full row content, chains to previous entry, inserts.
        """
        if span_id is None:
            span_id = str(uuid.uuid4())
        if trace_id is None:
            trace_id = str(uuid.uuid4())
        level_val = level.value if isinstance(level, LogLevel) else str(level)
        if epoch is None:
            epoch = time.time()
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        data_json = json.dumps(data, default=str) if data else None

        row = {
            'span_id': span_id,
            'trace_id': trace_id,
            'parent_span_id': parent_span_id,
            'event_type': event_type,
            'operation': operation,
            'level': level_val,
            'message': message,
            'module': module,
            'target': target,
            'status': status,
            'duration_ms': duration_ms,
            'data_json': data_json,
            'timestamp': timestamp,
            'epoch': epoch,
            'session_id': self._session_id,
        }

        # Compute HMAC chain
        row['row_hmac'] = self._compute_row_hmac(row)
        prev_chain = self._get_last_chain_hmac_conn_cached()
        row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)
        row['prev_chain_hmac'] = prev_chain

        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO events
                   (span_id, trace_id, parent_span_id, event_type, operation,
                    level, message, module, target, status, duration_ms,
                    data_json, timestamp, epoch, session_id,
                    row_hmac, chain_hmac, prev_chain_hmac)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row['span_id'], row['trace_id'], row['parent_span_id'],
                 row['event_type'], row['operation'], row['level'],
                 row['message'], row['module'], row['target'], row['status'],
                 row['duration_ms'], row['data_json'], row['timestamp'],
                 row['epoch'], row['session_id'],
                 row['row_hmac'], row['chain_hmac'], row['prev_chain_hmac'])
            )
            conn.commit()
        finally:
            conn.close()

        # Maintain in-memory mirror + JSONL for backward compat
        entry = self._row_to_entry(row)
        self._entries.append(entry)
        self._write_jsonl(entry)

        # Also log to Python logging
        log_level = getattr(logging, level_val.upper(), logging.INFO)
        prefix = f"[{event_type}]" if event_type != 'log' else ""
        msg_text = message or operation or event_type
        logger.log(log_level, f"[{level_val}] {prefix} {msg_text}")

        # Check rotation after write (unless we're already mid-rotation)
        if not self._rotating:
            self._maybe_rotate()

        return entry

    def _get_last_chain_hmac_conn_cached(self) -> Optional[str]:
        """Get last chain hmac (opens a quick connection)."""
        conn = self._get_conn()
        try:
            return self._get_last_chain_hmac(conn)
        finally:
            conn.close()

    def _row_to_entry(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a DB row dict to the legacy entry format (backward compat)."""
        data = None
        if row.get('data_json'):
            try:
                data = json.loads(row['data_json'])
            except (json.JSONDecodeError, TypeError):
                data = None
        return {
            'timestamp': row.get('timestamp', ''),
            'epoch': row.get('epoch', 0.0),
            'level': row.get('level', 'info'),
            'message': row.get('message') or row.get('operation') or row.get('event_type', ''),
            'module': row.get('module'),
            'target': row.get('target'),
            'data': data,
            'session_id': row.get('session_id', self._session_id),
            # New structured fields
            'span_id': row.get('span_id'),
            'trace_id': row.get('trace_id'),
            'parent_span_id': row.get('parent_span_id'),
            'event_type': row.get('event_type'),
            'operation': row.get('operation'),
            'status': row.get('status', 'active'),
            'duration_ms': row.get('duration_ms'),
        }

    def _write_jsonl(self, entry: Dict[str, Any]) -> None:
        """Write an entry to the legacy JSONL file (backward compat)."""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except IOError as e:
            logger.debug(f"JSONL write failed (non-fatal): {e}")

    # ─── Logging API (backward compatible) ─────────────────────────────────────

    def log(self, message: str, level: LogLevel = LogLevel.INFO,
            module: Optional[str] = None, target: Optional[str] = None,
            data: Optional[Dict[str, Any]] = None,
            span_id: Optional[str] = None,
            trace_id: Optional[str] = None) -> None:
        """Log an entry to the war log.

        Args:
            message: Log message
            level: Log level
            module: Module that generated the log
            target: Target of the operation
            data: Additional structured data
            span_id: If within a span, the span's UUID
            trace_id: If within a trace, the trace's UUID
        """
        parent_span = self._span_stack[-1][0] if self._span_stack else None
        parent_trace = self._span_stack[-1][1] if self._span_stack else None
        self._write_event(
            event_type='log',
            message=message,
            span_id=span_id or str(uuid.uuid4()),
            trace_id=trace_id or parent_trace or str(uuid.uuid4()),
            parent_span_id=parent_span if not span_id else span_id,
            operation=module or 'log',
            level=level,
            module=module,
            target=target,
            status='ok',
            data=data,
        )

    # ─── Convenience loggers (backward compatible) ────────────────────────────

    def log_recon(self, message: str, module: str, target: str,
                  data: Optional[Dict[str, Any]] = None) -> None:
        """Log a reconnaissance entry."""
        self.log(message, level=LogLevel.RECON, module=module, target=target, data=data)

    def log_exploit(self, message: str, module: str, target: str,
                    data: Optional[Dict[str, Any]] = None) -> None:
        """Log an exploit entry."""
        self.log(message, level=LogLevel.EXPLOIT, module=module, target=target, data=data)

    def log_stealth(self, message: str, module: str, target: str,
                    data: Optional[Dict[str, Any]] = None) -> None:
        """Log a stealth entry."""
        self.log(message, level=LogLevel.STEALTH, module=module, target=target, data=data)

    def log_exfil(self, message: str, module: str, target: str,
                  data: Optional[Dict[str, Any]] = None) -> None:
        """Log a data exfiltration entry."""
        self.log(message, level=LogLevel.EXFIL, module=module, target=target, data=data)

    def log_c2(self, message: str, module: str, target: str,
               data: Optional[Dict[str, Any]] = None) -> None:
        """Log a C2 entry."""
        self.log(message, level=LogLevel.C2, module=module, target=target, data=data)

    # ─── Span / Trace API (new — P1.4.1) ───────────────────────────────────────

    def start_span(self, operation: str,
                   trace_id: Optional[str] = None,
                   parent_span_id: Optional[str] = None,
                   level: Union[LogLevel, str] = LogLevel.INFO,
                   module: Optional[str] = None,
                   target: Optional[str] = None,
                   data: Optional[Dict[str, Any]] = None) -> Span:
        """Start a new span and return it.

        Args:
            operation: Name of the operation (e.g. "recon.port_scan").
            trace_id: Trace UUID. If None, a new trace is started.
            parent_span_id: Parent span UUID. If None and no span on stack,
                           this becomes a root span.
            level: Span log level.
            module: Source module.
            target: Operation target.
            data: Initial span attributes.
        """
        span_id = str(uuid.uuid4())
        # If parent not specified, attach to current span on stack.
        # Children inherit the parent's trace_id so the whole tree shares one trace.
        if parent_span_id is None and self._span_stack:
            parent_span_id, parent_trace = self._span_stack[-1]
            if trace_id is None:
                trace_id = parent_trace
        if trace_id is None:
            trace_id = str(uuid.uuid4())

        span = Span(self, span_id, trace_id, operation, parent_span_id,
                    level, module, target, data)
        span.start()
        self._span_stack.append((span_id, trace_id))
        return span

    @contextmanager
    def span(self, operation: str,
             trace_id: Optional[str] = None,
             parent_span_id: Optional[str] = None,
             level: Union[LogLevel, str] = LogLevel.INFO,
             module: Optional[str] = None,
             target: Optional[str] = None,
             data: Optional[Dict[str, Any]] = None) -> Iterator[Span]:
        """Context manager for a span. Usage:

            with warlog.span("recon.port_scan", target="10.0.0.1") as s:
                s.set_attr("ports", [22, 80, 443])
                ...
        """
        span = self.start_span(operation, trace_id, parent_span_id,
                               level, module, target, data)
        try:
            yield span
        except Exception as e:
            span.end(status="error", data={"error": str(e),
                                           "error_type": type(e).__name__})
            raise
        else:
            span.end(status="ok")
        finally:
            # Pop from span stack (stack now holds (span_id, trace_id) tuples)
            if self._span_stack and self._span_stack[-1][0] == span.span_id:
                self._span_stack.pop()
            else:
                for i, (sid, _) in enumerate(self._span_stack):
                    if sid == span.span_id:
                        self._span_stack.pop(i)
                        break

    # ─── Span.end writes through WarLog via Span.end → _write_event ──────────
    # (Span.end calls self._warlog._write_event directly)

    # ─── Query API (P1.4.4) ────────────────────────────────────────────────────

    def query_spans(self, operation: Optional[str] = None,
                    trace_id: Optional[str] = None,
                    status: Optional[str] = None,
                    level: Optional[Union[LogLevel, str]] = None,
                    time_range: Optional[tuple] = None,
                    target: Optional[str] = None,
                    limit: int = 1000) -> List[Dict[str, Any]]:
        """Query span events from the events table.

        Args:
            operation: Filter by operation name (exact match).
            trace_id: Filter by trace UUID.
            status: Filter by span status (active, ok, error, timeout).
            level: Filter by log level.
            time_range: Tuple of (start_epoch, end_epoch).
            target: Filter by target.
            limit: Max results (default 1000).

        Returns:
            List of span event dicts (both span_start and span_end events).
        """
        conditions = ["event_type IN ('span_start', 'span_end')"]
        params: List[Any] = []
        if operation:
            conditions.append("operation = ?")
            params.append(operation)
        if trace_id:
            conditions.append("trace_id = ?")
            params.append(trace_id)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if level:
            level_val = level.value if isinstance(level, LogLevel) else str(level)
            conditions.append("level = ?")
            params.append(level_val)
        if target:
            conditions.append("target = ?")
            params.append(target)
        if time_range:
            conditions.append("epoch >= ? AND epoch <= ?")
            params.extend([time_range[0], time_range[1]])

        query = (f"SELECT * FROM events WHERE {' AND '.join(conditions)} "
                 f"ORDER BY epoch ASC LIMIT ?")
        params.append(limit)

        conn = self._get_conn()
        try:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_entry(dict(r)) for r in rows]
        finally:
            conn.close()

    def trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get a structured summary of a trace.

        Returns dict with:
            trace_id, span_count, spans (list of span dicts with duration),
            total_duration_ms, status, operations (list).
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM events WHERE trace_id = ? ORDER BY epoch ASC",
                (trace_id,)
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            return {"trace_id": trace_id, "span_count": 0, "spans": [],
                    "total_duration_ms": 0, "status": "unknown", "operations": []}

        # Group by span_id
        spans: Dict[str, Dict] = {}
        operations: List[str] = []
        for r in rows:
            rd = dict(r)
            sid = rd['span_id']
            if sid not in spans:
                spans[sid] = {
                    'span_id': sid,
                    'trace_id': rd['trace_id'],
                    'parent_span_id': rd['parent_span_id'],
                    'operation': rd['operation'],
                    'level': rd['level'],
                    'status': rd['status'],
                    'duration_ms': rd.get('duration_ms'),
                    'start_epoch': rd['epoch'],
                }
                if rd['operation'] and rd['operation'] not in operations:
                    operations.append(rd['operation'])
            if rd['event_type'] == 'span_end':
                spans[sid]['status'] = rd['status']
                spans[sid]['duration_ms'] = rd.get('duration_ms')
                spans[sid]['end_epoch'] = rd['epoch']

        # Compute total duration (root span range)
        all_start = min(r['epoch'] for r in (dict(r) for r in rows))
        all_end = max(r['epoch'] for r in (dict(r) for r in rows))
        total_dur = round((all_end - all_start) * 1000, 3)

        # Overall status: error if any span has error, else ok
        statuses = [s['status'] for s in spans.values()]
        overall = 'error' if 'error' in statuses else 'ok'

        return {
            'trace_id': trace_id,
            'span_count': len(spans),
            'spans': sorted(spans.values(), key=lambda s: s['start_epoch']),
            'total_duration_ms': total_dur,
            'status': overall,
            'operations': operations,
        }

    # ─── Legacy Query API (backward compatible) ────────────────────────────────

    def get_entries(self, level: Optional[LogLevel] = None, module: Optional[str] = None,
                    target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get log entries with optional filtering (backward compatible).

        Queries the SQLite store and filters by level/module/target.
        """
        conditions = []
        params: List[Any] = []
        if level:
            level_val = level.value if isinstance(level, LogLevel) else str(level)
            conditions.append("level = ?")
            params.append(level_val)
        if module:
            conditions.append("module = ?")
            params.append(module)
        if target:
            conditions.append("target = ?")
            params.append(target)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM events {where} ORDER BY epoch ASC"
        conn = self._get_conn()
        try:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_entry(dict(r)) for r in rows]
        finally:
            conn.close()

    def get_summary(self) -> Dict[str, Any]:
        """Return a summary of the war log (backward compatible)."""
        duration = time.time() - self._start_time
        levels: Dict[str, int] = {}
        conn = self._get_conn()
        try:
            count_row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            total = count_row[0] if count_row else 0
            for r in conn.execute(
                "SELECT level, COUNT(*) as cnt FROM events GROUP BY level"
            ).fetchall():
                levels[r['level']] = r['cnt']
        except sqlite3.Error:
            total = len(self._entries)
        finally:
            conn.close()
        return {
            "session_id": self._session_id,
            "total_entries": total,
            "duration_seconds": round(duration, 2),
            "level_counts": levels,
            "log_file": self.log_file,
        }

    def export(self, filepath: str) -> None:
        """Export all entries to a JSON file (backward compatible)."""
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT * FROM events ORDER BY epoch ASC").fetchall()
            entries = [self._row_to_entry(dict(r)) for r in rows]
        finally:
            conn.close()
        with open(filepath, "w") as f:
            json.dump(entries, f, indent=2, default=str)
        logger.info(f"Exported {len(entries)} entries to {filepath}")

    def clear(self) -> None:
        """Clear the in-memory entries list (backward compatible).

        Note: The SQLite store is WORM (append-only). This only clears the
        in-memory mirror, not the persisted store. This preserves the original
        contract where clear() resets __len__ to 0 for test isolation.
        """
        self._entries.clear()
        logger.info("WarLog in-memory entries cleared (DB is WORM, untouched)")

    def __len__(self) -> int:
        return len(self._entries)

    # ─── Rotation (P1.4.3) ──────────────────────────────────────────────────────

    def _maybe_rotate(self) -> bool:
        """Check if rotation is needed and perform it. Returns True if rotated."""
        try:
            db_size = os.path.getsize(self._db_path)
        except OSError:
            return False

        should_rotate = False
        reason = None

        # Size-based
        if db_size >= self.max_db_size:
            should_rotate = True
            reason = "size"

        # Time-based: check oldest event
        if not should_rotate:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT MIN(epoch) as oldest FROM events"
                ).fetchone()
                if row and row['oldest']:
                    age_days = (time.time() - row['oldest']) / 86400.0
                    if age_days >= self.max_age_days:
                        should_rotate = True
                        reason = "age"
            except sqlite3.Error:
                pass
            finally:
                conn.close()

        if should_rotate:
            self._rotate(reason)
            return True
        return False

    def _rotate(self, reason: str = "manual") -> str:
        """Rotate: compress current DB to archive, start fresh DB.

        Steps:
            1. Close any open connections (WAL checkpoint)
            2. Copy current DB to archive path with timestamp
            3. Gzip the archive
            4. Delete the archive copy (keep .gz)
            5. Delete current DB + WAL/SHM files
            6. Re-init fresh schema
            7. Prune old archives beyond keep_archives

        Returns the archive path.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_base = os.path.join(self.log_dir, f"warlog.{ts}.db")
        archive_gz = archive_base + ".gz"

        # Set rotation guard so the rotation-event write doesn't re-trigger rotation
        self._rotating = True
        try:
            # WAL checkpoint to flush
            conn = self._get_conn()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                conn.commit()
            except sqlite3.Error:
                pass
            finally:
                conn.close()

            # Gzip the DB file directly
            with open(self._db_path, 'rb') as f_in:
                with gzip.open(archive_gz, 'wb') as f_out:
                    f_out.writelines(f_in)

            # Remove the current DB + WAL/SHM
            for suffix in ['', '-wal', '-shm']:
                p = self._db_path + suffix
                if os.path.exists(p):
                    os.remove(p)

            # Reset in-memory state
            self._entries.clear()
            self._span_stack.clear()
            self._session_id = str(uuid.uuid4())

            # Re-init fresh DB
            self._init_db()

            # Log rotation event
            self._write_event(
                event_type='log',
                message=f"WarLog rotated (reason={reason}, archive={os.path.basename(archive_gz)})",
                span_id=str(uuid.uuid4()),
                trace_id=str(uuid.uuid4()),
                operation='warlog.rotate',
                level=LogLevel.INFO,
                module='warlog',
                status='ok',
                data={'reason': reason, 'archive': archive_gz},
            )

            # Prune old archives
            self._prune_archives()

            logger.info(f"WarLog rotated (reason={reason}): {archive_gz}")
            return archive_gz
        finally:
            self._rotating = False

    def _prune_archives(self) -> int:
        """Delete old archives beyond keep_archives. Returns count deleted."""
        import glob as gl
        pattern = os.path.join(self.log_dir, "warlog.*.db.gz")
        archives = sorted(gl.glob(pattern), reverse=True)  # newest first
        deleted = 0
        for old in archives[self.keep_archives:]:
            try:
                os.remove(old)
                deleted += 1
            except OSError:
                pass
        return deleted

    def list_archives(self) -> List[str]:
        """List all archive files (newest first)."""
        import glob as gl
        return sorted(gl.glob(os.path.join(self.log_dir, "warlog.*.db.gz")),
                      reverse=True)

    # ─── Integrity Verification (P1.4.2) ───────────────────────────────────────

    def verify_integrity(self, progress=None) -> IntegrityReport:
        """Verify the HMAC chain integrity of all events.

        Checks:
            1. Every row's row_hmac matches recomputed HMAC of its content
            2. Every chain_hmac links correctly to the previous entry
            3. No gaps in the seq sequence

        Args:
            progress: optional ``cb(done, total, label)`` invoked once per
                verified event (W4-2.3c). Backward-compatible — defaults to
                None, and any exception it raises is swallowed.

        Returns IntegrityReport with details of any tampering.
        """
        report = IntegrityReport(verified=True, total_events=0)
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY seq ASC"
            ).fetchall()
            report.total_events = len(rows)
            prev_chain = None
            expected_seq = 1
            for i, row in enumerate(rows, start=1):
                row_dict = dict(row)
                seq = row_dict.get('seq')

                # Check sequence continuity
                if seq != expected_seq:
                    report.verified = False
                    report.broken_chain_links.append({
                        'seq': seq,
                        'issue': f'sequence gap (expected {expected_seq})'
                    })
                expected_seq += 1

                # Recompute row HMAC
                stored_hmac = row_dict.get('row_hmac', '')
                computed_hmac = self._compute_row_hmac(row_dict)
                if not hmac.compare_digest(stored_hmac, computed_hmac):
                    report.verified = False
                    report.broken_hmacs.append({
                        'seq': seq,
                        'span_id': row_dict.get('span_id', '?'),
                        'issue': 'row_hmac mismatch - content tampered'
                    })

                # Verify chain link
                stored_chain = row_dict.get('chain_hmac', '')
                computed_chain = self._compute_chain_hmac(stored_hmac, prev_chain)
                if not hmac.compare_digest(stored_chain, computed_chain):
                    report.verified = False
                    report.broken_chain_links.append({
                        'seq': seq,
                        'issue': 'chain link broken - entry inserted/removed/deleted'
                    })

                # Check prev_chain_hmac pointer
                if row_dict.get('prev_chain_hmac') != prev_chain:
                    report.verified = False
                    report.broken_chain_links.append({
                        'seq': seq,
                        'issue': 'prev_chain_hmac does not match previous entry'
                    })

                prev_chain = stored_chain

                if progress is not None:
                    try:
                        progress(i, len(rows), f"WarLog event {i}/{len(rows)}")
                    except Exception:  # noqa: BLE001
                        pass

            return report
        except sqlite3.Error as e:
            logger.error(f"Integrity verification failed: {e}")
            report.verified = False
            report.broken_hmacs.append({'seq': 0, 'span_id': 'system',
                                        'issue': f'verification error: {e}'})
            return report
        finally:
            conn.close()
