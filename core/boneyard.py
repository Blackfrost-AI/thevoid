"""THE VOID — Boneyard: Encrypted, tamper-evident, relational state store.

Phase 1.1 rewrite (VOID-CEP-2026-07). Replaces the flat JSON index + per-item
file store with a SQLite-backed relational database featuring:

  - Relational schema: hosts, services, vulns, creds, attack_paths, outcomes,
    findings (see boneyard_schema.sql)
  - Query API: query_hosts(), query_findings(), graph_attack_paths() replacing
    linear scans with indexed, parameterized queries
  - HMAC-SHA256 chain-of-custody: every row is signed; every audit entry is
    chained to the previous entry's hash. Tampering breaks the chain and is
    detected by verify_integrity().
  - Append-only WORM audit log: all writes logged with before/after state
  - AES-256-GCM encryption-at-rest: the database file is encrypted; the key
    is derived from a passphrase and never stored alongside the DB
  - JSON→SQLite migration: migrate_json_to_sqlite() imports legacy data

The public interface is backward-compatible with the previous Boneyard:
  store(category, data, tags) -> str (item_id)
  get(item_id) -> Optional[dict]
  search(category, tags, query) -> List[dict]
  count() -> int
  categories() -> List[str]
  delete(item_id) -> bool
  export(filepath, category) -> None
  summary() -> dict / get_summary() -> dict

New query API:
  query_hosts(filters) -> List[dict]
  query_findings(filters) -> List[dict]
  graph_attack_paths(host_id) -> dict
  verify_integrity() -> IntegrityReport
"""

from __future__ import annotations

import os
import json
import time
import uuid
import hmac
import hashlib
import sqlite3
import logging
import secrets
import struct
from ipaddress import ip_address as parse_ip_address
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Iterator, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("void.boneyard")

if TYPE_CHECKING:
    from orchestrator.difficulty import DifficultyReport

# ─── Schema path ────────────────────────────────────────────────────────────
_SCHEMA_DIR = os.path.dirname(os.path.abspath(__file__))
_SCHEMA_FILE = os.path.join(_SCHEMA_DIR, "boneyard_schema.sql")

# ─── Integrity constants ────────────────────────────────────────────────────
_HMAC_ALGO = "sha256"
_CHAIN_GENESIS = b"GENESIS"


@dataclass
class IntegrityReport:
    """Result of an integrity verification scan."""
    verified: bool
    total_rows_checked: int
    broken_hmacs: List[Dict[str, Any]] = field(default_factory=list)
    broken_chain_links: List[Dict[str, Any]] = field(default_factory=list)
    orphaned_audit_entries: List[Dict[str, Any]] = field(default_factory=list)
    table_counts: Dict[str, int] = field(default_factory=dict)
    audit_chain_length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QueryResult:
    """Iterator-friendly wrapper for query results."""
    rows: List[Dict[str, Any]]
    query_info: Dict[str, Any] = field(default_factory=dict)

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return self.rows[idx]


class Boneyard:
    """SQLite-backed, encrypted, tamper-evident boneyard.

    Args:
        storage_dir: Directory for the database file. If None, uses config default.
        passphrase: Passphrase for AES-256-GCM encryption-at-rest.
                    If None, a private per-store key is managed in the operator's
                    configuration directory. Existing legacy data is not re-keyed.
    """

    def __init__(self, storage_dir: Optional[str] = None,
                 passphrase: Optional[str] = None):
        if storage_dir is None:
            from config.defaults import BONEYARD_DIR
            storage_dir = BONEYARD_DIR
        # Refuse missing cryptography before creating or opening any store.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        from core.private_storage import private_directory, prepare_database, store_passphrase

        if passphrase == "":
            raise ValueError("An empty evidence passphrase is not permitted.")
        self.storage_dir = storage_dir
        private_directory(self.storage_dir)

        self._db_path = os.path.join(self.storage_dir, "boneyard.db")
        self._wal_path = self._db_path + "-wal"
        self._shm_path = self._db_path + "-shm"
        if passphrase is None:
            passphrase = store_passphrase(self._db_path)
        prepare_database(self._db_path)
        self._encrypted = True
        self._passphrase = passphrase
        self._key_id = self._derive_key_id(passphrase) if passphrase else "none"

        # Optional WarLog integration (P1.4.5). When attached, all state
        # changes (store/delete/audit) emit structured spans cross-referenced
        # by item_id. None means no warlog — fully backward-compatible.
        self._warlog: Optional[Any] = None

        # Initialize DB
        self._init_db()
        logger.info(
            f"Boneyard initialized at {self._db_path} "
            f"(encrypted={self._encrypted})"
        )

    # ─── WarLog integration (P1.4.5) ─────────────────────────────────────────

    def attach_warlog(self, warlog: Any) -> None:
        """Attach a WarLog so all state changes emit structured spans.

        After attaching, every store(), delete(), and internal audit write
        produces a span in the warlog. Parent/child linkage is automatic via
        the warlog span stack: a store() creates a parent span, and each
        audit entry (finding + relational tables) becomes a child span,
        all sharing one trace_id and cross-referenced by item_id.

        WarLog failures are non-fatal: if the warlog raises, the boneyard
        operation still completes normally.

        Args:
            warlog: A WarLog instance (core.warlog.WarLog).
        """
        self._warlog = warlog
        logger.info("WarLog attached to Boneyard — state changes will emit spans")

    def detach_warlog(self) -> None:
        """Detach the WarLog. Subsequent operations will not emit spans."""
        self._warlog = None
        logger.info("WarLog detached from Boneyard")

    def _begin_span(self, operation: str, **kwargs) -> Optional[Any]:
        """Start a warlog span if a warlog is attached. Returns Span or None.

        Non-fatal: if the warlog raises, returns None and the caller proceeds
        without span instrumentation.
        """
        if self._warlog is None:
            return None
        try:
            return self._warlog.start_span(operation, module="boneyard", **kwargs)
        except Exception as e:
            logger.debug(f"Warlog span start failed (non-fatal): {e}")
            return None

    def _finish_span(self, span: Optional[Any], status: str = "ok",
                     **attrs: Any) -> None:
        """End a warlog span and pop it from the span stack. Non-fatal.

        Mirrors the span() context manager's __exit__: end the span, then pop
        from _span_stack so children don't attach to a stale parent.
        """
        if span is None:
            return
        try:
            for k, v in attrs.items():
                span.set_attr(k, v)
            span.end(status=status)
        except Exception as e:
            logger.debug(f"Warlog span end failed (non-fatal): {e}")
        finally:
            # Pop from span stack (mirrors span() CM __exit__)
            try:
                stack = self._warlog._span_stack
                if stack and stack[-1][0] == span.span_id:
                    stack.pop()
                else:
                    for i, (sid, _) in enumerate(stack):
                        if sid == span.span_id:
                            stack.pop(i)
                            break
            except Exception:
                pass

    # ─── Database initialization ────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Get a new SQLite connection with secure pragmas."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA secure_delete = ON")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _init_db(self) -> None:
        """Initialize the database schema from the SQL file."""
        if not os.path.exists(_SCHEMA_FILE):
            raise FileNotFoundError(f"Schema file not found: {_SCHEMA_FILE}")
        with open(_SCHEMA_FILE, "r") as f:
            schema_sql = f.read()
        conn = self._get_conn()
        try:
            conn.executescript(schema_sql)
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Schema initialization failed: {e}")
            raise
        finally:
            conn.close()

    # ─── Encryption (AES-256-GCM at application layer) ───────────────────────

    def _derive_key_id(self, passphrase: str) -> str:
        """Derive a key identifier (not the key itself) for tracking."""
        import hashlib as _hl
        return _hl.sha256(passphrase.encode()[:64]).hexdigest()[:16]

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 32-byte AES-256 key from passphrase + salt (PBKDF2)."""
        import hashlib as _hl
        return _hl.pbkdf2_hmac('sha256', self._passphrase.encode(), salt, 200000, dklen=32)

    def _encrypt_field(self, plaintext: str) -> Tuple[str, str]:
        """Encrypt a field value with AES-256-GCM. Returns (ciphertext_b64, nonce_b64)."""
        if not self._encrypted or not self._passphrase:
            return plaintext, ""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise RuntimeError("Supported cryptography is required; encryption cannot fall back.") from None

        salt = secrets.token_bytes(16)
        key = self._derive_key(salt)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Prepend salt to ciphertext for key derivation on decrypt
        payload = salt + ct
        return _b64(payload), _b64(nonce)

    def _decrypt_field(self, ciphertext_b64: str, nonce_b64: str) -> str:
        """Decrypt a field value."""
        if not self._encrypted or not self._passphrase:
            return ciphertext_b64
        if not nonce_b64:
            return ciphertext_b64
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise RuntimeError("Supported cryptography is required; decryption cannot fall back.") from None

        try:
            payload = _unb64(ciphertext_b64)
            salt = payload[:16]
            ct = payload[16:]
            nonce = _unb64(nonce_b64)
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            pt = aesgcm.decrypt(nonce, ct, None)
            return pt.decode('utf-8')
        except Exception as exc:
            raise RuntimeError("Evidence decryption failed; verify the original key and database integrity.") from exc

    # ─── HMAC Integrity ───────────────────────────────────────────────────────

    def _compute_row_hmac(self, table: str, row: Dict[str, Any]) -> str:
        """Compute HMAC-SHA256 of a row's canonical representation."""
        # Build canonical representation: table + sorted column values
        # Excluded from HMAC:
        #   - row_hmac/chain_hmac/prev_chain_hmac: the integrity columns themselves
        #   - seq: autoincrement integer assigned by SQLite at insert time; unknown
        #          at write time, so including it makes the HMAC unverifiable.
        #          Ordering is validated separately by the chain-continuity check.
        _excluded = ('row_hmac', 'chain_hmac', 'prev_chain_hmac', 'seq')
        canonical_parts = [table]
        for key in sorted(row.keys()):
            if key in _excluded:
                continue
            val = row[key]
            if val is None:
                canonical_parts.append(f"{key}:NULL")
            else:
                canonical_parts.append(f"{key}:{str(val)}")
        canonical = "|".join(canonical_parts).encode('utf-8')
        mac = hmac.new(self._integrity_key(), canonical, hashlib.sha256)
        return mac.hexdigest()

    def _compute_chain_hmac(self, row_hmac: str, prev_chain_hmac: str) -> str:
        """Compute chain HMAC linking this entry to the previous one."""
        prev = prev_chain_hmac.encode('utf-8') if prev_chain_hmac else _CHAIN_GENESIS
        payload = row_hmac.encode('utf-8') + b"||" + prev
        mac = hmac.new(self._integrity_key(), payload, hashlib.sha256)
        return mac.hexdigest()

    def _integrity_key(self) -> bytes:
        """Derive the integrity HMAC key from the passphrase."""
        if self._passphrase:
            return hashlib.pbkdf2_hmac('sha256', self._passphrase.encode(),
                                       b'boneyard-integrity-v1', 200000, dklen=32)
        raise RuntimeError("A secret-managed integrity key is required.")

    def _get_last_chain_hmac(self, conn: sqlite3.Connection) -> str:
        """Get the last chain_hmac from the audit log for chaining."""
        row = conn.execute(
            "SELECT chain_hmac FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def _write_audit_entry(self, conn: sqlite3.Connection, operation: str,
                           table_name: str, row_id: str, actor: str,
                           reason: str, prev_state: Optional[Dict],
                           new_state: Optional[Dict]) -> None:
        """Write an append-only audit log entry with HMAC chain.

        If a WarLog is attached, also emits a child span cross-referenced by
        row_id (the item_id). The span attaches to whatever parent span is
        currently on the warlog span stack (e.g. the store() parent span).
        """
        audit_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        epoch = time.time()
        prev_json = json.dumps(prev_state, default=str) if prev_state else None
        new_json = json.dumps(new_state, default=str) if new_state else None

        # Canonical representation for HMAC
        audit_row = {
            'seq': None,  # autoincrement
            'id': audit_id,
            'timestamp': ts,
            'epoch': epoch,
            'operation': operation,
            'table_name': table_name,
            'row_id': row_id,
            'actor': actor,
            'reason': reason,
            'prev_state_json': prev_json,
            'new_state_json': new_json,
        }
        row_hmac = self._compute_row_hmac('audit_log', audit_row)
        prev_chain = self._get_last_chain_hmac(conn)
        chain_hmac = self._compute_chain_hmac(row_hmac, prev_chain)

        conn.execute(
            """INSERT INTO audit_log
               (id, timestamp, epoch, operation, table_name, row_id, actor, reason,
                prev_state_json, new_state_json, row_hmac, chain_hmac, prev_chain_hmac)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (audit_id, ts, epoch, operation, table_name, row_id, actor, reason,
             prev_json, new_json, row_hmac, chain_hmac, prev_chain)
        )

        # Emit warlog span for this state change (P1.4.5).
        # Cross-references the row_id (item_id) so warlog queries can find
        # all state changes for a given finding/host/service/cred/vuln.
        if self._warlog is not None:
            _audit_span = self._begin_span(
                f"boneyard.audit.{operation.lower()}",
                data={
                    'table': table_name,
                    'item_id': row_id,
                    'actor': actor,
                    'reason': reason,
                }
            )
            self._finish_span(
                _audit_span, status="ok",
                has_prev_state=prev_state is not None,
                has_new_state=new_state is not None,
            )

    # ─── Backward-compatible store/get/search API ────────────────────────────

    def store(self, category: str, data: Dict[str, Any],
              tags: Optional[List[str]] = None,
              epoch: Optional[float] = None) -> str:
        """Store a finding in the boneyard.

        Maps the legacy store(category, data, tags) interface to the new
        findings table. Structured data is routed to relational tables when
        possible; unstructured goes to findings with FTS indexing.

        Args:
            category: Finding category (recon, exploit, exfil, cred, loot, intel, other)
            data: Finding data as a dict
            tags: Optional tags list
            epoch: Optional pinned timestamp (demo seeding / deterministic
                   timelines). HMAC is computed over the stored value.

        Returns:
            The UUID of the stored finding
        """
        # P1.4.5: emit a parent span for this store operation. Child spans
        # (one per audit entry) are emitted automatically by _write_audit_entry
        # and attach to this span via the warlog span stack.
        _span = self._begin_span("boneyard.store", data={'category': category})

        item_id = str(uuid.uuid4())
        tags = tags or []
        epoch_val = epoch if epoch is not None else time.time()
        ts = datetime.fromtimestamp(epoch_val, tz=timezone.utc).isoformat()

        conn = None
        try:
            conn = self._get_conn()
            # Route structured data to relational tables
            host_id = self._route_structured_data(conn, category, data, item_id, ts, epoch_val)

            # Store as a finding (backward-compat layer)
            title = str(data.get('title', data.get('name', f"{category}_{item_id[:8]}")))
            data_json = json.dumps(data, default=str)
            fts_content = self._build_fts_content(category, title, data, tags)

            # Encrypt sensitive data fields if encryption is enabled.
            # Store as a JSON envelope so the nonce travels with the ciphertext
            # (no schema change needed; data_json stays valid JSON for HMAC + FTS).
            enc_data = data_json
            if self._encrypted and self._is_sensitive(category):
                ct_b64, nonce_b64 = self._encrypt_field(data_json)
                enc_data = json.dumps({"__enc__": True, "ct": ct_b64, "nonce": nonce_b64})

            row = {
                'id': item_id,
                'category': category,
                'title': title,
                'data_json': enc_data,
                'tags_json': json.dumps(tags),
                'host_id': host_id,
                'service_id': None,
                'risk_score': float(data.get('risk_score', 0.0)),
                'is_archived': 0,
                'created_at': ts,
                'epoch': epoch_val,
                'fts_content': fts_content,
                'deleted': 0,
            }
            row['row_hmac'] = self._compute_row_hmac('findings', row)
            prev_chain = self._get_last_chain_hmac(conn)
            row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

            conn.execute(
                """INSERT INTO findings
                   (id, category, title, data_json, tags_json, host_id, service_id,
                    risk_score, is_archived, created_at, epoch, fts_content,
                    row_hmac, chain_hmac, deleted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row['id'], row['category'], row['title'], row['data_json'],
                 row['tags_json'], row['host_id'], row['service_id'],
                 row['risk_score'], row['is_archived'], row['created_at'],
                 row['epoch'], row['fts_content'], row['row_hmac'],
                 row['chain_hmac'], row['deleted'])
            )

            # Audit log
            self._write_audit_entry(
                conn, 'INSERT', 'findings', item_id, 'boneyard.store',
                f'store({category})', None, {'id': item_id, 'category': category}
            )
            conn.commit()
            logger.info(f"Stored finding {item_id} category='{category}'")
            self._finish_span(_span, status="ok", item_id=item_id)
            return item_id
        except sqlite3.Error as e:
            logger.error(f"Store failed: {e}")
            if conn is not None:
                conn.rollback()
            self._finish_span(_span, status="error", error=str(e))
            raise
        finally:
            if conn is not None:
                conn.close()

    def _route_structured_data(self, conn: sqlite3.Connection, category: str,
                               data: Dict, item_id: str, ts: str, epoch: float) -> Optional[str]:
        """Route structured data to relational tables. Returns host_id if a host was created."""
        host_id = None
        try:
            # If data contains host info, create a host record
            if 'host' in data or 'ip' in data or 'target' in data:
                host_data = data.get('host', data.get('ip', data.get('target', {})))
                if isinstance(host_data, str):
                    # Route hostnames into the hostname column and reuse a
                    # matching host instead of adding one row per finding.
                    try:
                        parse_ip_address(host_data)
                        ip_value, hostname_value = host_data, ''
                    except ValueError:
                        ip_value, hostname_value = '', host_data
                    host_id = self._ensure_host_record(
                        conn, ip=ip_value, hostname=hostname_value,
                        data=data, ts=ts, epoch=epoch,
                    )
                elif isinstance(host_data, dict):
                    host_id = self._ensure_host_record(
                        conn, ip=host_data.get('ip', ''),
                        hostname=host_data.get('hostname', ''),
                        data=host_data, ts=ts, epoch=epoch,
                    )

            # If data contains service info, create service record
            services = data.get('services', data.get('open_ports', []))
            if isinstance(services, list) and host_id:
                for svc in services[:100]:  # cap
                    if isinstance(svc, dict) and 'port' in svc:
                        self._create_service_record(conn, host_id, svc, ts, epoch)

            # If data contains credentials, create cred records
            creds = data.get('credentials', data.get('creds', []))
            if isinstance(creds, list):
                for cred in creds[:100]:
                    if isinstance(cred, dict) and 'username' in cred:
                        self._create_cred_record(conn, host_id, cred, ts, epoch)

            # If data contains vulnerability info, create vuln records
            vulns = data.get('vulnerabilities', data.get('vulns', []))
            if isinstance(vulns, list):
                for vuln in vulns[:100]:
                    if isinstance(vuln, dict) and ('cve' in vuln or 'title' in vuln):
                        self._create_vuln_record(conn, host_id, None, vuln, ts, epoch)
        except Exception as e:
            logger.warning(f"Structured data routing failed (non-fatal): {e}")
        return host_id

    def _create_host_record(self, conn: sqlite3.Connection, ip: str = '',
                            hostname: str = '', data: Dict = None, ts: str = '',
                            epoch: float = 0.0) -> str:
        """Create a host record from structured data."""
        host_id = str(uuid.uuid4())
        data = data or {}
        row = {
            'id': host_id,
            'ip_address': str(ip or data.get('ip', '')),
            'hostname': str(hostname or data.get('hostname', '')),
            'domain': str(data.get('domain', '')),
            'os_family': str(data.get('os', data.get('os_family', ''))),
            'os_version': str(data.get('os_version', '')),
            'status': str(data.get('status', 'up')),
            'is_critical': int(data.get('is_critical', 0)),
            'notes': str(data.get('notes', '')),
            'first_seen': ts,
            'last_seen': ts,
            'created_at': ts,
            'epoch': epoch,
            'deleted': 0,
        }
        row['row_hmac'] = self._compute_row_hmac('hosts', row)
        prev_chain = self._get_last_chain_hmac(conn)
        row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

        conn.execute(
            """INSERT INTO hosts
               (id, ip_address, hostname, domain, os_family, os_version, status,
                is_critical, notes, first_seen, last_seen, created_at, epoch,
                row_hmac, chain_hmac, deleted)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row['id'], row['ip_address'], row['hostname'], row['domain'],
             row['os_family'], row['os_version'], row['status'], row['is_critical'],
             row['notes'], row['first_seen'], row['last_seen'], row['created_at'],
             row['epoch'], row['row_hmac'], row['chain_hmac'], row['deleted'])
        )
        self._write_audit_entry(conn, 'INSERT', 'hosts', host_id, 'boneyard._route',
                                'auto-route host from finding data', None, {'id': host_id})
        return host_id

    def _ensure_host_record(self, conn: sqlite3.Connection, ip: str = '',
                            hostname: str = '', data: Dict = None,
                            ts: str = '', epoch: float = 0.0) -> str:
        """Reuse a host inside an existing transaction or create it.

        The structured finding router already owns a SQLite transaction, so
        calling public ``ensure_host`` would open a competing connection. The
        cross-column matches also recognize rows produced by older builds that
        placed hostname strings in ``ip_address``.
        """
        clauses: List[str] = []
        params: List[str] = []
        if ip:
            clauses.append("(ip_address = ? OR hostname = ?)")
            params.extend((str(ip), str(ip)))
        if hostname:
            clauses.append("(hostname = ? OR ip_address = ?)")
            params.extend((str(hostname), str(hostname)))
        if clauses:
            row = conn.execute(
                "SELECT id FROM hosts WHERE deleted = 0 AND ("
                + " OR ".join(clauses)
                + ") ORDER BY epoch ASC LIMIT 1",
                params,
            ).fetchone()
            if row:
                return str(row[0])
        return self._create_host_record(
            conn, ip=ip, hostname=hostname, data=data or {}, ts=ts, epoch=epoch,
        )

    def _create_service_record(self, conn: sqlite3.Connection, host_id: str,
                               svc: Dict, ts: str, epoch: float) -> str:
        """Create a service record."""
        svc_id = str(uuid.uuid4())
        row = {
            'id': svc_id,
            'host_id': host_id,
            'port': int(svc.get('port', 0)),
            'protocol': str(svc.get('protocol', 'tcp')),
            'service_name': str(svc.get('name', svc.get('service', 'unknown'))),
            'service_version': str(svc.get('version', '')),
            'banner': str(svc.get('banner', ''))[:4096],
            'auth_type': str(svc.get('auth_type', 'none')),
            'is_external': int(svc.get('is_external', 0)),
            'risk_score': float(svc.get('risk_score', 0.0)),
            'notes': str(svc.get('notes', '')),
            'first_seen': ts,
            'last_seen': ts,
            'created_at': ts,
            'epoch': epoch,
            'deleted': 0,
        }
        row['row_hmac'] = self._compute_row_hmac('services', row)
        prev_chain = self._get_last_chain_hmac(conn)
        row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

        conn.execute(
            """INSERT INTO services
               (id, host_id, port, protocol, service_name, service_version, banner,
                auth_type, is_external, risk_score, notes, first_seen, last_seen,
                created_at, epoch, row_hmac, chain_hmac, deleted)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row['id'], row['host_id'], row['port'], row['protocol'],
             row['service_name'], row['service_version'], row['banner'],
             row['auth_type'], row['is_external'], row['risk_score'], row['notes'],
             row['first_seen'], row['last_seen'], row['created_at'], row['epoch'],
             row['row_hmac'], row['chain_hmac'], row['deleted'])
        )
        self._write_audit_entry(conn, 'INSERT', 'services', svc_id, 'boneyard._route',
                                'auto-route service from finding data', None, {'id': svc_id})
        return svc_id

    def _create_cred_record(self, conn: sqlite3.Connection, host_id: Optional[str],
                            cred: Dict, ts: str, epoch: float) -> str:
        """Create a credential record with encrypted password."""
        cred_id = str(uuid.uuid4())
        password = str(cred.get('password', cred.get('secret', cred.get('hash', ''))))
        enc_pass, enc_nonce = self._encrypt_field(password) if password else ("", "")

        row = {
            'id': cred_id,
            'host_id': host_id,
            'service_id': None,
            'username': str(cred.get('username', '')),
            'enc_password': enc_pass,
            'enc_nonce': enc_nonce,
            'enc_key_id': self._key_id if self._encrypted else 'none',
            'cred_type': str(cred.get('cred_type', 'password')),
            'hash_type': str(cred.get('hash_type', '')),
            'source': str(cred.get('source', 'other')),
            'is_valid': int(cred.get('is_valid', 0)),
            'validity_checked': ts,
            'created_at': ts,
            'epoch': epoch,
            'deleted': 0,
        }
        row['row_hmac'] = self._compute_row_hmac('creds', row)
        prev_chain = self._get_last_chain_hmac(conn)
        row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

        conn.execute(
            """INSERT INTO creds
               (id, host_id, service_id, username, enc_password, enc_nonce, enc_key_id,
                cred_type, hash_type, source, is_valid, validity_checked, created_at,
                epoch, row_hmac, chain_hmac, deleted)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row['id'], row['host_id'], row['service_id'], row['username'],
             row['enc_password'], row['enc_nonce'], row['enc_key_id'],
             row['cred_type'], row['hash_type'], row['source'], row['is_valid'],
             row['validity_checked'], row['created_at'], row['epoch'],
             row['row_hmac'], row['chain_hmac'], row['deleted'])
        )
        self._write_audit_entry(conn, 'INSERT', 'creds', cred_id, 'boneyard._route',
                                'auto-route credential from finding data', None, {'id': cred_id})
        return cred_id

    def _create_vuln_record(self, conn: sqlite3.Connection, host_id: Optional[str],
                            service_id: Optional[str], vuln: Dict, ts: str, epoch: float) -> str:
        """Create a vulnerability record."""
        vuln_id = str(uuid.uuid4())
        row = {
            'id': vuln_id,
            'host_id': host_id,
            'service_id': service_id,
            'cve_id': str(vuln.get('cve', vuln.get('cve_id', ''))),
            'title': str(vuln.get('title', 'Unknown vulnerability')),
            'description': str(vuln.get('description', ''))[:8192],
            'cvss_score': float(vuln.get('cvss_score', vuln.get('cvss', 0.0))),
            'cvss_vector': str(vuln.get('cvss_vector', '')),
            'exploitability': str(vuln.get('exploitability', 'theoretical')),
            'solution': str(vuln.get('solution', '')),
            'references_json': json.dumps(vuln.get('references', [])),
            'is_verified': int(vuln.get('is_verified', 0)),
            'verified_method': str(vuln.get('verified_method', '')),
            'created_at': ts,
            'epoch': epoch,
            'deleted': 0,
        }
        row['row_hmac'] = self._compute_row_hmac('vulns', row)
        prev_chain = self._get_last_chain_hmac(conn)
        row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

        conn.execute(
            """INSERT INTO vulns
               (id, host_id, service_id, cve_id, title, description, cvss_score,
                cvss_vector, exploitability, solution, references_json, is_verified,
                verified_method, created_at, epoch, row_hmac, chain_hmac, deleted)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row['id'], row['host_id'], row['service_id'], row['cve_id'], row['title'],
             row['description'], row['cvss_score'], row['cvss_vector'], row['exploitability'],
             row['solution'], row['references_json'], row['is_verified'],
             row['verified_method'], row['created_at'], row['epoch'],
             row['row_hmac'], row['chain_hmac'], row['deleted'])
        )
        self._write_audit_entry(conn, 'INSERT', 'vulns', vuln_id, 'boneyard._route',
                                'auto-route vuln from finding data', None, {'id': vuln_id})
        return vuln_id

    def _build_fts_content(self, category: str, title: str, data: Dict,
                           tags: List[str]) -> str:
        """Build denormalized text for FTS indexing."""
        if self._is_sensitive(category):
            return category
        parts = [category, title]
        parts.extend(tags)
        # Add key fields from data for searchability
        for key in ['host', 'ip', 'target', 'service', 'port', 'user', 'username',
                    'cve', 'vulnerability', 'technique']:
            if key in data:
                parts.append(f"{key}:{data[key]}")
        return " ".join(str(p) for p in parts)[:16384]  # cap at 16KB

    # ─── Backward-compatible read API ────────────────────────────────────────

    def get(self, item_id: str) -> Optional[Dict]:
        """Get a finding by ID (backward-compat)."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                """SELECT id, category, title, data_json, tags_json, host_id,
                          service_id, risk_score, created_at, epoch
                   FROM findings WHERE id = ? AND deleted = 0""",
                (item_id,)
            ).fetchone()
            if not row:
                return None
            data = self._decrypt_data(row['data_json'])
            return {
                'id': row['id'],
                'category': row['category'],
                'title': row['title'] or data.get('title'),
                'data': data,
                'tags': json.loads(row['tags_json']),
                'host_id': row['host_id'],
                'risk_score': row['risk_score'],
                'timestamp': row['created_at'],
                'epoch': row['epoch'],
            }
        except sqlite3.Error as e:
            logger.error(f"Get failed: {e}")
            return None
        finally:
            conn.close()

    def _decrypt_data(self, stored_json: str) -> Dict:
        """Decrypt data_json if encrypted, else parse directly.

        Encrypted findings are stored as a JSON envelope:
            {"__enc__": true, "ct": <b64 ciphertext>, "nonce": <b64 nonce>}
        Plaintext findings are stored as the original data dict JSON.
        """
        try:
            parsed = json.loads(stored_json)
        except (json.JSONDecodeError, TypeError):
            return {}
        # Encrypted envelope?
        if isinstance(parsed, dict) and parsed.get("__enc__") is True:
            ct_b64 = parsed.get("ct", "")
            nonce_b64 = parsed.get("nonce", "")
            plaintext = self._decrypt_field(ct_b64, nonce_b64)
            try:
                return json.loads(plaintext)
            except (json.JSONDecodeError, TypeError):
                return {}
        # Plaintext: parse as-is
        if isinstance(parsed, dict):
            return parsed
        return {}

    def _is_sensitive(self, category: str) -> bool:
        """Check if a category contains sensitive data requiring encryption."""
        return category.startswith("attack_") or category in (
            "cred", "creds", "secret", "secrets", "key", "keys", "password",
            "token", "credential", "aws", "azure", "gcp", "loot", "exfil",
        )

    def _is_sensitive_encrypted(self, data: str) -> bool:
        """Check if data appears to be encrypted (envelope marker)."""
        try:
            return json.loads(data).get("__enc__") is True
        except (json.JSONDecodeError, TypeError, AttributeError):
            return False

    def search(self, category: Optional[str] = None, tags: Optional[List[str]] = None,
               query: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        """Search findings (backward-compat). Uses indexed queries + FTS."""
        conn = self._get_conn()
        try:
            # Build parameterized query
            sql = """SELECT id, category, title, data_json, tags_json, host_id, risk_score,
                            created_at, epoch
                     FROM findings WHERE deleted = 0"""
            params = []

            if category:
                sql += " AND category = ?"
                params.append(category)

            if tags:
                # Filter by tags using JSON functions
                for tag in tags[:10]:  # cap
                    sql += " AND tags_json LIKE ?"
                    params.append(f'%"{tag}"%')

            if query:
                # Use FTS5 for full-text search
                fts_query = " ".join(f'"{t}"' for t in query.split()[:10])
                sql = sql.replace("FROM findings WHERE deleted = 0",
                                  """FROM findings JOIN findings_fts ON findings.rowid = findings_fts.rowid
                                     WHERE findings.deleted = 0 AND findings_fts MATCH ?""")
                params.insert(0, fts_query)

            sql += " ORDER BY epoch DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(sql, params).fetchall()
            results = []
            for row in rows:
                data = self._decrypt_data(row['data_json'])
                results.append({
                    'id': row['id'],
                    'category': row['category'],
                    'title': row['title'] or data.get('title'),
                    'data': data,
                    'tags': json.loads(row['tags_json']),
                    'host_id': row['host_id'],
                    'risk_score': row['risk_score'],
                    'timestamp': row['created_at'],
                    'epoch': row['epoch'],
                })
            return results
        except sqlite3.Error as e:
            logger.error(f"Search failed: {e}")
            return []
        finally:
            conn.close()

    def count(self) -> int:
        """Return total finding count."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE deleted = 0"
            ).fetchone()
            return row[0] if row else 0
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    def categories(self) -> List[str]:
        """Return all unique categories."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT DISTINCT category FROM findings WHERE deleted = 0"
            ).fetchall()
            return [r[0] for r in rows]
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def delete(self, item_id: str) -> bool:
        """Soft-delete a finding (audit retained)."""
        _span = self._begin_span("boneyard.delete", data={'item_id': item_id})
        conn = self._get_conn()
        try:
            # Get current state for audit
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ? AND deleted = 0", (item_id,)
            ).fetchone()
            if not row:
                self._finish_span(_span, status="ok", found=False)
                return False

            prev_state = dict(row) if row else None
            # Flip the deleted flag, then recompute the row_hmac so the
            # integrity check still passes (deleted IS part of the HMAC payload).
            new_row = dict(prev_state)
            new_row['deleted'] = 1
            new_row['row_hmac'] = self._compute_row_hmac('findings', new_row)
            conn.execute(
                "UPDATE findings SET deleted = 1, row_hmac = ? WHERE id = ?",
                (new_row['row_hmac'], item_id)
            )
            self._write_audit_entry(
                conn, 'DELETE', 'findings', item_id, 'boneyard.delete',
                'soft-delete finding', prev_state, None
            )
            conn.commit()
            self._finish_span(_span, status="ok", found=True, deleted=True)
            return True
        except sqlite3.Error as e:
            logger.error(f"Delete failed: {e}")
            conn.rollback()
            self._finish_span(_span, status="error", error=str(e))
            return False
        finally:
            conn.close()

    def export(self, filepath: str, category: Optional[str] = None) -> None:
        """Export findings to JSON."""
        items = self.search(category=category, limit=100000)
        with open(filepath, "w") as f:
            json.dump(items, f, indent=2, default=str)
        logger.info(f"Exported {len(items)} items to {filepath}")

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the boneyard."""
        conn = self._get_conn()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE deleted = 0"
            ).fetchone()[0]
            cats = conn.execute(
                "SELECT category, COUNT(*) FROM findings WHERE deleted = 0 GROUP BY category"
            ).fetchall()
            return {
                "total_items": total,
                "categories": {c[0]: c[1] for c in cats},
                "storage_dir": self.storage_dir,
                "encrypted": self._encrypted,
                "schema_version": self._get_schema_version(conn),
            }
        except sqlite3.Error as e:
            logger.error(f"Summary failed: {e}")
            return {"error": str(e), "storage_dir": self.storage_dir}
        finally:
            conn.close()

    def get_summary(self) -> Dict[str, Any]:
        """Alias for summary()."""
        return self.summary()

    def _get_schema_version(self, conn: sqlite3.Connection) -> str:
        try:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            return row[0] if row else "unknown"
        except sqlite3.Error:
            return "unknown"

    # ─── New Query API ──────────────────────────────────────────────────────────

    def query_hosts(self, filters: Optional[Dict[str, Any]] = None) -> QueryResult:
        """Query hosts with filters. Returns iterable QueryResult.

        Args:
            filters: Dict of column -> value to filter on. Supported:
                ip_address, hostname, domain, status, is_critical
                All values use exact match except hostname/domain which use LIKE
        Returns:
            QueryResult (iterable of dicts)
        """
        filters = filters or {}
        conn = self._get_conn()
        try:
            sql = "SELECT * FROM hosts WHERE deleted = 0"
            params = []
            allowed_filters = {'ip_address', 'hostname', 'domain', 'status', 'is_critical'}

            for key, val in filters.items():
                if key not in allowed_filters:
                    continue
                if key in ('hostname', 'domain'):
                    sql += f" AND {key} LIKE ?"
                    params.append(f"%{val}%")
                else:
                    sql += f" AND {key} = ?"
                    params.append(val)

            sql += " ORDER BY epoch DESC LIMIT 1000"
            rows = conn.execute(sql, params).fetchall()

            results = []
            for row in rows:
                r = dict(row)
                # Decrypt sensitive fields if needed
                results.append(r)

            return QueryResult(results, {
                'query': 'query_hosts', 'filters': filters,
                'result_count': len(results)
            })
        except sqlite3.Error as e:
            logger.error(f"query_hosts failed: {e}")
            return QueryResult([], {'error': str(e)})
        finally:
            conn.close()

    def query_findings(self, filters: Optional[Dict[str, Any]] = None) -> QueryResult:
        """Query findings with filters. Returns iterable QueryResult.

        Args:
            filters: Dict supporting:
                category: str
                host_id: str
                risk_min: float
                tags: List[str]
                since_epoch: float
                limit: int (default 1000, max 10000)
        """
        filters = filters or {}
        limit = min(int(filters.get('limit', 1000)), 10000)
        conn = self._get_conn()
        try:
            sql = """SELECT id, category, title, data_json, tags_json, host_id,
                            risk_score, created_at, epoch
                     FROM findings WHERE deleted = 0"""
            params = []

            if 'category' in filters:
                sql += " AND category = ?"
                params.append(filters['category'])
            if 'host_id' in filters:
                sql += " AND host_id = ?"
                params.append(filters['host_id'])
            if 'risk_min' in filters:
                sql += " AND risk_score >= ?"
                params.append(float(filters['risk_min']))
            if 'since_epoch' in filters:
                sql += " AND epoch >= ?"
                params.append(float(filters['since_epoch']))
            if 'tags' in filters:
                for tag in filters['tags'][:10]:
                    sql += " AND tags_json LIKE ?"
                    params.append(f'%"{tag}"%')

            sql += " ORDER BY epoch DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(sql, params).fetchall()
            results = []
            for row in rows:
                data = self._decrypt_data(row['data_json'])
                results.append({
                    'id': row['id'], 'category': row['category'],
                    'title': row['title'] or data.get('title'),
                    'data': data,
                    'tags': json.loads(row['tags_json']),
                    'host_id': row['host_id'],
                    'risk_score': row['risk_score'],
                    'timestamp': row['created_at'],
                    'epoch': row['epoch'],
                })
            return QueryResult(results, {
                'query': 'query_findings', 'filters': filters,
                'result_count': len(results)
            })
        except sqlite3.Error as e:
            logger.error(f"query_findings failed: {e}")
            return QueryResult([], {'error': str(e)})
        finally:
            conn.close()

    # ─── Attack Path Writers ────────────────────────────────────────────────
    # These persist engagement phases as attack-path steps + outcomes so the
    # Command Center Attack Graph, timeline, and live animation reflect REAL
    # engagement data (never synthesized). All rows are HMAC-chained + audited
    # exactly like the relational routing helpers above.

    def ensure_host(self, ip: str = "", hostname: str = "",
                    data: Optional[Dict] = None,
                    epoch: Optional[float] = None) -> str:
        """Find an existing host by ip/hostname or create one.

        Returns the host_id. Used by ``record_attack_step`` so every attack
        step has a valid ``host_id`` foreign key without forcing callers to
        pre-create hosts.

        ``epoch`` (optional) pins the host's timestamp — used by demo seeding
        to build a deterministic, spread-out timeline. HMAC is computed over
        the stored value, so integrity stays consistent.
        """
        data = data or {}
        conn = None
        try:
            conn = self._get_conn()
            epoch_val = epoch if epoch is not None else time.time()
            ts = datetime.fromtimestamp(epoch_val, tz=timezone.utc).isoformat()
            return self._ensure_host_record(
                conn, ip=ip, hostname=hostname, data=data, ts=ts, epoch=epoch_val,
            )
        except sqlite3.Error as e:
            logger.error(f"ensure_host failed: {e}")
            raise
        finally:
            if conn is not None:
                conn.commit()
                conn.close()

    def record_attack_step(self, host_id: str, step_type: str,
                           technique: str = "", description: str = "",
                           parent_step_id: Optional[str] = None,
                           outcome_status: str = "attempted",
                           detected_by: str = "", tool_used: str = "",
                           duration_sec: float = 0.0,
                           prerequisites: Optional[List[str]] = None,
                           epoch: Optional[float] = None) -> str:
        """Insert one attack-path step and return its id.

        Args:
            host_id: Target host (must exist — use ``ensure_host``).
            step_type: initial_access | privesc | lateral | persist | exfil | c2
                       (recon-style phases map to ``initial_access``).
            technique: MITRE ATT&CK technique id/description (honest — may be
                       empty if not mapped).
            outcome_status: planned | attempted | success | failed
            parent_step_id: Prior step id to chain (None = initial access).
            epoch: Optional pinned timestamp (demo seeding / deterministic
                   timelines). HMAC is computed over the stored value.

        Returns:
            The new attack-path step id (uuid).
        """
        step_id = str(uuid.uuid4())
        epoch_val = epoch if epoch is not None else time.time()
        ts = datetime.fromtimestamp(epoch_val, tz=timezone.utc).isoformat()
        conn = None
        try:
            conn = self._get_conn()
            row = {
                'id': step_id,
                'host_id': str(host_id),
                'parent_step_id': parent_step_id,
                'step_type': str(step_type),
                'technique': str(technique or ''),
                'description': str(description or '')[:4096],
                'prerequisites': json.dumps(prerequisites or []),
                'outcome_status': str(outcome_status or 'attempted'),
                'detected_by': str(detected_by or ''),
                'tool_used': str(tool_used or ''),
                'duration_sec': float(duration_sec or 0.0),
                'created_at': ts,
                'epoch': epoch_val,
                'deleted': 0,
            }
            row['row_hmac'] = self._compute_row_hmac('attack_paths', row)
            prev_chain = self._get_last_chain_hmac(conn)
            row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

            conn.execute(
                """INSERT INTO attack_paths
                   (id, host_id, parent_step_id, step_type, technique, description,
                    prerequisites, outcome_status, detected_by, tool_used,
                    duration_sec, created_at, epoch, row_hmac, chain_hmac, deleted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row['id'], row['host_id'], row['parent_step_id'], row['step_type'],
                 row['technique'], row['description'], row['prerequisites'],
                 row['outcome_status'], row['detected_by'], row['tool_used'],
                 row['duration_sec'], row['created_at'], row['epoch'],
                 row['row_hmac'], row['chain_hmac'], row['deleted'])
            )
            self._write_audit_entry(
                conn, 'INSERT', 'attack_paths', step_id, 'boneyard.record_attack_step',
                f'step({step_type}) on host {host_id}', None,
                {'id': step_id, 'step_type': row['step_type']}
            )
            conn.commit()
            logger.info(f"Recorded attack step {step_id} type='{step_type}' host={host_id}")
            return step_id
        except sqlite3.Error as e:
            logger.error(f"record_attack_step failed: {e}")
            if conn is not None:
                conn.rollback()
            raise
        finally:
            if conn is not None:
                conn.close()

    def record_outcome(self, attack_path_id: str, outcome_type: str,
                       success: bool = False,
                       evidence: Optional[Dict] = None,
                       output_raw: str = "", mitigation: str = "",
                       epoch: Optional[float] = None) -> str:
        """Attach an outcome to an attack-path step and return its id.

        Args:
            attack_path_id: The step this outcome belongs to.
            outcome_type: access | credential | data | privilege | persistence
                          | detection
            success: Whether the outcome succeeded.
            evidence: Arbitrary JSON evidence (screenshots, logs, paths).
            output_raw: Truncated raw output (capped).
            epoch: Optional pinned timestamp (demo seeding / deterministic
                   timelines). HMAC is computed over the stored value.

        Returns:
            The new outcome id (uuid).
        """
        out_id = str(uuid.uuid4())
        epoch_val = epoch if epoch is not None else time.time()
        ts = datetime.fromtimestamp(epoch_val, tz=timezone.utc).isoformat()
        conn = None
        try:
            conn = self._get_conn()
            row = {
                'id': out_id,
                'attack_path_id': str(attack_path_id),
                'outcome_type': str(outcome_type),
                'success': int(1 if success else 0),
                'evidence': json.dumps(evidence or {}, default=str),
                'output_raw': str(output_raw or '')[:4096],
                'artifacts_path': '',
                'detected_by_defender': 0,
                'detection_method': '',
                'mitigation': str(mitigation or '')[:2048],
                'created_at': ts,
                'epoch': epoch_val,
                'deleted': 0,
            }
            row['row_hmac'] = self._compute_row_hmac('outcomes', row)
            prev_chain = self._get_last_chain_hmac(conn)
            row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

            conn.execute(
                """INSERT INTO outcomes
                   (id, attack_path_id, outcome_type, success, evidence, output_raw,
                    artifacts_path, detected_by_defender, detection_method,
                    mitigation, created_at, epoch, row_hmac, chain_hmac, deleted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row['id'], row['attack_path_id'], row['outcome_type'], row['success'],
                 row['evidence'], row['output_raw'], row['artifacts_path'],
                 row['detected_by_defender'], row['detection_method'],
                 row['mitigation'], row['created_at'], row['epoch'],
                 row['row_hmac'], row['chain_hmac'], row['deleted'])
            )
            self._write_audit_entry(
                conn, 'INSERT', 'outcomes', out_id, 'boneyard.record_outcome',
                f'outcome({outcome_type}) on step {attack_path_id}', None,
                {'id': out_id, 'outcome_type': row['outcome_type']}
            )
            conn.commit()
            logger.info(f"Recorded outcome {out_id} type='{outcome_type}' step={attack_path_id}")
            return out_id
        except sqlite3.Error as e:
            logger.error(f"record_outcome failed: {e}")
            if conn is not None:
                conn.rollback()
            raise
        finally:
            if conn is not None:
                conn.close()

    def graph_attack_paths(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        """Build and return an attack-path graph.

        Returns nodes (attack steps) and edges (parent->child) as a dict
        suitable for graph visualization or traversal.
        """
        conn = self._get_conn()
        try:
            sql = "SELECT * FROM attack_paths WHERE deleted = 0"
            params = []
            if host_id:
                sql += " AND host_id = ?"
                params.append(host_id)
            sql += " ORDER BY epoch ASC LIMIT 5000"

            nodes = conn.execute(sql, params).fetchall()
            # Get outcomes for each node
            graph = {'nodes': [], 'edges': [], 'outcomes': []}
            node_ids = set()
            for node in nodes:
                node_ids.add(node['id'])
                graph['nodes'].append({
                    'id': node['id'],
                    'host_id': node['host_id'],
                    'parent_step_id': node['parent_step_id'],
                    'step_type': node['step_type'],
                    'technique': node['technique'],
                    'outcome_status': node['outcome_status'],
                    'created_at': node['created_at'],
                })
                if node['parent_step_id']:
                    graph['edges'].append({
                        'from': node['parent_step_id'],
                        'to': node['id'],
                    })
                # Get outcomes
                outcomes = conn.execute(
                    "SELECT * FROM outcomes WHERE attack_path_id = ? AND deleted = 0",
                    (node['id'],)
                ).fetchall()
                for oc in outcomes:
                    graph['outcomes'].append({
                        'attack_path_id': node['id'],
                        'type': oc['outcome_type'],
                        'success': bool(oc['success']),
                    })

            return graph
        except sqlite3.Error as e:
            logger.error(f"graph_attack_paths failed: {e}")
            return {'nodes': [], 'edges': [], 'outcomes': [], 'error': str(e)}
        finally:
            conn.close()

    # ─── Integrity Verification ──────────────────────────────────────────────

    def verify_integrity(self, progress=None) -> IntegrityReport:
        """Verify the integrity of all tables via HMAC chain verification.

        Checks:
        1. Every row's row_hmac matches the recomputed HMAC of its content
        2. Every audit_log chain_hmac links correctly to the previous entry
        3. No gaps in the audit log sequence

        Args:
            progress: optional ``cb(done, total, label)`` invoked once per
                verified row (W4-2.3c). Backward-compatible — defaults to
                None, and any exception it raises is swallowed.

        Returns IntegrityReport with details of any tampering detected.
        """
        report = IntegrityReport(verified=True, total_rows_checked=0)
        conn = self._get_conn()

        audit_done = 0
        grand_total = 0
        audit_count = 0
        if progress is not None:
            # Pre-count rows so the progress bar can show an accurate total.
            try:
                c = conn.execute(
                    "SELECT COUNT(*) AS c FROM audit_log"
                ).fetchone()
                audit_count = int(c["c"]) if c is not None else 0
            except Exception:
                audit_count = 0

        def _tick(label: str) -> None:
            if progress is None:
                return
            try:
                progress(report.total_rows_checked + audit_done,
                         grand_total, label)
            except Exception:  # noqa: BLE001
                pass
        try:
            tables = ['hosts', 'services', 'vulns', 'creds', 'attack_paths',
                      'outcomes', 'findings', 'difficulty']

            # Compute the grand total up front (row counts) for the progress bar.
            if progress is not None:
                for table in tables:
                    try:
                        c = conn.execute(
                            f"SELECT COUNT(*) AS c FROM {table}"
                        ).fetchone()
                        grand_total += int(c["c"]) if c is not None else 0
                    except Exception:
                        pass
                grand_total += audit_count

            for table in tables:
                try:
                    rows = conn.execute(
                        f"SELECT * FROM {table} ORDER BY epoch ASC"
                    ).fetchall()
                    report.table_counts[table] = len(rows)
                    for row in rows:
                        report.total_rows_checked += 1
                        row_dict = dict(row)
                        stored_hmac = row_dict.get('row_hmac', '')
                        computed_hmac = self._compute_row_hmac(table, row_dict)
                        if not hmac.compare_digest(stored_hmac, computed_hmac):
                            report.verified = False
                            report.broken_hmacs.append({
                                'table': table, 'row_id': row_dict.get('id', '?'),
                                'issue': 'row_hmac mismatch - content tampered'
                            })
                        _tick(f"Verifying {table} rows")
                except sqlite3.Error as e:
                    logger.warning(f"Could not verify {table}: {e}")

            # Verify audit log chain
            audit_rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY seq ASC"
            ).fetchall()
            report.audit_chain_length = len(audit_rows)
            prev_chain = None
            expected_seq = 1
            for row in audit_rows:
                row_dict = dict(row)
                # Check sequence continuity
                if row_dict.get('seq') != expected_seq:
                    report.verified = False
                    report.broken_chain_links.append({
                        'seq': row_dict.get('seq'),
                        'issue': f'audit log sequence gap (expected {expected_seq})'
                    })
                expected_seq += 1

                # Recompute row HMAC
                stored_hmac = row_dict.get('row_hmac', '')
                computed_hmac = self._compute_row_hmac('audit_log', row_dict)
                if not hmac.compare_digest(stored_hmac, computed_hmac):
                    report.verified = False
                    report.broken_hmacs.append({
                        'table': 'audit_log', 'row_id': row_dict.get('id', '?'),
                        'issue': 'audit entry HMAC mismatch - entry tampered'
                    })

                # Verify chain link
                stored_chain = row_dict.get('chain_hmac', '')
                computed_chain = self._compute_chain_hmac(stored_hmac, prev_chain)
                if not hmac.compare_digest(stored_chain, computed_chain):
                    report.verified = False
                    report.broken_chain_links.append({
                        'seq': row_dict.get('seq'),
                        'issue': 'chain link broken - entry inserted/removed out of order'
                    })

                # Check for orphaned entries (references to non-existent prev)
                if row_dict.get('prev_chain_hmac') != prev_chain:
                    report.verified = False
                    report.orphaned_audit_entries.append({
                        'seq': row_dict.get('seq'),
                        'issue': 'prev_chain_hmac does not match previous entry'
                    })

                prev_chain = stored_chain
                audit_done += 1
                _tick("Verifying audit chain")

            return report
        except sqlite3.Error as e:
            logger.error(f"Integrity verification failed: {e}")
            report.verified = False
            report.broken_hmacs.append({'table': 'system', 'row_id': 'system',
                                        'issue': f'verification error: {e}'})
            return report
        finally:
            conn.close()

    # ─── Migration from legacy JSON ───────────────────────────────────────────

    def migrate_json_to_sqlite(self, legacy_dir: Optional[str] = None,
                                dry_run: bool = False) -> Dict[str, Any]:
        """Migrate legacy JSON boneyard data to SQLite.

        Args:
            legacy_dir: Directory with index.json + per-item files. If None, uses self.storage_dir.
            dry_run: If True, count records but don't insert.

        Returns:
            Dict with migration statistics
        """
        legacy_dir = legacy_dir or self.storage_dir
        index_file = os.path.join(legacy_dir, "index.json")
        stats = {
            'total_legacy': 0, 'migrated': 0, 'failed': 0,
            'errors': [], 'dry_run': dry_run
        }

        if not os.path.exists(index_file):
            logger.info(f"No legacy index.json at {index_file}, nothing to migrate")
            return stats

        try:
            with open(index_file, "r") as f:
                legacy_index = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            stats['errors'].append(f"Failed to read index: {e}")
            return stats

        stats['total_legacy'] = len(legacy_index)
        logger.info(f"Migrating {len(legacy_index)} legacy records (dry_run={dry_run})")

        if dry_run:
            return stats

        for item_id, item in legacy_index.items():
            try:
                category = item.get('category', 'legacy')
                data = item.get('data', {})
                tags = item.get('tags', [])
                # Use the normal store path which routes to relational tables
                self.store(category, data, tags)
                stats['migrated'] += 1
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append(f"{item_id}: {e}")
                logger.error(f"Migration failed for {item_id}: {e}")

        # Verify count matches
        actual = self.count()
        stats['sqlite_count'] = actual
        stats['count_match'] = (actual == stats['migrated'])
        logger.info(f"Migration complete: {stats['migrated']}/{stats['total_legacy']} migrated")
        return stats

    # ─── Utility ──────────────────────────────────────────────────────────────

    def _audit_log_count(self) -> int:
        """Return audit log entry count."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
            return row[0] if row else 0
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    # ─── Difficulty Assessment Store (P1.2.4) ────────────────────────────────

    def store_difficulty(self, report: DifficultyReport) -> str:
        """Store a difficulty assessment in the difficulty table.

        Args:
            report: A DifficultyReport (from orchestrator.difficulty). Duck-typed:
                    must expose action.name, action.phase, action.technique,
                    action.target, axes (dict of 4 scores), weights, score,
                    mode, rationale, timestamp.

        Returns:
            The UUID of the stored assessment row.
        """
        _span = self._begin_span("boneyard.store_difficulty",
                                 data={'action': getattr(report.action, 'name', '?')})
        item_id = str(uuid.uuid4())
        ts = getattr(report, 'timestamp', None) or datetime.now(timezone.utc).isoformat()
        epoch = time.time()
        conn = None
        try:
            conn = self._get_conn()
            row = {
                'id': item_id,
                'action_name': getattr(report.action, 'name', 'unknown'),
                'phase': getattr(report.action, 'phase', None),
                'technique': getattr(report.action, 'technique', None),
                'target': getattr(report.action, 'target', None),
                'horizon_score': float(report.axes.get('horizon', 0.0)),
                'confidence_score': float(report.axes.get('confidence', 0.0)),
                'context_load_score': float(report.axes.get('context_load', 0.0)),
                'history_score': float(report.axes.get('history', 0.0)),
                'composite_score': float(report.score),
                'mode': str(report.mode),
                'rationale': str(report.rationale),
                'axes_json': json.dumps(report.axes, default=str),
                'weights_json': json.dumps(report.weights, default=str),
                'outcome': 'pending',
                'created_at': ts,
                'epoch': epoch,
                'deleted': 0,
            }
            row['row_hmac'] = self._compute_row_hmac('difficulty', row)
            prev_chain = self._get_last_chain_hmac(conn)
            row['chain_hmac'] = self._compute_chain_hmac(row['row_hmac'], prev_chain)

            conn.execute(
                """INSERT INTO difficulty
                   (id, action_name, phase, technique, target,
                    horizon_score, confidence_score, context_load_score, history_score,
                    composite_score, mode, rationale, axes_json, weights_json,
                    outcome, created_at, epoch, row_hmac, chain_hmac, deleted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (row['id'], row['action_name'], row['phase'], row['technique'], row['target'],
                 row['horizon_score'], row['confidence_score'], row['context_load_score'],
                 row['history_score'], row['composite_score'], row['mode'], row['rationale'],
                 row['axes_json'], row['weights_json'], row['outcome'],
                 row['created_at'], row['epoch'], row['row_hmac'],
                 row['chain_hmac'], row['deleted'])
            )
            self._write_audit_entry(
                conn, 'INSERT', 'difficulty', item_id, 'boneyard.store_difficulty',
                f'assess({row["action_name"]})', None,
                {'id': item_id, 'action': row['action_name'], 'mode': row['mode']}
            )
            conn.commit()
            logger.info(f"Stored difficulty assessment {item_id} action='{row['action_name']}' mode={row['mode']}")
            self._finish_span(_span, status="ok", item_id=item_id)
            return item_id
        except sqlite3.Error as e:
            logger.error(f"store_difficulty failed: {e}")
            if conn is not None:
                conn.rollback()
            self._finish_span(_span, status="error", error=str(e))
            raise
        finally:
            if conn is not None:
                conn.close()

    def query_difficulty(self, action_name: Optional[str] = None,
                         mode: Optional[str] = None,
                         outcome: Optional[str] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """Query past difficulty assessments for calibration/feedback.

        Args:
            action_name: Filter by action name (exact match). None = all.
            mode: Filter by assessed mode (explore/exploit/abort). None = all.
            outcome: Filter by outcome (success/failure/skipped/pending). None = all.
            limit: Max rows to return (most recent first).

        Returns:
            List of dicts with keys: id, action_name, phase, technique, target,
            horizon_score, confidence_score, context_load_score, history_score,
            composite_score, mode, rationale, outcome, epoch, created_at.
        """
        conn = None
        try:
            conn = self._get_conn()
            sql = "SELECT * FROM difficulty WHERE deleted = 0"
            params: List[Any] = []
            if action_name is not None:
                sql += " AND action_name = ?"
                params.append(action_name)
            if mode is not None:
                sql += " AND mode = ?"
                params.append(mode)
            if outcome is not None:
                sql += " AND outcome = ?"
                params.append(outcome)
            sql += " ORDER BY epoch DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                result.append({
                    'id': d['id'],
                    'action_name': d['action_name'],
                    'phase': d['phase'],
                    'technique': d['technique'],
                    'target': d['target'],
                    'horizon_score': d['horizon_score'],
                    'confidence_score': d['confidence_score'],
                    'context_load_score': d['context_load_score'],
                    'history_score': d['history_score'],
                    'composite_score': d['composite_score'],
                    'mode': d['mode'],
                    'rationale': d['rationale'],
                    'outcome': d['outcome'],
                    'epoch': d['epoch'],
                    'created_at': d['created_at'],
                })
            return result
        except sqlite3.Error as e:
            logger.error(f"query_difficulty failed: {e}")
            return []
        finally:
            if conn is not None:
                conn.close()

    def update_difficulty_outcome(self, assessment_id: str, outcome: str) -> bool:
        """Update the outcome of a stored difficulty assessment.

        Used by the feedback loop: after the action executes, record whether it
        succeeded/failed/was skipped. This populates the calibration signal for
        future _score_history() lookups.

        Args:
            assessment_id: UUID of the difficulty row.
            outcome: 'success' | 'failure' | 'skipped' (any string accepted).

        Returns:
            True if updated, False if row not found.
        """
        conn = None
        try:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT * FROM difficulty WHERE id = ? AND deleted = 0",
                (assessment_id,)
            ).fetchone()
            if row is None:
                logger.warning(f"update_difficulty_outcome: id {assessment_id} not found")
                return False
            prev = dict(row)
            # Recompute HMAC over the updated row content (outcome changes)
            new_row = dict(prev)
            new_row['outcome'] = outcome
            new_row['row_hmac'] = self._compute_row_hmac('difficulty', new_row)
            conn.execute(
                "UPDATE difficulty SET outcome = ?, row_hmac = ? WHERE id = ?",
                (outcome, new_row['row_hmac'], assessment_id)
            )
            self._write_audit_entry(
                conn, 'UPDATE', 'difficulty', assessment_id,
                'boneyard.update_difficulty_outcome',
                f'outcome={outcome}', {'outcome': prev['outcome']}, {'outcome': outcome}
            )
            conn.commit()
            logger.info(f"Updated difficulty {assessment_id} outcome={outcome}")
            return True
        except sqlite3.Error as e:
            logger.error(f"update_difficulty_outcome failed: {e}")
            if conn is not None:
                conn.rollback()
            return False
        finally:
            if conn is not None:
                conn.close()

    def close(self) -> None:
        """Close any persistent connections (no-op for per-op connections)."""
        pass


# ─── Helpers ───────────────────────────────────────────────────────────────────
def _b64(data: bytes) -> str:
    """Base64 encode bytes to string."""
    import base64
    return base64.b64encode(data).decode('ascii')

def _unb64(data: str) -> bytes:
    """Base64 decode string to bytes."""
    import base64
    return base64.b64decode(data)
