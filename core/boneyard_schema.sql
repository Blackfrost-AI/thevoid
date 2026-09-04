-- ═══════════════════════════════════════════════════════════════════════════════
-- THE VOID — Boneyard Relational Schema (SQLite)
-- Phase 1.1.1 — VOID-CEP-2026-07
--
-- This schema replaces the flat JSON index + per-item file store.
-- It provides relational integrity, structured queries, graph traversal
-- for attack paths, and HMAC chain-of-custody for tamper-evidence.
--
-- Design principles:
--   1. Every table has a surrogate UUID primary key (id TEXT, UUID v4)
--   2. Every table has created_at (UTC ISO8601) and epoch (Unix float) for ordering
--   3. Foreign keys link findings to hosts/services/vulns/creds for graph queries
--   4. An audit_log table records every write operation with HMAC-SHA256 chain
--   5. The chain links each audit entry to the previous entry's hash (WORM)
--   6. Sensitive fields (credentials, tokens) are stored encrypted via app layer
--   7. All timestamps are UTC; all text is UTF-8
--
-- SQLite pragmas applied at runtime by Boneyard class:
--   PRAGMA foreign_keys = ON;
--   PRAGMA journal_mode = WAL;
--   PRAGMA secure_delete = ON;
--   PRAGMA synchronous = FULL;
--   (SQLCipher PRAGMA key applied before any other pragma if encryption enabled)
-- ═══════════════════════════════════════════════════════════════════════════════

-- ─── Entity Tables ───────────────────────────────────────────────────────────

-- Hosts: discovered network targets (IPs, domains)
CREATE TABLE IF NOT EXISTS hosts (
    id              TEXT PRIMARY KEY,       -- UUID v4
    ip_address      TEXT,                   -- IPv4/IPv6 address
    hostname        TEXT,                   -- resolved hostname
    domain          TEXT,                   -- domain name
    os_family       TEXT,                   -- detected OS family
    os_version      TEXT,                   -- detected OS version
    status          TEXT DEFAULT 'unknown', -- unknown | up | down | compromised
    is_critical     INTEGER DEFAULT 0,      -- boolean flag
    notes           TEXT,                   -- free-text notes
    first_seen      TEXT,                    -- ISO8601 UTC
    last_seen       TEXT,                    -- ISO8601 UTC
    created_at      TEXT NOT NULL,          -- ISO8601 UTC
    epoch           REAL NOT NULL,          -- Unix timestamp for ordering
    -- Integrity: HMAC of all above fields (computed by app layer)
    row_hmac        TEXT NOT NULL,
    -- Chain: HMAC of this row's HMAC + previous row's HMAC (WORM chain)
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0      -- soft-delete flag (audit retained)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_hosts_domain ON hosts(domain);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_created ON hosts(epoch);

-- Services: network services on hosts
CREATE TABLE IF NOT EXISTS services (
    id              TEXT PRIMARY KEY,       -- UUID v4
    host_id         TEXT NOT NULL,          -- FK -> hosts.id
    port            INTEGER,                -- 1-65535
    protocol        TEXT,                   -- tcp | udp
    service_name    TEXT,                   -- http, ssh, smb, etc.
    service_version TEXT,                    -- detected version
    banner          TEXT,                    -- raw banner
    auth_type       TEXT,                    -- none | password | key | cert | kerberos
    is_external     INTEGER DEFAULT 0,      -- exposed to internet?
    risk_score      REAL DEFAULT 0.0,       -- 0.0-1.0 assessed risk
    notes           TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    created_at      TEXT NOT NULL,
    epoch           REAL NOT NULL,
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_port_proto ON services(port, protocol);
CREATE INDEX IF NOT EXISTS idx_services_name ON services(service_name);

-- Vulnerabilities: CVEs and findings on hosts/services
CREATE TABLE IF NOT EXISTS vulns (
    id              TEXT PRIMARY KEY,
    host_id         TEXT,                    -- FK -> hosts.id (nullable: some vulns are service-level)
    service_id      TEXT,                    -- FK -> services.id (nullable)
    cve_id          TEXT,                    -- CVE-YYYY-NNNNN
    title           TEXT NOT NULL,
    description     TEXT,
    cvss_score      REAL DEFAULT 0.0,       -- 0.0-10.0
    cvss_vector     TEXT,
    exploitability  TEXT,                     -- theoretical | poc | weaponized | active
    solution        TEXT,                     -- remediation guidance
    references_json TEXT,                     -- JSON array of reference URLs
    is_verified     INTEGER DEFAULT 0,       -- confirmed by exploit?
    verified_method TEXT,                     -- how verified
    created_at      TEXT NOT NULL,
    epoch           REAL NOT NULL,
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulns(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_service ON vulns(service_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulns(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_exploitability ON vulns(exploitability);

-- Credentials: captured/guessed credentials
CREATE TABLE IF NOT EXISTS creds (
    id              TEXT PRIMARY KEY,
    host_id         TEXT,                    -- FK -> hosts.id (where cred was obtained)
    service_id      TEXT,                    -- FK -> services.id (which service it targets)
    username        TEXT NOT NULL,
    -- Passwords/tokens are stored AES-256 encrypted by the app layer.
    -- The enc_* fields hold ciphertext + nonce + key_id.
    enc_password    TEXT,                     -- AES-256-GCM ciphertext (base64)
    enc_nonce       TEXT,                     -- GCM nonce (base64)
    enc_key_id      TEXT,                     -- which key version was used
    cred_type       TEXT,                     -- password | hash | key | token | cookie | cert
    hash_type       TEXT,                     -- if cred_type=hash: ntlm | kerberos | sha | md5
    source          TEXT,                     -- brute | spray | dump | leak | mimikatz | other
    is_valid        INTEGER DEFAULT 0,       -- verified working?
    validity_checked TEXT,                    -- when last checked
    created_at      TEXT NOT NULL,
    epoch           REAL NOT NULL,
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_creds_host ON creds(host_id);
CREATE INDEX IF NOT EXISTS idx_creds_service ON creds(service_id);
CREATE INDEX IF NOT EXISTS idx_creds_username ON creds(username);
CREATE INDEX IF NOT EXISTS idx_creds_type ON creds(cred_type);

-- Attack paths: graph edges between compromise steps
-- Each row is a node in an attack graph. The attack_path_edges table
-- links nodes into paths (lateral movement, privilege escalation chains).
CREATE TABLE IF NOT EXISTS attack_paths (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL,            -- FK -> hosts.id (target of this step)
    parent_step_id  TEXT,                     -- FK self -> attack_paths.id (previous step, NULL = initial access)
    step_type       TEXT NOT NULL,            -- initial_access | privesc | lateral | persist | exfil | c2
    technique       TEXT,                     -- MITRE ATT&CK technique ID or description
    description     TEXT,
    prerequisites   TEXT,                     -- JSON array of required prior conditions
    outcome_status  TEXT DEFAULT 'planned',   -- planned | attempted | success | failed
    detected_by     TEXT,                     -- what detected this (recon, exploit, post-exploit)
    tool_used       TEXT,                     -- tool that performed this step
    duration_sec    REAL DEFAULT 0.0,
    created_at      TEXT NOT NULL,
    epoch           REAL NOT NULL,
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_step_id) REFERENCES attack_paths(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_host ON attack_paths(host_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_parent ON attack_paths(parent_step_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_type ON attack_paths(step_type);
CREATE INDEX IF NOT EXISTS idx_attack_paths_status ON attack_paths(outcome_status);

-- Outcomes: results of attack path steps (success/fail with evidence)
CREATE TABLE IF NOT EXISTS outcomes (
    id              TEXT PRIMARY KEY,
    attack_path_id  TEXT NOT NULL,            -- FK -> attack_paths.id
    outcome_type    TEXT NOT NULL,            -- access | credential | data | privilege | persistence | detection
    success         INTEGER DEFAULT 0,       -- boolean
    evidence        TEXT,                     -- JSON: screenshots, logs, file paths
    output_raw      TEXT,                     -- truncated command output / tool response
    artifacts_path  TEXT,                     -- path to stored artifacts (loot dir)
    detected_by_defender INTEGER DEFAULT 0,  -- was this detected by blue team?
    detection_method TEXT,                    -- how detected (if at all)
    mitigation      TEXT,                     -- what defender did to block
    created_at      TEXT NOT NULL,
    epoch           REAL NOT NULL,
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0,
    FOREIGN KEY (attack_path_id) REFERENCES attack_paths(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_outcomes_attack_path ON outcomes(attack_path_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_type ON outcomes(outcome_type);

-- Findings: general intelligence/recon data that doesn't fit other tables
-- This is the backward-compatibility layer for the old boneyard.store(category, data)
-- pattern. Category-tagged JSON blobs with full-text search.
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    category        TEXT NOT NULL,            -- recon | exploit | exfil | cred | loot | intel | other
    title           TEXT,
    data_json       TEXT NOT NULL,            -- JSON blob (structured finding data)
    tags_json       TEXT DEFAULT '[]',        -- JSON array of tags
    host_id         TEXT,                     -- FK -> hosts.id (optional link)
    service_id      TEXT,                     -- FK -> services.id (optional link)
    risk_score      REAL DEFAULT 0.0,
    is_archived     INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    epoch           REAL NOT NULL,
    -- FTS5 virtual table is linked via external content; this is the source
    fts_content     TEXT,                     -- denormalized text for FTS indexing
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(epoch);
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk_score);

-- ─── Difficulty Assessments (P1.2) ─────────────────────────────────────────
-- Records each difficulty assessment made by DifficultyAssessor. Used both for
-- the chaos.py engagement gate (P1.2.3) and as a feedback/calibration source
-- for future assessments (P1.2.4). Full HMAC chain integrity like all tables.
CREATE TABLE IF NOT EXISTS difficulty (
    id              TEXT PRIMARY KEY,       -- UUID v4
    action_name     TEXT NOT NULL,          -- canonical action name (e.g. 'recon_phase', 'exploit_phase')
    phase           TEXT,                   -- engagement phase identifier
    technique       TEXT,                   -- technique/attack ID being assessed
    target          TEXT,                   -- target identifier (host/IP/scope)
    -- 4-axis raw scores (0.0-1.0, higher = harder)
    horizon_score   REAL NOT NULL,
    confidence_score REAL NOT NULL,
    context_load_score REAL NOT NULL,
    history_score   REAL NOT NULL,
    -- Composite
    composite_score REAL NOT NULL,          -- weighted sum of axes
    mode            TEXT NOT NULL,          -- explore | exploit | abort
    rationale       TEXT,                   -- human-readable explanation
    axes_json       TEXT,                   -- JSON: full axes breakdown for audit
    weights_json    TEXT,                   -- JSON: weights used for this assessment
    outcome         TEXT DEFAULT 'pending', -- pending | success | failure | skipped (updated later)
    created_at      TEXT NOT NULL,          -- ISO8601 UTC
    epoch           REAL NOT NULL,          -- Unix timestamp for ordering
    row_hmac        TEXT NOT NULL,
    chain_hmac      TEXT NOT NULL,
    deleted         INTEGER DEFAULT 0       -- soft-delete flag
);

CREATE INDEX IF NOT EXISTS idx_difficulty_action ON difficulty(action_name);
CREATE INDEX IF NOT EXISTS idx_difficulty_mode ON difficulty(mode);
CREATE INDEX IF NOT EXISTS idx_difficulty_outcome ON difficulty(outcome);
CREATE INDEX IF NOT EXISTS idx_difficulty_phase ON difficulty(phase);
CREATE INDEX IF NOT EXISTS idx_difficulty_created ON difficulty(epoch);

-- ─── Full-Text Search (FTS5) for findings ──────────────────────────────────
-- Allows efficient text search across finding data without scanning all rows.
-- The external content pattern links FTS to the findings table so that when
-- a finding is deleted (soft or hard), the FTS entry is also removed.
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    content,
    content='findings',
    content_rowid='rowid',
    tokenize='unicode61'
);

-- Triggers to keep FTS in sync with findings table
CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid, content) VALUES (new.rowid, new.fts_content);
END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, content) VALUES('delete', old.rowid, old.fts_content);
END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, content) VALUES('delete', old.rowid, old.fts_content);
    INSERT INTO findings_fts(rowid, content) VALUES (new.rowid, new.fts_content);
END;

-- ═══════════════════════════════════════════════════════════════════════════════
-- AUDIT LOG — Append-Only WORM with Hash Chain
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- Every write operation (insert/update/delete) on any table above is recorded
-- here. Each audit entry contains:
--   - The operation type and target table/row
--   - A hash of the row content BEFORE the operation (for rollback/reconstruction)
--   - An HMAC-SHA256 of the audit entry itself (row_hmac)
--   - A chain HMAC that links to the PREVIOUS audit entry's chain_hmac
--
-- The chain is: chain_hmac[n] = HMAC(key, row_hmac[n] || chain_hmac[n-1] || seq[n])
-- Tampering with any row, deleting a row, or inserting out-of-order breaks the
-- chain and is detected by verify_integrity().
--
-- This table has NO UPDATE or DELETE triggers. It is append-only by design.
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS audit_log (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic sequence
    id              TEXT NOT NULL UNIQUE,                -- UUID v4
    timestamp       TEXT NOT NULL,                       -- ISO8601 UTC
    epoch           REAL NOT NULL,                       -- Unix timestamp
    operation       TEXT NOT NULL,                       -- INSERT | UPDATE | DELETE | CREATE | DROP
    table_name      TEXT NOT NULL,                       -- affected table
    row_id          TEXT,                                -- affected row PK
    actor           TEXT,                                -- who performed the action (module/agent)
    reason          TEXT,                                -- why the action was taken
    -- Snapshot of row state BEFORE operation (JSON). For INSERT this is null.
    -- For UPDATE/DELETE this is the prior row content, allowing reconstruction.
    prev_state_json TEXT,
    -- Snapshot of row state AFTER operation (JSON). For DELETE this is null.
    new_state_json  TEXT,
    -- HMAC-SHA256 of this audit entry's canonical representation
    -- (seq || id || timestamp || epoch || operation || table_name || row_id || prev_state_json || new_state_json)
    row_hmac        TEXT NOT NULL,
    -- Chain link: HMAC of (this row_hmac || previous audit entry's chain_hmac)
    -- First entry: chain_hmac = HMAC(key, row_hmac || "GENESIS")
    chain_hmac      TEXT NOT NULL,
    -- Previous entry's chain_hmac (for verification traversal)
    prev_chain_hmac TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_table ON audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_row ON audit_log(row_id);
CREATE INDEX IF NOT EXISTS idx_audit_epoch ON audit_log(epoch);
CREATE INDEX IF NOT EXISTS idx_audit_op ON audit_log(operation);

-- ─── Integrity Verification Views ──────────────────────────────────────────
-- These views expose the current integrity status of each table for monitoring.

CREATE VIEW IF NOT EXISTS integrity_status AS
SELECT 'hosts' AS table_name, COUNT(*) AS rows_total,
       SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) AS rows_deleted
FROM hosts
UNION ALL
SELECT 'services', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM services
UNION ALL
SELECT 'vulns', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM vulns
UNION ALL
SELECT 'creds', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM creds
UNION ALL
SELECT 'attack_paths', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM attack_paths
UNION ALL
SELECT 'outcomes', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM outcomes
UNION ALL
SELECT 'findings', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM findings
UNION ALL
SELECT 'difficulty', COUNT(*), SUM(CASE WHEN deleted=1 THEN 1 ELSE 0 END) FROM difficulty
UNION ALL
SELECT 'audit_log', COUNT(*), 0 FROM audit_log;

-- ─── Schema Metadata ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- Schema version tracking for migrations
INSERT OR IGNORE INTO schema_meta (key, value, updated_at) VALUES
    ('schema_version', '1.0.0', datetime('now')),
    ('schema_created', datetime('now'), datetime('now')),
    ('integrity_algorithm', 'HMAC-SHA256', datetime('now')),
    ('encryption_algorithm', 'AES-256-GCM', datetime('now'));
