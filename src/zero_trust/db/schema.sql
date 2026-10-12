-- Zero-Trust Access Control Platform SQLite Schema
-- Configured for SQLite WAL (Write-Ahead Logging) Mode

PRAGMA foreign_keys = ON;

-- 1. Policies Table
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    effect TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    min_trust_score REAL NOT NULL DEFAULT 50.0,
    allowed_roles TEXT NOT NULL DEFAULT '[]', -- JSON array
    allowed_departments TEXT NOT NULL DEFAULT '[]', -- JSON array
    max_sensitivity TEXT NOT NULL DEFAULT 'CRITICAL',
    require_encryption INTEGER NOT NULL DEFAULT 1,
    require_edr INTEGER NOT NULL DEFAULT 1,
    conditions TEXT NOT NULL DEFAULT '{}', -- JSON object
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 2. Access Evaluations Table (Audit Trail of every PDP evaluation)
CREATE TABLE IF NOT EXISTS access_evaluations (
    evaluation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    total_trust_score REAL NOT NULL,
    matched_policy_id TEXT,
    reasons TEXT NOT NULL DEFAULT '[]', -- JSON array
    evaluated_at TEXT NOT NULL,
    FOREIGN KEY (matched_policy_id) REFERENCES policies(policy_id) ON DELETE SET NULL
);

-- 3. Active Sessions Table
CREATE TABLE IF NOT EXISTS active_sessions (
    session_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_fingerprint_hash TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    session_token TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    network_zone TEXT NOT NULL,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    revocation_reason TEXT,
    created_at TEXT NOT NULL,
    last_verified_at TEXT NOT NULL
);

-- 4. Audit Events Table
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}', -- JSON object
    timestamp TEXT NOT NULL
);

-- Indexes for high-performance lookups
CREATE INDEX IF NOT EXISTS idx_evaluations_subject ON access_evaluations(subject_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_timestamp ON access_evaluations(evaluated_at);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON active_sessions(subject_id);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON active_sessions(is_revoked);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
