PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    confidence INTEGER NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    threat_score INTEGER NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    source_ip TEXT,
    destination_ip TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT DEFAULT 'Open',
    summary TEXT,
    attack_stage TEXT,
    kill_chain_phase TEXT,
    mitre_techniques TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    evidence_type TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    description TEXT,
    risk_points INTEGER DEFAULT 0 CHECK (risk_points >= 0),
    raw_event TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attack_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    event_time TEXT,
    attack_stage TEXT,
    kill_chain_phase TEXT,
    description TEXT,
    mitre_technique TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Analyst',
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS incident_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    assigned_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    user_id INTEGER,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'automatic',
    confidence INTEGER NOT NULL DEFAULT 70 CHECK (confidence BETWEEN 0 AND 100),
    threat_score INTEGER NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (incident_id, ioc_type, normalized_value),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ioc_intel_cache (
    ioc_type TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (ioc_type, normalized_value)
);

CREATE TABLE IF NOT EXISTS ioc_lookup_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    local_match_count INTEGER NOT NULL DEFAULT 0,
    provider_score INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Compatibility cache retained for existing v2/v3 installations and map queries.
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip_address TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_tool ON evidence(source_tool);
CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline_incident ON attack_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_activity_incident ON activity_log(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_iocs_incident ON iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(normalized_value);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_ioc_lookup_created ON ioc_lookup_history(created_at);
