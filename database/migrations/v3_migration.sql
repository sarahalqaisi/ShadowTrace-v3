-- ShadowTrace v3 migration is intentionally additive and data-preserving.
ALTER TABLE incidents ADD COLUMN threat_score INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'automatic',
    confidence INTEGER NOT NULL DEFAULT 70,
    threat_score INTEGER NOT NULL DEFAULT 0,
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
