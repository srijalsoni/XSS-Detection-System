-- P_211 Database Schema
-- Standardized UTC timestamps, strict typing, and query indexes

-- Comments Table
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at);

-- Single-User Application Profile Record
CREATE TABLE IF NOT EXISTS profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    display_name TEXT NOT NULL,
    bio TEXT,
    website TEXT,
    updated_at TEXT NOT NULL
);

-- Security Events Table (Telemetry and Future Detection Results)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    action TEXT NOT NULL,
    rule_id TEXT,
    input_hash TEXT,
    request_id TEXT,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_sec_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_sec_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sec_events_risk ON security_events(risk_level);
CREATE INDEX IF NOT EXISTS idx_sec_events_req_id ON security_events(request_id);

-- General Application Events Table
CREATE TABLE IF NOT EXISTS application_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    request_id TEXT,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_app_events_created_at ON application_events(created_at);
CREATE INDEX IF NOT EXISTS idx_app_events_req_id ON application_events(request_id);
