-- ARTASF SQLite schema
-- Applied automatically by Database._create_schema() on first connection.
-- This file is the canonical reference; keep it in sync with db.py.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    network     TEXT NOT NULL,
    phase       TEXT NOT NULL DEFAULT 'init',
    status      TEXT NOT NULL DEFAULT 'active',
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    json_blob   TEXT NOT NULL          -- full EngagementSession JSON
);

CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    ip          TEXT NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    scanned_at  TEXT NOT NULL,
    json_blob   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulns (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    target_id   TEXT NOT NULL REFERENCES targets(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,         -- critical/high/medium/low/info
    cvss_score  REAL,
    cve         TEXT,
    json_blob   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exploit_attempts (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    step        INTEGER NOT NULL,
    module      TEXT NOT NULL,
    status      TEXT NOT NULL,         -- success/failed/skipped
    started_at  TEXT,
    ended_at    TEXT,
    json_blob   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS loot (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    target_id   TEXT NOT NULL,
    type        TEXT NOT NULL,         -- credential/file/hash/env/etc.
    source      TEXT,
    captured_at TEXT NOT NULL,
    json_blob   TEXT NOT NULL
);
