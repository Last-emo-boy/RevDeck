CREATE TABLE IF NOT EXISTS trace_sessions (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    label TEXT NOT NULL,
    source_path TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    thread_count INTEGER NOT NULL DEFAULT 0,
    diagnostics_json TEXT NOT NULL DEFAULT '[]',
    imported_at TEXT NOT NULL,
    UNIQUE(artifact_key, session_id)
);

CREATE TABLE IF NOT EXISTS trace_events (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    session_key TEXT NOT NULL REFERENCES trace_sessions(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    event_index INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    timestamp_ns INTEGER,
    function_name TEXT,
    address INTEGER,
    message TEXT NOT NULL DEFAULT '',
    correlated_object_key TEXT REFERENCES objects(object_key) ON DELETE SET NULL,
    raw_json TEXT NOT NULL,
    UNIQUE(session_key, event_index),
    UNIQUE(session_key, event_id)
);

CREATE INDEX IF NOT EXISTS idx_trace_sessions_artifact
    ON trace_sessions(artifact_key, imported_at);

CREATE INDEX IF NOT EXISTS idx_trace_events_session_timeline
    ON trace_events(session_key, thread_id, timestamp_ns, event_index);

CREATE INDEX IF NOT EXISTS idx_trace_events_artifact_address
    ON trace_events(artifact_key, address);

CREATE INDEX IF NOT EXISTS idx_trace_events_correlated
    ON trace_events(correlated_object_key);
