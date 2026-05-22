CREATE TABLE IF NOT EXISTS crash_reports (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    crash_id TEXT NOT NULL,
    label TEXT NOT NULL,
    source_path TEXT NOT NULL,
    sanitizer TEXT NOT NULL DEFAULT 'unknown',
    crash_class TEXT NOT NULL DEFAULT 'unknown',
    signal TEXT,
    message TEXT NOT NULL DEFAULT '',
    signature TEXT NOT NULL,
    frame_count INTEGER NOT NULL DEFAULT 0,
    correlated_frame_count INTEGER NOT NULL DEFAULT 0,
    diagnostics_json TEXT NOT NULL DEFAULT '[]',
    imported_at TEXT NOT NULL,
    UNIQUE(artifact_key, crash_id)
);

CREATE TABLE IF NOT EXISTS crash_frames (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    report_key TEXT NOT NULL REFERENCES crash_reports(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    frame_index INTEGER NOT NULL,
    module TEXT,
    function_name TEXT,
    address INTEGER,
    offset INTEGER,
    source_location TEXT,
    confidence TEXT NOT NULL DEFAULT 'reported',
    correlated_object_key TEXT REFERENCES objects(object_key) ON DELETE SET NULL,
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(report_key, frame_index)
);

CREATE INDEX IF NOT EXISTS idx_crash_reports_artifact_signature
    ON crash_reports(artifact_key, signature, imported_at);

CREATE INDEX IF NOT EXISTS idx_crash_reports_class
    ON crash_reports(sanitizer, crash_class, signal);

CREATE INDEX IF NOT EXISTS idx_crash_frames_report_stack
    ON crash_frames(report_key, frame_index);

CREATE INDEX IF NOT EXISTS idx_crash_frames_artifact_address
    ON crash_frames(artifact_key, address);

CREATE INDEX IF NOT EXISTS idx_crash_frames_correlated
    ON crash_frames(correlated_object_key);
