CREATE TABLE IF NOT EXISTS analysis_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    artifact_key TEXT REFERENCES artifacts(object_key) ON DELETE CASCADE,
    pass_name TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'skipped')),
    progress_current INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER,
    objects_produced INTEGER NOT NULL DEFAULT 0,
    diagnostics_count INTEGER NOT NULL DEFAULT 0,
    byte_limit INTEGER,
    function_limit INTEGER,
    time_limit_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_run
    ON analysis_jobs(analysis_run_id, pass_name);

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_artifact
    ON analysis_jobs(artifact_key, status, started_at);
