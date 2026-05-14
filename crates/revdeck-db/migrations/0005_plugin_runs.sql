CREATE TABLE IF NOT EXISTS plugin_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    config_digest TEXT,
    status TEXT NOT NULL CHECK (status IN ('validated', 'running', 'succeeded', 'failed', 'canceled')),
    permissions_json TEXT NOT NULL DEFAULT '{}',
    diagnostics_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_plugin_runs_plugin
    ON plugin_runs(plugin_id, plugin_version, status);
