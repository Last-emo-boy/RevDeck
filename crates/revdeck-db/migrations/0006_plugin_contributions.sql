CREATE TABLE IF NOT EXISTS plugin_attributes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_run_id INTEGER NOT NULL REFERENCES plugin_runs(id) ON DELETE CASCADE,
    subject_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    attr_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(plugin_run_id, subject_object_key, namespace, schema_id, attr_key)
);

CREATE INDEX IF NOT EXISTS idx_plugin_attributes_subject
    ON plugin_attributes(subject_object_key, namespace, schema_id);

CREATE TABLE IF NOT EXISTS plugin_diagnostics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_run_id INTEGER NOT NULL REFERENCES plugin_runs(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_plugin_diagnostics_run
    ON plugin_diagnostics(plugin_run_id, severity, code);
