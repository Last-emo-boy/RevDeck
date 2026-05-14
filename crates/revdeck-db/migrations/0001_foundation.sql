PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS project_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS artifacts (
    object_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    source_path TEXT NOT NULL,
    stored_path TEXT,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_key TEXT REFERENCES artifacts(object_key) ON DELETE SET NULL,
    analyzer_id TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'canceled')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    diagnostics_json TEXT,
    error_json TEXT,
    recoverable INTEGER NOT NULL DEFAULT 1 CHECK (recoverable IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_artifact
    ON analysis_runs(artifact_key, analyzer_id, input_hash);

CREATE TABLE objects (
    object_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    artifact_key TEXT REFERENCES artifacts(object_key) ON DELETE CASCADE,
    display_name TEXT,
    address INTEGER,
    size INTEGER,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(kind, object_key)
);

CREATE INDEX IF NOT EXISTS idx_objects_kind ON objects(kind);
CREATE INDEX IF NOT EXISTS idx_objects_artifact_kind ON objects(artifact_key, kind);

CREATE TABLE edges (
    edge_key TEXT PRIMARY KEY,
    src_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    dst_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(src_object_key, dst_object_key, kind)
);

CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_object_key, kind);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_object_key, kind);

CREATE TABLE IF NOT EXISTS sections (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    name TEXT NOT NULL,
    virtual_address INTEGER,
    file_offset INTEGER,
    size INTEGER NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    entropy REAL
);

CREATE TABLE IF NOT EXISTS symbols (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    name TEXT NOT NULL,
    virtual_address INTEGER,
    size INTEGER,
    symbol_kind TEXT NOT NULL DEFAULT 'unknown',
    binding TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS functions (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    name TEXT NOT NULL,
    virtual_address INTEGER,
    size INTEGER,
    boundary_source TEXT NOT NULL,
    boundary_confidence REAL NOT NULL DEFAULT 1.0,
    call_count INTEGER NOT NULL DEFAULT 0,
    string_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS strings (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    value TEXT NOT NULL,
    virtual_address INTEGER,
    file_offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    encoding TEXT NOT NULL DEFAULT 'ascii'
);

CREATE TABLE IF NOT EXISTS imports (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    module TEXT,
    symbol TEXT NOT NULL,
    ordinal INTEGER,
    virtual_address INTEGER
);

CREATE TABLE IF NOT EXISTS xrefs (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    src_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    dst_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    address INTEGER,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS score_reasons (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    scored_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    score_kind TEXT NOT NULL,
    signal_key TEXT NOT NULL,
    contribution INTEGER NOT NULL,
    evidence_object_key TEXT REFERENCES objects(object_key) ON DELETE SET NULL,
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS annotations (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    subject_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    annotation_kind TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_key TEXT NOT NULL REFERENCES findings(object_key) ON DELETE CASCADE,
    evidence_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    evidence_role TEXT NOT NULL,
    evidence_order INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(finding_key, evidence_object_key, evidence_role)
);
