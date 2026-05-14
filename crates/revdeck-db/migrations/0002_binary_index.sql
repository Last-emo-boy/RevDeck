PRAGMA foreign_keys = ON;

ALTER TABLE artifacts ADD COLUMN format TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE artifacts ADD COLUMN architecture TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE artifacts ADD COLUMN import_status TEXT NOT NULL DEFAULT 'pending';

CREATE INDEX IF NOT EXISTS idx_artifacts_status
    ON artifacts(import_status, format, architecture);

CREATE TABLE IF NOT EXISTS functions_v2 (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    name TEXT NOT NULL,
    virtual_address INTEGER,
    size INTEGER,
    boundary_source TEXT NOT NULL,
    boundary_confidence TEXT NOT NULL DEFAULT 'unknown',
    call_count INTEGER NOT NULL DEFAULT 0,
    string_count INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO functions_v2 (
    object_key, name, virtual_address, size, boundary_source, boundary_confidence,
    call_count, string_count
)
SELECT
    object_key,
    name,
    virtual_address,
    size,
    boundary_source,
    CASE
        WHEN boundary_confidence IN ('symbol', 'entrypoint', 'import_thunk', 'heuristic', 'external_adapter', 'unknown')
            THEN boundary_confidence
        WHEN boundary_source IN ('symbol', 'entrypoint', 'import_thunk', 'heuristic', 'external_adapter', 'unknown')
            THEN boundary_source
        ELSE 'unknown'
    END,
    call_count,
    string_count
FROM functions;

DROP TABLE functions;
ALTER TABLE functions_v2 RENAME TO functions;
