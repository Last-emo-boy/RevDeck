CREATE TABLE IF NOT EXISTS firmware_files (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    firmware_artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    path TEXT NOT NULL,
    parent_path TEXT,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    file_type TEXT NOT NULL,
    executable INTEGER NOT NULL DEFAULT 0 CHECK (executable IN (0, 1)),
    nested_artifact_key TEXT REFERENCES artifacts(object_key) ON DELETE SET NULL,
    imported_at TEXT NOT NULL,
    UNIQUE(firmware_artifact_key, path)
);

CREATE INDEX IF NOT EXISTS idx_firmware_files_artifact_path
    ON firmware_files(firmware_artifact_key, path);

CREATE INDEX IF NOT EXISTS idx_firmware_files_artifact_type
    ON firmware_files(firmware_artifact_key, file_type, executable);

CREATE INDEX IF NOT EXISTS idx_firmware_files_nested_artifact
    ON firmware_files(nested_artifact_key);
