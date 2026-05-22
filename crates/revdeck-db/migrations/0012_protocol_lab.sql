CREATE TABLE IF NOT EXISTS protocol_samples (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    sample_id TEXT NOT NULL,
    label TEXT NOT NULL,
    source_path TEXT NOT NULL,
    schema_hypothesis TEXT,
    message_count INTEGER NOT NULL DEFAULT 0,
    field_count INTEGER NOT NULL DEFAULT 0,
    diagnostics_json TEXT NOT NULL DEFAULT '[]',
    imported_at TEXT NOT NULL,
    UNIQUE(artifact_key, sample_id)
);

CREATE TABLE IF NOT EXISTS protocol_messages (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    sample_key TEXT NOT NULL REFERENCES protocol_samples(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    message_index INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'unknown',
    payload_len INTEGER NOT NULL DEFAULT 0,
    field_count INTEGER NOT NULL DEFAULT 0,
    schema_hypothesis TEXT,
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(sample_key, message_index)
);

CREATE TABLE IF NOT EXISTS protocol_fields (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    message_key TEXT NOT NULL REFERENCES protocol_messages(object_key) ON DELETE CASCADE,
    sample_key TEXT NOT NULL REFERENCES protocol_samples(object_key) ON DELETE CASCADE,
    artifact_key TEXT NOT NULL REFERENCES artifacts(object_key) ON DELETE CASCADE,
    field_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    byte_offset INTEGER NOT NULL,
    byte_length INTEGER NOT NULL,
    field_type TEXT NOT NULL DEFAULT 'bytes',
    confidence TEXT NOT NULL DEFAULT 'inferred',
    entropy REAL NOT NULL DEFAULT 0.0,
    printable_ratio REAL NOT NULL DEFAULT 0.0,
    integer_value INTEGER,
    string_hint TEXT,
    correlated_object_key TEXT REFERENCES objects(object_key),
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(message_key, field_index)
);

CREATE INDEX IF NOT EXISTS idx_protocol_samples_artifact
    ON protocol_samples(artifact_key, imported_at);

CREATE INDEX IF NOT EXISTS idx_protocol_messages_sample
    ON protocol_messages(sample_key, message_index);

CREATE INDEX IF NOT EXISTS idx_protocol_fields_message
    ON protocol_fields(message_key, field_index);

CREATE INDEX IF NOT EXISTS idx_protocol_fields_artifact_offset
    ON protocol_fields(artifact_key, byte_offset, byte_length);

CREATE INDEX IF NOT EXISTS idx_protocol_fields_correlated
    ON protocol_fields(correlated_object_key);
