PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS score_reasons_v2 (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    scored_object_key TEXT NOT NULL REFERENCES objects(object_key) ON DELETE CASCADE,
    score_kind TEXT NOT NULL,
    signal_key TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    display_label TEXT NOT NULL,
    contribution INTEGER NOT NULL,
    weight INTEGER NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    source_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(scored_object_key, score_kind, reason_code, evidence_refs_json)
);

INSERT OR IGNORE INTO score_reasons_v2 (
    object_key, scored_object_key, score_kind, signal_key, reason_code, display_label,
    contribution, weight, evidence_refs_json, source_run_id, metadata_json
)
SELECT
    object_key,
    scored_object_key,
    score_kind,
    signal_key,
    signal_key,
    signal_key,
    contribution,
    contribution,
    CASE
        WHEN evidence_object_key IS NULL THEN '[]'
        ELSE json_array(evidence_object_key)
    END,
    source_run_id,
    detail_json
FROM score_reasons;

DROP TABLE score_reasons;
ALTER TABLE score_reasons_v2 RENAME TO score_reasons;

CREATE INDEX IF NOT EXISTS idx_score_reasons_scored
    ON score_reasons(scored_object_key, score_kind, contribution DESC, reason_code);

CREATE INDEX IF NOT EXISTS idx_score_reasons_run
    ON score_reasons(source_run_id);
