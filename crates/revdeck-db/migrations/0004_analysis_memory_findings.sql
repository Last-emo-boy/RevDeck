PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS annotation_evidence (
    annotation_key TEXT NOT NULL,
    evidence_object_key TEXT NOT NULL,
    evidence_object_kind TEXT NOT NULL,
    evidence_order INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(annotation_key, evidence_object_key, evidence_order)
);

CREATE TABLE IF NOT EXISTS annotations_v2 (
    object_key TEXT PRIMARY KEY REFERENCES objects(object_key) ON DELETE CASCADE,
    subject_object_key TEXT NOT NULL,
    subject_object_kind TEXT NOT NULL,
    annotation_kind TEXT NOT NULL,
    body TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO annotations_v2 (
    object_key, subject_object_key, subject_object_kind, annotation_kind, body, display_name,
    created_at, updated_at
)
SELECT
    a.object_key,
    a.subject_object_key,
    coalesce(o.kind, 'file'),
    a.annotation_kind,
    a.body,
    a.body,
    a.created_at,
    a.updated_at
FROM annotations a
LEFT JOIN objects o ON o.object_key = a.subject_object_key;

DROP TABLE annotations;
ALTER TABLE annotations_v2 RENAME TO annotations;

CREATE TABLE IF NOT EXISTS findings_v2 (
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

INSERT OR IGNORE INTO findings_v2 (
    object_key, title, severity, status, summary, body, tags_json, created_at, updated_at
)
SELECT
    object_key,
    title,
    severity,
    status,
    summary,
    body,
    tags_json,
    created_at,
    updated_at
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_v2 RENAME TO findings;

CREATE TABLE IF NOT EXISTS finding_evidence_v2 (
    finding_key TEXT NOT NULL REFERENCES findings(object_key) ON DELETE CASCADE,
    evidence_object_key TEXT NOT NULL,
    evidence_object_kind TEXT NOT NULL,
    evidence_role TEXT NOT NULL,
    evidence_order INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(finding_key, evidence_object_key, evidence_role)
);

INSERT OR IGNORE INTO finding_evidence_v2 (
    finding_key, evidence_object_key, evidence_object_kind, evidence_role, evidence_order, note
)
SELECT
    fe.finding_key,
    fe.evidence_object_key,
    coalesce(o.kind, 'file'),
    fe.evidence_role,
    fe.evidence_order,
    fe.note
FROM finding_evidence fe
LEFT JOIN objects o ON o.object_key = fe.evidence_object_key;

DROP TABLE finding_evidence;
ALTER TABLE finding_evidence_v2 RENAME TO finding_evidence;

CREATE INDEX IF NOT EXISTS idx_annotations_subject_kind
    ON annotations(subject_object_key, annotation_kind, body);

CREATE INDEX IF NOT EXISTS idx_annotation_evidence_annotation
    ON annotation_evidence(annotation_key, evidence_order);

CREATE INDEX IF NOT EXISTS idx_findings_status_severity
    ON findings(status, severity, title);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
    ON finding_evidence(finding_key, evidence_order);
