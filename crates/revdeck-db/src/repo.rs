use revdeck_core::{
    AnalysisRun, AnalysisRunStatus, Annotation, AnnotationEvidence, AnnotationKind, ArtifactFormat,
    ArtifactKind, DiffSummaryViewModel, EdgeKind, ExportAnalysisJob, ExportCaseMetadata,
    ExportCaseNote, ExportContext, ExportPluginRun, Finding, FindingEvidence, FindingSeverity,
    FindingStatus, FunctionScore, FunctionScoreInput, HexOffsetMappingRange, ImportStatus,
    NewAnalysisRun, ObjectKind, ObjectRef, RadarEvidence, Report, ScoreReason, StableObjectKey,
    FUNCTION_RADAR_SCORE_KIND,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub object_ref: ObjectRef,
    pub display_name: String,
    pub source_path: String,
    pub stored_path: Option<String>,
    pub sha256: String,
    pub size: u64,
    pub kind: String,
    pub format: String,
    pub architecture: String,
    pub import_status: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub object_ref: ObjectRef,
    pub artifact_key: Option<String>,
    pub display_name: Option<String>,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub source_run_id: Option<i64>,
    pub metadata_json: String,
}

pub struct ArtifactRepository<'conn> {
    connection: &'conn Connection,
}

pub struct ObjectRepository<'conn> {
    connection: &'conn Connection,
}

pub struct AnalysisRunRepository<'conn> {
    connection: &'conn Connection,
}

pub struct AnalysisJobRepository<'conn> {
    connection: &'conn Connection,
}

pub struct TraceRepository<'conn> {
    connection: &'conn Connection,
}

pub struct FirmwareRepository<'conn> {
    connection: &'conn Connection,
}

pub struct CrashRepository<'conn> {
    connection: &'conn Connection,
}

pub struct ProtocolRepository<'conn> {
    connection: &'conn Connection,
}

pub struct PluginRunRepository<'conn> {
    connection: &'conn Connection,
}

pub struct ProjectMetadataRepository<'conn> {
    connection: &'conn Connection,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredEdge {
    pub edge_ref: ObjectRef,
    pub source: ObjectRef,
    pub target: ObjectRef,
    pub kind: EdgeKind,
    pub confidence: f64,
    pub source_run_id: Option<i64>,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPluginRun {
    pub analysis_run_id: Option<i64>,
    pub plugin_id: String,
    pub plugin_version: String,
    pub manifest_digest: String,
    pub input_digest: String,
    pub config_digest: Option<String>,
    pub status: String,
    pub permissions_json: String,
    pub diagnostics_json: String,
    pub started_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRunRecord {
    pub id: i64,
    pub analysis_run_id: Option<i64>,
    pub plugin_id: String,
    pub plugin_version: String,
    pub manifest_digest: String,
    pub input_digest: String,
    pub config_digest: Option<String>,
    pub status: String,
    pub permissions_json: String,
    pub diagnostics_json: String,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMetadataRecord {
    pub key: String,
    pub value: String,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectNoteRecord {
    pub note_id: i64,
    pub category: String,
    pub title: String,
    pub body: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAnalysisJob {
    pub analysis_run_id: Option<i64>,
    pub artifact_key: Option<String>,
    pub pass_name: String,
    pub profile: String,
    pub status: String,
    pub progress_current: u64,
    pub progress_total: Option<u64>,
    pub objects_produced: u64,
    pub diagnostics_count: u64,
    pub byte_limit: Option<u64>,
    pub function_limit: Option<u64>,
    pub time_limit_ms: Option<u64>,
    pub metadata_json: String,
    pub started_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisJobRecord {
    pub id: i64,
    pub analysis_run_id: Option<i64>,
    pub artifact_key: Option<String>,
    pub pass_name: String,
    pub profile: String,
    pub status: String,
    pub progress_current: u64,
    pub progress_total: Option<u64>,
    pub objects_produced: u64,
    pub diagnostics_count: u64,
    pub byte_limit: Option<u64>,
    pub function_limit: Option<u64>,
    pub time_limit_ms: Option<u64>,
    pub metadata_json: String,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisJobUpdate {
    pub status: String,
    pub progress_current: u64,
    pub progress_total: Option<u64>,
    pub objects_produced: u64,
    pub diagnostics_count: u64,
    pub metadata_json: String,
    pub finished_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSessionRecord {
    pub object_ref: ObjectRef,
    pub artifact: ObjectRef,
    pub session_id: String,
    pub label: String,
    pub source_path: String,
    pub event_count: u64,
    pub thread_count: u64,
    pub diagnostics: Vec<String>,
    pub imported_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEventRecord {
    pub object_ref: ObjectRef,
    pub session: ObjectRef,
    pub artifact: ObjectRef,
    pub event_index: u64,
    pub event_id: String,
    pub thread_id: String,
    pub event_kind: String,
    pub timestamp_ns: Option<u64>,
    pub function_name: Option<String>,
    pub address: Option<u64>,
    pub message: String,
    pub correlated: Option<ObjectRef>,
    pub correlation_method: String,
    pub correlation_confidence: String,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceImportOutcome {
    pub session: ObjectRef,
    pub events_imported: u64,
    pub correlated_events: u64,
    pub malformed_lines: u64,
    pub diagnostics: Vec<String>,
    pub threads: Vec<String>,
    pub analysis_job_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareFileRecord {
    pub object_ref: ObjectRef,
    pub firmware_artifact: ObjectRef,
    pub path: String,
    pub parent_path: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub file_type: String,
    pub executable: bool,
    pub nested_artifact: Option<ObjectRef>,
    pub imported_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareImportOutcome {
    pub firmware: ObjectRef,
    pub files_imported: u64,
    pub binaries_detected: u64,
    pub unsupported_files: u64,
    pub total_bytes: u64,
    pub analysis_job_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashReportRecord {
    pub object_ref: ObjectRef,
    pub artifact: ObjectRef,
    pub crash_id: String,
    pub label: String,
    pub source_path: String,
    pub sanitizer: String,
    pub crash_class: String,
    pub signal: Option<String>,
    pub message: String,
    pub signature: String,
    pub frame_count: u64,
    pub correlated_frame_count: u64,
    pub diagnostics: Vec<String>,
    pub imported_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashFrameRecord {
    pub object_ref: ObjectRef,
    pub report: ObjectRef,
    pub artifact: ObjectRef,
    pub frame_index: u64,
    pub module: Option<String>,
    pub function_name: Option<String>,
    pub address: Option<u64>,
    pub offset: Option<u64>,
    pub source_location: Option<String>,
    pub confidence: String,
    pub correlated: Option<ObjectRef>,
    pub correlation_method: String,
    pub correlation_confidence: String,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashImportOutcome {
    pub report: ObjectRef,
    pub frames_imported: u64,
    pub correlated_frames: u64,
    pub clustered_reports: u64,
    pub findings_created: u64,
    pub signature: String,
    pub diagnostics: Vec<String>,
    pub analysis_job_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSampleRecord {
    pub object_ref: ObjectRef,
    pub artifact: ObjectRef,
    pub sample_id: String,
    pub label: String,
    pub source_path: String,
    pub schema_hypothesis: Option<String>,
    pub message_count: u64,
    pub field_count: u64,
    pub diagnostics: Vec<String>,
    pub imported_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMessageRecord {
    pub object_ref: ObjectRef,
    pub sample: ObjectRef,
    pub artifact: ObjectRef,
    pub message_index: u64,
    pub message_id: String,
    pub direction: String,
    pub payload_len: u64,
    pub field_count: u64,
    pub schema_hypothesis: Option<String>,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolFieldRecord {
    pub object_ref: ObjectRef,
    pub message: ObjectRef,
    pub sample: ObjectRef,
    pub artifact: ObjectRef,
    pub field_index: u64,
    pub name: String,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub field_type: String,
    pub confidence: String,
    pub entropy: f64,
    pub printable_ratio: f64,
    pub integer_value: Option<u64>,
    pub string_hint: Option<String>,
    pub correlated: Option<ObjectRef>,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolImportOutcome {
    pub sample: ObjectRef,
    pub messages_imported: u64,
    pub fields_imported: u64,
    pub correlated_fields: u64,
    pub diagnostics: Vec<String>,
    pub schema_hypothesis: Option<String>,
    pub analysis_job_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTraceEvent {
    event_index: u64,
    event_id: String,
    thread_id: String,
    event_kind: String,
    timestamp_ns: Option<u64>,
    function_name: Option<String>,
    address: Option<u64>,
    message: String,
    correlated: Option<ObjectRef>,
    correlation_method: String,
    correlation_confidence: String,
    raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedFirmwareFile {
    source_path: PathBuf,
    relative_path: String,
    parent_path: Option<String>,
    size: u64,
    sha256: String,
    file_type: String,
    executable: bool,
    nested_artifact: Option<ObjectRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCrashReport {
    crash_id: String,
    label: String,
    sanitizer: String,
    crash_class: String,
    signal: Option<String>,
    message: String,
    signature: String,
    diagnostics: Vec<String>,
    frames: Vec<ParsedCrashFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCrashFrame {
    frame_index: u64,
    module: Option<String>,
    function_name: Option<String>,
    address: Option<u64>,
    offset: Option<u64>,
    source_location: Option<String>,
    confidence: String,
    correlated: Option<ObjectRef>,
    correlation_method: String,
    correlation_confidence: String,
    raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionCorrelation {
    target: ObjectRef,
    method: String,
    confidence: String,
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedProtocolSample {
    sample_id: String,
    label: String,
    schema_hypothesis: Option<String>,
    diagnostics: Vec<String>,
    messages: Vec<ParsedProtocolMessage>,
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedProtocolMessage {
    message_index: u64,
    message_id: String,
    direction: String,
    payload: Vec<u8>,
    schema_hypothesis: Option<String>,
    fields: Vec<ParsedProtocolField>,
    raw_json: String,
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedProtocolField {
    field_index: u64,
    name: String,
    byte_offset: u64,
    byte_length: u64,
    field_type: String,
    confidence: String,
    value_hex: String,
    entropy: f64,
    printable_ratio: f64,
    integer_value: Option<u64>,
    string_hint: Option<String>,
    correlated: Option<ObjectRef>,
    raw_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SectionRecord {
    pub object_ref: ObjectRef,
    pub name: String,
    pub virtual_address: Option<u64>,
    pub file_offset: Option<u64>,
    pub size: u64,
    pub flags: String,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRecord {
    pub object_ref: ObjectRef,
    pub name: String,
    pub virtual_address: Option<u64>,
    pub size: Option<u64>,
    pub symbol_kind: String,
    pub binding: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRecord {
    pub object_ref: ObjectRef,
    pub name: String,
    pub virtual_address: Option<u64>,
    pub size: Option<u64>,
    pub boundary_source: String,
    pub boundary_confidence: String,
    pub call_count: u64,
    pub string_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringRecord {
    pub object_ref: ObjectRef,
    pub value: String,
    pub virtual_address: Option<u64>,
    pub file_offset: u64,
    pub length: u64,
    pub encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRecord {
    pub object_ref: ObjectRef,
    pub module: Option<String>,
    pub symbol: String,
    pub ordinal: Option<u64>,
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefRecord {
    pub object_ref: ObjectRef,
    pub source: ObjectRef,
    pub target: ObjectRef,
    pub relation: String,
    pub address: Option<u64>,
    pub source_run_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlockRecord {
    pub object_ref: ObjectRef,
    pub function: ObjectRef,
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
    pub ordinal: u64,
    pub terminator: String,
    pub confidence: f64,
    pub source_run_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstructionRecord {
    pub object_ref: ObjectRef,
    pub function: ObjectRef,
    pub block: ObjectRef,
    pub address: u64,
    pub size: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands_text: String,
    pub ordinal: u64,
    pub confidence: f64,
    pub source_run_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CfgEdgeRecord {
    pub edge_ref: ObjectRef,
    pub source_block: ObjectRef,
    pub target_block: ObjectRef,
    pub edge_kind: String,
    pub confidence: f64,
    pub source_run_id: Option<i64>,
    pub metadata_json: String,
}

pub struct IndexRepository<'conn> {
    connection: &'conn Connection,
}

pub struct RadarRepository<'conn> {
    connection: &'conn Connection,
}

pub struct MemoryRepository<'conn> {
    connection: &'conn Connection,
}

pub struct FindingRepository<'conn> {
    connection: &'conn Connection,
}

impl<'conn> ArtifactRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn upsert_artifact(&self, artifact: &ArtifactRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO artifacts (
                object_key, display_name, source_path, stored_path, sha256, size, kind,
                format, architecture, import_status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(object_key) DO UPDATE SET
                display_name = excluded.display_name,
                source_path = excluded.source_path,
                stored_path = excluded.stored_path,
                sha256 = excluded.sha256,
                size = excluded.size,
                kind = excluded.kind,
                format = excluded.format,
                architecture = excluded.architecture,
                import_status = excluded.import_status",
            params![
                artifact.object_ref.key.as_str(),
                artifact.display_name,
                artifact.source_path,
                artifact.stored_path.as_deref(),
                artifact.sha256,
                to_i64(artifact.size),
                artifact.kind,
                artifact.format,
                artifact.architecture,
                artifact.import_status,
                format_time(artifact.created_at)?,
            ],
        )?;
        Ok(())
    }

    pub fn get_artifact(&self, object_ref: &ObjectRef) -> rusqlite::Result<Option<ArtifactRecord>> {
        self.connection
            .query_row(
                "SELECT object_key, display_name, source_path, stored_path, sha256, size, kind,
                    format, architecture, import_status, created_at
                FROM artifacts
                WHERE object_key = ?1",
                [object_ref.key.as_str()],
                |row| {
                    let key: String = row.get(0)?;
                    let created_at: String = row.get(10)?;
                    Ok(ArtifactRecord {
                        object_ref: ObjectRef::new(
                            object_ref.kind,
                            key.parse().map_err(from_core_error)?,
                        ),
                        display_name: row.get(1)?,
                        source_path: row.get(2)?,
                        stored_path: row.get(3)?,
                        sha256: row.get(4)?,
                        size: from_i64(row.get(5)?),
                        kind: row.get(6)?,
                        format: row.get(7)?,
                        architecture: row.get(8)?,
                        import_status: row.get(9)?,
                        created_at: parse_time(&created_at)?,
                    })
                },
            )
            .optional()
    }

    pub fn list_artifacts(&self, limit: usize) -> rusqlite::Result<Vec<ArtifactRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT object_key, display_name, source_path, stored_path, sha256, size, kind,
                format, architecture, import_status, created_at
            FROM artifacts
            ORDER BY created_at DESC, object_key
            LIMIT ?1",
        )?;
        let records = statement
            .query_map([limit], |row| {
                let key: String = row.get(0)?;
                let kind: String = row.get(6)?;
                let created_at: String = row.get(10)?;
                Ok(ArtifactRecord {
                    object_ref: ObjectRef::new(
                        ObjectKind::Artifact,
                        key.parse().map_err(from_core_error)?,
                    ),
                    display_name: row.get(1)?,
                    source_path: row.get(2)?,
                    stored_path: row.get(3)?,
                    sha256: row.get(4)?,
                    size: from_i64(row.get(5)?),
                    kind,
                    format: row.get(7)?,
                    architecture: row.get(8)?,
                    import_status: row.get(9)?,
                    created_at: parse_time(&created_at)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(records)
    }
}

impl<'conn> ObjectRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn upsert_object(&self, object: &StoredObject) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO objects (
                object_key, kind, artifact_key, display_name, address, size, source_run_id, metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(object_key) DO UPDATE SET
                kind = excluded.kind,
                artifact_key = excluded.artifact_key,
                display_name = excluded.display_name,
                address = excluded.address,
                size = excluded.size,
                source_run_id = excluded.source_run_id,
                metadata_json = excluded.metadata_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![
                object.object_ref.key.as_str(),
                object.object_ref.kind.as_str(),
                object.artifact_key.as_deref(),
                object.display_name.as_deref(),
                object.address.map(to_i64),
                object.size.map(to_i64),
                object.source_run_id,
                object.metadata_json,
            ],
        )?;
        Ok(())
    }

    pub fn get_object(&self, object_ref: &ObjectRef) -> rusqlite::Result<Option<StoredObject>> {
        self.connection
            .query_row(
                "SELECT object_key, kind, artifact_key, display_name, address, size, source_run_id, metadata_json
                FROM objects WHERE object_key = ?1 AND kind = ?2",
                params![object_ref.key.as_str(), object_ref.kind.as_str()],
                |row| {
                    let kind: String = row.get(1)?;
                    let key: String = row.get(0)?;
                    Ok(StoredObject {
                        object_ref: ObjectRef::new(
                            kind.parse().map_err(from_core_error)?,
                            key.parse().map_err(from_core_error)?,
                        ),
                        artifact_key: row.get(2)?,
                        display_name: row.get(3)?,
                        address: row.get::<_, Option<i64>>(4)?.map(from_i64),
                        size: row.get::<_, Option<i64>>(5)?.map(from_i64),
                        source_run_id: row.get(6)?,
                        metadata_json: row.get(7)?,
                    })
                },
            )
            .optional()
    }

    pub fn insert_edge(
        &self,
        edge_ref: &ObjectRef,
        source: &ObjectRef,
        target: &ObjectRef,
        kind: EdgeKind,
        source_run_id: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.upsert_edge(&StoredEdge {
            edge_ref: edge_ref.clone(),
            source: source.clone(),
            target: target.clone(),
            kind,
            confidence: 1.0,
            source_run_id,
            metadata_json: "{}".to_string(),
        })
    }

    pub fn upsert_edge(&self, edge: &StoredEdge) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO edges (
                edge_key, src_object_key, dst_object_key, kind, confidence, source_run_id,
                metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(edge_key) DO UPDATE SET
                src_object_key = excluded.src_object_key,
                dst_object_key = excluded.dst_object_key,
                kind = excluded.kind,
                confidence = excluded.confidence,
                source_run_id = excluded.source_run_id,
                metadata_json = excluded.metadata_json",
            params![
                edge.edge_ref.key.as_str(),
                edge.source.key.as_str(),
                edge.target.key.as_str(),
                edge.kind.as_str(),
                edge.confidence,
                edge.source_run_id,
                edge.metadata_json,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_diff_rows(
        &self,
        artifact: &ObjectRef,
        summary: &DiffSummaryViewModel,
    ) -> rusqlite::Result<()> {
        for row in &summary.rows {
            let metadata_json = serde_json::to_string(&serde_json::json!({
                "lab_id": "diff",
                "change": row.change.as_str(),
                "entity_kind": row.entity_kind.as_str(),
                "match_key": &row.match_key,
                "before": row.before.as_ref().map(ToString::to_string),
                "after": row.after.as_ref().map(ToString::to_string),
                "before_label": row.before_label.as_deref(),
                "after_label": row.after_label.as_deref(),
                "command_previews": &row.command_previews,
                "risk_level": row.risk_level.as_deref(),
                "risk_reasons": &row.risk_reasons
            }))
            .map_err(json_to_sql_error)?;
            self.upsert_object(&StoredObject {
                object_ref: row.delta_ref.clone(),
                artifact_key: Some(artifact.key.to_string()),
                display_name: Some(row.title.clone()),
                address: None,
                size: None,
                source_run_id: None,
                metadata_json,
            })?;

            if let Some(before) = &row.before {
                self.ensure_diff_reference_object(before, artifact)?;
                self.upsert_diff_reference_edge(&row.delta_ref, before, "before")?;
            }
            if let Some(after) = &row.after {
                self.ensure_diff_reference_object(after, artifact)?;
                self.upsert_diff_reference_edge(&row.delta_ref, after, "after")?;
            }
        }
        Ok(())
    }

    fn ensure_diff_reference_object(
        &self,
        object_ref: &ObjectRef,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM objects WHERE object_key = ?1 AND kind = ?2
            )",
            params![object_ref.key.as_str(), object_ref.kind.as_str()],
            |row| row.get(0),
        )?;
        if exists || object_ref.kind != ObjectKind::Edge {
            return Ok(());
        }

        let edge_label = self
            .connection
            .query_row(
                "SELECT e.kind || ' ' || src.kind || ':' || e.src_object_key
                    || ' -> ' || dst.kind || ':' || e.dst_object_key
                FROM edges e
                JOIN objects src ON src.object_key = e.src_object_key
                JOIN objects dst ON dst.object_key = e.dst_object_key
                WHERE e.edge_key = ?1
                LIMIT 1",
                [object_ref.key.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| object_ref.key.as_str().to_string());
        self.upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(edge_label),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "diff",
                "mirror_kind": "edge",
                "edge_key": object_ref.key.as_str()
            })
            .to_string(),
        })
    }

    fn upsert_diff_reference_edge(
        &self,
        delta_ref: &ObjectRef,
        target_ref: &ObjectRef,
        side: &str,
    ) -> rusqlite::Result<()> {
        let edge_ref = ObjectRef::new(
            ObjectKind::Edge,
            StableObjectKey::new(format!(
                "edge/edge_kind=differs_from/source={}/target={}/side={}",
                sanitize_key_component(delta_ref.key.as_str()),
                sanitize_key_component(target_ref.key.as_str()),
                side
            ))
            .map_err(from_core_error)?,
        );
        self.upsert_edge(&StoredEdge {
            edge_ref,
            source: delta_ref.clone(),
            target: target_ref.clone(),
            kind: EdgeKind::DiffersFrom,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "diff",
                "side": side
            })
            .to_string(),
        })
    }

    pub fn edge_count_for_artifact(&self, artifact_key: &str) -> rusqlite::Result<u64> {
        self.connection
            .query_row(
                "SELECT COUNT(*)
                FROM edges e
                JOIN objects s ON s.object_key = e.src_object_key
                WHERE s.artifact_key = ?1 OR e.src_object_key = ?1",
                [artifact_key],
                |row| row.get::<_, i64>(0),
            )
            .map(from_i64)
    }
}

impl<'conn> IndexRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn remove_indexed_facts_for_artifact(&self, artifact: &ObjectRef) -> rusqlite::Result<()> {
        self.connection.execute(
            "DELETE FROM edges
            WHERE src_object_key IN (
                SELECT object_key FROM objects WHERE artifact_key = ?1 AND kind IN (
                    'section', 'symbol', 'function', 'string', 'import', 'instruction',
                    'basic_block', 'xref', 'edge', 'score'
                )
            )
            OR dst_object_key IN (
                SELECT object_key FROM objects WHERE artifact_key = ?1 AND kind IN (
                    'section', 'symbol', 'function', 'string', 'import', 'instruction',
                    'basic_block', 'xref', 'edge', 'score'
                )
            )",
            [artifact.key.as_str()],
        )?;
        self.connection.execute(
            "DELETE FROM objects
            WHERE artifact_key = ?1
            AND kind IN (
                'section', 'symbol', 'function', 'string', 'import', 'instruction',
                'basic_block', 'xref', 'edge', 'score'
            )
            AND object_key NOT IN (SELECT subject_object_key FROM annotations)
            AND object_key NOT IN (SELECT evidence_object_key FROM finding_evidence)",
            [artifact.key.as_str()],
        )?;
        Ok(())
    }

    pub fn upsert_section(&self, section: &SectionRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO sections (
                object_key, name, virtual_address, file_offset, size, flags, entropy
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(object_key) DO UPDATE SET
                name = excluded.name,
                virtual_address = excluded.virtual_address,
                file_offset = excluded.file_offset,
                size = excluded.size,
                flags = excluded.flags,
                entropy = excluded.entropy",
            params![
                section.object_ref.key.as_str(),
                section.name,
                section.virtual_address.map(to_i64),
                section.file_offset.map(to_i64),
                to_i64(section.size),
                section.flags,
                section.entropy,
            ],
        )?;
        Ok(())
    }

    pub fn section_offset_mappings(
        &self,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<Vec<HexOffsetMappingRange>> {
        let mut statement = self.connection.prepare(
            "SELECT sec.name, sec.virtual_address, sec.file_offset, sec.size
            FROM sections sec
            JOIN objects o ON o.object_key = sec.object_key
            WHERE o.artifact_key = ?1
              AND sec.virtual_address IS NOT NULL
              AND sec.file_offset IS NOT NULL
              AND sec.size > 0
            ORDER BY sec.virtual_address, sec.file_offset, sec.name",
        )?;
        let mappings = statement
            .query_map([artifact.key.as_str()], |row| {
                Ok(HexOffsetMappingRange {
                    section_name: row.get(0)?,
                    virtual_address: from_i64(row.get(1)?),
                    file_offset: from_i64(row.get(2)?),
                    size: from_i64(row.get(3)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(mappings)
    }

    pub fn upsert_symbol(&self, symbol: &SymbolRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO symbols (
                object_key, name, virtual_address, size, symbol_kind, binding
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(object_key) DO UPDATE SET
                name = excluded.name,
                virtual_address = excluded.virtual_address,
                size = excluded.size,
                symbol_kind = excluded.symbol_kind,
                binding = excluded.binding",
            params![
                symbol.object_ref.key.as_str(),
                symbol.name,
                symbol.virtual_address.map(to_i64),
                symbol.size.map(to_i64),
                symbol.symbol_kind,
                symbol.binding,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_function(&self, function: &FunctionRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO functions (
                object_key, name, virtual_address, size, boundary_source, boundary_confidence,
                call_count, string_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(object_key) DO UPDATE SET
                name = excluded.name,
                virtual_address = excluded.virtual_address,
                size = excluded.size,
                boundary_source = excluded.boundary_source,
                boundary_confidence = excluded.boundary_confidence,
                call_count = excluded.call_count,
                string_count = excluded.string_count",
            params![
                function.object_ref.key.as_str(),
                function.name,
                function.virtual_address.map(to_i64),
                function.size.map(to_i64),
                function.boundary_source,
                function.boundary_confidence,
                to_i64(function.call_count),
                to_i64(function.string_count),
            ],
        )?;
        Ok(())
    }

    pub fn upsert_string(&self, string: &StringRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO strings (
                object_key, value, virtual_address, file_offset, length, encoding
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(object_key) DO UPDATE SET
                value = excluded.value,
                virtual_address = excluded.virtual_address,
                file_offset = excluded.file_offset,
                length = excluded.length,
                encoding = excluded.encoding",
            params![
                string.object_ref.key.as_str(),
                string.value,
                string.virtual_address.map(to_i64),
                to_i64(string.file_offset),
                to_i64(string.length),
                string.encoding,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_import(&self, import: &ImportRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO imports (
                object_key, module, symbol, ordinal, virtual_address
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(object_key) DO UPDATE SET
                module = excluded.module,
                symbol = excluded.symbol,
                ordinal = excluded.ordinal,
                virtual_address = excluded.virtual_address",
            params![
                import.object_ref.key.as_str(),
                import.module.as_deref(),
                import.symbol,
                import.ordinal.map(to_i64),
                import.virtual_address.map(to_i64),
            ],
        )?;
        Ok(())
    }

    pub fn upsert_xref(&self, xref: &XrefRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO xrefs (
                object_key, src_object_key, dst_object_key, relation, address, source_run_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(object_key) DO UPDATE SET
                src_object_key = excluded.src_object_key,
                dst_object_key = excluded.dst_object_key,
                relation = excluded.relation,
                address = excluded.address,
                source_run_id = excluded.source_run_id",
            params![
                xref.object_ref.key.as_str(),
                xref.source.key.as_str(),
                xref.target.key.as_str(),
                xref.relation,
                xref.address.map(to_i64),
                xref.source_run_id,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_basic_block(&self, block: &BasicBlockRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO basic_blocks (
                object_key, function_key, start_address, end_address, size, ordinal,
                terminator, confidence, source_run_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(object_key) DO UPDATE SET
                function_key = excluded.function_key,
                start_address = excluded.start_address,
                end_address = excluded.end_address,
                size = excluded.size,
                ordinal = excluded.ordinal,
                terminator = excluded.terminator,
                confidence = excluded.confidence,
                source_run_id = excluded.source_run_id",
            params![
                block.object_ref.key.as_str(),
                block.function.key.as_str(),
                to_i64(block.start_address),
                to_i64(block.end_address),
                to_i64(block.size),
                to_i64(block.ordinal),
                block.terminator.as_str(),
                block.confidence,
                block.source_run_id,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_instruction(&self, instruction: &InstructionRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO instructions (
                object_key, function_key, block_key, address, size, bytes_hex, mnemonic,
                operands_text, ordinal, confidence, source_run_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(object_key) DO UPDATE SET
                function_key = excluded.function_key,
                block_key = excluded.block_key,
                address = excluded.address,
                size = excluded.size,
                bytes_hex = excluded.bytes_hex,
                mnemonic = excluded.mnemonic,
                operands_text = excluded.operands_text,
                ordinal = excluded.ordinal,
                confidence = excluded.confidence,
                source_run_id = excluded.source_run_id",
            params![
                instruction.object_ref.key.as_str(),
                instruction.function.key.as_str(),
                instruction.block.key.as_str(),
                to_i64(instruction.address),
                to_i64(instruction.size),
                instruction.bytes_hex.as_str(),
                instruction.mnemonic.as_str(),
                instruction.operands_text.as_str(),
                to_i64(instruction.ordinal),
                instruction.confidence,
                instruction.source_run_id,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_cfg_edge(&self, edge: &CfgEdgeRecord) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO cfg_edges (
                edge_key, src_block_key, dst_block_key, edge_kind, confidence, source_run_id,
                metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(edge_key) DO UPDATE SET
                src_block_key = excluded.src_block_key,
                dst_block_key = excluded.dst_block_key,
                edge_kind = excluded.edge_kind,
                confidence = excluded.confidence,
                source_run_id = excluded.source_run_id,
                metadata_json = excluded.metadata_json",
            params![
                edge.edge_ref.key.as_str(),
                edge.source_block.key.as_str(),
                edge.target_block.key.as_str(),
                edge.edge_kind.as_str(),
                edge.confidence,
                edge.source_run_id,
                edge.metadata_json.as_str(),
            ],
        )?;
        Ok(())
    }

    pub fn count_kind(&self, artifact: &ObjectRef, kind: ObjectKind) -> rusqlite::Result<u64> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM objects WHERE artifact_key = ?1 AND kind = ?2",
                params![artifact.key.as_str(), kind.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(from_i64)
    }

    pub fn function_boundary_confidences(
        &self,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT f.boundary_confidence
            FROM functions f
            JOIN objects o ON o.object_key = f.object_key
            WHERE o.artifact_key = ?1
            ORDER BY f.virtual_address, f.name",
        )?;
        let confidences = statement
            .query_map([artifact.key.as_str()], |row| row.get::<_, String>(0))?
            .collect();
        confidences
    }

    pub fn latest_analysis_run(
        &self,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<Option<AnalysisRun>> {
        self.connection
            .query_row(
                "SELECT id, artifact_key, analyzer_id, analyzer_version, input_hash, status,
                    started_at, finished_at, diagnostics_json, error_json, recoverable
                FROM analysis_runs
                WHERE artifact_key = ?1
                ORDER BY id DESC
                LIMIT 1",
                [artifact.key.as_str()],
                |row| {
                    let status: String = row.get(5)?;
                    let started_at: String = row.get(6)?;
                    let finished_at: Option<String> = row.get(7)?;
                    Ok(AnalysisRun {
                        id: row.get(0)?,
                        artifact_key: row.get(1)?,
                        analyzer_id: row.get(2)?,
                        analyzer_version: row.get(3)?,
                        input_hash: row.get(4)?,
                        status: status.parse().map_err(from_core_error)?,
                        started_at: parse_time(&started_at)?,
                        finished_at: finished_at.as_deref().map(parse_time).transpose()?,
                        diagnostics_json: row.get(8)?,
                        error_json: row.get(9)?,
                        recoverable: row.get::<_, bool>(10)?,
                    })
                },
            )
            .optional()
    }
}

impl<'conn> MemoryRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn upsert_annotation(&self, annotation: &Annotation) -> rusqlite::Result<()> {
        let normalized = annotation.clone().normalized();
        self.connection.execute(
            "INSERT INTO objects (
                object_key, kind, artifact_key, display_name, address, size, source_run_id,
                metadata_json
            ) VALUES (?1, 'annotation', NULL, ?2, NULL, NULL, NULL, ?3)
            ON CONFLICT(object_key) DO UPDATE SET
                display_name = excluded.display_name,
                metadata_json = excluded.metadata_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![
                normalized.object_ref.key.as_str(),
                format!("{} {}", normalized.kind, normalized.subject),
                serde_json::json!({
                    "subject": normalized.subject.to_string(),
                    "kind": normalized.kind.as_str(),
                    "body": normalized.body
                })
                .to_string(),
            ],
        )?;
        self.connection.execute(
            "INSERT INTO annotations (
                object_key, subject_object_key, subject_object_kind, annotation_kind, body,
                display_name, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(object_key) DO UPDATE SET
                subject_object_key = excluded.subject_object_key,
                subject_object_kind = excluded.subject_object_kind,
                annotation_kind = excluded.annotation_kind,
                body = excluded.body,
                display_name = excluded.display_name,
                updated_at = excluded.updated_at",
            params![
                normalized.object_ref.key.as_str(),
                normalized.subject.key.as_str(),
                normalized.subject.kind.as_str(),
                normalized.kind.as_str(),
                normalized.body,
                normalized.body,
                format_time(normalized.created_at)?,
                format_time(normalized.updated_at)?,
            ],
        )?;
        self.replace_annotation_evidence(&normalized.object_ref, &normalized.evidence)?;
        Ok(())
    }

    pub fn list_annotations_for_subject(
        &self,
        subject: &ObjectRef,
    ) -> rusqlite::Result<Vec<Annotation>> {
        let mut statement = self.connection.prepare(
            "SELECT a.object_key, a.annotation_kind, a.body, a.created_at, a.updated_at
            FROM annotations a
            WHERE a.subject_object_key = ?1
              AND a.subject_object_kind = ?2
            ORDER BY a.created_at, a.object_key",
        )?;
        let rows = statement.query_map(
            params![subject.key.as_str(), subject.kind.as_str()],
            |row| {
                let key: String = row.get(0)?;
                let kind: String = row.get(1)?;
                let created_at: String = row.get(3)?;
                let updated_at: String = row.get(4)?;
                let object_ref = ObjectRef::new(
                    ObjectKind::Annotation,
                    key.parse().map_err(from_core_error)?,
                );
                Ok(Annotation::new(
                    object_ref.clone(),
                    subject.clone(),
                    kind.parse::<AnnotationKind>()
                        .map_err(|err| string_from_sql_error(err, rusqlite::types::Type::Text))?,
                    row.get::<_, String>(2)?,
                    self.list_annotation_evidence(&object_ref)?,
                    parse_time(&created_at)?,
                    parse_time(&updated_at)?,
                ))
            },
        )?;
        rows.collect()
    }

    pub fn replace_annotation_evidence(
        &self,
        annotation: &ObjectRef,
        evidence: &[AnnotationEvidence],
    ) -> rusqlite::Result<()> {
        self.connection.execute(
            "DELETE FROM annotation_evidence WHERE annotation_key = ?1",
            [annotation.key.as_str()],
        )?;
        for evidence in evidence {
            self.connection.execute(
                "INSERT INTO annotation_evidence (
                    annotation_key, evidence_object_key, evidence_object_kind, evidence_order, note
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    annotation.key.as_str(),
                    evidence.object_ref.key.as_str(),
                    evidence.object_ref.kind.as_str(),
                    to_i64(evidence.order),
                    evidence.note,
                ],
            )?;
        }
        Ok(())
    }

    pub fn list_annotation_evidence(
        &self,
        annotation: &ObjectRef,
    ) -> rusqlite::Result<Vec<AnnotationEvidence>> {
        let mut statement = self.connection.prepare(
            "SELECT evidence_object_key, evidence_object_kind, evidence_order, note
            FROM annotation_evidence
            WHERE annotation_key = ?1
            ORDER BY evidence_order, evidence_object_key",
        )?;
        let rows = statement.query_map([annotation.key.as_str()], |row| {
            let key: String = row.get(0)?;
            let kind: String = row.get(1)?;
            Ok(AnnotationEvidence::new(
                ObjectRef::new(
                    kind.parse().map_err(from_core_error)?,
                    key.parse().map_err(from_core_error)?,
                ),
                from_i64(row.get(2)?),
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect()
    }

    fn upsert_annotation_body(
        &self,
        subject: &ObjectRef,
        kind: AnnotationKind,
        body: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        evidence: Vec<AnnotationEvidence>,
    ) -> rusqlite::Result<Annotation> {
        let body = body.into();
        let object_ref = ObjectRef::new(
            ObjectKind::Annotation,
            StableObjectKey::annotation(subject, kind.as_str(), &format_time(created_at)?)
                .map_err(from_core_error)?,
        );
        let annotation = Annotation::new(
            object_ref,
            subject.clone(),
            kind,
            body,
            evidence,
            created_at,
            updated_at,
        );
        self.upsert_annotation(&annotation)?;
        Ok(annotation)
    }

    pub fn upsert_tag(
        &self,
        subject: &ObjectRef,
        tag: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> rusqlite::Result<Annotation> {
        self.upsert_annotation_body(
            subject,
            AnnotationKind::Tag,
            tag,
            created_at,
            updated_at,
            Vec::new(),
        )
    }

    pub fn upsert_status(
        &self,
        subject: &ObjectRef,
        status: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> rusqlite::Result<Annotation> {
        self.upsert_annotation_body(
            subject,
            AnnotationKind::Status,
            status,
            created_at,
            updated_at,
            Vec::new(),
        )
    }

    pub fn upsert_note(
        &self,
        subject: &ObjectRef,
        note: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        evidence: Vec<AnnotationEvidence>,
    ) -> rusqlite::Result<Annotation> {
        self.upsert_annotation_body(
            subject,
            AnnotationKind::Note,
            note,
            created_at,
            updated_at,
            evidence,
        )
    }

    pub fn upsert_rename(
        &self,
        subject: &ObjectRef,
        renamed_to: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> rusqlite::Result<Annotation> {
        self.upsert_annotation_body(
            subject,
            AnnotationKind::Rename,
            renamed_to,
            created_at,
            updated_at,
            Vec::new(),
        )
    }

    pub fn upsert_todo(
        &self,
        subject: &ObjectRef,
        todo: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        evidence: Vec<AnnotationEvidence>,
    ) -> rusqlite::Result<Annotation> {
        self.upsert_annotation_body(
            subject,
            AnnotationKind::Todo,
            todo,
            created_at,
            updated_at,
            evidence,
        )
    }

    pub fn upsert_hypothesis(
        &self,
        subject: &ObjectRef,
        hypothesis: impl Into<String>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        evidence: Vec<AnnotationEvidence>,
    ) -> rusqlite::Result<Annotation> {
        self.upsert_annotation_body(
            subject,
            AnnotationKind::Hypothesis,
            hypothesis,
            created_at,
            updated_at,
            evidence,
        )
    }

    pub fn annotation_count_for_subject(&self, subject: &ObjectRef) -> rusqlite::Result<u64> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM annotations WHERE subject_object_key = ?1 AND subject_object_kind = ?2",
                params![subject.key.as_str(), subject.kind.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(from_i64)
    }
}

impl<'conn> FindingRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn upsert_finding(&self, finding: &Finding) -> rusqlite::Result<()> {
        let finding = finding.clone().normalized();
        self.connection.execute(
            "INSERT INTO objects (
                object_key, kind, artifact_key, display_name, address, size, source_run_id,
                metadata_json
            ) VALUES (?1, 'finding', NULL, ?2, NULL, NULL, NULL, ?3)
            ON CONFLICT(object_key) DO UPDATE SET
                display_name = excluded.display_name,
                metadata_json = excluded.metadata_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![
                finding.object_ref.key.as_str(),
                finding.title,
                serde_json::json!({
                    "severity": finding.severity.as_str(),
                    "status": finding.status.as_str()
                })
                .to_string(),
            ],
        )?;
        let tags_json = serde_json::to_string(&finding.tags).map_err(json_to_sql_error)?;
        self.connection.execute(
            "INSERT INTO findings (
                object_key, title, severity, status, summary, body, tags_json, created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(object_key) DO UPDATE SET
                title = excluded.title,
                severity = excluded.severity,
                status = excluded.status,
                summary = excluded.summary,
                body = excluded.body,
                tags_json = excluded.tags_json,
                updated_at = excluded.updated_at",
            params![
                finding.object_ref.key.as_str(),
                finding.title,
                finding.severity.as_str(),
                finding.status.as_str(),
                finding.summary,
                finding.body,
                tags_json,
                format_time(finding.created_at)?,
                format_time(finding.updated_at)?,
            ],
        )?;
        self.replace_evidence(&finding.object_ref, &finding.evidence)
    }

    pub fn replace_evidence(
        &self,
        finding: &ObjectRef,
        evidence: &[FindingEvidence],
    ) -> rusqlite::Result<()> {
        self.connection.execute(
            "DELETE FROM finding_evidence WHERE finding_key = ?1",
            [finding.key.as_str()],
        )?;
        for evidence in evidence {
            let evidence = evidence.clone().normalized();
            self.connection.execute(
                "INSERT INTO finding_evidence (
                    finding_key, evidence_object_key, evidence_object_kind, evidence_role,
                    evidence_order, note
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    finding.key.as_str(),
                    evidence.evidence.key.as_str(),
                    evidence.evidence.kind.as_str(),
                    evidence.role,
                    to_i64(evidence.order),
                    evidence.note,
                ],
            )?;
        }
        Ok(())
    }

    pub fn list_findings(&self) -> rusqlite::Result<Vec<Finding>> {
        let mut statement = self.connection.prepare(
            "SELECT object_key, title, severity, status, summary, body, tags_json, created_at,
                updated_at
            FROM findings
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                title,
                object_key",
        )?;
        let rows = statement.query_map([], |row| {
            let key: String = row.get(0)?;
            let severity: String = row.get(2)?;
            let status: String = row.get(3)?;
            let tags_json: String = row.get(6)?;
            let created_at: String = row.get(7)?;
            let updated_at: String = row.get(8)?;
            let object_ref =
                ObjectRef::new(ObjectKind::Finding, key.parse().map_err(from_core_error)?);
            Ok(Finding {
                evidence: self.list_evidence(&object_ref)?,
                object_ref,
                title: row.get(1)?,
                severity: severity
                    .parse::<FindingSeverity>()
                    .map_err(|err| string_from_sql_error(err, rusqlite::types::Type::Text))?,
                status: status
                    .parse::<FindingStatus>()
                    .map_err(|err| string_from_sql_error(err, rusqlite::types::Type::Text))?,
                summary: row.get(4)?,
                body: row.get(5)?,
                tags: serde_json::from_str(&tags_json).map_err(json_from_sql_error)?,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })?;
        rows.collect()
    }

    pub fn export_context(
        &self,
        generated_at: time::OffsetDateTime,
    ) -> rusqlite::Result<ExportContext> {
        let findings = self.list_findings()?;
        let mut evidence_objects = Vec::new();
        let mut seen = BTreeSet::new();
        for finding in &findings {
            for evidence in &finding.evidence {
                if seen.insert(evidence.evidence.clone()) {
                    if let Some(object) = self.load_object_summary(&evidence.evidence)? {
                        evidence_objects.push(object);
                    }
                }
            }
        }
        let mut context = ExportContext::new(
            Report {
                generated_at,
                findings,
            },
            evidence_objects,
        );

        let analysis_jobs = AnalysisJobRepository::new(self.connection);
        let mut seen_jobs = BTreeSet::new();
        for artifact_key in export_artifact_keys(&context.evidence_objects) {
            for job in analysis_jobs.list_recent_by_artifact_key(&artifact_key, 20)? {
                if seen_jobs.insert(job.id) {
                    context.analysis_jobs.push(export_analysis_job(job));
                }
            }
        }

        let plugin_runs = PluginRunRepository::new(self.connection);
        let mut seen_plugin_runs = BTreeSet::new();
        for object in &context.evidence_objects {
            if let Some(plugin_run_id) = metadata_plugin_run_id(&object.metadata_json) {
                if seen_plugin_runs.insert(plugin_run_id) {
                    if let Some(run) = plugin_runs.get(plugin_run_id)? {
                        context.plugin_runs.push(export_plugin_run(run));
                    }
                }
            }
        }
        for run in plugin_runs.list_recent(50)? {
            if seen_plugin_runs.insert(run.id) {
                context.plugin_runs.push(export_plugin_run(run));
            }
        }

        let project_metadata = ProjectMetadataRepository::new(self.connection);
        context.case_metadata = project_metadata
            .list_metadata()?
            .into_iter()
            .map(export_case_metadata)
            .collect();
        context.case_notes = project_metadata
            .list_notes(25)?
            .into_iter()
            .map(export_case_note)
            .collect();

        context.refresh_lab_summaries();
        Ok(context)
    }

    fn list_evidence(&self, finding: &ObjectRef) -> rusqlite::Result<Vec<FindingEvidence>> {
        let mut statement = self.connection.prepare(
            "SELECT fe.evidence_object_key, coalesce(o.kind, fe.evidence_object_kind),
                fe.evidence_role, fe.evidence_order, fe.note,
                coalesce(rn.body, o.display_name)
            FROM finding_evidence fe
            LEFT JOIN objects o ON o.object_key = fe.evidence_object_key
            LEFT JOIN annotations rn
              ON rn.subject_object_key = fe.evidence_object_key
             AND rn.subject_object_kind = coalesce(o.kind, fe.evidence_object_kind)
             AND rn.annotation_kind = 'rename'
            WHERE fe.finding_key = ?1
            ORDER BY fe.evidence_order, fe.evidence_role, fe.evidence_object_key, rn.updated_at DESC",
        )?;
        let rows = statement.query_map([finding.key.as_str()], |row| {
            let key: String = row.get(0)?;
            let kind: Option<String> = row.get(1)?;
            Ok(FindingEvidence {
                evidence: ObjectRef::new(
                    kind.as_deref()
                        .unwrap_or("file")
                        .parse()
                        .map_err(from_core_error)?,
                    key.parse().map_err(from_core_error)?,
                ),
                role: row.get(2)?,
                order: from_i64(row.get(3)?),
                note: row.get(4)?,
                label: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    fn load_object_summary(
        &self,
        object_ref: &ObjectRef,
    ) -> rusqlite::Result<Option<revdeck_core::ObjectSummary>> {
        self.connection
            .query_row(
                "SELECT o.object_key, o.kind, o.artifact_key, coalesce(rn.body, o.display_name),
                    o.address, o.size, o.metadata_json
                FROM objects o
                LEFT JOIN annotations rn
                  ON rn.subject_object_key = o.object_key
                 AND rn.subject_object_kind = o.kind
                 AND rn.annotation_kind = 'rename'
                WHERE o.object_key = ?1
                ORDER BY rn.updated_at DESC
                LIMIT 1",
                [object_ref.key.as_str()],
                |row| {
                    let key: String = row.get(0)?;
                    let kind: String = row.get(1)?;
                    Ok(revdeck_core::ObjectSummary {
                        object_ref: ObjectRef::new(
                            kind.parse().map_err(from_core_error)?,
                            key.parse().map_err(from_core_error)?,
                        ),
                        artifact_key: row.get(2)?,
                        display_name: row.get(3)?,
                        address: row.get::<_, Option<i64>>(4)?.map(from_i64),
                        size: row.get::<_, Option<i64>>(5)?.map(from_i64),
                        metadata_json: row.get(6)?,
                    })
                },
            )
            .optional()
    }
}

impl<'conn> RadarRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn load_function_inputs(
        &self,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<Vec<FunctionScoreInput>> {
        let entrypoint = self.artifact_entrypoint(artifact)?;
        let mut statement = self.connection.prepare(
            "SELECT
                o.object_key, coalesce(rn.body, o.display_name), o.address, o.size,
                f.name, f.virtual_address, f.size, f.boundary_source, f.boundary_confidence,
                f.call_count, f.string_count
            FROM functions f
            JOIN objects o ON o.object_key = f.object_key
            LEFT JOIN annotations rn
              ON rn.subject_object_key = o.object_key
             AND rn.subject_object_kind = o.kind
             AND rn.annotation_kind = 'rename'
            WHERE o.artifact_key = ?1
            ORDER BY f.virtual_address, coalesce(rn.body, f.name), o.object_key",
        )?;
        let rows = statement.query_map([artifact.key.as_str()], |row| {
            let object_key: String = row.get(0)?;
            let renamed: Option<String> = row.get(1)?;
            let name: String = renamed.unwrap_or(row.get(4)?);
            let function_ref = ObjectRef::new(
                ObjectKind::Function,
                object_key.parse().map_err(from_core_error)?,
            );
            Ok(FunctionScoreInput {
                artifact_ref: artifact.clone(),
                function_ref: function_ref.clone(),
                name,
                virtual_address: row.get::<_, Option<i64>>(5)?.map(from_i64),
                size: row.get::<_, Option<i64>>(6)?.map(from_i64),
                boundary_source: row.get(7)?,
                boundary_confidence: row.get(8)?,
                call_count: from_i64(row.get(9)?),
                string_count: from_i64(row.get(10)?),
                xref_count: 0,
                entrypoint,
                referenced_strings: Vec::new(),
                called_imports: Vec::new(),
                tags: Vec::new(),
                status: None,
            })
        })?;
        let mut inputs = rows.collect::<rusqlite::Result<Vec<_>>>()?;

        for input in &mut inputs {
            input.referenced_strings = self.function_string_evidence(&input.function_ref)?;
            input.called_imports = self.function_import_evidence(&input.function_ref)?;
            input.xref_count = self.function_xref_count(&input.function_ref)?;
            let (tags, status) = self.function_annotations(&input.function_ref)?;
            input.tags = tags;
            input.status = status;
        }

        Ok(inputs)
    }

    pub fn replace_function_scores(
        &self,
        artifact: &ObjectRef,
        source_run_id: i64,
        scores: &[FunctionScore],
    ) -> rusqlite::Result<()> {
        self.connection.execute(
            "DELETE FROM score_reasons
            WHERE score_kind = ?2
              AND scored_object_key IN (
                SELECT object_key FROM objects WHERE artifact_key = ?1 AND kind = 'function'
              )",
            params![artifact.key.as_str(), FUNCTION_RADAR_SCORE_KIND],
        )?;
        self.connection.execute(
            "DELETE FROM objects
            WHERE kind = 'score'
              AND artifact_key = ?1
              AND object_key NOT IN (SELECT object_key FROM score_reasons)",
            [artifact.key.as_str()],
        )?;

        for score in scores {
            let score_ref = ObjectRef::new(
                ObjectKind::Score,
                StableObjectKey::score(
                    &score.function_ref,
                    FUNCTION_RADAR_SCORE_KIND,
                    Some(source_run_id),
                )
                .map_err(from_core_error)?,
            );
            self.connection.execute(
                "INSERT INTO objects (
                    object_key, kind, artifact_key, display_name, address, size, source_run_id,
                    metadata_json
                ) VALUES (?1, 'score', ?2, ?3, ?4, NULL, ?5, ?6)
                ON CONFLICT(object_key) DO UPDATE SET
                    artifact_key = excluded.artifact_key,
                    display_name = excluded.display_name,
                    address = excluded.address,
                    source_run_id = excluded.source_run_id,
                    metadata_json = excluded.metadata_json,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                params![
                    score_ref.key.as_str(),
                    artifact.key.as_str(),
                    format!("Function Radar score {}", score.score),
                    score.virtual_address.map(to_i64),
                    source_run_id,
                    serde_json::json!({
                        "score_kind": FUNCTION_RADAR_SCORE_KIND,
                        "score": score.score,
                        "subject": score.function_ref.to_string(),
                        "boundary_confidence": score.boundary_confidence,
                        "boundary_source": score.boundary_source
                    })
                    .to_string(),
                ],
            )?;

            for (index, reason) in score.reasons.iter().enumerate() {
                self.insert_score_reason(
                    artifact,
                    &score.function_ref,
                    &score_ref,
                    source_run_id,
                    index,
                    reason,
                )?;
            }
        }

        Ok(())
    }

    pub fn load_function_scores(
        &self,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<Vec<FunctionScore>> {
        let mut scores = revdeck_core::score_functions(self.load_function_inputs(artifact)?);
        let mut reasons_by_function = self.load_score_reasons(artifact)?;
        for score in &mut scores {
            if let Some(reasons) = reasons_by_function.remove(score.function_ref.key.as_str()) {
                score.reasons = reasons;
                score.score = score
                    .reasons
                    .iter()
                    .map(|reason| reason.contribution)
                    .sum::<i32>()
                    .max(0);
            }
        }
        revdeck_core::sort_function_scores(&mut scores);
        Ok(scores)
    }

    pub fn reason_count_for_run(&self, source_run_id: i64) -> rusqlite::Result<u64> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM score_reasons WHERE source_run_id = ?1",
                [source_run_id],
                |row| row.get::<_, i64>(0),
            )
            .map(from_i64)
    }

    fn insert_score_reason(
        &self,
        artifact: &ObjectRef,
        function_ref: &ObjectRef,
        score_ref: &ObjectRef,
        source_run_id: i64,
        index: usize,
        reason: &ScoreReason,
    ) -> rusqlite::Result<()> {
        let reason_ref = ObjectRef::new(
            ObjectKind::Score,
            StableObjectKey::new(format!(
                "{}/reason={}/index={:04}",
                score_ref.key.as_str(),
                sanitize_key_component(&reason.reason_code),
                index
            ))
            .map_err(from_core_error)?,
        );
        let evidence_refs_json =
            serde_json::to_string(&reason.evidence_refs).map_err(json_to_sql_error)?;
        let metadata_json = serde_json::to_string(&reason.metadata).map_err(json_to_sql_error)?;
        self.connection.execute(
            "INSERT INTO objects (
                object_key, kind, artifact_key, display_name, address, size, source_run_id,
                metadata_json
            ) VALUES (?1, 'score', ?2, ?3, NULL, NULL, ?4, ?5)
            ON CONFLICT(object_key) DO UPDATE SET
                display_name = excluded.display_name,
                source_run_id = excluded.source_run_id,
                metadata_json = excluded.metadata_json,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![
                reason_ref.key.as_str(),
                artifact.key.as_str(),
                reason.display_label,
                source_run_id,
                metadata_json,
            ],
        )?;
        self.connection.execute(
            "INSERT INTO score_reasons (
                object_key, scored_object_key, score_kind, signal_key, reason_code,
                display_label, contribution, weight, evidence_refs_json, source_run_id,
                metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(object_key) DO UPDATE SET
                scored_object_key = excluded.scored_object_key,
                score_kind = excluded.score_kind,
                signal_key = excluded.signal_key,
                reason_code = excluded.reason_code,
                display_label = excluded.display_label,
                contribution = excluded.contribution,
                weight = excluded.weight,
                evidence_refs_json = excluded.evidence_refs_json,
                source_run_id = excluded.source_run_id,
                metadata_json = excluded.metadata_json",
            params![
                reason_ref.key.as_str(),
                function_ref.key.as_str(),
                FUNCTION_RADAR_SCORE_KIND,
                reason.signal_key,
                reason.reason_code,
                reason.display_label,
                reason.contribution,
                reason.weight,
                evidence_refs_json,
                source_run_id,
                metadata_json,
            ],
        )?;
        Ok(())
    }

    fn load_score_reasons(
        &self,
        artifact: &ObjectRef,
    ) -> rusqlite::Result<BTreeMap<String, Vec<ScoreReason>>> {
        let mut statement = self.connection.prepare(
            "SELECT
                sr.scored_object_key, sr.signal_key, sr.reason_code, sr.display_label,
                sr.contribution, sr.weight, sr.evidence_refs_json, sr.source_run_id,
                sr.metadata_json
            FROM score_reasons sr
            JOIN objects o ON o.object_key = sr.scored_object_key
            WHERE o.artifact_key = ?1 AND sr.score_kind = ?2
            ORDER BY sr.scored_object_key, sr.contribution DESC, sr.reason_code, sr.object_key",
        )?;
        let rows = statement.query_map(
            params![artifact.key.as_str(), FUNCTION_RADAR_SCORE_KIND],
            |row| {
                let scored_object_key: String = row.get(0)?;
                let evidence_json: String = row.get(6)?;
                let metadata_json: String = row.get(8)?;
                let evidence_refs = serde_json::from_str::<Vec<ObjectRef>>(&evidence_json)
                    .map_err(json_from_sql_error)?;
                let metadata = serde_json::from_str::<BTreeMap<String, String>>(&metadata_json)
                    .map_err(json_from_sql_error)?;
                Ok((
                    scored_object_key,
                    ScoreReason {
                        signal_key: row.get(1)?,
                        reason_code: row.get(2)?,
                        display_label: row.get(3)?,
                        contribution: row.get(4)?,
                        weight: row.get(5)?,
                        evidence_refs,
                        source_run_id: row.get(7)?,
                        metadata,
                    },
                ))
            },
        )?;
        let mut reasons = BTreeMap::<String, Vec<ScoreReason>>::new();
        for row in rows {
            let (key, reason) = row?;
            reasons.entry(key).or_default().push(reason);
        }
        Ok(reasons)
    }

    fn artifact_entrypoint(&self, artifact: &ObjectRef) -> rusqlite::Result<Option<u64>> {
        let metadata_json = self
            .connection
            .query_row(
                "SELECT metadata_json FROM objects WHERE object_key = ?1 AND kind = 'artifact'",
                [artifact.key.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(metadata_json) = metadata_json else {
            return Ok(None);
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&metadata_json) else {
            return Ok(None);
        };
        Ok(value.get("entrypoint").and_then(serde_json::Value::as_u64))
    }

    fn function_string_evidence(
        &self,
        function_ref: &ObjectRef,
    ) -> rusqlite::Result<Vec<RadarEvidence>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT
                dst.object_key, coalesce(dst.display_name, st.value), st.value, dst.address
            FROM edges e
            JOIN objects dst ON dst.object_key = e.dst_object_key
            JOIN strings st ON st.object_key = dst.object_key
            WHERE e.src_object_key = ?1
              AND e.kind IN ('references', 'has_xref')
            ORDER BY st.value, dst.object_key",
        )?;
        let rows = statement.query_map([function_ref.key.as_str()], |row| {
            let key: String = row.get(0)?;
            Ok(RadarEvidence {
                object_ref: ObjectRef::new(
                    ObjectKind::String,
                    key.parse().map_err(from_core_error)?,
                ),
                label: row.get(1)?,
                value: row.get(2)?,
                address: row.get::<_, Option<i64>>(3)?.map(from_i64),
            })
        })?;
        rows.collect()
    }

    fn function_import_evidence(
        &self,
        function_ref: &ObjectRef,
    ) -> rusqlite::Result<Vec<RadarEvidence>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT
                dst.object_key,
                coalesce(im.module || '!', '') || im.symbol,
                im.symbol,
                dst.address
            FROM edges e
            JOIN objects dst ON dst.object_key = e.dst_object_key
            JOIN imports im ON im.object_key = dst.object_key
            WHERE e.src_object_key = ?1
              AND e.kind IN ('calls_import', 'calls')
            ORDER BY im.symbol, dst.object_key",
        )?;
        let rows = statement.query_map([function_ref.key.as_str()], |row| {
            let key: String = row.get(0)?;
            Ok(RadarEvidence {
                object_ref: ObjectRef::new(
                    ObjectKind::Import,
                    key.parse().map_err(from_core_error)?,
                ),
                label: row.get(1)?,
                value: row.get(2)?,
                address: row.get::<_, Option<i64>>(3)?.map(from_i64),
            })
        })?;
        rows.collect()
    }

    fn function_xref_count(&self, function_ref: &ObjectRef) -> rusqlite::Result<u64> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM xrefs WHERE src_object_key = ?1 OR dst_object_key = ?1",
                [function_ref.key.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(from_i64)
    }

    fn function_annotations(
        &self,
        function_ref: &ObjectRef,
    ) -> rusqlite::Result<(Vec<String>, Option<String>)> {
        let mut statement = self.connection.prepare(
            "SELECT annotation_kind, body
            FROM annotations
            WHERE subject_object_key = ?1
              AND annotation_kind IN ('tag', 'status')
            ORDER BY annotation_kind, body",
        )?;
        let rows = statement.query_map([function_ref.key.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut tags = BTreeSet::new();
        let mut status = None;
        for row in rows {
            let (kind, body) = row?;
            match kind.as_str() {
                "tag" => {
                    tags.insert(body);
                }
                "status" => {
                    status = Some(body);
                }
                _ => {}
            }
        }
        Ok((tags.into_iter().collect(), status))
    }
}

impl<'conn> AnalysisRunRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn start(&self, run: &NewAnalysisRun) -> rusqlite::Result<AnalysisRun> {
        self.connection.execute(
            "INSERT INTO analysis_runs (
                artifact_key, analyzer_id, analyzer_version, input_hash, status, started_at
            ) VALUES (?1, ?2, ?3, ?4, 'running', ?5)",
            params![
                run.artifact_key.as_deref(),
                run.analyzer_id,
                run.analyzer_version,
                run.input_hash,
                format_time(run.started_at)?,
            ],
        )?;
        let id = self.connection.last_insert_rowid();
        self.get(id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn finish(
        &self,
        id: i64,
        status: AnalysisRunStatus,
        finished_at: OffsetDateTime,
        diagnostics_json: Option<&str>,
        error_json: Option<&str>,
        recoverable: bool,
    ) -> rusqlite::Result<AnalysisRun> {
        self.connection.execute(
            "UPDATE analysis_runs
            SET status = ?2,
                finished_at = ?3,
                diagnostics_json = ?4,
                error_json = ?5,
                recoverable = ?6
            WHERE id = ?1",
            params![
                id,
                status.as_str(),
                format_time(finished_at)?,
                diagnostics_json,
                error_json,
                recoverable,
            ],
        )?;
        self.get(id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn get(&self, id: i64) -> rusqlite::Result<Option<AnalysisRun>> {
        self.connection
            .query_row(
                "SELECT id, artifact_key, analyzer_id, analyzer_version, input_hash, status,
                    started_at, finished_at, diagnostics_json, error_json, recoverable
                FROM analysis_runs
                WHERE id = ?1",
                [id],
                |row| {
                    let status: String = row.get(5)?;
                    let started_at: String = row.get(6)?;
                    let finished_at: Option<String> = row.get(7)?;
                    Ok(AnalysisRun {
                        id: row.get(0)?,
                        artifact_key: row.get(1)?,
                        analyzer_id: row.get(2)?,
                        analyzer_version: row.get(3)?,
                        input_hash: row.get(4)?,
                        status: status.parse().map_err(from_core_error)?,
                        started_at: parse_time(&started_at)?,
                        finished_at: finished_at.as_deref().map(parse_time).transpose()?,
                        diagnostics_json: row.get(8)?,
                        error_json: row.get(9)?,
                        recoverable: row.get::<_, bool>(10)?,
                    })
                },
            )
            .optional()
    }
}

impl<'conn> AnalysisJobRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn insert(&self, job: &NewAnalysisJob) -> rusqlite::Result<AnalysisJobRecord> {
        self.connection.execute(
            "INSERT INTO analysis_jobs (
                analysis_run_id, artifact_key, pass_name, profile, status,
                progress_current, progress_total, objects_produced, diagnostics_count,
                byte_limit, function_limit, time_limit_ms, metadata_json, started_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                job.analysis_run_id,
                job.artifact_key.as_deref(),
                job.pass_name,
                job.profile,
                job.status,
                to_i64(job.progress_current),
                job.progress_total.map(to_i64),
                to_i64(job.objects_produced),
                to_i64(job.diagnostics_count),
                job.byte_limit.map(to_i64),
                job.function_limit.map(to_i64),
                job.time_limit_ms.map(to_i64),
                job.metadata_json,
                format_time(job.started_at)?,
            ],
        )?;
        let id = self.connection.last_insert_rowid();
        self.get(id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn finish(
        &self,
        id: i64,
        update: &AnalysisJobUpdate,
    ) -> rusqlite::Result<AnalysisJobRecord> {
        let finished_at = format_time(update.finished_at)?;
        self.connection.execute(
            "UPDATE analysis_jobs
            SET status = ?2,
                progress_current = ?3,
                progress_total = ?4,
                objects_produced = ?5,
                diagnostics_count = ?6,
                metadata_json = ?7,
                finished_at = ?8,
                updated_at = ?8
            WHERE id = ?1",
            params![
                id,
                update.status,
                to_i64(update.progress_current),
                update.progress_total.map(to_i64),
                to_i64(update.objects_produced),
                to_i64(update.diagnostics_count),
                update.metadata_json,
                finished_at,
            ],
        )?;
        self.get(id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn list_recent(&self, limit: usize) -> rusqlite::Result<Vec<AnalysisJobRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT id, analysis_run_id, artifact_key, pass_name, profile, status,
                progress_current, progress_total, objects_produced, diagnostics_count,
                byte_limit, function_limit, time_limit_ms, metadata_json,
                started_at, finished_at, updated_at
            FROM analysis_jobs
            ORDER BY started_at DESC, id DESC
            LIMIT ?1",
        )?;
        let records = statement
            .query_map([limit], Self::record_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(records)
    }

    pub fn list_recent_for_artifact(
        &self,
        artifact: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<AnalysisJobRecord>> {
        self.list_recent_by_artifact_key(artifact.key.as_str(), limit)
    }

    pub fn list_recent_by_artifact_key(
        &self,
        artifact_key: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<AnalysisJobRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT id, analysis_run_id, artifact_key, pass_name, profile, status,
                progress_current, progress_total, objects_produced, diagnostics_count,
                byte_limit, function_limit, time_limit_ms, metadata_json,
                started_at, finished_at, updated_at
            FROM analysis_jobs
            WHERE artifact_key = ?1
            ORDER BY started_at DESC, id DESC
            LIMIT ?2",
        )?;
        let records = statement
            .query_map(params![artifact_key, limit], Self::record_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(records)
    }

    pub fn get(&self, id: i64) -> rusqlite::Result<Option<AnalysisJobRecord>> {
        self.connection
            .query_row(
                "SELECT id, analysis_run_id, artifact_key, pass_name, profile, status,
                    progress_current, progress_total, objects_produced, diagnostics_count,
                    byte_limit, function_limit, time_limit_ms, metadata_json,
                    started_at, finished_at, updated_at
                FROM analysis_jobs
                WHERE id = ?1",
                [id],
                Self::record_from_row,
            )
            .optional()
    }

    fn record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AnalysisJobRecord> {
        let started_at: String = row.get(14)?;
        let finished_at: Option<String> = row.get(15)?;
        let updated_at: String = row.get(16)?;
        Ok(AnalysisJobRecord {
            id: row.get(0)?,
            analysis_run_id: row.get(1)?,
            artifact_key: row.get(2)?,
            pass_name: row.get(3)?,
            profile: row.get(4)?,
            status: row.get(5)?,
            progress_current: from_i64(row.get(6)?),
            progress_total: row.get::<_, Option<i64>>(7)?.map(from_i64),
            objects_produced: from_i64(row.get(8)?),
            diagnostics_count: from_i64(row.get(9)?),
            byte_limit: row.get::<_, Option<i64>>(10)?.map(from_i64),
            function_limit: row.get::<_, Option<i64>>(11)?.map(from_i64),
            time_limit_ms: row.get::<_, Option<i64>>(12)?.map(from_i64),
            metadata_json: row.get(13)?,
            started_at: parse_time(&started_at)?,
            finished_at: finished_at.as_deref().map(parse_time).transpose()?,
            updated_at: parse_time(&updated_at)?,
        })
    }
}

impl<'conn> FirmwareRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn import_directory(
        &self,
        firmware_dir: &Path,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<FirmwareImportOutcome> {
        let files = collect_firmware_files(firmware_dir)?;
        let digest = firmware_digest(&files);
        let source_path = firmware_dir.display().to_string();
        let display_name = firmware_dir
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("firmware")
            .to_string();
        let firmware = ObjectRef::artifact(&digest, &source_path).map_err(from_core_error)?;
        let total_bytes = files.iter().map(|file| file.size).sum::<u64>();
        let binaries_detected = files
            .iter()
            .filter(|file| file.nested_artifact.is_some())
            .count() as u64;
        let unsupported_files = files
            .iter()
            .filter(|file| file.nested_artifact.is_none())
            .count() as u64;

        ArtifactRepository::new(self.connection).upsert_artifact(&ArtifactRecord {
            object_ref: firmware.clone(),
            display_name: display_name.clone(),
            source_path: source_path.clone(),
            stored_path: None,
            sha256: digest.clone(),
            size: total_bytes,
            kind: ArtifactKind::Firmware.as_str().to_string(),
            format: ArtifactFormat::Unknown.as_str().to_string(),
            architecture: "mixed".to_string(),
            import_status: ImportStatus::Indexed.as_str().to_string(),
            created_at: imported_at,
        })?;
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: firmware.clone(),
            artifact_key: None,
            display_name: Some(display_name),
            address: None,
            size: Some(total_bytes),
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "firmware",
                "source_path": source_path,
                "file_count": files.len(),
                "binary_count": binaries_detected,
                "unsupported_files": unsupported_files,
                "total_bytes": total_bytes,
                "command_previews": [
                    format!(":open {firmware}"),
                    format!(":xrefs {firmware}")
                ]
            })
            .to_string(),
        })?;

        for file in &files {
            self.upsert_firmware_file(&firmware, file, imported_at)?;
        }

        let job = AnalysisJobRepository::new(self.connection).insert(&NewAnalysisJob {
            analysis_run_id: None,
            artifact_key: Some(firmware.key.to_string()),
            pass_name: "firmware.import".to_string(),
            profile: "firmware".to_string(),
            status: "succeeded".to_string(),
            progress_current: files.len() as u64,
            progress_total: Some(files.len() as u64),
            objects_produced: files.len() as u64 + binaries_detected + 1,
            diagnostics_count: 0,
            byte_limit: None,
            function_limit: None,
            time_limit_ms: None,
            metadata_json: serde_json::json!({
                "lab_id": "firmware",
                "pass_name": "firmware.import",
                "pass_phase": "import",
                "firmware": firmware.to_string(),
                "source_path": firmware_dir.display().to_string(),
                "files_imported": files.len(),
                "binaries_detected": binaries_detected,
                "unsupported_files": unsupported_files,
                "total_bytes": total_bytes,
                "parameters": {
                    "mode": "directory"
                },
                "log_snippets": [
                    format!("Firmware Lab imported {} files", files.len()),
                    format!("detected {} nested binaries", binaries_detected)
                ]
            })
            .to_string(),
            started_at: imported_at,
        })?;

        Ok(FirmwareImportOutcome {
            firmware,
            files_imported: files.len() as u64,
            binaries_detected,
            unsupported_files,
            total_bytes,
            analysis_job_id: job.id,
        })
    }

    pub fn list_files_for_artifact(
        &self,
        firmware: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<FirmwareFileRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT ff.object_key, ff.firmware_artifact_key, ff.path, ff.parent_path,
                ff.size, ff.sha256, ff.file_type, ff.executable,
                ff.nested_artifact_key, nested.kind, ff.imported_at
            FROM firmware_files ff
            LEFT JOIN objects nested ON nested.object_key = ff.nested_artifact_key
            WHERE ff.firmware_artifact_key = ?1
            ORDER BY ff.path
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![firmware.key.as_str(), limit], |row| {
            Self::firmware_file_from_row(row)
        })?;
        rows.collect()
    }

    fn upsert_firmware_file(
        &self,
        firmware: &ObjectRef,
        file: &ParsedFirmwareFile,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<()> {
        let file_ref = ObjectRef::lab_object(
            ObjectKind::FirmwareFile,
            Some(&firmware.key),
            "firmware",
            &format!("file/{}", file.relative_path),
        )
        .map_err(from_core_error)?;
        let object_repo = ObjectRepository::new(self.connection);

        if let Some(nested_artifact) = &file.nested_artifact {
            ArtifactRepository::new(self.connection).upsert_artifact(&ArtifactRecord {
                object_ref: nested_artifact.clone(),
                display_name: file.relative_path.clone(),
                source_path: file.source_path.display().to_string(),
                stored_path: None,
                sha256: file.sha256.clone(),
                size: file.size,
                kind: ArtifactKind::Binary.as_str().to_string(),
                format: file.file_type.clone(),
                architecture: "unknown".to_string(),
                import_status: ImportStatus::Pending.as_str().to_string(),
                created_at: imported_at,
            })?;
            object_repo.upsert_object(&StoredObject {
                object_ref: nested_artifact.clone(),
                artifact_key: Some(firmware.key.to_string()),
                display_name: Some(file.relative_path.clone()),
                address: None,
                size: Some(file.size),
                source_run_id: None,
                metadata_json: serde_json::json!({
                        "lab_id": "firmware",
                    "parent_artifact": firmware.to_string(),
                    "source_file": file_ref.to_string(),
                    "path": file.relative_path,
                    "sha256": file.sha256,
                    "file_type": file.file_type,
                    "nested_artifact_summary": {
                        "artifact": nested_artifact.to_string(),
                        "source_file": file_ref.to_string(),
                        "path": file.relative_path,
                        "sha256": file.sha256,
                        "size": file.size,
                        "import_status": ImportStatus::Pending.as_str()
                    },
                    "command_previews": [
                        format!(":open {nested_artifact}"),
                        format!(":xrefs {nested_artifact}"),
                        format!("revdeck inspect <project> {nested_artifact}")
                    ]
                })
                .to_string(),
            })?;
        }

        object_repo.upsert_object(&StoredObject {
            object_ref: file_ref.clone(),
            artifact_key: Some(firmware.key.to_string()),
            display_name: Some(file.relative_path.clone()),
            address: None,
            size: Some(file.size),
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "firmware",
                "firmware": firmware.to_string(),
                "path": file.relative_path,
                "parent_path": file.parent_path,
                "source_path": file.source_path.display().to_string(),
                "sha256": file.sha256,
                "size": file.size,
                "file_type": file.file_type,
                "executable": file.executable,
                "nested_artifact": file.nested_artifact.as_ref().map(ToString::to_string),
                "nested_artifact_summary": file.nested_artifact.as_ref().map(|nested_artifact| serde_json::json!({
                    "artifact": nested_artifact.to_string(),
                    "path": file.relative_path,
                    "sha256": file.sha256,
                    "size": file.size,
                    "file_type": file.file_type
                })),
                "command_previews": file.nested_artifact.as_ref().map(|nested_artifact| {
                    vec![
                        format!(":open {file_ref}"),
                        format!(":open {nested_artifact}"),
                        format!(":xrefs {nested_artifact}"),
                        format!(":finding link <finding> {file_ref} evidence")
                    ]
                }).unwrap_or_else(|| vec![
                    format!(":open {file_ref}"),
                    format!(":finding link <finding> {file_ref} evidence")
                ])
            })
            .to_string(),
        })?;
        self.connection.execute(
            "INSERT INTO firmware_files (
                object_key, firmware_artifact_key, path, parent_path, size, sha256,
                file_type, executable, nested_artifact_key, imported_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(object_key) DO UPDATE SET
                firmware_artifact_key = excluded.firmware_artifact_key,
                path = excluded.path,
                parent_path = excluded.parent_path,
                size = excluded.size,
                sha256 = excluded.sha256,
                file_type = excluded.file_type,
                executable = excluded.executable,
                nested_artifact_key = excluded.nested_artifact_key,
                imported_at = excluded.imported_at",
            params![
                file_ref.key.as_str(),
                firmware.key.as_str(),
                file.relative_path,
                file.parent_path.as_deref(),
                to_i64(file.size),
                file.sha256,
                file.file_type,
                file.executable,
                file.nested_artifact
                    .as_ref()
                    .map(|artifact| artifact.key.as_str()),
                format_time(imported_at)?,
            ],
        )?;
        object_repo.upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(EdgeKind::Contains, firmware, &file_ref)
                    .map_err(from_core_error)?,
            ),
            source: firmware.clone(),
            target: file_ref.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "firmware",
                "path": file.relative_path,
                "file_type": file.file_type
            })
            .to_string(),
        })?;
        if let Some(nested_artifact) = &file.nested_artifact {
            object_repo.upsert_edge(&StoredEdge {
                edge_ref: ObjectRef::new(
                    ObjectKind::Edge,
                    StableObjectKey::edge(EdgeKind::DerivedFrom, nested_artifact, &file_ref)
                        .map_err(from_core_error)?,
                ),
                source: nested_artifact.clone(),
                target: file_ref,
                kind: EdgeKind::DerivedFrom,
                confidence: 1.0,
                source_run_id: None,
                metadata_json: serde_json::json!({
                    "lab_id": "firmware",
                    "path": file.relative_path,
                    "sha256": file.sha256
                })
                .to_string(),
            })?;
        }
        Ok(())
    }

    fn firmware_file_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FirmwareFileRecord> {
        let object_key: String = row.get(0)?;
        let firmware_key: String = row.get(1)?;
        let nested_key: Option<String> = row.get(8)?;
        let nested_kind: Option<String> = row.get(9)?;
        let imported_at: String = row.get(10)?;
        Ok(FirmwareFileRecord {
            object_ref: ObjectRef::new(
                ObjectKind::FirmwareFile,
                object_key.parse().map_err(from_core_error)?,
            ),
            firmware_artifact: ObjectRef::new(
                ObjectKind::Artifact,
                firmware_key.parse().map_err(from_core_error)?,
            ),
            path: row.get(2)?,
            parent_path: row.get(3)?,
            size: from_i64(row.get(4)?),
            sha256: row.get(5)?,
            file_type: row.get(6)?,
            executable: row.get(7)?,
            nested_artifact: if let (Some(key), Some(kind)) = (nested_key, nested_kind) {
                Some(ObjectRef::new(
                    kind.parse().map_err(from_core_error)?,
                    key.parse().map_err(from_core_error)?,
                ))
            } else {
                None
            },
            imported_at: parse_time(&imported_at)?,
        })
    }
}

impl<'conn> TraceRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn import_jsonl(
        &self,
        artifact: &ObjectRef,
        source_path: &str,
        jsonl: &str,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<TraceImportOutcome> {
        let mut session_id = derive_trace_session_id(source_path);
        let mut label = session_id.clone();
        let mut diagnostics = Vec::new();
        let mut malformed_lines = 0u64;
        let mut events = Vec::new();

        for (line_index, line) in jsonl.lines().enumerate() {
            let line_number = line_index + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value = match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(value) => value,
                Err(err) => {
                    malformed_lines += 1;
                    diagnostics.push(format!("line {line_number}: invalid JSONL: {err}"));
                    continue;
                }
            };
            let record_type = value
                .get("type")
                .or_else(|| value.get("record_type"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("event");
            if record_type == "session" {
                if let Some(value) = trace_string(&value, &["session_id", "id", "name"]) {
                    session_id = value;
                }
                if let Some(value) = trace_string(&value, &["label", "display_name"]) {
                    label = value;
                } else {
                    label = session_id.clone();
                }
                continue;
            }

            if record_type != "event" {
                malformed_lines += 1;
                diagnostics.push(format!(
                    "line {line_number}: unsupported trace record `{record_type}`"
                ));
                continue;
            }

            let event_index = events.len() as u64;
            let event_id = trace_string(&value, &["event_id", "id"])
                .unwrap_or_else(|| format!("{event_index:06}"));
            let thread_id = trace_string(&value, &["thread_id", "thread"])
                .unwrap_or_else(|| "main".to_string());
            let event_kind = trace_string(&value, &["event_kind", "kind"])
                .unwrap_or_else(|| "event".to_string());
            let timestamp_ns = trace_u64(&value, &["timestamp_ns", "time_ns", "ts"]);
            let function_name = trace_string(&value, &["function", "symbol", "function_name"]);
            let address = trace_u64(&value, &["address", "pc", "ip"]);
            if has_any_key(&value, &["address", "pc", "ip"]) && address.is_none() {
                diagnostics.push(format!(
                    "line {line_number}: address could not be parsed for event {event_id}"
                ));
            }
            let message =
                trace_string(&value, &["message", "summary"]).unwrap_or_else(|| event_kind.clone());
            let raw_json = serde_json::to_string(&value).map_err(json_to_sql_error)?;
            let correlation =
                self.correlate_function(artifact, address, function_name.as_deref())?;
            let correlated = correlation.as_ref().map(|item| item.target.clone());
            let correlation_method = correlation
                .as_ref()
                .map(|item| item.method.clone())
                .unwrap_or_else(|| correlation_miss_reason(address, function_name.as_deref()));
            let correlation_confidence = correlation
                .as_ref()
                .map(|item| item.confidence.clone())
                .unwrap_or_else(|| "none".to_string());

            events.push(ParsedTraceEvent {
                event_index,
                event_id,
                thread_id,
                event_kind,
                timestamp_ns,
                function_name,
                address,
                message,
                correlated,
                correlation_method,
                correlation_confidence,
                raw_json,
            });
        }

        let threads = events
            .iter()
            .map(|event| event.thread_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let session_ref = ObjectRef::lab_object(
            ObjectKind::TraceSession,
            Some(&artifact.key),
            "trace",
            &format!("session/{session_id}"),
        )
        .map_err(from_core_error)?;
        let correlated_events = events
            .iter()
            .filter(|event| event.correlated.is_some())
            .count() as u64;
        let uncorrelated_events = events.len() as u64 - correlated_events;
        let correlation_confidence_counts = correlation_confidence_counts(
            events
                .iter()
                .map(|event| event.correlation_confidence.as_str()),
        );
        let session_metadata = serde_json::json!({
            "lab_id": "trace",
            "session_id": session_id,
            "source_path": source_path,
            "event_count": events.len(),
            "thread_count": threads.len(),
            "correlated_event_count": correlated_events,
            "uncorrelated_event_count": uncorrelated_events,
            "correlation_confidence": correlation_confidence_counts,
            "diagnostics": diagnostics,
            "command_previews": [
                format!(":open {session_ref}"),
                format!(":xrefs {session_ref}")
            ]
        })
        .to_string();
        ObjectRepository::new(self.connection).upsert_object(&StoredObject {
            object_ref: session_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(format!("Trace session {label}")),
            address: None,
            size: Some(events.len() as u64),
            source_run_id: None,
            metadata_json: session_metadata,
        })?;
        self.upsert_session_row(
            &session_ref,
            artifact,
            &session_id,
            &label,
            source_path,
            events.len() as u64,
            threads.len() as u64,
            &diagnostics,
            imported_at,
        )?;

        for event in &events {
            self.upsert_event(&session_ref, artifact, event)?;
        }

        let status = if events.is_empty() && malformed_lines > 0 {
            "failed"
        } else {
            "succeeded"
        };
        let job = AnalysisJobRepository::new(self.connection).insert(&NewAnalysisJob {
            analysis_run_id: None,
            artifact_key: Some(artifact.key.to_string()),
            pass_name: "trace.import".to_string(),
            profile: "trace".to_string(),
            status: status.to_string(),
            progress_current: events.len() as u64,
            progress_total: Some(events.len() as u64 + malformed_lines),
            objects_produced: events.len() as u64 + 1,
            diagnostics_count: diagnostics.len() as u64,
            byte_limit: None,
            function_limit: None,
            time_limit_ms: None,
            metadata_json: serde_json::json!({
                "lab_id": "trace",
                "session": session_ref.to_string(),
                "source_path": source_path,
                "events_imported": events.len(),
                "correlated_events": correlated_events,
                "uncorrelated_events": uncorrelated_events,
                "correlation_confidence": correlation_confidence_counts,
                "malformed_lines": malformed_lines,
                "threads": threads,
                "diagnostics": diagnostics,
                "log_snippets": [
                    format!("Trace Lab imported {} events", events.len()),
                    format!("correlated {} events to functions", correlated_events)
                ]
            })
            .to_string(),
            started_at: imported_at,
        })?;

        Ok(TraceImportOutcome {
            session: session_ref,
            events_imported: events.len() as u64,
            correlated_events,
            malformed_lines,
            diagnostics,
            threads,
            analysis_job_id: job.id,
        })
    }

    pub fn list_sessions_for_artifact(
        &self,
        artifact: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<TraceSessionRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT object_key, artifact_key, session_id, label, source_path, event_count,
                thread_count, diagnostics_json, imported_at
            FROM trace_sessions
            WHERE artifact_key = ?1
            ORDER BY imported_at DESC, object_key
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![artifact.key.as_str(), limit], |row| {
            self.trace_session_from_row(row)
        })?;
        rows.collect()
    }

    pub fn list_events_for_session(
        &self,
        session: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<TraceEventRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT te.object_key, te.session_key, te.artifact_key, te.event_index,
                te.event_id, te.thread_id, te.event_kind, te.timestamp_ns, te.function_name,
                te.address, te.message, te.correlated_object_key, co.kind, te.raw_json
            FROM trace_events te
            LEFT JOIN objects co ON co.object_key = te.correlated_object_key
            WHERE te.session_key = ?1
            ORDER BY te.event_index
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![session.key.as_str(), limit], |row| {
            Self::trace_event_from_row(row)
        })?;
        rows.collect()
    }

    fn upsert_session_row(
        &self,
        session_ref: &ObjectRef,
        artifact: &ObjectRef,
        session_id: &str,
        label: &str,
        source_path: &str,
        event_count: u64,
        thread_count: u64,
        diagnostics: &[String],
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<()> {
        let diagnostics_json = serde_json::to_string(diagnostics).map_err(json_to_sql_error)?;
        self.connection.execute(
            "INSERT INTO trace_sessions (
                object_key, artifact_key, session_id, label, source_path, event_count,
                thread_count, diagnostics_json, imported_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(object_key) DO UPDATE SET
                artifact_key = excluded.artifact_key,
                session_id = excluded.session_id,
                label = excluded.label,
                source_path = excluded.source_path,
                event_count = excluded.event_count,
                thread_count = excluded.thread_count,
                diagnostics_json = excluded.diagnostics_json,
                imported_at = excluded.imported_at",
            params![
                session_ref.key.as_str(),
                artifact.key.as_str(),
                session_id,
                label,
                source_path,
                to_i64(event_count),
                to_i64(thread_count),
                diagnostics_json,
                format_time(imported_at)?,
            ],
        )?;
        Ok(())
    }

    fn upsert_event(
        &self,
        session_ref: &ObjectRef,
        artifact: &ObjectRef,
        event: &ParsedTraceEvent,
    ) -> rusqlite::Result<()> {
        let event_ref = ObjectRef::lab_object(
            ObjectKind::TraceEvent,
            Some(&artifact.key),
            "trace",
            &format!(
                "session/{}/event/{}",
                session_ref.key.as_str(),
                event.event_id
            ),
        )
        .map_err(from_core_error)?;
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: event_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(format!(
                "{} {} {}",
                event.thread_id, event.event_kind, event.message
            )),
            address: event.address,
            size: None,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "trace",
                "session": session_ref.to_string(),
                "event_id": event.event_id,
                "event_index": event.event_index,
                "thread_id": event.thread_id,
                "event_kind": event.event_kind,
                "timestamp_ns": event.timestamp_ns,
                "function": event.function_name,
                "address": event.address,
                "message": event.message,
                "correlated": event.correlated.as_ref().map(ToString::to_string),
                "correlation_method": event.correlation_method,
                "correlation_confidence": event.correlation_confidence,
                "raw": serde_json::from_str::<serde_json::Value>(&event.raw_json)
                    .unwrap_or_else(|_| serde_json::json!({ "raw": event.raw_json })),
                "command_previews": event.correlated.as_ref().map(|target| {
                    vec![
                        format!(":open {target}"),
                        format!(":finding link <finding> {} evidence", event_ref)
                    ]
                }).unwrap_or_else(|| vec![format!(":open {event_ref}")])
            })
            .to_string(),
        })?;
        self.connection.execute(
            "INSERT INTO trace_events (
                object_key, session_key, artifact_key, event_index, event_id, thread_id,
                event_kind, timestamp_ns, function_name, address, message,
                correlated_object_key, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(object_key) DO UPDATE SET
                session_key = excluded.session_key,
                artifact_key = excluded.artifact_key,
                event_index = excluded.event_index,
                event_id = excluded.event_id,
                thread_id = excluded.thread_id,
                event_kind = excluded.event_kind,
                timestamp_ns = excluded.timestamp_ns,
                function_name = excluded.function_name,
                address = excluded.address,
                message = excluded.message,
                correlated_object_key = excluded.correlated_object_key,
                raw_json = excluded.raw_json",
            params![
                event_ref.key.as_str(),
                session_ref.key.as_str(),
                artifact.key.as_str(),
                to_i64(event.event_index),
                event.event_id,
                event.thread_id,
                event.event_kind,
                event.timestamp_ns.map(to_i64),
                event.function_name.as_deref(),
                event.address.map(to_i64),
                event.message,
                event.correlated.as_ref().map(|target| target.key.as_str()),
                event.raw_json,
            ],
        )?;

        object_repo.upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(EdgeKind::Timeline, session_ref, &event_ref)
                    .map_err(from_core_error)?,
            ),
            source: session_ref.clone(),
            target: event_ref.clone(),
            kind: EdgeKind::Timeline,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "trace",
                "event_index": event.event_index,
                "thread_id": event.thread_id
            })
            .to_string(),
        })?;
        if let Some(target) = &event.correlated {
            object_repo.upsert_edge(&StoredEdge {
                edge_ref: ObjectRef::new(
                    ObjectKind::Edge,
                    StableObjectKey::edge(EdgeKind::Correlates, &event_ref, target)
                        .map_err(from_core_error)?,
                ),
                source: event_ref,
                target: target.clone(),
                kind: EdgeKind::Correlates,
                confidence: 1.0,
                source_run_id: None,
                metadata_json: serde_json::json!({
                    "lab_id": "trace",
                    "address": event.address,
                    "function": event.function_name,
                    "correlation_method": event.correlation_method,
                    "correlation_confidence": event.correlation_confidence
                })
                .to_string(),
            })?;
        }
        Ok(())
    }

    fn correlate_function(
        &self,
        artifact: &ObjectRef,
        address: Option<u64>,
        function_name: Option<&str>,
    ) -> rusqlite::Result<Option<FunctionCorrelation>> {
        if let Some(address) = address {
            let correlated = self
                .connection
                .query_row(
                    "SELECT o.object_key
                    FROM functions f
                    JOIN objects o ON o.object_key = f.object_key
                    WHERE o.artifact_key = ?1
                      AND f.virtual_address IS NOT NULL
                      AND f.virtual_address <= ?2
                      AND (f.size IS NULL OR ?2 < f.virtual_address + f.size)
                    ORDER BY f.virtual_address DESC
                    LIMIT 1",
                    params![artifact.key.as_str(), to_i64(address)],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(key) = correlated {
                return Ok(Some(FunctionCorrelation {
                    target: ObjectRef::new(
                        ObjectKind::Function,
                        key.parse().map_err(from_core_error)?,
                    ),
                    method: "address_range".to_string(),
                    confidence: "high".to_string(),
                }));
            }
        }
        if let Some(function_name) = function_name {
            let correlated = self
                .connection
                .query_row(
                    "SELECT o.object_key
                    FROM functions f
                    JOIN objects o ON o.object_key = f.object_key
                    WHERE o.artifact_key = ?1
                      AND lower(f.name) = lower(?2)
                    ORDER BY f.virtual_address, f.object_key
                    LIMIT 1",
                    params![artifact.key.as_str(), function_name],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(key) = correlated {
                return Ok(Some(FunctionCorrelation {
                    target: ObjectRef::new(
                        ObjectKind::Function,
                        key.parse().map_err(from_core_error)?,
                    ),
                    method: "exact_symbol".to_string(),
                    confidence: "medium".to_string(),
                }));
            }
        }
        Ok(None)
    }

    fn trace_session_from_row(
        &self,
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<TraceSessionRecord> {
        let object_key: String = row.get(0)?;
        let artifact_key: String = row.get(1)?;
        let diagnostics_json: String = row.get(7)?;
        let imported_at: String = row.get(8)?;
        Ok(TraceSessionRecord {
            object_ref: ObjectRef::new(
                ObjectKind::TraceSession,
                object_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            session_id: row.get(2)?,
            label: row.get(3)?,
            source_path: row.get(4)?,
            event_count: from_i64(row.get(5)?),
            thread_count: from_i64(row.get(6)?),
            diagnostics: serde_json::from_str(&diagnostics_json).map_err(json_from_sql_error)?,
            imported_at: parse_time(&imported_at)?,
        })
    }

    fn trace_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TraceEventRecord> {
        let object_key: String = row.get(0)?;
        let session_key: String = row.get(1)?;
        let artifact_key: String = row.get(2)?;
        let correlated_key: Option<String> = row.get(11)?;
        let correlated_kind: Option<String> = row.get(12)?;
        let function_name: Option<String> = row.get(8)?;
        let address = row.get::<_, Option<i64>>(9)?.map(from_i64);
        let has_correlation = correlated_key.is_some();
        let correlated =
            if let (Some(key), Some(kind)) = (correlated_key.as_ref(), correlated_kind.as_ref()) {
                Some(ObjectRef::new(
                    kind.parse().map_err(from_core_error)?,
                    key.parse().map_err(from_core_error)?,
                ))
            } else {
                None
            };
        Ok(TraceEventRecord {
            object_ref: ObjectRef::new(
                ObjectKind::TraceEvent,
                object_key.parse().map_err(from_core_error)?,
            ),
            session: ObjectRef::new(
                ObjectKind::TraceSession,
                session_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            event_index: from_i64(row.get(3)?),
            event_id: row.get(4)?,
            thread_id: row.get(5)?,
            event_kind: row.get(6)?,
            timestamp_ns: row.get::<_, Option<i64>>(7)?.map(from_i64),
            function_name: function_name.clone(),
            address,
            message: row.get(10)?,
            correlated,
            correlation_method: correlation_miss_reason(address, function_name.as_deref()),
            correlation_confidence: if has_correlation {
                "legacy".to_string()
            } else {
                "none".to_string()
            },
            raw_json: row.get(13)?,
        })
    }
}

impl<'conn> CrashRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn import_log(
        &self,
        artifact: &ObjectRef,
        source_path: &str,
        log: &str,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<CrashImportOutcome> {
        let mut parsed = parse_crash_log(source_path, log)?;
        for frame in &mut parsed.frames {
            let correlation =
                self.correlate_function(artifact, frame.address, frame.function_name.as_deref())?;
            frame.correlated = correlation.as_ref().map(|item| item.target.clone());
            frame.correlation_method = correlation
                .as_ref()
                .map(|item| item.method.clone())
                .unwrap_or_else(|| {
                    correlation_miss_reason(frame.address, frame.function_name.as_deref())
                });
            frame.correlation_confidence = correlation
                .as_ref()
                .map(|item| item.confidence.clone())
                .unwrap_or_else(|| "none".to_string());
        }
        let correlated_frames = parsed
            .frames
            .iter()
            .filter(|frame| frame.correlated.is_some())
            .count() as u64;
        let uncorrelated_frames = parsed.frames.len() as u64 - correlated_frames;
        let correlation_confidence_counts = correlation_confidence_counts(
            parsed
                .frames
                .iter()
                .map(|frame| frame.correlation_confidence.as_str()),
        );
        let report_ref = ObjectRef::lab_object(
            ObjectKind::CrashReport,
            Some(&artifact.key),
            "crash",
            &format!("report/{}", parsed.crash_id),
        )
        .map_err(from_core_error)?;
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: report_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(format!("Crash report {}", parsed.label)),
            address: parsed.frames.first().and_then(|frame| frame.address),
            size: Some(parsed.frames.len() as u64),
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "crash",
                "crash_id": &parsed.crash_id,
                "source_path": source_path,
                "sanitizer": &parsed.sanitizer,
                "crash_class": &parsed.crash_class,
                "signal": &parsed.signal,
                "message": &parsed.message,
                "signature": &parsed.signature,
                "frame_count": parsed.frames.len(),
                "correlated_frame_count": correlated_frames,
                "uncorrelated_frame_count": uncorrelated_frames,
                "correlation_confidence": correlation_confidence_counts,
                "diagnostics": &parsed.diagnostics,
                "command_previews": [
                    format!(":open {report_ref}"),
                    format!(":xrefs {report_ref}"),
                    format!(":finding link <finding> {report_ref} evidence")
                ]
            })
            .to_string(),
        })?;
        self.upsert_report_row(
            &report_ref,
            artifact,
            source_path,
            &parsed,
            correlated_frames,
            imported_at,
        )?;

        for frame in &parsed.frames {
            self.upsert_frame(&report_ref, artifact, frame)?;
        }
        let clustered_reports = self.upsert_cluster_edges(&report_ref, artifact, &parsed)?;
        let findings_created = self.upsert_crash_finding(
            &report_ref,
            artifact,
            parsed.frames.first(),
            &parsed,
            clustered_reports,
            imported_at,
        )?;

        let status = if parsed.frames.is_empty() {
            "failed"
        } else {
            "succeeded"
        };
        let job = AnalysisJobRepository::new(self.connection).insert(&NewAnalysisJob {
            analysis_run_id: None,
            artifact_key: Some(artifact.key.to_string()),
            pass_name: "crash.import".to_string(),
            profile: "crash".to_string(),
            status: status.to_string(),
            progress_current: parsed.frames.len() as u64,
            progress_total: Some(parsed.frames.len() as u64),
            objects_produced: parsed.frames.len() as u64 + 1 + findings_created,
            diagnostics_count: parsed.diagnostics.len() as u64,
            byte_limit: None,
            function_limit: None,
            time_limit_ms: None,
            metadata_json: serde_json::json!({
                "lab_id": "crash",
                "report": report_ref.to_string(),
                "source_path": source_path,
                "sanitizer": &parsed.sanitizer,
                "crash_class": &parsed.crash_class,
                "signal": &parsed.signal,
                "signature": &parsed.signature,
                "frames_imported": parsed.frames.len(),
                "correlated_frames": correlated_frames,
                "uncorrelated_frames": uncorrelated_frames,
                "correlation_confidence": correlation_confidence_counts,
                "clustered_reports": clustered_reports,
                "findings_created": findings_created,
                "diagnostics": &parsed.diagnostics,
                "log_snippets": [
                    format!("Crash Lab imported {} stack frames", parsed.frames.len()),
                    format!("correlated {} frames to functions", correlated_frames),
                    format!("clustered with {} prior reports", clustered_reports)
                ]
            })
            .to_string(),
            started_at: imported_at,
        })?;

        Ok(CrashImportOutcome {
            report: report_ref,
            frames_imported: parsed.frames.len() as u64,
            correlated_frames,
            clustered_reports,
            findings_created,
            signature: parsed.signature,
            diagnostics: parsed.diagnostics,
            analysis_job_id: job.id,
        })
    }

    pub fn list_reports_for_artifact(
        &self,
        artifact: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<CrashReportRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT object_key, artifact_key, crash_id, label, source_path, sanitizer,
                crash_class, signal, message, signature, frame_count, correlated_frame_count,
                diagnostics_json, imported_at
            FROM crash_reports
            WHERE artifact_key = ?1
            ORDER BY imported_at DESC, object_key
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![artifact.key.as_str(), limit], |row| {
            Self::crash_report_from_row(row)
        })?;
        rows.collect()
    }

    pub fn list_frames_for_report(
        &self,
        report: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<CrashFrameRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT cf.object_key, cf.report_key, cf.artifact_key, cf.frame_index, cf.module,
                cf.function_name, cf.address, cf.offset, cf.source_location, cf.confidence,
                cf.correlated_object_key, co.kind, cf.raw_json
            FROM crash_frames cf
            LEFT JOIN objects co ON co.object_key = cf.correlated_object_key
            WHERE cf.report_key = ?1
            ORDER BY cf.frame_index
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![report.key.as_str(), limit], |row| {
            Self::crash_frame_from_row(row)
        })?;
        rows.collect()
    }

    fn upsert_report_row(
        &self,
        report_ref: &ObjectRef,
        artifact: &ObjectRef,
        source_path: &str,
        report: &ParsedCrashReport,
        correlated_frames: u64,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<()> {
        let diagnostics_json =
            serde_json::to_string(&report.diagnostics).map_err(json_to_sql_error)?;
        self.connection.execute(
            "INSERT INTO crash_reports (
                object_key, artifact_key, crash_id, label, source_path, sanitizer,
                crash_class, signal, message, signature, frame_count,
                correlated_frame_count, diagnostics_json, imported_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            ON CONFLICT(object_key) DO UPDATE SET
                artifact_key = excluded.artifact_key,
                crash_id = excluded.crash_id,
                label = excluded.label,
                source_path = excluded.source_path,
                sanitizer = excluded.sanitizer,
                crash_class = excluded.crash_class,
                signal = excluded.signal,
                message = excluded.message,
                signature = excluded.signature,
                frame_count = excluded.frame_count,
                correlated_frame_count = excluded.correlated_frame_count,
                diagnostics_json = excluded.diagnostics_json,
                imported_at = excluded.imported_at",
            params![
                report_ref.key.as_str(),
                artifact.key.as_str(),
                report.crash_id,
                report.label,
                source_path,
                report.sanitizer,
                report.crash_class,
                report.signal.as_deref(),
                report.message,
                report.signature,
                to_i64(report.frames.len() as u64),
                to_i64(correlated_frames),
                diagnostics_json,
                format_time(imported_at)?,
            ],
        )?;
        Ok(())
    }

    fn upsert_frame(
        &self,
        report_ref: &ObjectRef,
        artifact: &ObjectRef,
        frame: &ParsedCrashFrame,
    ) -> rusqlite::Result<()> {
        let frame_ref = ObjectRef::lab_object(
            ObjectKind::CrashFrame,
            Some(&artifact.key),
            "crash",
            &format!(
                "report/{}/frame/{}",
                report_ref.key.as_str(),
                frame.frame_index
            ),
        )
        .map_err(from_core_error)?;
        let label = crash_frame_label(frame);
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: frame_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(label),
            address: frame.address,
            size: None,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "crash",
                "report": report_ref.to_string(),
                "frame_index": frame.frame_index,
                "module": &frame.module,
                "function": &frame.function_name,
                "address": frame.address,
                "offset": frame.offset,
                "source_location": &frame.source_location,
                "confidence": &frame.confidence,
                "correlated": frame.correlated.as_ref().map(ToString::to_string),
                "correlation_method": frame.correlation_method,
                "correlation_confidence": frame.correlation_confidence,
                "raw": serde_json::from_str::<serde_json::Value>(&frame.raw_json)
                    .unwrap_or_else(|_| serde_json::json!({ "raw": &frame.raw_json })),
                "command_previews": frame.correlated.as_ref().map(|target| {
                    vec![
                        format!(":open {target}"),
                        format!(":finding link <finding> {} evidence", frame_ref)
                    ]
                }).unwrap_or_else(|| vec![format!(":open {frame_ref}")])
            })
            .to_string(),
        })?;
        self.connection.execute(
            "INSERT INTO crash_frames (
                object_key, report_key, artifact_key, frame_index, module, function_name,
                address, offset, source_location, confidence, correlated_object_key, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(object_key) DO UPDATE SET
                report_key = excluded.report_key,
                artifact_key = excluded.artifact_key,
                frame_index = excluded.frame_index,
                module = excluded.module,
                function_name = excluded.function_name,
                address = excluded.address,
                offset = excluded.offset,
                source_location = excluded.source_location,
                confidence = excluded.confidence,
                correlated_object_key = excluded.correlated_object_key,
                raw_json = excluded.raw_json",
            params![
                frame_ref.key.as_str(),
                report_ref.key.as_str(),
                artifact.key.as_str(),
                to_i64(frame.frame_index),
                frame.module.as_deref(),
                frame.function_name.as_deref(),
                frame.address.map(to_i64),
                frame.offset.map(to_i64),
                frame.source_location.as_deref(),
                frame.confidence,
                frame.correlated.as_ref().map(|target| target.key.as_str()),
                frame.raw_json,
            ],
        )?;
        object_repo.upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(EdgeKind::Contains, report_ref, &frame_ref)
                    .map_err(from_core_error)?,
            ),
            source: report_ref.clone(),
            target: frame_ref.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "crash",
                "frame_index": frame.frame_index
            })
            .to_string(),
        })?;
        if let Some(target) = &frame.correlated {
            object_repo.upsert_edge(&StoredEdge {
                edge_ref: ObjectRef::new(
                    ObjectKind::Edge,
                    StableObjectKey::edge(EdgeKind::Correlates, &frame_ref, target)
                        .map_err(from_core_error)?,
                ),
                source: frame_ref,
                target: target.clone(),
                kind: EdgeKind::Correlates,
                confidence: 1.0,
                source_run_id: None,
                metadata_json: serde_json::json!({
                    "lab_id": "crash",
                    "address": frame.address,
                    "function": &frame.function_name,
                    "confidence": &frame.confidence,
                    "correlation_method": frame.correlation_method,
                    "correlation_confidence": frame.correlation_confidence
                })
                .to_string(),
            })?;
        }
        Ok(())
    }

    fn upsert_cluster_edges(
        &self,
        report_ref: &ObjectRef,
        artifact: &ObjectRef,
        report: &ParsedCrashReport,
    ) -> rusqlite::Result<u64> {
        let mut statement = self.connection.prepare(
            "SELECT object_key
            FROM crash_reports
            WHERE artifact_key = ?1 AND signature = ?2 AND object_key != ?3
            ORDER BY imported_at DESC, object_key
            LIMIT 25",
        )?;
        let rows = statement.query_map(
            params![
                artifact.key.as_str(),
                report.signature,
                report_ref.key.as_str()
            ],
            |row| row.get::<_, String>(0),
        )?;
        let prior = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let object_repo = ObjectRepository::new(self.connection);
        for key in &prior {
            let target = ObjectRef::new(
                ObjectKind::CrashReport,
                key.parse().map_err(from_core_error)?,
            );
            object_repo.upsert_edge(&StoredEdge {
                edge_ref: ObjectRef::new(
                    ObjectKind::Edge,
                    StableObjectKey::edge(EdgeKind::ClustersWith, report_ref, &target)
                        .map_err(from_core_error)?,
                ),
                source: report_ref.clone(),
                target,
                kind: EdgeKind::ClustersWith,
                confidence: 1.0,
                source_run_id: None,
                metadata_json: serde_json::json!({
                    "lab_id": "crash",
                    "signature": &report.signature,
                    "sanitizer": &report.sanitizer,
                    "crash_class": &report.crash_class
                })
                .to_string(),
            })?;
        }
        Ok(prior.len() as u64)
    }

    fn upsert_crash_finding(
        &self,
        report_ref: &ObjectRef,
        artifact: &ObjectRef,
        top_frame: Option<&ParsedCrashFrame>,
        report: &ParsedCrashReport,
        clustered_reports: u64,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<u64> {
        let high_risk = crash_class_is_high_risk(&report.crash_class);
        if !high_risk && clustered_reports == 0 {
            return Ok(0);
        }
        let slug = format!("crash-{}", sanitize_key_component(&report.crash_id));
        let created_at = format_time(imported_at)?;
        let finding_ref = ObjectRef::new(
            ObjectKind::Finding,
            StableObjectKey::finding(&slug, &created_at).map_err(from_core_error)?,
        );
        let mut evidence = vec![FindingEvidence::new(
            report_ref.clone(),
            "primary",
            0,
            "Crash report imported by Crash Lab.",
            Some(report.label.clone()),
        )];
        if let Some(frame) = top_frame {
            let frame_ref = ObjectRef::lab_object(
                ObjectKind::CrashFrame,
                Some(&artifact.key),
                "crash",
                &format!(
                    "report/{}/frame/{}",
                    report_ref.key.as_str(),
                    frame.frame_index
                ),
            )
            .unwrap_or_else(|_| report_ref.clone());
            evidence.push(FindingEvidence::new(
                frame_ref,
                "stack_frame",
                1,
                "Top relevant crash stack frame.",
                frame.function_name.clone(),
            ));
        }
        FindingRepository::new(self.connection).upsert_finding(&Finding {
            object_ref: finding_ref,
            title: format!("Crash Lab: {}", report.label),
            severity: if high_risk {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            status: FindingStatus::Draft,
            summary: format!(
                "{} {} crash signature `{}`.",
                report.sanitizer, report.crash_class, report.signature
            ),
            body: format!(
                "Crash Lab imported {} frames, correlated {} top-level evidence edges, and clustered with {} prior reports.",
                report.frames.len(),
                report.frames.iter().filter(|frame| frame.correlated.is_some()).count(),
                clustered_reports
            ),
            tags: vec!["crash".to_string(), report.sanitizer.clone()],
            evidence,
            created_at: imported_at,
            updated_at: imported_at,
        })?;
        Ok(1)
    }

    fn correlate_function(
        &self,
        artifact: &ObjectRef,
        address: Option<u64>,
        function_name: Option<&str>,
    ) -> rusqlite::Result<Option<FunctionCorrelation>> {
        if let Some(address) = address {
            let correlated = self
                .connection
                .query_row(
                    "SELECT o.object_key
                    FROM functions f
                    JOIN objects o ON o.object_key = f.object_key
                    WHERE o.artifact_key = ?1
                      AND f.virtual_address IS NOT NULL
                      AND f.virtual_address <= ?2
                      AND (f.size IS NULL OR ?2 < f.virtual_address + f.size)
                    ORDER BY f.virtual_address DESC
                    LIMIT 1",
                    params![artifact.key.as_str(), to_i64(address)],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(key) = correlated {
                return Ok(Some(FunctionCorrelation {
                    target: ObjectRef::new(
                        ObjectKind::Function,
                        key.parse().map_err(from_core_error)?,
                    ),
                    method: "address_range".to_string(),
                    confidence: "high".to_string(),
                }));
            }
        }
        if let Some(function_name) = function_name {
            let correlated = self
                .connection
                .query_row(
                    "SELECT o.object_key
                    FROM functions f
                    JOIN objects o ON o.object_key = f.object_key
                    WHERE o.artifact_key = ?1
                      AND lower(f.name) = lower(?2)
                    ORDER BY f.virtual_address, f.object_key
                    LIMIT 1",
                    params![artifact.key.as_str(), function_name],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(key) = correlated {
                return Ok(Some(FunctionCorrelation {
                    target: ObjectRef::new(
                        ObjectKind::Function,
                        key.parse().map_err(from_core_error)?,
                    ),
                    method: "exact_symbol".to_string(),
                    confidence: "medium".to_string(),
                }));
            }
        }
        Ok(None)
    }

    fn crash_report_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CrashReportRecord> {
        let object_key: String = row.get(0)?;
        let artifact_key: String = row.get(1)?;
        let diagnostics_json: String = row.get(12)?;
        let imported_at: String = row.get(13)?;
        Ok(CrashReportRecord {
            object_ref: ObjectRef::new(
                ObjectKind::CrashReport,
                object_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            crash_id: row.get(2)?,
            label: row.get(3)?,
            source_path: row.get(4)?,
            sanitizer: row.get(5)?,
            crash_class: row.get(6)?,
            signal: row.get(7)?,
            message: row.get(8)?,
            signature: row.get(9)?,
            frame_count: from_i64(row.get(10)?),
            correlated_frame_count: from_i64(row.get(11)?),
            diagnostics: serde_json::from_str(&diagnostics_json).map_err(json_from_sql_error)?,
            imported_at: parse_time(&imported_at)?,
        })
    }

    fn crash_frame_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CrashFrameRecord> {
        let object_key: String = row.get(0)?;
        let report_key: String = row.get(1)?;
        let artifact_key: String = row.get(2)?;
        let correlated_key: Option<String> = row.get(10)?;
        let correlated_kind: Option<String> = row.get(11)?;
        let function_name: Option<String> = row.get(5)?;
        let address = row.get::<_, Option<i64>>(6)?.map(from_i64);
        let has_correlation = correlated_key.is_some();
        let correlated =
            if let (Some(key), Some(kind)) = (correlated_key.as_ref(), correlated_kind.as_ref()) {
                Some(ObjectRef::new(
                    kind.parse().map_err(from_core_error)?,
                    key.parse().map_err(from_core_error)?,
                ))
            } else {
                None
            };
        Ok(CrashFrameRecord {
            object_ref: ObjectRef::new(
                ObjectKind::CrashFrame,
                object_key.parse().map_err(from_core_error)?,
            ),
            report: ObjectRef::new(
                ObjectKind::CrashReport,
                report_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            frame_index: from_i64(row.get(3)?),
            module: row.get(4)?,
            function_name: function_name.clone(),
            address,
            offset: row.get::<_, Option<i64>>(7)?.map(from_i64),
            source_location: row.get(8)?,
            confidence: row.get(9)?,
            correlated,
            correlation_method: correlation_miss_reason(address, function_name.as_deref()),
            correlation_confidence: if has_correlation {
                "legacy".to_string()
            } else {
                "none".to_string()
            },
            raw_json: row.get(12)?,
        })
    }
}

impl<'conn> ProtocolRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn import_sample(
        &self,
        artifact: &ObjectRef,
        source_path: &str,
        sample_json: &str,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<ProtocolImportOutcome> {
        let mut parsed = parse_protocol_sample(source_path, sample_json)?;
        let mut correlated_fields = 0u64;
        for message in &mut parsed.messages {
            for field in &mut message.fields {
                field.correlated = self.correlate_string(artifact, field.string_hint.as_deref())?;
                if field.correlated.is_some() {
                    correlated_fields += 1;
                }
            }
        }

        let field_count = parsed
            .messages
            .iter()
            .map(|message| message.fields.len() as u64)
            .sum::<u64>();
        let sample_ref = ObjectRef::lab_object(
            ObjectKind::ProtocolSample,
            Some(&artifact.key),
            "protocol",
            &format!("sample/{}", parsed.sample_id),
        )
        .map_err(from_core_error)?;
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: sample_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(format!("Protocol sample {}", parsed.label)),
            address: None,
            size: Some(field_count),
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "protocol",
                "sample_id": &parsed.sample_id,
                "source_path": source_path,
                "schema_hypothesis": &parsed.schema_hypothesis,
                "message_count": parsed.messages.len(),
                "field_count": field_count,
                "correlated_field_count": correlated_fields,
                "diagnostics": &parsed.diagnostics,
                "command_previews": [
                    format!(":open {sample_ref}"),
                    format!(":xrefs {sample_ref}"),
                    format!(":finding link <finding> {sample_ref} evidence")
                ]
            })
            .to_string(),
        })?;
        self.upsert_sample_row(
            &sample_ref,
            artifact,
            source_path,
            &parsed,
            field_count,
            imported_at,
        )?;

        for message in &parsed.messages {
            let message_ref = self.upsert_message(&sample_ref, artifact, message)?;
            for field in &message.fields {
                self.upsert_field(&sample_ref, &message_ref, artifact, field)?;
            }
        }

        let status = if parsed.messages.is_empty() {
            "failed"
        } else {
            "succeeded"
        };
        let job = AnalysisJobRepository::new(self.connection).insert(&NewAnalysisJob {
            analysis_run_id: None,
            artifact_key: Some(artifact.key.to_string()),
            pass_name: "protocol.import".to_string(),
            profile: "protocol".to_string(),
            status: status.to_string(),
            progress_current: parsed.messages.len() as u64,
            progress_total: Some(parsed.messages.len() as u64),
            objects_produced: parsed.messages.len() as u64 + field_count + 1,
            diagnostics_count: parsed.diagnostics.len() as u64,
            byte_limit: None,
            function_limit: None,
            time_limit_ms: None,
            metadata_json: serde_json::json!({
                "lab_id": "protocol",
                "sample": sample_ref.to_string(),
                "source_path": source_path,
                "messages_imported": parsed.messages.len(),
                "fields_imported": field_count,
                "correlated_fields": correlated_fields,
                "schema_hypothesis": &parsed.schema_hypothesis,
                "diagnostics": &parsed.diagnostics,
                "log_snippets": [
                    format!("Protocol Lab imported {} messages", parsed.messages.len()),
                    format!("normalized {} protocol fields", field_count),
                    format!("linked {} fields to binary strings", correlated_fields)
                ]
            })
            .to_string(),
            started_at: imported_at,
        })?;

        Ok(ProtocolImportOutcome {
            sample: sample_ref,
            messages_imported: parsed.messages.len() as u64,
            fields_imported: field_count,
            correlated_fields,
            diagnostics: parsed.diagnostics,
            schema_hypothesis: parsed.schema_hypothesis,
            analysis_job_id: job.id,
        })
    }

    pub fn list_samples_for_artifact(
        &self,
        artifact: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<ProtocolSampleRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT object_key, artifact_key, sample_id, label, source_path, schema_hypothesis,
                message_count, field_count, diagnostics_json, imported_at
            FROM protocol_samples
            WHERE artifact_key = ?1
            ORDER BY imported_at DESC, object_key
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![artifact.key.as_str(), limit], |row| {
            Self::protocol_sample_from_row(row)
        })?;
        rows.collect()
    }

    pub fn list_messages_for_sample(
        &self,
        sample: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<ProtocolMessageRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT object_key, sample_key, artifact_key, message_index, message_id, direction,
                payload_len, field_count, schema_hypothesis, raw_json
            FROM protocol_messages
            WHERE sample_key = ?1
            ORDER BY message_index
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![sample.key.as_str(), limit], |row| {
            Self::protocol_message_from_row(row)
        })?;
        rows.collect()
    }

    pub fn list_fields_for_message(
        &self,
        message: &ObjectRef,
        limit: usize,
    ) -> rusqlite::Result<Vec<ProtocolFieldRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT pf.object_key, pf.message_key, pf.sample_key, pf.artifact_key,
                pf.field_index, pf.name, pf.byte_offset, pf.byte_length, pf.field_type,
                pf.confidence, pf.entropy, pf.printable_ratio, pf.integer_value,
                pf.string_hint, pf.correlated_object_key, co.kind, pf.raw_json
            FROM protocol_fields pf
            LEFT JOIN objects co ON co.object_key = pf.correlated_object_key
            WHERE pf.message_key = ?1
            ORDER BY pf.field_index
            LIMIT ?2",
        )?;
        let rows = statement.query_map(params![message.key.as_str(), limit], |row| {
            Self::protocol_field_from_row(row)
        })?;
        rows.collect()
    }

    fn upsert_sample_row(
        &self,
        sample_ref: &ObjectRef,
        artifact: &ObjectRef,
        source_path: &str,
        sample: &ParsedProtocolSample,
        field_count: u64,
        imported_at: OffsetDateTime,
    ) -> rusqlite::Result<()> {
        let diagnostics_json =
            serde_json::to_string(&sample.diagnostics).map_err(json_to_sql_error)?;
        self.connection.execute(
            "INSERT INTO protocol_samples (
                object_key, artifact_key, sample_id, label, source_path, schema_hypothesis,
                message_count, field_count, diagnostics_json, imported_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(object_key) DO UPDATE SET
                artifact_key = excluded.artifact_key,
                sample_id = excluded.sample_id,
                label = excluded.label,
                source_path = excluded.source_path,
                schema_hypothesis = excluded.schema_hypothesis,
                message_count = excluded.message_count,
                field_count = excluded.field_count,
                diagnostics_json = excluded.diagnostics_json,
                imported_at = excluded.imported_at",
            params![
                sample_ref.key.as_str(),
                artifact.key.as_str(),
                sample.sample_id,
                sample.label,
                source_path,
                sample.schema_hypothesis.as_deref(),
                to_i64(sample.messages.len() as u64),
                to_i64(field_count),
                diagnostics_json,
                format_time(imported_at)?,
            ],
        )?;
        Ok(())
    }

    fn upsert_message(
        &self,
        sample_ref: &ObjectRef,
        artifact: &ObjectRef,
        message: &ParsedProtocolMessage,
    ) -> rusqlite::Result<ObjectRef> {
        let message_ref = ObjectRef::lab_object(
            ObjectKind::ProtocolMessage,
            Some(&artifact.key),
            "protocol",
            &format!(
                "sample/{}/message/{}",
                sample_ref.key.as_str(),
                message.message_id
            ),
        )
        .map_err(from_core_error)?;
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: message_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(format!(
                "{} {} fields={}",
                message.direction,
                message.message_id,
                message.fields.len()
            )),
            address: None,
            size: Some(message.payload.len() as u64),
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "protocol",
                "sample": sample_ref.to_string(),
                "message_id": &message.message_id,
                "message_index": message.message_index,
                "direction": &message.direction,
                "payload_len": message.payload.len(),
                "field_count": message.fields.len(),
                "schema_hypothesis": &message.schema_hypothesis,
                "payload_hex": hex_digest(&message.payload),
                "raw": serde_json::from_str::<serde_json::Value>(&message.raw_json)
                    .unwrap_or_else(|_| serde_json::json!({ "raw": &message.raw_json })),
                "command_previews": [
                    format!(":open {message_ref}"),
                    format!(":xrefs {message_ref}"),
                    format!(":finding link <finding> {message_ref} evidence")
                ]
            })
            .to_string(),
        })?;
        self.connection.execute(
            "INSERT INTO protocol_messages (
                object_key, sample_key, artifact_key, message_index, message_id, direction,
                payload_len, field_count, schema_hypothesis, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(object_key) DO UPDATE SET
                sample_key = excluded.sample_key,
                artifact_key = excluded.artifact_key,
                message_index = excluded.message_index,
                message_id = excluded.message_id,
                direction = excluded.direction,
                payload_len = excluded.payload_len,
                field_count = excluded.field_count,
                schema_hypothesis = excluded.schema_hypothesis,
                raw_json = excluded.raw_json",
            params![
                message_ref.key.as_str(),
                sample_ref.key.as_str(),
                artifact.key.as_str(),
                to_i64(message.message_index),
                message.message_id,
                message.direction,
                to_i64(message.payload.len() as u64),
                to_i64(message.fields.len() as u64),
                message.schema_hypothesis.as_deref(),
                message.raw_json,
            ],
        )?;
        object_repo.upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(EdgeKind::Contains, sample_ref, &message_ref)
                    .map_err(from_core_error)?,
            ),
            source: sample_ref.clone(),
            target: message_ref.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "protocol",
                "message_index": message.message_index,
                "direction": &message.direction
            })
            .to_string(),
        })?;
        Ok(message_ref)
    }

    fn upsert_field(
        &self,
        sample_ref: &ObjectRef,
        message_ref: &ObjectRef,
        artifact: &ObjectRef,
        field: &ParsedProtocolField,
    ) -> rusqlite::Result<()> {
        let field_ref = ObjectRef::lab_object(
            ObjectKind::ProtocolField,
            Some(&artifact.key),
            "protocol",
            &format!(
                "message/{}/field/{}",
                message_ref.key.as_str(),
                field.field_index
            ),
        )
        .map_err(from_core_error)?;
        let object_repo = ObjectRepository::new(self.connection);
        object_repo.upsert_object(&StoredObject {
            object_ref: field_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(format!(
                "{} off={} len={}",
                field.name, field.byte_offset, field.byte_length
            )),
            address: None,
            size: Some(field.byte_length),
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "protocol",
                "sample": sample_ref.to_string(),
                "message": message_ref.to_string(),
                "field_index": field.field_index,
                "name": &field.name,
                "byte_offset": field.byte_offset,
                "byte_length": field.byte_length,
                "byte_range": {
                    "start": field.byte_offset,
                    "end": field.byte_offset + field.byte_length,
                    "length": field.byte_length
                },
                "field_type": &field.field_type,
                "confidence": &field.confidence,
                "entropy": field.entropy,
                "printable_ratio": field.printable_ratio,
                "integer_value": field.integer_value,
                "string_hint": &field.string_hint,
                "value_hex": &field.value_hex,
                "correlated": field.correlated.as_ref().map(ToString::to_string),
                "pivots": protocol_field_pivots(field, &field_ref),
                "raw": serde_json::from_str::<serde_json::Value>(&field.raw_json)
                    .unwrap_or_else(|_| serde_json::json!({ "raw": &field.raw_json })),
                "command_previews": field.correlated.as_ref().map(|target| {
                    vec![
                        format!(":open {target}"),
                        format!("revdeck strings <project> --contains \"{}\" --json", field.string_hint.as_deref().unwrap_or(&field.name)),
                        format!(":finding link <finding> {} evidence", field_ref)
                    ]
                }).unwrap_or_else(|| vec![
                    format!(":open {field_ref}"),
                    format!("revdeck inspect <project> {field_ref} --json"),
                    format!(":finding link <finding> {field_ref} evidence")
                ])
            })
            .to_string(),
        })?;
        self.connection.execute(
            "INSERT INTO protocol_fields (
                object_key, message_key, sample_key, artifact_key, field_index, name,
                byte_offset, byte_length, field_type, confidence, entropy, printable_ratio,
                integer_value, string_hint, correlated_object_key, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(object_key) DO UPDATE SET
                message_key = excluded.message_key,
                sample_key = excluded.sample_key,
                artifact_key = excluded.artifact_key,
                field_index = excluded.field_index,
                name = excluded.name,
                byte_offset = excluded.byte_offset,
                byte_length = excluded.byte_length,
                field_type = excluded.field_type,
                confidence = excluded.confidence,
                entropy = excluded.entropy,
                printable_ratio = excluded.printable_ratio,
                integer_value = excluded.integer_value,
                string_hint = excluded.string_hint,
                correlated_object_key = excluded.correlated_object_key,
                raw_json = excluded.raw_json",
            params![
                field_ref.key.as_str(),
                message_ref.key.as_str(),
                sample_ref.key.as_str(),
                artifact.key.as_str(),
                to_i64(field.field_index),
                field.name,
                to_i64(field.byte_offset),
                to_i64(field.byte_length),
                field.field_type,
                field.confidence,
                field.entropy,
                field.printable_ratio,
                field
                    .integer_value
                    .and_then(|value| i64::try_from(value).ok()),
                field.string_hint.as_deref(),
                field.correlated.as_ref().map(|target| target.key.as_str()),
                field.raw_json,
            ],
        )?;
        object_repo.upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(EdgeKind::Contains, message_ref, &field_ref)
                    .map_err(from_core_error)?,
            ),
            source: message_ref.clone(),
            target: field_ref.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: serde_json::json!({
                "lab_id": "protocol",
                "field_index": field.field_index,
                "name": &field.name
            })
            .to_string(),
        })?;
        if let Some(target) = &field.correlated {
            object_repo.upsert_edge(&StoredEdge {
                edge_ref: ObjectRef::new(
                    ObjectKind::Edge,
                    StableObjectKey::edge(EdgeKind::References, &field_ref, target)
                        .map_err(from_core_error)?,
                ),
                source: field_ref,
                target: target.clone(),
                kind: EdgeKind::References,
                confidence: 0.85,
                source_run_id: None,
                metadata_json: serde_json::json!({
                    "lab_id": "protocol",
                    "string_hint": &field.string_hint,
                    "field_name": &field.name
                })
                .to_string(),
            })?;
        }
        Ok(())
    }

    fn correlate_string(
        &self,
        artifact: &ObjectRef,
        string_hint: Option<&str>,
    ) -> rusqlite::Result<Option<ObjectRef>> {
        let Some(string_hint) = string_hint.map(str::trim).filter(|value| value.len() >= 3) else {
            return Ok(None);
        };
        let correlated = self
            .connection
            .query_row(
                "SELECT o.object_key
                FROM strings s
                JOIN objects o ON o.object_key = s.object_key
                WHERE o.artifact_key = ?1
                  AND length(s.value) >= 3
                  AND (
                    lower(s.value) = lower(?2)
                    OR instr(lower(s.value), lower(?2)) > 0
                    OR instr(lower(?2), lower(s.value)) > 0
                  )
                ORDER BY length(s.value) DESC, o.object_key
                LIMIT 1",
                params![artifact.key.as_str(), string_hint],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(correlated.map(|key| {
            ObjectRef::new(
                ObjectKind::String,
                key.parse().expect("stored string key must be valid"),
            )
        }))
    }

    fn protocol_sample_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProtocolSampleRecord> {
        let object_key: String = row.get(0)?;
        let artifact_key: String = row.get(1)?;
        let diagnostics_json: String = row.get(8)?;
        let imported_at: String = row.get(9)?;
        Ok(ProtocolSampleRecord {
            object_ref: ObjectRef::new(
                ObjectKind::ProtocolSample,
                object_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            sample_id: row.get(2)?,
            label: row.get(3)?,
            source_path: row.get(4)?,
            schema_hypothesis: row.get(5)?,
            message_count: from_i64(row.get(6)?),
            field_count: from_i64(row.get(7)?),
            diagnostics: serde_json::from_str(&diagnostics_json).map_err(json_from_sql_error)?,
            imported_at: parse_time(&imported_at)?,
        })
    }

    fn protocol_message_from_row(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<ProtocolMessageRecord> {
        let object_key: String = row.get(0)?;
        let sample_key: String = row.get(1)?;
        let artifact_key: String = row.get(2)?;
        Ok(ProtocolMessageRecord {
            object_ref: ObjectRef::new(
                ObjectKind::ProtocolMessage,
                object_key.parse().map_err(from_core_error)?,
            ),
            sample: ObjectRef::new(
                ObjectKind::ProtocolSample,
                sample_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            message_index: from_i64(row.get(3)?),
            message_id: row.get(4)?,
            direction: row.get(5)?,
            payload_len: from_i64(row.get(6)?),
            field_count: from_i64(row.get(7)?),
            schema_hypothesis: row.get(8)?,
            raw_json: row.get(9)?,
        })
    }

    fn protocol_field_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProtocolFieldRecord> {
        let object_key: String = row.get(0)?;
        let message_key: String = row.get(1)?;
        let sample_key: String = row.get(2)?;
        let artifact_key: String = row.get(3)?;
        let correlated_key: Option<String> = row.get(14)?;
        let correlated_kind: Option<String> = row.get(15)?;
        Ok(ProtocolFieldRecord {
            object_ref: ObjectRef::new(
                ObjectKind::ProtocolField,
                object_key.parse().map_err(from_core_error)?,
            ),
            message: ObjectRef::new(
                ObjectKind::ProtocolMessage,
                message_key.parse().map_err(from_core_error)?,
            ),
            sample: ObjectRef::new(
                ObjectKind::ProtocolSample,
                sample_key.parse().map_err(from_core_error)?,
            ),
            artifact: ObjectRef::new(
                ObjectKind::Artifact,
                artifact_key.parse().map_err(from_core_error)?,
            ),
            field_index: from_i64(row.get(4)?),
            name: row.get(5)?,
            byte_offset: from_i64(row.get(6)?),
            byte_length: from_i64(row.get(7)?),
            field_type: row.get(8)?,
            confidence: row.get(9)?,
            entropy: row.get(10)?,
            printable_ratio: row.get(11)?,
            integer_value: row.get::<_, Option<i64>>(12)?.map(from_i64),
            string_hint: row.get(13)?,
            correlated: if let (Some(key), Some(kind)) = (correlated_key, correlated_kind) {
                Some(ObjectRef::new(
                    kind.parse().map_err(from_core_error)?,
                    key.parse().map_err(from_core_error)?,
                ))
            } else {
                None
            },
            raw_json: row.get(16)?,
        })
    }
}

impl<'conn> PluginRunRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn insert(&self, run: &NewPluginRun) -> rusqlite::Result<PluginRunRecord> {
        self.connection.execute(
            "INSERT INTO plugin_runs (
                analysis_run_id, plugin_id, plugin_version, manifest_digest, input_digest,
                config_digest, status, permissions_json, diagnostics_json, started_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run.analysis_run_id,
                run.plugin_id,
                run.plugin_version,
                run.manifest_digest,
                run.input_digest,
                run.config_digest.as_deref(),
                run.status,
                run.permissions_json,
                run.diagnostics_json,
                format_time(run.started_at)?,
            ],
        )?;
        let id = self.connection.last_insert_rowid();
        self.get(id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn finish(
        &self,
        id: i64,
        status: &str,
        diagnostics_json: &str,
        finished_at: OffsetDateTime,
    ) -> rusqlite::Result<PluginRunRecord> {
        self.connection.execute(
            "UPDATE plugin_runs
            SET status = ?2,
                diagnostics_json = ?3,
                finished_at = ?4
            WHERE id = ?1",
            params![id, status, diagnostics_json, format_time(finished_at)?],
        )?;
        self.get(id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn list_recent(&self, limit: usize) -> rusqlite::Result<Vec<PluginRunRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT id, analysis_run_id, plugin_id, plugin_version, manifest_digest,
                input_digest, config_digest, status, permissions_json, diagnostics_json,
                started_at, finished_at
            FROM plugin_runs
            ORDER BY started_at DESC, id DESC
            LIMIT ?1",
        )?;
        let records = statement
            .query_map([limit], Self::record_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(records)
    }

    pub fn get(&self, id: i64) -> rusqlite::Result<Option<PluginRunRecord>> {
        self.connection
            .query_row(
                "SELECT id, analysis_run_id, plugin_id, plugin_version, manifest_digest,
                    input_digest, config_digest, status, permissions_json, diagnostics_json,
                    started_at, finished_at
                FROM plugin_runs
                WHERE id = ?1",
                [id],
                Self::record_from_row,
            )
            .optional()
    }

    fn record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PluginRunRecord> {
        let started_at: String = row.get(10)?;
        let finished_at: Option<String> = row.get(11)?;
        Ok(PluginRunRecord {
            id: row.get(0)?,
            analysis_run_id: row.get(1)?,
            plugin_id: row.get(2)?,
            plugin_version: row.get(3)?,
            manifest_digest: row.get(4)?,
            input_digest: row.get(5)?,
            config_digest: row.get(6)?,
            status: row.get(7)?,
            permissions_json: row.get(8)?,
            diagnostics_json: row.get(9)?,
            started_at: parse_time(&started_at)?,
            finished_at: finished_at.as_deref().map(parse_time).transpose()?,
        })
    }
}

fn export_artifact_keys(evidence_objects: &[revdeck_core::ObjectSummary]) -> BTreeSet<String> {
    evidence_objects
        .iter()
        .filter_map(|object| {
            object.artifact_key.clone().or_else(|| {
                (object.object_ref.kind == ObjectKind::Artifact)
                    .then(|| object.object_ref.key.to_string())
            })
        })
        .collect()
}

impl<'conn> ProjectMetadataRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn set_metadata(
        &self,
        key: &str,
        value: &str,
        updated_at: OffsetDateTime,
    ) -> rusqlite::Result<()> {
        let key = validate_metadata_key(key)?;
        self.connection.execute(
            "INSERT INTO project_metadata (key, value, updated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at",
            params![key, value, format_time(updated_at)?],
        )?;
        Ok(())
    }

    pub fn get_metadata(&self, key: &str) -> rusqlite::Result<Option<ProjectMetadataRecord>> {
        let key = validate_metadata_key(key)?;
        self.connection
            .query_row(
                "SELECT key, value, updated_at FROM project_metadata WHERE key = ?1",
                params![key],
                Self::metadata_from_row,
            )
            .optional()
    }

    pub fn list_metadata(&self) -> rusqlite::Result<Vec<ProjectMetadataRecord>> {
        let mut statement = self
            .connection
            .prepare("SELECT key, value, updated_at FROM project_metadata ORDER BY key")?;
        let rows = statement.query_map([], Self::metadata_from_row)?;
        rows.collect()
    }

    pub fn add_note(
        &self,
        category: &str,
        title: &str,
        body: &str,
        created_at: OffsetDateTime,
    ) -> rusqlite::Result<ProjectNoteRecord> {
        let category = validate_note_field("category", category)?;
        let title = validate_note_field("title", title)?;
        self.connection.execute(
            "INSERT INTO project_notes (category, title, body, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)",
            params![category, title, body, format_time(created_at)?],
        )?;
        let note_id = self.connection.last_insert_rowid();
        self.get_note(note_id)?.ok_or_else(|| {
            string_from_sql_error(
                "inserted note was not found".to_string(),
                rusqlite::types::Type::Integer,
            )
        })
    }

    pub fn list_notes(&self, limit: usize) -> rusqlite::Result<Vec<ProjectNoteRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT note_id, category, title, body, created_at, updated_at
            FROM project_notes
            ORDER BY updated_at DESC, note_id DESC
            LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], Self::note_from_row)?;
        rows.collect()
    }

    pub fn get_note(&self, note_id: i64) -> rusqlite::Result<Option<ProjectNoteRecord>> {
        self.connection
            .query_row(
                "SELECT note_id, category, title, body, created_at, updated_at
                FROM project_notes
                WHERE note_id = ?1",
                params![note_id],
                Self::note_from_row,
            )
            .optional()
    }

    fn metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectMetadataRecord> {
        let updated_at: String = row.get(2)?;
        Ok(ProjectMetadataRecord {
            key: row.get(0)?,
            value: row.get(1)?,
            updated_at: parse_time(&updated_at)?,
        })
    }

    fn note_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectNoteRecord> {
        let created_at: String = row.get(4)?;
        let updated_at: String = row.get(5)?;
        Ok(ProjectNoteRecord {
            note_id: row.get(0)?,
            category: row.get(1)?,
            title: row.get(2)?,
            body: row.get(3)?,
            created_at: parse_time(&created_at)?,
            updated_at: parse_time(&updated_at)?,
        })
    }
}

fn export_analysis_job(job: AnalysisJobRecord) -> ExportAnalysisJob {
    ExportAnalysisJob {
        id: job.id,
        artifact_key: job.artifact_key,
        pass_name: job.pass_name,
        profile: job.profile,
        status: job.status,
        diagnostics_count: job.diagnostics_count,
        metadata_json: job.metadata_json,
        started_at: job.started_at,
        finished_at: job.finished_at,
    }
}

fn export_plugin_run(run: PluginRunRecord) -> ExportPluginRun {
    ExportPluginRun {
        id: run.id,
        plugin_id: run.plugin_id,
        plugin_version: run.plugin_version,
        manifest_digest: run.manifest_digest,
        input_digest: run.input_digest,
        config_digest: run.config_digest,
        status: run.status,
        permissions_json: run.permissions_json,
        diagnostics_json: run.diagnostics_json,
        started_at: run.started_at,
        finished_at: run.finished_at,
    }
}

fn export_case_metadata(record: ProjectMetadataRecord) -> ExportCaseMetadata {
    ExportCaseMetadata {
        key: record.key,
        value: record.value,
        updated_at: record.updated_at,
    }
}

fn export_case_note(record: ProjectNoteRecord) -> ExportCaseNote {
    ExportCaseNote {
        note_id: record.note_id,
        category: record.category,
        title: record.title,
        body: record.body,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn metadata_plugin_run_id(metadata_json: &str) -> Option<i64> {
    let value = serde_json::from_str::<serde_json::Value>(metadata_json).ok()?;
    value.get("plugin_run_id").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
            .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
    })
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).expect("foundation addresses must fit SQLite signed integers")
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).expect("stored unsigned value must be non-negative")
}

fn format_time(value: OffsetDateTime) -> rusqlite::Result<String> {
    value
        .format(&Rfc3339)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
}

fn parse_time(value: &str) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn validate_metadata_key(key: &str) -> rusqlite::Result<&str> {
    let key = key.trim();
    if key.is_empty() {
        return Err(string_from_sql_error(
            "metadata key must not be empty".to_string(),
            rusqlite::types::Type::Text,
        ));
    }
    if key.chars().any(char::is_whitespace) {
        return Err(string_from_sql_error(
            "metadata key must not contain whitespace".to_string(),
            rusqlite::types::Type::Text,
        ));
    }
    Ok(key)
}

fn validate_note_field<'a>(field: &str, value: &'a str) -> rusqlite::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(string_from_sql_error(
            format!("{field} must not be empty"),
            rusqlite::types::Type::Text,
        ));
    }
    Ok(value)
}

fn collect_firmware_files(firmware_dir: &Path) -> rusqlite::Result<Vec<ParsedFirmwareFile>> {
    let root = firmware_dir.canonicalize().map_err(io_to_sql_error)?;
    if !root.is_dir() {
        return Err(string_from_sql_error(
            format!(
                "firmware path is not a directory: {}",
                firmware_dir.display()
            ),
            rusqlite::types::Type::Text,
        ));
    }
    let mut paths = Vec::new();
    collect_file_paths(&root, &mut paths)?;
    paths.sort();

    let mut files = Vec::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(io_to_sql_error)?;
        let metadata = fs::metadata(&path).map_err(io_to_sql_error)?;
        let relative_path = normalize_firmware_relative_path(&root, &path);
        let parent_path = Path::new(&relative_path)
            .parent()
            .and_then(|parent| parent.to_str())
            .map(|parent| parent.replace('\\', "/"))
            .filter(|parent| !parent.is_empty());
        let sha256 = sha256_hex(&bytes);
        let file_type = detect_firmware_file_type(&path, &bytes);
        let executable = is_firmware_executable(&path, &file_type);
        let nested_artifact = if matches!(file_type.as_str(), "elf" | "pe") {
            Some(ObjectRef::artifact(&sha256, &relative_path).map_err(from_core_error)?)
        } else {
            None
        };
        files.push(ParsedFirmwareFile {
            source_path: path,
            relative_path,
            parent_path,
            size: metadata.len(),
            sha256,
            file_type,
            executable,
            nested_artifact,
        });
    }
    Ok(files)
}

fn collect_file_paths(root: &Path, output: &mut Vec<PathBuf>) -> rusqlite::Result<()> {
    for entry in fs::read_dir(root).map_err(io_to_sql_error)? {
        let entry = entry.map_err(io_to_sql_error)?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(io_to_sql_error)?;
        if metadata.is_dir() {
            collect_file_paths(&path, output)?;
        } else if metadata.is_file() {
            output.push(path);
        }
    }
    Ok(())
}

fn normalize_firmware_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn firmware_digest(files: &[ParsedFirmwareFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(file.sha256.as_bytes());
        hasher.update([0]);
        hasher.update(file.size.to_string().as_bytes());
        hasher.update([0]);
    }
    hex_digest(hasher.finalize().as_slice())
}

fn detect_firmware_file_type(path: &Path, bytes: &[u8]) -> String {
    if bytes.starts_with(b"\x7fELF") {
        return "elf".to_string();
    }
    if bytes.starts_with(b"MZ") {
        return "pe".to_string();
    }
    if bytes.starts_with(b"#!") {
        return "script".to_string();
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "sh" | "bash" | "ps1" | "py" => "script".to_string(),
        "conf" | "cfg" | "ini" | "json" | "txt" | "xml" | "service" => "text".to_string(),
        "so" | "bin" | "elf" => "binary".to_string(),
        _ if is_mostly_printable(bytes) => "text".to_string(),
        _ => "data".to_string(),
    }
}

fn is_firmware_executable(path: &Path, file_type: &str) -> bool {
    if matches!(file_type, "elf" | "pe" | "script") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "exe" | "bin" | "so"
    )
}

fn is_mostly_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    printable * 100 / bytes.len() >= 85
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn derive_trace_session_id(source_path: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;
    let stem = std::path::Path::new(source_path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(source_path);
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            output.push('-');
            last_was_dash = true;
        }
    }
    let output = output.trim_matches('-').to_string();
    if output.is_empty() {
        "trace-session".to_string()
    } else {
        output
    }
}

fn trace_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    if value.is_number() || value.is_boolean() {
                        Some(value.to_string())
                    } else {
                        None
                    }
                })
        })
}

fn trace_u64(value: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(|value| {
            value.as_u64().or_else(|| {
                let text = value.as_str()?.trim();
                if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    text.parse::<u64>().ok()
                }
            })
        })
}

fn has_any_key(value: &serde_json::Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| value.get(*key).is_some())
}

fn parse_protocol_sample(
    source_path: &str,
    sample_json: &str,
) -> rusqlite::Result<ParsedProtocolSample> {
    let trimmed = sample_json.trim();
    if trimmed.is_empty() {
        return Err(string_from_sql_error(
            "protocol sample is empty".to_string(),
            rusqlite::types::Type::Text,
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(trimmed).map_err(json_from_sql_error)?;
    if !value.is_object() {
        return Err(string_from_sql_error(
            format!(
                "protocol sample must be a JSON object, got {}",
                value_type_name(&value)
            ),
            rusqlite::types::Type::Text,
        ));
    }

    let mut diagnostics = Vec::new();
    let record_type =
        trace_string(&value, &["type", "record_type"]).unwrap_or_else(|| "protocol".to_string());
    if !matches!(
        record_type.as_str(),
        "protocol" | "protocol_sample" | "sample"
    ) {
        diagnostics.push(format!("unsupported protocol record type `{record_type}`"));
    }
    let sample_id = trace_string(&value, &["sample_id", "id", "name"])
        .unwrap_or_else(|| derive_protocol_sample_id(source_path, trimmed));
    let label = trace_string(&value, &["label", "title", "display_name"])
        .unwrap_or_else(|| sample_id.clone());
    let schema_hypothesis = trace_string(&value, &["schema_hypothesis", "schema", "hypothesis"]);
    let mut messages = Vec::new();

    if let Some(array) = value
        .get("messages")
        .or_else(|| value.get("samples"))
        .and_then(serde_json::Value::as_array)
    {
        for (index, message_value) in array.iter().enumerate() {
            if !message_value.is_object() {
                diagnostics.push(format!("message {index}: expected object"));
                continue;
            }
            messages.push(parse_protocol_message(
                message_value,
                index as u64,
                &mut diagnostics,
            )?);
        }
    } else if has_any_key(&value, &["payload_hex", "payload", "payload_text", "bytes"]) {
        messages.push(parse_protocol_message(&value, 0, &mut diagnostics)?);
    } else {
        diagnostics.push("no protocol messages found".to_string());
    }

    Ok(ParsedProtocolSample {
        sample_id,
        label,
        schema_hypothesis,
        diagnostics,
        messages,
    })
}

fn parse_protocol_message(
    value: &serde_json::Value,
    default_index: u64,
    diagnostics: &mut Vec<String>,
) -> rusqlite::Result<ParsedProtocolMessage> {
    let message_index = trace_u64(value, &["message_index", "index", "n"]).unwrap_or(default_index);
    let message_id = trace_string(value, &["message_id", "id", "name"])
        .unwrap_or_else(|| format!("message-{message_index:04}"));
    let direction = trace_string(value, &["direction", "dir"])
        .map(|value| normalize_protocol_token(&value))
        .unwrap_or_else(|| "unknown".to_string());
    let payload = decode_protocol_payload(value, diagnostics, &message_id)?;
    let schema_hypothesis = trace_string(value, &["schema_hypothesis", "schema", "hypothesis"]);
    let mut fields = Vec::new();
    if let Some(array) = value.get("fields").and_then(serde_json::Value::as_array) {
        for (index, field_value) in array.iter().enumerate() {
            if !field_value.is_object() {
                diagnostics.push(format!("{message_id} field {index}: expected object"));
                continue;
            }
            if let Some(field) = parse_protocol_field(
                field_value,
                index as u64,
                &payload,
                diagnostics,
                &message_id,
            )? {
                fields.push(field);
            }
        }
    } else if !payload.is_empty() {
        diagnostics.push(format!(
            "{message_id}: no fields declared; created whole-payload field"
        ));
        let value = serde_json::json!({
            "name": "payload",
            "offset": 0,
            "length": payload.len(),
            "type": "bytes",
            "confidence": "fallback"
        });
        if let Some(field) = parse_protocol_field(&value, 0, &payload, diagnostics, &message_id)? {
            fields.push(field);
        }
    }
    fields.sort_by_key(|field| field.field_index);

    Ok(ParsedProtocolMessage {
        message_index,
        message_id,
        direction,
        payload,
        schema_hypothesis,
        fields,
        raw_json: serde_json::to_string(value).map_err(json_to_sql_error)?,
    })
}

fn parse_protocol_field(
    value: &serde_json::Value,
    default_index: u64,
    payload: &[u8],
    diagnostics: &mut Vec<String>,
    message_id: &str,
) -> rusqlite::Result<Option<ParsedProtocolField>> {
    let field_index = trace_u64(value, &["field_index", "index", "n"]).unwrap_or(default_index);
    let name = trace_string(value, &["name", "field", "label"])
        .unwrap_or_else(|| format!("field_{field_index:02}"));
    let Some(byte_offset) = trace_u64(value, &["byte_offset", "offset", "start"]) else {
        diagnostics.push(format!("{message_id} field {field_index}: missing offset"));
        return Ok(None);
    };
    let Some(byte_length) = trace_u64(value, &["byte_length", "length", "len", "size"]) else {
        diagnostics.push(format!("{message_id} field {field_index}: missing length"));
        return Ok(None);
    };
    let start = usize::try_from(byte_offset).unwrap_or(usize::MAX);
    let length = usize::try_from(byte_length).unwrap_or(usize::MAX);
    let end = start.saturating_add(length);
    if start > payload.len() || end > payload.len() {
        diagnostics.push(format!(
            "{message_id} field {field_index}: slice {byte_offset}+{byte_length} exceeds payload length {}",
            payload.len()
        ));
        return Ok(None);
    }
    let bytes = &payload[start..end];
    let field_type = trace_string(value, &["field_type", "type", "kind"])
        .map(|value| normalize_protocol_token(&value))
        .unwrap_or_else(|| infer_protocol_field_type(bytes));
    let confidence = trace_string(value, &["confidence"]).unwrap_or_else(|| "inferred".to_string());
    let explicit_hint = trace_string(value, &["string_hint", "hint", "value"]);
    let string_hint = explicit_hint.or_else(|| infer_protocol_string_hint(bytes, &field_type));
    Ok(Some(ParsedProtocolField {
        field_index,
        name,
        byte_offset,
        byte_length,
        field_type,
        confidence,
        value_hex: hex_digest(bytes),
        entropy: byte_entropy(bytes),
        printable_ratio: printable_ratio(bytes),
        integer_value: integer_like_value(bytes),
        string_hint,
        correlated: None,
        raw_json: serde_json::to_string(value).map_err(json_to_sql_error)?,
    }))
}

fn decode_protocol_payload(
    value: &serde_json::Value,
    diagnostics: &mut Vec<String>,
    message_id: &str,
) -> rusqlite::Result<Vec<u8>> {
    if let Some(hex) = trace_string(value, &["payload_hex", "hex", "bytes_hex"]) {
        return decode_hex_bytes(&hex).ok_or_else(|| {
            string_from_sql_error(
                format!("{message_id}: invalid payload_hex"),
                rusqlite::types::Type::Text,
            )
        });
    }
    if let Some(text) = trace_string(value, &["payload_text", "text"]) {
        return Ok(text.into_bytes());
    }
    if let Some(payload) = value.get("payload") {
        if let Some(text) = payload.as_str() {
            if let Some(bytes) = decode_hex_bytes(text) {
                return Ok(bytes);
            }
            diagnostics.push(format!(
                "{message_id}: payload string is not hex; imported as UTF-8 bytes"
            ));
            return Ok(text.as_bytes().to_vec());
        }
    }
    if let Some(array) = value.get("bytes").and_then(serde_json::Value::as_array) {
        let mut bytes = Vec::with_capacity(array.len());
        for (index, byte) in array.iter().enumerate() {
            let Some(value) = byte.as_u64().filter(|value| *value <= 0xff) else {
                return Err(string_from_sql_error(
                    format!("{message_id}: bytes[{index}] is not a byte"),
                    rusqlite::types::Type::Integer,
                ));
            };
            bytes.push(value as u8);
        }
        return Ok(bytes);
    }
    diagnostics.push(format!("{message_id}: missing payload"));
    Ok(Vec::new())
}

fn derive_protocol_sample_id(source_path: &str, seed: &str) -> String {
    let stem = Path::new(source_path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("protocol");
    let slug = sanitize_key_component(stem).trim_matches('-').to_string();
    let digest = short_content_digest(seed.as_bytes());
    if slug.is_empty() {
        format!("protocol-{digest}")
    } else {
        format!("{slug}-{digest}")
    }
}

fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    let mut normalized = value.trim();
    if let Some(stripped) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        normalized = stripped;
    }
    let digits = normalized
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != ':' && *ch != '-' && *ch != '_')
        .collect::<String>();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for index in (0..digits.len()).step_by(2) {
        let byte = u8::from_str_radix(&digits[index..index + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

fn byte_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .copied()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    printable as f64 / bytes.len() as f64
}

fn integer_like_value(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
    )
}

fn infer_protocol_field_type(bytes: &[u8]) -> String {
    if infer_protocol_string_hint(bytes, "string").is_some() {
        "string".to_string()
    } else if bytes.len() <= 8 {
        "integer".to_string()
    } else {
        "bytes".to_string()
    }
}

fn infer_protocol_string_hint(bytes: &[u8], field_type: &str) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(bytes)
        .ok()?
        .trim_matches(char::from(0))
        .trim();
    if text.len() < 3 {
        return None;
    }
    if normalize_protocol_token(field_type) == "string" || printable_ratio(bytes) >= 0.85 {
        Some(text.to_string())
    } else {
        None
    }
}

fn normalize_protocol_token(value: &str) -> String {
    normalize_crash_token(value)
}

fn protocol_field_pivots(
    field: &ParsedProtocolField,
    field_ref: &ObjectRef,
) -> Vec<serde_json::Value> {
    let mut pivots = vec![
        serde_json::json!({
            "kind": "field",
            "label": "Open protocol field",
            "target": field_ref.to_string(),
            "command": format!("revdeck inspect <project> {field_ref} --json")
        }),
        serde_json::json!({
            "kind": "offset",
            "label": "Payload byte range",
            "byte_offset": field.byte_offset,
            "byte_length": field.byte_length
        }),
    ];
    if let Some(hint) = field.string_hint.as_deref() {
        pivots.push(serde_json::json!({
            "kind": "string_hint",
            "label": "Search matching binary strings",
            "value": hint,
            "correlated": field.correlated.as_ref().map(ToString::to_string),
            "command": format!("revdeck strings <project> --contains \"{hint}\" --json")
        }));
    }
    pivots
}

fn correlation_miss_reason(address: Option<u64>, function_name: Option<&str>) -> String {
    match (
        address,
        function_name
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ) {
        (Some(_), Some(_)) => "unresolved_address_symbol".to_string(),
        (Some(_), None) => "unresolved_address".to_string(),
        (None, Some(_)) => "unresolved_symbol".to_string(),
        (None, None) => "missing_address_symbol".to_string(),
    }
}

fn correlation_confidence_counts<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.to_string()).or_default() += 1;
    }
    counts
}

fn parse_crash_log(source_path: &str, log: &str) -> rusqlite::Result<ParsedCrashReport> {
    let trimmed = log.trim();
    if trimmed.is_empty() {
        return Err(string_from_sql_error(
            "crash log is empty".to_string(),
            rusqlite::types::Type::Text,
        ));
    }

    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(value) if value.is_object() => parse_crash_json(source_path, &value),
        Ok(value) => {
            let mut parsed = parse_crash_text(source_path, trimmed)?;
            parsed.diagnostics.push(format!(
                "top-level JSON value `{}` is not a crash object; parsed as text fallback",
                value_type_name(&value)
            ));
            Ok(parsed)
        }
        Err(_) => parse_crash_text(source_path, trimmed),
    }
}

fn parse_crash_json(
    source_path: &str,
    value: &serde_json::Value,
) -> rusqlite::Result<ParsedCrashReport> {
    let mut diagnostics = Vec::new();
    let record_type =
        trace_string(value, &["type", "record_type"]).unwrap_or_else(|| "crash".into());
    if !matches!(record_type.as_str(), "crash" | "crash_report" | "report") {
        diagnostics.push(format!("unsupported crash record type `{record_type}`"));
    }

    let sanitizer = trace_string(value, &["sanitizer", "tool", "runtime"])
        .map(|value| normalize_crash_token(&value))
        .unwrap_or_else(|| infer_sanitizer_from_text(&value.to_string()));
    let crash_class = trace_string(value, &["crash_class", "class", "bug_type", "kind"])
        .map(|value| normalize_crash_token(&value))
        .unwrap_or_else(|| "unknown".to_string());
    let signal = trace_string(value, &["signal", "exception", "fatal_signal"]);
    let message = trace_string(value, &["message", "summary", "description"])
        .unwrap_or_else(|| format!("{sanitizer} {crash_class}"));
    let label = trace_string(value, &["label", "title", "name"])
        .unwrap_or_else(|| format!("{sanitizer} {crash_class}"));

    let mut frames = Vec::new();
    if let Some(array) = value
        .get("frames")
        .or_else(|| value.get("stack"))
        .or_else(|| value.get("stack_frames"))
        .and_then(serde_json::Value::as_array)
    {
        for (index, frame_value) in array.iter().enumerate() {
            if !frame_value.is_object() {
                diagnostics.push(format!("frame {index}: expected object"));
                continue;
            }
            let frame_index =
                trace_u64(frame_value, &["frame_index", "index", "n"]).unwrap_or(index as u64);
            let address = trace_u64(frame_value, &["address", "pc", "ip"]);
            if has_any_key(frame_value, &["address", "pc", "ip"]) && address.is_none() {
                diagnostics.push(format!("frame {frame_index}: address could not be parsed"));
            }
            let raw_json = serde_json::to_string(frame_value).map_err(json_to_sql_error)?;
            frames.push(ParsedCrashFrame {
                frame_index,
                module: trace_string(frame_value, &["module", "binary", "image"]),
                function_name: trace_string(frame_value, &["function", "symbol", "function_name"]),
                address,
                offset: trace_u64(frame_value, &["offset", "module_offset"]),
                source_location: trace_string(
                    frame_value,
                    &["source", "source_location", "location", "file_line"],
                ),
                confidence: trace_string(frame_value, &["confidence"])
                    .unwrap_or_else(|| "reported".to_string()),
                correlated: None,
                correlation_method: "unresolved".to_string(),
                correlation_confidence: "none".to_string(),
                raw_json,
            });
        }
    } else if let Some(stack) = value.get("stack").and_then(serde_json::Value::as_str) {
        frames = parse_crash_text_frames(stack, &mut diagnostics);
    } else {
        diagnostics.push("no stack frames found in crash JSON".to_string());
    }

    frames.sort_by_key(|frame| frame.frame_index);
    let mut report = ParsedCrashReport {
        crash_id: trace_string(value, &["crash_id", "id", "case_id"])
            .unwrap_or_else(|| derive_crash_id(source_path, &message)),
        label,
        sanitizer,
        crash_class,
        signal,
        message,
        signature: String::new(),
        diagnostics,
        frames,
    };
    report.signature = trace_string(value, &["signature", "dedupe_signature"])
        .unwrap_or_else(|| build_crash_signature(&report));
    Ok(report)
}

fn parse_crash_text(source_path: &str, log: &str) -> rusqlite::Result<ParsedCrashReport> {
    let mut diagnostics = Vec::new();
    let frames = parse_crash_text_frames(log, &mut diagnostics);
    let first_line = log
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("crash log");
    let sanitizer = infer_sanitizer_from_text(log);
    let crash_class = infer_crash_class_from_text(log);
    let signal = infer_signal_from_text(log);
    let message = first_line.to_string();
    let label = if sanitizer == "unknown" && crash_class == "unknown" {
        first_line.to_string()
    } else {
        format!("{sanitizer} {crash_class}")
    };
    if frames.is_empty() {
        diagnostics.push("no stack frames found in crash text".to_string());
    }
    let mut report = ParsedCrashReport {
        crash_id: derive_crash_id(source_path, log),
        label,
        sanitizer,
        crash_class,
        signal,
        message,
        signature: String::new(),
        diagnostics,
        frames,
    };
    report.signature = build_crash_signature(&report);
    Ok(report)
}

fn parse_crash_text_frames(log: &str, diagnostics: &mut Vec<String>) -> Vec<ParsedCrashFrame> {
    let mut frames = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix('#') else {
            continue;
        };
        let digits = rest
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if digits.is_empty() {
            continue;
        }
        let frame_index = digits.parse::<u64>().unwrap_or(frames.len() as u64);
        let body = rest[digits.len()..].trim();
        let tokens = body.split_whitespace().collect::<Vec<_>>();
        let address = tokens.iter().find_map(|token| {
            parse_u64_text(token.trim_matches(|ch: char| ch == '(' || ch == ')'))
        });
        let function_name = tokens
            .windows(2)
            .find_map(|window| (window[0] == "in").then(|| clean_symbol_token(window[1])))
            .or_else(|| {
                tokens
                    .iter()
                    .find(|token| !token.starts_with("0x"))
                    .map(|token| clean_symbol_token(token))
            });
        let module = tokens
            .iter()
            .find(|token| token.contains('(') || token.ends_with(".so") || token.ends_with(".elf"))
            .map(|token| {
                token
                    .trim_matches(|ch: char| ch == '(' || ch == ')')
                    .to_string()
            });
        let source_location = tokens
            .iter()
            .rev()
            .find(|token| token.contains(':') && !token.starts_with("0x"))
            .map(|token| {
                token
                    .trim_matches(|ch: char| ch == '(' || ch == ')')
                    .to_string()
            });
        if address.is_none() && function_name.is_none() {
            diagnostics.push(format!(
                "frame {frame_index}: no address or function parsed"
            ));
        }
        frames.push(ParsedCrashFrame {
            frame_index,
            module,
            function_name,
            address,
            offset: None,
            source_location,
            confidence: "reported".to_string(),
            correlated: None,
            correlation_method: "unresolved".to_string(),
            correlation_confidence: "none".to_string(),
            raw_json: serde_json::json!({ "line": trimmed }).to_string(),
        });
    }
    frames
}

fn build_crash_signature(report: &ParsedCrashReport) -> String {
    let top = report
        .frames
        .first()
        .and_then(frame_identity)
        .unwrap_or_else(|| "no-frame".to_string());
    let stack_prefix = report
        .frames
        .iter()
        .take(4)
        .filter_map(frame_identity)
        .collect::<Vec<_>>()
        .join(">");
    format!(
        "{}|{}|{}|{}|{}",
        normalize_crash_token(&report.sanitizer),
        normalize_crash_token(&report.crash_class),
        report.signal.as_deref().unwrap_or("no-signal"),
        normalize_crash_token(&top),
        if stack_prefix.is_empty() {
            "no-stack".to_string()
        } else {
            normalize_crash_token(&stack_prefix)
        }
    )
}

fn frame_identity(frame: &ParsedCrashFrame) -> Option<String> {
    frame
        .function_name
        .clone()
        .or_else(|| frame.address.map(|address| format!("0x{address:x}")))
}

fn crash_frame_label(frame: &ParsedCrashFrame) -> String {
    let subject = frame
        .function_name
        .as_deref()
        .or(frame.module.as_deref())
        .unwrap_or("unknown");
    let address = frame
        .address
        .map(|address| format!(" @ 0x{address:x}"))
        .unwrap_or_default();
    format!("#{} {subject}{address}", frame.frame_index)
}

fn crash_class_is_high_risk(crash_class: &str) -> bool {
    let normalized = normalize_crash_token(crash_class);
    matches!(
        normalized.as_str(),
        "heap-use-after-free"
            | "stack-use-after-free"
            | "use-after-free"
            | "heap-buffer-overflow"
            | "stack-buffer-overflow"
            | "global-buffer-overflow"
            | "double-free"
            | "wild-free"
            | "out-of-bounds"
    ) || normalized.contains("use-after-free")
        || normalized.contains("buffer-overflow")
}

fn infer_sanitizer_from_text(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("addresssanitizer") || lower.contains("asan") {
        "asan".to_string()
    } else if lower.contains("threadsanitizer") || lower.contains("tsan") {
        "tsan".to_string()
    } else if lower.contains("undefinedbehaviorsanitizer") || lower.contains("ubsan") {
        "ubsan".to_string()
    } else if lower.contains("memorysanitizer") || lower.contains("msan") {
        "msan".to_string()
    } else if lower.contains("panicked at") || lower.contains("panic") {
        "panic".to_string()
    } else {
        "unknown".to_string()
    }
}

fn infer_crash_class_from_text(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    for marker in [
        "heap-use-after-free",
        "stack-use-after-free",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
        "double-free",
        "segmentation fault",
        "panic",
    ] {
        if lower.contains(marker) {
            return normalize_crash_token(marker);
        }
    }
    "unknown".to_string()
}

fn infer_signal_from_text(text: &str) -> Option<String> {
    text.split(|ch: char| ch.is_whitespace() || ch == ':' || ch == ',' || ch == ')')
        .find(|token| token.starts_with("SIG") && token.len() > 3)
        .map(str::to_string)
}

fn derive_crash_id(source_path: &str, seed: &str) -> String {
    let stem = Path::new(source_path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("crash");
    let slug = sanitize_key_component(stem).trim_matches('-').to_string();
    let digest = short_content_digest(seed.as_bytes());
    if slug.is_empty() {
        format!("crash-{digest}")
    } else {
        format!("{slug}-{digest}")
    }
}

fn normalize_crash_token(value: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            output.push('-');
            last_dash = true;
        }
    }
    let output = output.trim_matches('-').to_string();
    if output.is_empty() {
        "unknown".to_string()
    } else {
        output
    }
}

fn clean_symbol_token(value: &str) -> String {
    value
        .trim_matches(|ch: char| {
            ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == ',' || ch == ':'
        })
        .to_string()
}

fn parse_u64_text(value: &str) -> Option<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u64>().ok()
    }
}

fn short_content_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_digest(&digest[..6])
}

fn value_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn from_core_error(err: revdeck_core::RevDeckError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
}

fn json_to_sql_error(err: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(err))
}

fn json_from_sql_error(err: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
}

fn string_from_sql_error(err: String, ty: rusqlite::types::Type) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, ty, err.into())
}

fn io_to_sql_error(err: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(err))
}

fn sanitize_key_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::migrate;
    use revdeck_core::{ObjectKind, StableObjectKeyBuilder};
    use rusqlite::Connection;
    use time::macros::datetime;

    fn migrated_connection() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        connection
    }

    fn artifact_record(object_ref: ObjectRef, display_name: &str) -> ArtifactRecord {
        ArtifactRecord {
            object_ref,
            display_name: display_name.to_string(),
            source_path: format!("fixtures/{display_name}"),
            stored_path: None,
            sha256: format!("{display_name}-sha256"),
            size: 12,
            kind: "binary".to_string(),
            format: "elf".to_string(),
            architecture: "x86_64".to_string(),
            import_status: "indexed".to_string(),
            created_at: datetime!(2026-05-13 00:00 UTC),
        }
    }

    #[test]
    fn analysis_runs_record_success_and_failure_details() {
        let connection = migrated_connection();
        let repo = AnalysisRunRepository::new(&connection);
        let new_run = NewAnalysisRun::new(
            None,
            "fixture.importer",
            "0.1.0",
            "input-hash",
            datetime!(2026-05-13 00:00 UTC),
        )
        .unwrap();

        let running = repo.start(&new_run).unwrap();
        assert_eq!(running.status, AnalysisRunStatus::Running);
        assert!(!running.status.is_terminal());

        let finished = repo
            .finish(
                running.id,
                AnalysisRunStatus::Succeeded,
                datetime!(2026-05-13 00:01 UTC),
                Some(r#"{"objects":0}"#),
                None,
                true,
            )
            .unwrap();
        assert_eq!(finished.status, AnalysisRunStatus::Succeeded);
        assert_eq!(
            finished.diagnostics_json.as_deref(),
            Some(r#"{"objects":0}"#)
        );
        assert!(finished.error_json.is_none());
        assert!(finished.recoverable);
        assert!(finished.finished_at.is_some());
    }

    #[test]
    fn analysis_jobs_round_trip_pass_status() {
        let connection = migrated_connection();
        let run_repo = AnalysisRunRepository::new(&connection);
        let job_repo = AnalysisJobRepository::new(&connection);
        let run = run_repo
            .start(
                &NewAnalysisRun::new(
                    None,
                    "fixture.importer",
                    "0.1.0",
                    "input-hash",
                    datetime!(2026-05-13 00:00 UTC),
                )
                .unwrap(),
            )
            .unwrap();

        let started_at = datetime!(2026-05-13 00:00 UTC);
        let finished_at = datetime!(2026-05-13 00:01 UTC);
        let job = job_repo
            .insert(&NewAnalysisJob {
                analysis_run_id: Some(run.id),
                artifact_key: None,
                pass_name: "binary.parse".to_string(),
                profile: "quick".to_string(),
                status: "running".to_string(),
                progress_current: 0,
                progress_total: Some(1),
                objects_produced: 0,
                diagnostics_count: 0,
                byte_limit: Some(4096),
                function_limit: None,
                time_limit_ms: None,
                metadata_json: "{}".to_string(),
                started_at,
            })
            .unwrap();
        assert_eq!(job.status, "running");
        assert_eq!(job.profile, "quick");
        assert_eq!(job.byte_limit, Some(4096));

        let finished = job_repo
            .finish(
                job.id,
                &AnalysisJobUpdate {
                    status: "succeeded".to_string(),
                    progress_current: 1,
                    progress_total: Some(1),
                    objects_produced: 5,
                    diagnostics_count: 0,
                    metadata_json: r#"{"sections":2}"#.to_string(),
                    finished_at,
                },
            )
            .unwrap();
        assert_eq!(finished.status, "succeeded");
        assert_eq!(finished.progress_current, 1);
        assert_eq!(finished.objects_produced, 5);
        assert_eq!(finished.finished_at, Some(finished_at));

        let recent = job_repo.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].pass_name, "binary.parse");
    }

    #[test]
    fn analysis_jobs_list_recent_for_artifact_filters_and_preserves_partial_status() {
        let connection = migrated_connection();
        let artifact_a = ObjectRef::artifact("aaa", "fixtures/a").unwrap();
        let artifact_b = ObjectRef::artifact("bbb", "fixtures/b").unwrap();
        let artifact_repo = ArtifactRepository::new(&connection);
        artifact_repo
            .upsert_artifact(&artifact_record(artifact_a.clone(), "a"))
            .unwrap();
        artifact_repo
            .upsert_artifact(&artifact_record(artifact_b.clone(), "b"))
            .unwrap();
        let job_repo = AnalysisJobRepository::new(&connection);

        for (artifact, pass_name, status, started_at, progress_total) in [
            (
                &artifact_a,
                "binary.parse",
                "succeeded",
                datetime!(2026-05-13 00:00 UTC),
                Some(1),
            ),
            (
                &artifact_b,
                "binary.triage",
                "failed",
                datetime!(2026-05-13 00:01 UTC),
                Some(1),
            ),
            (
                &artifact_a,
                "binary.cfg",
                "skipped",
                datetime!(2026-05-13 00:02 UTC),
                None,
            ),
            (
                &artifact_a,
                "binary.dataflow",
                "running",
                datetime!(2026-05-13 00:03 UTC),
                None,
            ),
        ] {
            job_repo
                .insert(&NewAnalysisJob {
                    analysis_run_id: None,
                    artifact_key: Some(artifact.key.to_string()),
                    pass_name: pass_name.to_string(),
                    profile: "quick".to_string(),
                    status: status.to_string(),
                    progress_current: 0,
                    progress_total,
                    objects_produced: 0,
                    diagnostics_count: 0,
                    byte_limit: None,
                    function_limit: None,
                    time_limit_ms: None,
                    metadata_json: "{}".to_string(),
                    started_at,
                })
                .unwrap();
        }

        let recent = job_repo.list_recent_for_artifact(&artifact_a, 10).unwrap();

        assert_eq!(recent.len(), 3);
        assert!(recent
            .iter()
            .all(|job| job.artifact_key.as_deref() == Some(artifact_a.key.as_str())));
        assert_eq!(recent[0].pass_name, "binary.dataflow");
        assert_eq!(recent[0].status, "running");
        assert!(recent[0].finished_at.is_none());
        assert!(recent[0].progress_total.is_none());
        assert!(recent.iter().any(|job| job.status == "skipped"));
        assert!(recent.iter().all(|job| job.pass_name != "binary.triage"));

        let limited = job_repo
            .list_recent_by_artifact_key(artifact_a.key.as_str(), 2)
            .unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].pass_name, "binary.dataflow");
        assert_eq!(limited[1].pass_name, "binary.cfg");
        assert!(job_repo
            .list_recent_by_artifact_key("missing-artifact", 10)
            .unwrap()
            .is_empty());
        assert!(job_repo
            .list_recent_for_artifact(&artifact_a, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn analysis_jobs_preserve_metadata_snippets_and_limits() {
        let connection = migrated_connection();
        let artifact = ObjectRef::artifact("snippet", "fixtures/snippet").unwrap();
        ArtifactRepository::new(&connection)
            .upsert_artifact(&artifact_record(artifact.clone(), "snippet"))
            .unwrap();
        let job_repo = AnalysisJobRepository::new(&connection);
        let metadata_json = r#"{
            "parameters":{"profile":"quick","native_cfg":false},
            "diagnostic_snippets":["pass_skipped_by_profile: quick skipped cfg"],
            "log_snippets":["cfg skipped by profile"],
            "cfg_edges":0
        }"#;

        let job = job_repo
            .insert(&NewAnalysisJob {
                analysis_run_id: None,
                artifact_key: Some(artifact.key.to_string()),
                pass_name: "binary.cfg".to_string(),
                profile: "quick".to_string(),
                status: "skipped".to_string(),
                progress_current: 0,
                progress_total: None,
                objects_produced: 0,
                diagnostics_count: 1,
                byte_limit: Some(4096),
                function_limit: Some(50),
                time_limit_ms: Some(1000),
                metadata_json: metadata_json.to_string(),
                started_at: datetime!(2026-05-13 00:00 UTC),
            })
            .unwrap();

        let loaded = job_repo.get(job.id).unwrap().unwrap();

        assert_eq!(loaded.byte_limit, Some(4096));
        assert_eq!(loaded.function_limit, Some(50));
        assert_eq!(loaded.time_limit_ms, Some(1000));
        assert!(loaded.metadata_json.contains("parameters"));
        assert!(loaded.metadata_json.contains("diagnostic_snippets"));
        assert!(loaded.metadata_json.contains("log_snippets"));
    }

    #[test]
    fn plugin_runs_round_trip_audit_record() {
        let connection = migrated_connection();
        let repo = PluginRunRepository::new(&connection);
        let started_at = datetime!(2026-05-13 12:00 UTC);
        let finished_at = datetime!(2026-05-13 12:01 UTC);

        let run = repo
            .insert(&NewPluginRun {
                analysis_run_id: None,
                plugin_id: "com.revdeck.test".to_string(),
                plugin_version: "0.1.0".to_string(),
                manifest_digest: "manifest".to_string(),
                input_digest: "input".to_string(),
                config_digest: Some("config".to_string()),
                status: "running".to_string(),
                permissions_json: "{\"network\":false}".to_string(),
                diagnostics_json: "[]".to_string(),
                started_at,
            })
            .unwrap();
        assert_eq!(run.plugin_id, "com.revdeck.test");
        assert_eq!(run.status, "running");
        assert_eq!(run.finished_at, None);

        let finished = repo
            .finish(run.id, "succeeded", "[{\"code\":\"ok\"}]", finished_at)
            .unwrap();
        assert_eq!(finished.status, "succeeded");
        assert_eq!(finished.finished_at, Some(finished_at));
        assert_eq!(finished.diagnostics_json, "[{\"code\":\"ok\"}]");
    }

    #[test]
    fn object_repository_round_trips_stable_refs() {
        let connection = migrated_connection();
        let repo = ObjectRepository::new(&connection);
        let key = StableObjectKeyBuilder::new(ObjectKind::Artifact)
            .component("sha256", "abc123")
            .unwrap()
            .component("path", "fixtures/minimal")
            .unwrap()
            .finish()
            .unwrap();
        let object_ref = ObjectRef::new(ObjectKind::Artifact, key);
        let stored = StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: None,
            display_name: Some("minimal".to_string()),
            address: None,
            size: Some(12),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        };

        repo.upsert_object(&stored).unwrap();
        assert_eq!(repo.get_object(&object_ref).unwrap(), Some(stored));
    }

    #[test]
    fn artifact_repository_round_trips_index_metadata() {
        let connection = migrated_connection();
        let repo = ArtifactRepository::new(&connection);
        let object_ref = ObjectRef::artifact("abc123", "fixtures/minimal").unwrap();
        let artifact = ArtifactRecord {
            object_ref: object_ref.clone(),
            display_name: "minimal".to_string(),
            source_path: "fixtures/minimal".to_string(),
            stored_path: None,
            sha256: "abc123".to_string(),
            size: 12,
            kind: "binary".to_string(),
            format: "elf".to_string(),
            architecture: "x86_64".to_string(),
            import_status: "indexed".to_string(),
            created_at: datetime!(2026-05-13 00:00 UTC),
        };

        repo.upsert_artifact(&artifact).unwrap();
        assert_eq!(repo.get_artifact(&object_ref).unwrap(), Some(artifact));
    }

    #[test]
    fn reindex_idempotent_indexed_facts() {
        let connection = migrated_connection();
        let artifact_ref = ObjectRef::artifact("abc123", "fixtures/minimal").unwrap();
        ArtifactRepository::new(&connection)
            .upsert_artifact(&ArtifactRecord {
                object_ref: artifact_ref.clone(),
                display_name: "minimal".to_string(),
                source_path: "fixtures/minimal".to_string(),
                stored_path: None,
                sha256: "abc123".to_string(),
                size: 12,
                kind: "binary".to_string(),
                format: "elf".to_string(),
                architecture: "x86_64".to_string(),
                import_status: "indexed".to_string(),
                created_at: datetime!(2026-05-13 00:00 UTC),
            })
            .unwrap();
        let object_repo = ObjectRepository::new(&connection);
        object_repo
            .upsert_object(&StoredObject {
                object_ref: artifact_ref.clone(),
                artifact_key: None,
                display_name: Some("minimal".to_string()),
                address: None,
                size: Some(12),
                source_run_id: None,
                metadata_json: "{}".to_string(),
            })
            .unwrap();

        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            revdeck_core::StableObjectKey::function(
                &artifact_ref.key,
                0x401000,
                Some(16),
                Some("main"),
            )
            .unwrap(),
        );
        let index_repo = IndexRepository::new(&connection);
        let run_repo = AnalysisRunRepository::new(&connection);
        for suffix in ["first", "second"] {
            let run = run_repo
                .start(
                    &NewAnalysisRun::new(
                        Some(artifact_ref.key.to_string()),
                        "revdeck.native_elf",
                        "0.1.0",
                        suffix,
                        datetime!(2026-05-13 00:00 UTC),
                    )
                    .unwrap(),
                )
                .unwrap();
            index_repo
                .remove_indexed_facts_for_artifact(&artifact_ref)
                .unwrap();
            object_repo
                .upsert_object(&StoredObject {
                    object_ref: function_ref.clone(),
                    artifact_key: Some(artifact_ref.key.to_string()),
                    display_name: Some("main".to_string()),
                    address: Some(0x401000),
                    size: Some(16),
                    source_run_id: Some(run.id),
                    metadata_json: r#"{"boundary_confidence":"symbol"}"#.to_string(),
                })
                .unwrap();
            index_repo
                .upsert_function(&FunctionRecord {
                    object_ref: function_ref.clone(),
                    name: "main".to_string(),
                    virtual_address: Some(0x401000),
                    size: Some(16),
                    boundary_source: "symbol".to_string(),
                    boundary_confidence: "symbol".to_string(),
                    call_count: 0,
                    string_count: 0,
                })
                .unwrap();
        }

        assert_eq!(
            index_repo
                .count_kind(&artifact_ref, ObjectKind::Function)
                .unwrap(),
            1
        );
        assert_eq!(
            index_repo
                .function_boundary_confidences(&artifact_ref)
                .unwrap(),
            vec!["symbol".to_string()]
        );
    }

    #[test]
    fn section_offset_mappings_return_only_provable_ranges() {
        let connection = migrated_connection();
        let artifact_ref = ObjectRef::artifact("abc123", "fixtures/mappings").unwrap();
        ArtifactRepository::new(&connection)
            .upsert_artifact(&artifact_record(artifact_ref.clone(), "mappings"))
            .unwrap();
        let object_repo = ObjectRepository::new(&connection);
        object_repo
            .upsert_object(&StoredObject {
                object_ref: artifact_ref.clone(),
                artifact_key: None,
                display_name: Some("mappings".to_string()),
                address: None,
                size: Some(256),
                source_run_id: None,
                metadata_json: "{}".to_string(),
            })
            .unwrap();
        let mapped_section = ObjectRef::new(
            ObjectKind::Section,
            revdeck_core::StableObjectKey::section(&artifact_ref.key, ".text", 0x401000, 0x80)
                .unwrap(),
        );
        let unmapped_section = ObjectRef::new(
            ObjectKind::Section,
            revdeck_core::StableObjectKey::section(&artifact_ref.key, ".bss", 0x402000, 0x40)
                .unwrap(),
        );
        for section in [&mapped_section, &unmapped_section] {
            object_repo
                .upsert_object(&StoredObject {
                    object_ref: section.clone(),
                    artifact_key: Some(artifact_ref.key.to_string()),
                    display_name: Some(section.key.to_string()),
                    address: Some(0x401000),
                    size: Some(0x80),
                    source_run_id: None,
                    metadata_json: "{}".to_string(),
                })
                .unwrap();
        }
        let index_repo = IndexRepository::new(&connection);
        index_repo
            .upsert_section(&SectionRecord {
                object_ref: mapped_section,
                name: ".text".to_string(),
                virtual_address: Some(0x401000),
                file_offset: Some(0x200),
                size: 0x80,
                flags: "AX".to_string(),
                entropy: None,
            })
            .unwrap();
        index_repo
            .upsert_section(&SectionRecord {
                object_ref: unmapped_section,
                name: ".bss".to_string(),
                virtual_address: Some(0x402000),
                file_offset: None,
                size: 0x40,
                flags: "WA".to_string(),
                entropy: None,
            })
            .unwrap();

        let mappings = index_repo.section_offset_mappings(&artifact_ref).unwrap();

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].section_name, ".text");
        assert_eq!(mappings[0].virtual_address, 0x401000);
        assert_eq!(mappings[0].file_offset, 0x200);
        assert_eq!(mappings[0].size, 0x80);
    }

    #[test]
    fn reindex_preserves_analysis_memory() {
        let connection = migrated_connection();
        let artifact_ref = ObjectRef::artifact("abc123", "fixtures/memory").unwrap();
        ArtifactRepository::new(&connection)
            .upsert_artifact(&ArtifactRecord {
                object_ref: artifact_ref.clone(),
                display_name: "memory".to_string(),
                source_path: "fixtures/memory".to_string(),
                stored_path: None,
                sha256: "abc123".to_string(),
                size: 64,
                kind: "binary".to_string(),
                format: "elf".to_string(),
                architecture: "x86_64".to_string(),
                import_status: "indexed".to_string(),
                created_at: datetime!(2026-05-13 00:00 UTC),
            })
            .unwrap();
        let object_repo = ObjectRepository::new(&connection);
        object_repo
            .upsert_object(&StoredObject {
                object_ref: artifact_ref.clone(),
                artifact_key: None,
                display_name: Some("memory".to_string()),
                address: None,
                size: Some(64),
                source_run_id: None,
                metadata_json: "{}".to_string(),
            })
            .unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            revdeck_core::StableObjectKey::function(
                &artifact_ref.key,
                0x401000,
                Some(32),
                Some("main"),
            )
            .unwrap(),
        );
        object_repo
            .upsert_object(&StoredObject {
                object_ref: function_ref.clone(),
                artifact_key: Some(artifact_ref.key.to_string()),
                display_name: Some("main".to_string()),
                address: Some(0x401000),
                size: Some(32),
                source_run_id: None,
                metadata_json: "{}".to_string(),
            })
            .unwrap();
        IndexRepository::new(&connection)
            .upsert_function(&FunctionRecord {
                object_ref: function_ref.clone(),
                name: "main".to_string(),
                virtual_address: Some(0x401000),
                size: Some(32),
                boundary_source: "symbol".to_string(),
                boundary_confidence: "symbol".to_string(),
                call_count: 0,
                string_count: 0,
            })
            .unwrap();

        let memory = MemoryRepository::new(&connection);
        memory
            .upsert_tag(
                &function_ref,
                "suspicious",
                datetime!(2026-05-13 00:01 UTC),
                datetime!(2026-05-13 00:01 UTC),
            )
            .unwrap();
        memory
            .upsert_rename(
                &function_ref,
                "auth_gate",
                datetime!(2026-05-13 00:02 UTC),
                datetime!(2026-05-13 00:02 UTC),
            )
            .unwrap();
        let finding_ref = ObjectRef::new(
            ObjectKind::Finding,
            revdeck_core::StableObjectKey::finding("auth-gate", "2026-05-13T00:03:00Z").unwrap(),
        );
        FindingRepository::new(&connection)
            .upsert_finding(&Finding {
                object_ref: finding_ref.clone(),
                title: "Auth gate".to_string(),
                severity: FindingSeverity::High,
                status: FindingStatus::Confirmed,
                summary: "Evidence stays linked.".to_string(),
                body: String::new(),
                tags: vec!["auth".to_string()],
                evidence: vec![FindingEvidence::new(
                    function_ref.clone(),
                    "primary",
                    0,
                    "stable ref",
                    None,
                )],
                created_at: datetime!(2026-05-13 00:03 UTC),
                updated_at: datetime!(2026-05-13 00:03 UTC),
            })
            .unwrap();

        IndexRepository::new(&connection)
            .remove_indexed_facts_for_artifact(&artifact_ref)
            .unwrap();
        object_repo
            .upsert_object(&StoredObject {
                object_ref: function_ref.clone(),
                artifact_key: Some(artifact_ref.key.to_string()),
                display_name: Some("main".to_string()),
                address: Some(0x401000),
                size: Some(32),
                source_run_id: None,
                metadata_json: "{}".to_string(),
            })
            .unwrap();
        IndexRepository::new(&connection)
            .upsert_function(&FunctionRecord {
                object_ref: function_ref.clone(),
                name: "main".to_string(),
                virtual_address: Some(0x401000),
                size: Some(32),
                boundary_source: "symbol".to_string(),
                boundary_confidence: "symbol".to_string(),
                call_count: 0,
                string_count: 0,
            })
            .unwrap();

        let annotations = memory.list_annotations_for_subject(&function_ref).unwrap();
        assert_eq!(annotations.len(), 2);
        assert!(annotations.iter().any(|item| item.body == "auth_gate"));
        let context = FindingRepository::new(&connection)
            .export_context(datetime!(2026-05-13 00:04 UTC))
            .unwrap();
        assert_eq!(
            context.report.findings[0].evidence[0].evidence,
            function_ref
        );
        assert_eq!(
            context.evidence_objects[0].display_name.as_deref(),
            Some("auth_gate")
        );
    }
}
