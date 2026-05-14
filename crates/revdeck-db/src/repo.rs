use revdeck_core::{
    AnalysisRun, AnalysisRunStatus, Annotation, AnnotationEvidence, AnnotationKind, EdgeKind,
    ExportContext, Finding, FindingEvidence, FindingSeverity, FindingStatus, FunctionScore,
    FunctionScoreInput, NewAnalysisRun, ObjectKind, ObjectRef, RadarEvidence, Report, ScoreReason,
    StableObjectKey, FUNCTION_RADAR_SCORE_KIND,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
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

pub struct PluginRunRepository<'conn> {
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
        Ok(ExportContext {
            report: Report {
                generated_at,
                findings,
            },
            evidence_objects,
        })
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

    pub fn get(&self, id: i64) -> rusqlite::Result<Option<PluginRunRecord>> {
        self.connection
            .query_row(
                "SELECT id, analysis_run_id, plugin_id, plugin_version, manifest_digest,
                    input_digest, config_digest, status, permissions_json, diagnostics_json,
                    started_at, finished_at
                FROM plugin_runs
                WHERE id = ?1",
                [id],
                |row| {
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
                },
            )
            .optional()
    }
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
                pass_name: "parse".to_string(),
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
        assert_eq!(recent[0].pass_name, "parse");
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
