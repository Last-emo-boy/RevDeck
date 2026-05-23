use object::{
    endian::LittleEndian as LE,
    read::pe::{
        ImageNtHeaders, ImageOptionalHeader, ImageThunkData, Import as PeImport, PeFile32, PeFile64,
    },
    FileKind, Object, ObjectSection, ObjectSymbol, SymbolKind,
};
use revdeck_core::{
    AnalysisDiagnostic, AnalysisRunStatus, AnalysisSummary, ArtifactFormat, ArtifactKind,
    BoundaryConfidence, DiagnosticSeverity, DiagnosticStage, EdgeKind, ImportStatus,
    NewAnalysisRun, ObjectKind, ObjectRef, RevDeckError, RevDeckResult, StableObjectKey,
};
use revdeck_db::{
    AnalysisJobRecord, AnalysisJobRepository, AnalysisJobUpdate, AnalysisRunRepository,
    ArtifactRecord, ArtifactRepository, BasicBlockRecord, CfgEdgeRecord, FunctionRecord,
    ImportRecord, IndexRepository, InstructionRecord, NewAnalysisJob, ObjectRepository,
    RadarRepository, SectionRecord, StoredEdge, StoredObject, StringRecord, SymbolRecord,
    XrefRecord,
};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;

mod native_decode;

use native_decode::{
    bytes_hex, decode_native_instructions, DecodedInstruction, DecodedOperand, InstructionFlow,
};

pub const NATIVE_ELF_ANALYZER_ID: &str = "revdeck.native_elf";
pub const NATIVE_ELF_ANALYZER_VERSION: &str = "0.1.0";
pub const NATIVE_BINARY_ANALYZER_ID: &str = "revdeck.native_binary";
pub const NATIVE_BINARY_ANALYZER_VERSION: &str = "0.2.0";
pub const FUNCTION_RADAR_ANALYZER_ID: &str = "revdeck.function_radar";
pub const FUNCTION_RADAR_ANALYZER_VERSION: &str = "0.1.0";
const DEFAULT_FUNCTION_SEED_SIZE: u64 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisProfile {
    Quick,
    Balanced,
    Deep,
}

impl AnalysisProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Balanced => "balanced",
            Self::Deep => "deep",
        }
    }

    const fn collects_native_cfg(self) -> bool {
        !matches!(self, Self::Quick)
    }
}

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub project_root: PathBuf,
    pub artifact_path: PathBuf,
    pub profile: AnalysisProfile,
}

impl ImportOptions {
    pub fn new(project_root: PathBuf, artifact_path: PathBuf) -> Self {
        Self {
            project_root,
            artifact_path,
            profile: AnalysisProfile::Balanced,
        }
    }

    pub fn with_profile(
        project_root: PathBuf,
        artifact_path: PathBuf,
        profile: AnalysisProfile,
    ) -> Self {
        Self {
            project_root,
            artifact_path,
            profile,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportOutcome {
    pub artifact_ref: ObjectRef,
    pub run_id: i64,
    pub profile: AnalysisProfile,
    pub status: AnalysisRunStatus,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Clone)]
pub struct BinaryRegistration {
    pub artifact_ref: ObjectRef,
    pub run_id: i64,
    pub parse_job_id: i64,
    pub profile: AnalysisProfile,
    pub project_root: PathBuf,
    pub source_path: PathBuf,
    pub display_name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
struct ParsedSection {
    object_ref: ObjectRef,
    name: String,
    address: Option<u64>,
    offset: Option<u64>,
    size: u64,
    flags: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ParsedSymbol {
    object_ref: ObjectRef,
    name: String,
    address: Option<u64>,
    size: Option<u64>,
    kind: String,
    binding: String,
}

#[derive(Debug, Clone)]
struct ParsedImport {
    object_ref: ObjectRef,
    module: Option<String>,
    symbol: String,
    address: Option<u64>,
}

#[derive(Debug, Clone)]
struct ParsedString {
    object_ref: ObjectRef,
    value: String,
    address: Option<u64>,
    offset: u64,
    length: u64,
    encoding: String,
}

#[derive(Debug, Clone)]
struct ParsedFunction {
    object_ref: ObjectRef,
    name: String,
    address: Option<u64>,
    size: Option<u64>,
    boundary_source: String,
    boundary_confidence: String,
    frame_pointer: Option<String>,
    stack_frame_size: Option<u64>,
    stack_cleanup_size: Option<u64>,
    epilogue_kind: Option<String>,
    has_frame_epilogue: bool,
    stack_slots: Vec<StackSlot>,
    calling_convention: Option<String>,
    argument_registers: Vec<ArgumentRegisterHint>,
    string_count: u64,
    call_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StackSlot {
    base: String,
    offset: i64,
    width_bits: Option<u16>,
    accesses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ArgumentRegisterHint {
    ordinal: u8,
    register: String,
}

#[derive(Debug, Clone)]
struct ParsedBasicBlock {
    object_ref: ObjectRef,
    function: ObjectRef,
    address: u64,
    end_address: u64,
    size: u64,
    ordinal: u64,
    terminator: String,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct ParsedInstruction {
    object_ref: ObjectRef,
    function: ObjectRef,
    block: ObjectRef,
    address: u64,
    size: u64,
    bytes_hex: String,
    mnemonic: String,
    operands_text: String,
    typed_operands: Vec<DecodedOperand>,
    register_reads: Vec<String>,
    register_writes: Vec<String>,
    register_sources: Vec<RegisterSource>,
    constant_writes: Vec<RegisterConstantWrite>,
    constant_sources: Vec<RegisterConstantSource>,
    target: Option<u64>,
    flow_kind: Option<String>,
    data_target: Option<u64>,
    condition_source: Option<ObjectRef>,
    condition_summary: Option<String>,
    ordinal: u64,
    confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegisterSource {
    register: String,
    source: ObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegisterConstantWrite {
    register: String,
    value: u64,
    width_bits: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegisterConstantSource {
    register: String,
    value: u64,
    width_bits: Option<u16>,
    source: ObjectRef,
}

#[derive(Debug, Clone)]
struct ParsedCfgEdge {
    edge_ref: ObjectRef,
    source: ObjectRef,
    target: ObjectRef,
    edge_kind: String,
    condition_summary: Option<String>,
    known_outcome: Option<String>,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct ParsedXref {
    object_ref: ObjectRef,
    source: ObjectRef,
    target: ObjectRef,
    relation: EdgeKind,
    address: Option<u64>,
}

#[derive(Debug, Clone)]
struct ParsedBinary {
    format: ArtifactFormat,
    architecture: String,
    entrypoint: Option<u64>,
    sections: Vec<ParsedSection>,
    symbols: Vec<ParsedSymbol>,
    imports: Vec<ParsedImport>,
    strings: Vec<ParsedString>,
    functions: Vec<ParsedFunction>,
    basic_blocks: Vec<ParsedBasicBlock>,
    instructions: Vec<ParsedInstruction>,
    cfg_edges: Vec<ParsedCfgEdge>,
    xrefs: Vec<ParsedXref>,
    diagnostics: Vec<AnalysisDiagnostic>,
}

#[derive(Debug, Clone, Copy)]
struct SectionMapping {
    address: u64,
    offset: u64,
    size: u64,
}

struct ArtifactRecordInput<'path> {
    object_ref: ObjectRef,
    display_name: String,
    source_path: &'path Path,
    sha256: &'path str,
    size: u64,
    kind: ArtifactKind,
    format: ArtifactFormat,
    architecture: &'path str,
    status: ImportStatus,
}

struct FailureContext<'path> {
    artifact_ref: &'path ObjectRef,
    display_name: String,
    source_path: &'path Path,
    sha256: &'path str,
    size: u64,
    run_id: i64,
    profile: AnalysisProfile,
    diagnostic: AnalysisDiagnostic,
}

pub fn import_binary(
    connection: &Connection,
    options: ImportOptions,
) -> Result<ImportOutcome, ImportError> {
    let source_path = options.artifact_path.clone();
    let bytes = fs::read(&source_path).map_err(|err| ImportError::Io {
        path: source_path,
        source: err,
    })?;
    let registration = register_binary_bytes(connection, options, &bytes)?;
    finish_registered_binary_bytes(connection, registration, &bytes)
}

pub fn finish_registered_binary_analysis(
    connection: &Connection,
    registration: BinaryRegistration,
) -> Result<ImportOutcome, ImportError> {
    let bytes = match fs::read(&registration.source_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let diagnostic = AnalysisDiagnostic::new(
                DiagnosticSeverity::Error,
                DiagnosticStage::Parse,
                "binary_read_failed",
                format!(
                    "unable to read binary artifact {}: {err}",
                    registration.source_path.display()
                ),
                true,
            )
            .expect("static diagnostic fields are valid");
            return fail_registered_binary_analysis(connection, registration, diagnostic);
        }
    };
    finish_registered_binary_bytes(connection, registration, &bytes)
}

pub fn fail_registered_binary_analysis(
    connection: &Connection,
    registration: BinaryRegistration,
    diagnostic: AnalysisDiagnostic,
) -> Result<ImportOutcome, ImportError> {
    let job_repo = AnalysisJobRepository::new(connection);
    finish_analysis_job(
        &job_repo,
        registration.parse_job_id,
        AnalysisJobFinish {
            status: "failed",
            progress_current: 0,
            progress_total: Some(1),
            objects_produced: 0,
            diagnostics_count: 1,
            metadata: job_metadata(
                serde_json::json!({ "diagnostic": diagnostic.clone() }),
                registration.profile,
                "binary.parse",
                diagnostic_snippets(std::slice::from_ref(&diagnostic)),
                vec!["background worker failed before parsing completed".to_string()],
            ),
        },
    )?;
    persist_failure(
        connection,
        FailureContext {
            artifact_ref: &registration.artifact_ref,
            display_name: registration.display_name,
            source_path: &registration.source_path,
            sha256: &registration.sha256,
            size: registration.size,
            run_id: registration.run_id,
            profile: registration.profile,
            diagnostic,
        },
    )
}

fn finish_registered_binary_bytes(
    connection: &Connection,
    registration: BinaryRegistration,
    bytes: &[u8],
) -> Result<ImportOutcome, ImportError> {
    let BinaryRegistration {
        artifact_ref,
        run_id,
        parse_job_id,
        profile,
        source_path,
        display_name,
        sha256,
        size,
        ..
    } = registration;
    let job_repo = AnalysisJobRepository::new(connection);

    match parse_binary(&artifact_ref, &bytes, profile) {
        Ok(parsed) => {
            finish_analysis_job(
                &job_repo,
                parse_job_id,
                AnalysisJobFinish {
                    status: "succeeded",
                    progress_current: 1,
                    progress_total: Some(1),
                    objects_produced: 1,
                    diagnostics_count: parsed.diagnostics.len() as u64,
                    metadata: job_metadata(
                        serde_json::json!({
                        "format": parsed.format,
                        "architecture": parsed.architecture,
                        "entrypoint": parsed.entrypoint
                        }),
                        profile,
                        "binary.parse",
                        diagnostic_snippets(&parsed.diagnostics),
                        vec![format!(
                            "parsed {} {} artifact with entrypoint {:?}",
                            parsed.format.as_str(),
                            parsed.architecture,
                            parsed.entrypoint
                        )],
                    ),
                },
            )?;
            let indexed_artifact = artifact_record(ArtifactRecordInput {
                object_ref: artifact_ref.clone(),
                display_name,
                source_path: &source_path,
                sha256: &sha256,
                size,
                kind: ArtifactKind::Binary,
                format: parsed.format,
                architecture: &parsed.architecture,
                status: ImportStatus::Indexed,
            });
            persist_success(
                connection,
                &artifact_ref,
                &indexed_artifact,
                run_id,
                profile,
                parsed,
            )
        }
        Err(diagnostic) => {
            finish_analysis_job(
                &job_repo,
                parse_job_id,
                AnalysisJobFinish {
                    status: "failed",
                    progress_current: 0,
                    progress_total: Some(1),
                    objects_produced: 0,
                    diagnostics_count: 1,
                    metadata: job_metadata(
                        serde_json::json!({ "diagnostic": diagnostic }),
                        profile,
                        "binary.parse",
                        diagnostic_snippets(std::slice::from_ref(&diagnostic)),
                        vec!["parse failed before indexed facts were persisted".to_string()],
                    ),
                },
            )?;
            persist_failure(
                connection,
                FailureContext {
                    artifact_ref: &artifact_ref,
                    display_name,
                    source_path: &source_path,
                    sha256: &sha256,
                    size,
                    run_id,
                    profile,
                    diagnostic,
                },
            )
        }
    }
}

pub fn register_binary_for_analysis(
    connection: &Connection,
    options: ImportOptions,
) -> Result<BinaryRegistration, ImportError> {
    let source_path = options.artifact_path.clone();
    let bytes = fs::read(&source_path).map_err(|err| ImportError::Io {
        path: source_path,
        source: err,
    })?;
    register_binary_bytes(connection, options, &bytes)
}

fn register_binary_bytes(
    connection: &Connection,
    options: ImportOptions,
    bytes: &[u8],
) -> Result<BinaryRegistration, ImportError> {
    let ImportOptions {
        project_root,
        artifact_path,
        profile,
    } = options;
    let source_path = artifact_path;
    let sha256 = sha256_hex(&bytes);
    let size = bytes.len() as u64;
    let normalized_path = normalize_path(&project_root, &source_path);
    let artifact_ref = ObjectRef::artifact(&sha256, &normalized_path)?;
    let display_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact")
        .to_string();

    let artifact_repo = ArtifactRepository::new(connection);
    let object_repo = ObjectRepository::new(connection);
    let run_repo = AnalysisRunRepository::new(connection);
    let job_repo = AnalysisJobRepository::new(connection);

    let pending_artifact = artifact_record(ArtifactRecordInput {
        object_ref: artifact_ref.clone(),
        display_name: display_name.clone(),
        source_path: &source_path,
        sha256: &sha256,
        size,
        kind: ArtifactKind::Binary,
        format: ArtifactFormat::Unknown,
        architecture: "unknown",
        status: ImportStatus::Pending,
    });
    artifact_repo.upsert_artifact(&pending_artifact)?;
    object_repo.upsert_object(&StoredObject {
        object_ref: artifact_ref.clone(),
        artifact_key: None,
        display_name: Some(display_name.clone()),
        address: None,
        size: Some(size),
        source_run_id: None,
        metadata_json: serde_json::json!({
            "sha256": sha256.clone(),
            "source_path": source_path.display().to_string(),
            "analysis_profile": profile.as_str(),
            "source-controlled": true
        })
        .to_string(),
    })?;

    let run = run_repo.start(&NewAnalysisRun::new(
        Some(artifact_ref.key.to_string()),
        NATIVE_BINARY_ANALYZER_ID,
        NATIVE_BINARY_ANALYZER_VERSION,
        format!("{}:profile:{}", sha256, profile.as_str()),
        OffsetDateTime::now_utc(),
    )?)?;
    let parse_job = start_analysis_job(
        &job_repo,
        Some(run.id),
        &artifact_ref,
        profile,
        "binary.parse",
        job_metadata(
            serde_json::json!({ "bytes": size }),
            profile,
            "binary.parse",
            Vec::new(),
            vec![format!(
                "parse job queued for {size} bytes with {} profile",
                profile.as_str()
            )],
        ),
    )?;

    Ok(BinaryRegistration {
        artifact_ref,
        run_id: run.id,
        parse_job_id: parse_job.id,
        profile,
        project_root,
        source_path,
        display_name,
        sha256,
        size,
    })
}

fn persist_success(
    connection: &Connection,
    artifact_ref: &ObjectRef,
    artifact: &ArtifactRecord,
    run_id: i64,
    profile: AnalysisProfile,
    parsed: ParsedBinary,
) -> Result<ImportOutcome, ImportError> {
    let artifact_repo = ArtifactRepository::new(connection);
    let object_repo = ObjectRepository::new(connection);
    let index_repo = IndexRepository::new(connection);
    let run_repo = AnalysisRunRepository::new(connection);
    let job_repo = AnalysisJobRepository::new(connection);
    let surface_count =
        parsed.sections.len() + parsed.symbols.len() + parsed.imports.len() + parsed.strings.len();
    let function_count = parsed.functions.len();
    let basic_block_count = parsed.basic_blocks.len();
    let instruction_count = parsed.instructions.len();
    let cfg_edge_count = parsed.cfg_edges.len();
    let diagnostic_count = parsed.diagnostics.len();

    index_repo.remove_indexed_facts_for_artifact(artifact_ref)?;
    artifact_repo.upsert_artifact(artifact)?;
    object_repo.upsert_object(&StoredObject {
        object_ref: artifact_ref.clone(),
        artifact_key: None,
        display_name: Some(artifact.display_name.clone()),
        address: parsed.entrypoint,
        size: Some(artifact.size),
        source_run_id: Some(run_id),
        metadata_json: serde_json::json!({
            "sha256": artifact.sha256,
            "format": artifact.format,
            "architecture": artifact.architecture,
            "import_status": artifact.import_status,
            "entrypoint": parsed.entrypoint,
            "analysis_profile": profile.as_str(),
            "source-controlled": true
        })
        .to_string(),
    })?;

    let mut summary = AnalysisSummary {
        sections: parsed.sections.len(),
        symbols: parsed.symbols.len(),
        imports: parsed.imports.len(),
        strings: parsed.strings.len(),
        functions: parsed.functions.len(),
        xrefs: parsed.xrefs.len(),
        edges: 0,
        diagnostics: parsed.diagnostics.clone(),
    };

    for section in &parsed.sections {
        object_repo.upsert_object(&StoredObject {
            object_ref: section.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(section.name.clone()),
            address: section.address,
            size: Some(section.size),
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({"flags": section.flags}).to_string(),
        })?;
        index_repo.upsert_section(&SectionRecord {
            object_ref: section.object_ref.clone(),
            name: section.name.clone(),
            virtual_address: section.address,
            file_offset: section.offset,
            size: section.size,
            flags: section.flags.clone(),
            entropy: Some(entropy(&section.bytes)),
        })?;
        upsert_edge(
            &object_repo,
            artifact_ref,
            &section.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "section",
        )?;
        summary.edges += 1;
    }

    for symbol in &parsed.symbols {
        object_repo.upsert_object(&StoredObject {
            object_ref: symbol.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(symbol.name.clone()),
            address: symbol.address,
            size: symbol.size,
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({
                "symbol_kind": symbol.kind,
                "binding": symbol.binding
            })
            .to_string(),
        })?;
        index_repo.upsert_symbol(&SymbolRecord {
            object_ref: symbol.object_ref.clone(),
            name: symbol.name.clone(),
            virtual_address: symbol.address,
            size: symbol.size,
            symbol_kind: symbol.kind.clone(),
            binding: symbol.binding.clone(),
        })?;
        upsert_edge(
            &object_repo,
            artifact_ref,
            &symbol.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "symbol",
        )?;
        summary.edges += 1;
    }

    for import in &parsed.imports {
        object_repo.upsert_object(&StoredObject {
            object_ref: import.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(import.symbol.clone()),
            address: import.address,
            size: None,
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({"module": import.module}).to_string(),
        })?;
        index_repo.upsert_import(&ImportRecord {
            object_ref: import.object_ref.clone(),
            module: import.module.clone(),
            symbol: import.symbol.clone(),
            ordinal: None,
            virtual_address: import.address,
        })?;
        upsert_edge(
            &object_repo,
            artifact_ref,
            &import.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "import",
        )?;
        summary.edges += 1;
    }

    for string in &parsed.strings {
        object_repo.upsert_object(&StoredObject {
            object_ref: string.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(string.value.clone()),
            address: string.address,
            size: Some(string.length),
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({"encoding": string.encoding}).to_string(),
        })?;
        index_repo.upsert_string(&StringRecord {
            object_ref: string.object_ref.clone(),
            value: string.value.clone(),
            virtual_address: string.address,
            file_offset: string.offset,
            length: string.length,
            encoding: string.encoding.clone(),
        })?;
        upsert_edge(
            &object_repo,
            artifact_ref,
            &string.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "string",
        )?;
        summary.edges += 1;
    }

    for function in &parsed.functions {
        object_repo.upsert_object(&StoredObject {
            object_ref: function.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(function.name.clone()),
            address: function.address,
            size: function.size,
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({
                "boundary_source": function.boundary_source,
                "boundary_confidence": function.boundary_confidence,
                "frame_pointer": function.frame_pointer,
                "stack_frame_size": function.stack_frame_size,
                "stack_cleanup_size": function.stack_cleanup_size,
                "epilogue_kind": function.epilogue_kind,
                "has_frame_epilogue": function.has_frame_epilogue,
                "stack_slots": function.stack_slots,
                "calling_convention": function.calling_convention,
                "argument_registers": function.argument_registers
            })
            .to_string(),
        })?;
        index_repo.upsert_function(&FunctionRecord {
            object_ref: function.object_ref.clone(),
            name: function.name.clone(),
            virtual_address: function.address,
            size: function.size,
            boundary_source: function.boundary_source.clone(),
            boundary_confidence: function.boundary_confidence.clone(),
            call_count: function.call_count,
            string_count: function.string_count,
        })?;
        upsert_edge(
            &object_repo,
            artifact_ref,
            &function.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "function",
        )?;
        summary.edges += 1;
    }

    for block in &parsed.basic_blocks {
        object_repo.upsert_object(&StoredObject {
            object_ref: block.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(format!("block_{:x}", block.address)),
            address: Some(block.address),
            size: Some(block.size),
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({
                "native_analyzer": true,
                "terminator": block.terminator,
                "confidence": block.confidence
            })
            .to_string(),
        })?;
        index_repo.upsert_basic_block(&BasicBlockRecord {
            object_ref: block.object_ref.clone(),
            function: block.function.clone(),
            start_address: block.address,
            end_address: block.end_address,
            size: block.size,
            ordinal: block.ordinal,
            terminator: block.terminator.clone(),
            confidence: block.confidence,
            source_run_id: Some(run_id),
        })?;
        upsert_edge(
            &object_repo,
            &block.function,
            &block.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "basic_block",
        )?;
        summary.edges += 1;
    }

    for instruction in &parsed.instructions {
        object_repo.upsert_object(&StoredObject {
            object_ref: instruction.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(format!(
                "{:x}: {} {}",
                instruction.address, instruction.mnemonic, instruction.operands_text
            )),
            address: Some(instruction.address),
            size: Some(instruction.size),
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({
                "native_analyzer": true,
                "bytes": instruction.bytes_hex,
                "mnemonic": instruction.mnemonic,
                "operands": instruction.operands_text,
                "typed_operands": instruction.typed_operands,
                "register_reads": instruction.register_reads,
                "register_writes": instruction.register_writes,
                "register_sources": instruction.register_sources,
                "constant_writes": instruction.constant_writes,
                "constant_sources": instruction.constant_sources,
                "target": instruction.target,
                "flow_kind": instruction.flow_kind,
                "data_target": instruction.data_target,
                "condition_source": instruction.condition_source,
                "condition_summary": instruction.condition_summary,
                "confidence": instruction.confidence
            })
            .to_string(),
        })?;
        index_repo.upsert_instruction(&InstructionRecord {
            object_ref: instruction.object_ref.clone(),
            function: instruction.function.clone(),
            block: instruction.block.clone(),
            address: instruction.address,
            size: instruction.size,
            bytes_hex: instruction.bytes_hex.clone(),
            mnemonic: instruction.mnemonic.clone(),
            operands_text: instruction.operands_text.clone(),
            ordinal: instruction.ordinal,
            confidence: instruction.confidence,
            source_run_id: Some(run_id),
        })?;
        upsert_edge(
            &object_repo,
            &instruction.block,
            &instruction.object_ref,
            EdgeKind::Contains,
            1.0,
            run_id,
            "instruction",
        )?;
        summary.edges += 1;
    }

    for cfg_edge in &parsed.cfg_edges {
        object_repo.upsert_edge(&StoredEdge {
            edge_ref: cfg_edge.edge_ref.clone(),
            source: cfg_edge.source.clone(),
            target: cfg_edge.target.clone(),
            kind: EdgeKind::ControlFlow,
            confidence: cfg_edge.confidence,
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({
                "relation": EdgeKind::ControlFlow.label(),
                "cfg_edge_kind": cfg_edge.edge_kind,
                "condition_summary": cfg_edge.condition_summary,
                "known_outcome": cfg_edge.known_outcome,
                "source": "native_cfg"
            })
            .to_string(),
        })?;
        index_repo.upsert_cfg_edge(&CfgEdgeRecord {
            edge_ref: cfg_edge.edge_ref.clone(),
            source_block: cfg_edge.source.clone(),
            target_block: cfg_edge.target.clone(),
            edge_kind: cfg_edge.edge_kind.clone(),
            confidence: cfg_edge.confidence,
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({
                "source": "native_cfg",
                "condition_summary": cfg_edge.condition_summary,
                "known_outcome": cfg_edge.known_outcome,
            })
            .to_string(),
        })?;
        summary.edges += 1;
    }

    for xref in &parsed.xrefs {
        object_repo.upsert_object(&StoredObject {
            object_ref: xref.object_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some(xref.relation.label().to_string()),
            address: xref.address,
            size: None,
            source_run_id: Some(run_id),
            metadata_json: serde_json::json!({"relation": xref.relation.label()}).to_string(),
        })?;
        index_repo.upsert_xref(&XrefRecord {
            object_ref: xref.object_ref.clone(),
            source: xref.source.clone(),
            target: xref.target.clone(),
            relation: xref.relation.as_str().to_string(),
            address: xref.address,
            source_run_id: Some(run_id),
        })?;
        upsert_edge(
            &object_repo,
            &xref.source,
            &xref.target,
            xref.relation,
            0.8,
            run_id,
            xref.relation.label(),
        )?;
        upsert_edge(
            &object_repo,
            &xref.target,
            &xref.source,
            EdgeKind::XrefFrom,
            0.8,
            run_id,
            EdgeKind::XrefFrom.label(),
        )?;
        upsert_edge(
            &object_repo,
            &xref.object_ref,
            &xref.source,
            EdgeKind::DerivedFrom,
            1.0,
            run_id,
            EdgeKind::DerivedFrom.label(),
        )?;
        summary.edges += 3;
    }

    record_completed_job(
        &job_repo,
        artifact_ref,
        profile,
        CompletedAnalysisJob {
            run_id: Some(run_id),
            pass_name: "binary.surface",
            status: "succeeded",
            objects_produced: surface_count as u64,
            diagnostics_count: diagnostic_count as u64,
            metadata: job_metadata(
                serde_json::json!({
                    "sections": summary.sections,
                    "symbols": summary.symbols,
                    "imports": summary.imports,
                    "strings": summary.strings
                }),
                profile,
                "binary.surface",
                diagnostic_snippets(&summary.diagnostics),
                vec![format!(
                    "persisted sections={} symbols={} imports={} strings={}",
                    summary.sections, summary.symbols, summary.imports, summary.strings
                )],
            ),
        },
    )?;
    record_completed_job(
        &job_repo,
        artifact_ref,
        profile,
        CompletedAnalysisJob {
            run_id: Some(run_id),
            pass_name: "binary.seed",
            status: "succeeded",
            objects_produced: function_count as u64,
            diagnostics_count: 0,
            metadata: job_metadata(
                serde_json::json!({ "functions": summary.functions }),
                profile,
                "binary.seed",
                Vec::new(),
                vec![format!("seeded {function_count} function records")],
            ),
        },
    )?;
    let native_status = if profile.collects_native_cfg() {
        "succeeded"
    } else {
        "skipped"
    };
    record_completed_job(
        &job_repo,
        artifact_ref,
        profile,
        CompletedAnalysisJob {
            run_id: Some(run_id),
            pass_name: "binary.linear",
            status: native_status,
            objects_produced: instruction_count as u64,
            diagnostics_count: 0,
            metadata: job_metadata(
                serde_json::json!({ "instructions": instruction_count }),
                profile,
                "binary.linear",
                native_job_diagnostics(&summary.diagnostics, native_status),
                native_job_logs(profile, native_status, "linear"),
            ),
        },
    )?;
    record_completed_job(
        &job_repo,
        artifact_ref,
        profile,
        CompletedAnalysisJob {
            run_id: Some(run_id),
            pass_name: "binary.cfg",
            status: native_status,
            objects_produced: (basic_block_count + cfg_edge_count) as u64,
            diagnostics_count: 0,
            metadata: job_metadata(
                serde_json::json!({
                    "basic_blocks": basic_block_count,
                    "cfg_edges": cfg_edge_count
                }),
                profile,
                "binary.cfg",
                native_job_diagnostics(&summary.diagnostics, native_status),
                native_job_logs(profile, native_status, "cfg"),
            ),
        },
    )?;
    record_completed_job(
        &job_repo,
        artifact_ref,
        profile,
        CompletedAnalysisJob {
            run_id: Some(run_id),
            pass_name: "binary.dataflow",
            status: native_status,
            objects_produced: instruction_count as u64,
            diagnostics_count: 0,
            metadata: job_metadata(
                serde_json::json!({ "instructions": instruction_count }),
                profile,
                "binary.dataflow",
                native_job_diagnostics(&summary.diagnostics, native_status),
                native_job_logs(profile, native_status, "dataflow"),
            ),
        },
    )?;

    let diagnostics_json = serde_json::to_string(&summary)?;
    run_repo.finish(
        run_id,
        AnalysisRunStatus::Succeeded,
        OffsetDateTime::now_utc(),
        Some(&diagnostics_json),
        None,
        true,
    )?;
    let scoring_run_id = run_function_radar_scoring(connection, artifact_ref, run_id)?;
    record_completed_job(
        &job_repo,
        artifact_ref,
        profile,
        CompletedAnalysisJob {
            run_id: Some(scoring_run_id),
            pass_name: "binary.triage",
            status: "succeeded",
            objects_produced: function_count as u64,
            diagnostics_count: 0,
            metadata: job_metadata(
                serde_json::json!({
                    "functions": function_count,
                    "input_run_id": run_id
                }),
                profile,
                "binary.triage",
                Vec::new(),
                vec![format!("scored {function_count} functions for triage")],
            ),
        },
    )?;
    Ok(ImportOutcome {
        artifact_ref: artifact_ref.clone(),
        run_id: scoring_run_id,
        profile,
        status: AnalysisRunStatus::Succeeded,
        summary,
    })
}

pub fn run_function_radar_scoring(
    connection: &Connection,
    artifact_ref: &ObjectRef,
    input_run_id: i64,
) -> Result<i64, ImportError> {
    let run_repo = AnalysisRunRepository::new(connection);
    let radar_repo = RadarRepository::new(connection);
    let run = run_repo.start(&NewAnalysisRun::new(
        Some(artifact_ref.key.to_string()),
        FUNCTION_RADAR_ANALYZER_ID,
        FUNCTION_RADAR_ANALYZER_VERSION,
        format!(
            "artifact:{}:input-run:{input_run_id}",
            artifact_ref.key.as_str()
        ),
        OffsetDateTime::now_utc(),
    )?)?;
    let scores = revdeck_core::score_functions(radar_repo.load_function_inputs(artifact_ref)?)
        .into_iter()
        .map(|score| score.with_source_run_id(run.id))
        .collect::<Vec<_>>();
    radar_repo.replace_function_scores(artifact_ref, run.id, &scores)?;
    let reason_count = radar_repo.reason_count_for_run(run.id)?;
    let diagnostics_json = serde_json::json!({
        "analyzer": FUNCTION_RADAR_ANALYZER_ID,
        "functions": scores.len(),
        "score_reasons": reason_count,
        "input_run_id": input_run_id
    })
    .to_string();
    run_repo.finish(
        run.id,
        AnalysisRunStatus::Succeeded,
        OffsetDateTime::now_utc(),
        Some(&diagnostics_json),
        None,
        true,
    )?;
    Ok(run.id)
}

fn persist_failure(
    connection: &Connection,
    context: FailureContext<'_>,
) -> Result<ImportOutcome, ImportError> {
    let artifact_repo = ArtifactRepository::new(connection);
    let object_repo = ObjectRepository::new(connection);
    let run_repo = AnalysisRunRepository::new(connection);
    let artifact = artifact_record(ArtifactRecordInput {
        object_ref: context.artifact_ref.clone(),
        display_name: context.display_name.clone(),
        source_path: context.source_path,
        sha256: context.sha256,
        size: context.size,
        kind: ArtifactKind::Binary,
        format: ArtifactFormat::Unknown,
        architecture: "unknown",
        status: ImportStatus::Failed,
    });
    artifact_repo.upsert_artifact(&artifact)?;
    object_repo.upsert_object(&StoredObject {
        object_ref: context.artifact_ref.clone(),
        artifact_key: None,
        display_name: Some(context.display_name),
        address: None,
        size: Some(context.size),
        source_run_id: Some(context.run_id),
        metadata_json: serde_json::json!({
            "sha256": context.sha256,
            "format": "unknown",
            "architecture": "unknown",
            "import_status": "failed",
            "analysis_profile": context.profile.as_str(),
            "source-controlled": true
        })
        .to_string(),
    })?;
    let mut summary = AnalysisSummary::default();
    summary.diagnostics.push(context.diagnostic.clone());
    let diagnostics_json = serde_json::to_string(&summary)?;
    let error_json = serde_json::to_string(&context.diagnostic)?;
    run_repo.finish(
        context.run_id,
        AnalysisRunStatus::Failed,
        OffsetDateTime::now_utc(),
        Some(&diagnostics_json),
        Some(&error_json),
        context.diagnostic.recoverable,
    )?;
    Ok(ImportOutcome {
        artifact_ref: context.artifact_ref.clone(),
        run_id: context.run_id,
        profile: context.profile,
        status: AnalysisRunStatus::Failed,
        summary,
    })
}

fn parse_binary(
    artifact_ref: &ObjectRef,
    bytes: &[u8],
    profile: AnalysisProfile,
) -> Result<ParsedBinary, AnalysisDiagnostic> {
    let file = object::File::parse(bytes).map_err(|err| {
        AnalysisDiagnostic::new(
            DiagnosticSeverity::Error,
            DiagnosticStage::Parse,
            "binary_parse_failed",
            format!("unable to parse binary artifact: {err}"),
            true,
        )
        .expect("static diagnostic fields are valid")
    })?;

    let Some(format) = artifact_format_for(file.format()) else {
        return Err(AnalysisDiagnostic::new(
            DiagnosticSeverity::Error,
            DiagnosticStage::Parse,
            "unsupported_format",
            format!(
                "native importer only supports ELF and PE artifacts; got {:?}",
                file.format()
            ),
            true,
        )
        .expect("static diagnostic fields are valid"));
    };

    let architecture = format!("{:?}", file.architecture()).to_ascii_lowercase();
    let entrypoint = file.entry();
    let entrypoint = (entrypoint != 0).then_some(entrypoint);
    let mut diagnostics = Vec::new();
    let mut section_mappings = Vec::new();
    let mut sections = Vec::new();

    for section in file.sections() {
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let address = (section.address() != 0).then_some(section.address());
        let size = section.size();
        let offset = section.file_range().map(|range| range.0);
        let data = section.uncompressed_data().unwrap_or_default().to_vec();
        if let (Some(address), Some(offset)) = (address, offset) {
            section_mappings.push(SectionMapping {
                address,
                offset,
                size,
            });
        }
        let key = StableObjectKey::section(&artifact_ref.key, &name, address.unwrap_or(0), size)
            .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexSections, err))?;
        sections.push(ParsedSection {
            object_ref: ObjectRef::new(ObjectKind::Section, key),
            name,
            address,
            offset,
            size,
            flags: format!("{:?}", section.flags()),
            bytes: data,
        });
    }

    if sections.is_empty() {
        diagnostics.push(
            AnalysisDiagnostic::new(
                DiagnosticSeverity::Warning,
                DiagnosticStage::IndexSections,
                "no_sections",
                "binary parsed without indexable sections",
                true,
            )
            .expect("static diagnostic fields are valid"),
        );
    }

    let imports = collect_imports(artifact_ref, &file, bytes)
        .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexImports, err))?;
    let symbols = collect_symbols(artifact_ref, &file)
        .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexSymbols, err))?;
    let strings = collect_strings(artifact_ref, bytes, &section_mappings)
        .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexStrings, err))?;
    let functions = collect_functions(
        artifact_ref,
        format,
        entrypoint,
        &symbols,
        &strings,
        &imports,
        &sections,
    )
    .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexFunctions, err))?;
    let native_cfg = if profile.collects_native_cfg() {
        collect_native_cfg(artifact_ref, &sections, &functions, &strings, &imports)
            .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexEdges, err))?
    } else {
        diagnostics.push(profile_skipped_diagnostic(
            profile,
            "native_cfg",
            "native CFG, instruction persistence, and dataflow enrichment",
        ));
        NativeCfgFacts::default()
    };
    let mut functions = functions;
    apply_native_function_call_counts(&mut functions, &native_cfg.function_call_counts);
    apply_native_function_string_counts(&mut functions, &native_cfg.function_string_counts);
    let mut xrefs = collect_xrefs(artifact_ref, &functions, &strings, &imports)
        .map_err(|err| diagnostic_from_core(DiagnosticStage::IndexEdges, err))?;
    xrefs.extend(native_cfg.xrefs.clone());

    Ok(ParsedBinary {
        format,
        architecture,
        entrypoint,
        sections,
        symbols,
        imports,
        strings,
        functions,
        basic_blocks: native_cfg.basic_blocks,
        instructions: native_cfg.instructions,
        cfg_edges: native_cfg.cfg_edges,
        xrefs,
        diagnostics,
    })
}

fn collect_imports(
    artifact_ref: &ObjectRef,
    file: &object::File<'_>,
    bytes: &[u8],
) -> RevDeckResult<Vec<ParsedImport>> {
    let mut seen = BTreeSet::new();
    let mut imports = Vec::new();
    let addresses = collect_pe_import_addresses(bytes);
    for import in file.imports().unwrap_or_default() {
        let symbol = String::from_utf8_lossy(import.name()).to_string();
        if symbol.trim().is_empty() {
            continue;
        }
        let module = match import.library() {
            [] => None,
            value => Some(String::from_utf8_lossy(value).to_string()),
        };
        if !seen.insert((module.clone(), symbol.clone())) {
            continue;
        }
        let address = addresses.get(&(module.clone(), symbol.clone())).copied();
        let key = StableObjectKey::import(&artifact_ref.key, module.as_deref(), &symbol, None)?;
        imports.push(ParsedImport {
            object_ref: ObjectRef::new(ObjectKind::Import, key),
            module,
            symbol,
            address,
        });
    }
    Ok(imports)
}

fn collect_pe_import_addresses(bytes: &[u8]) -> BTreeMap<(Option<String>, String), u64> {
    match FileKind::parse(bytes) {
        Ok(FileKind::Pe32) => PeFile32::parse(bytes)
            .map(|file| collect_pe_import_addresses_from_file(&file))
            .unwrap_or_default(),
        Ok(FileKind::Pe64) => PeFile64::parse(bytes)
            .map(|file| collect_pe_import_addresses_from_file(&file))
            .unwrap_or_default(),
        _ => BTreeMap::new(),
    }
}

fn collect_pe_import_addresses_from_file<Pe>(
    file: &object::read::pe::PeFile<'_, Pe>,
) -> BTreeMap<(Option<String>, String), u64>
where
    Pe: ImageNtHeaders,
{
    let image_base = file.nt_headers().optional_header().image_base();
    let mut addresses = BTreeMap::new();
    let Ok(Some(import_table)) = file.import_table() else {
        return addresses;
    };
    let Ok(mut descriptors) = import_table.descriptors() else {
        return addresses;
    };
    while let Ok(Some(descriptor)) = descriptors.next() {
        let Ok(library) = import_table.name(descriptor.name.get(LE)) else {
            continue;
        };
        let module = String::from_utf8_lossy(library).to_string();
        let mut lookup_rva = descriptor.original_first_thunk.get(LE);
        if lookup_rva == 0 {
            lookup_rva = descriptor.first_thunk.get(LE);
        }
        let iat_rva = descriptor.first_thunk.get(LE);
        let Ok(mut lookup_thunks) = import_table.thunks(lookup_rva) else {
            continue;
        };
        let thunk_size = std::mem::size_of::<Pe::ImageThunkData>() as u32;
        let mut index = 0u32;
        while let Ok(Some(thunk)) = lookup_thunks.next::<Pe>() {
            if !thunk.is_ordinal() {
                if let Ok(PeImport::Name(_hint, name)) = import_table.import::<Pe>(thunk) {
                    let symbol = String::from_utf8_lossy(name).to_string();
                    let slot = image_base
                        .wrapping_add(iat_rva as u64)
                        .wrapping_add((index * thunk_size) as u64);
                    addresses.insert((Some(module.clone()), symbol), slot);
                }
            }
            index = index.saturating_add(1);
        }
    }
    addresses
}

fn collect_symbols(
    artifact_ref: &ObjectRef,
    file: &object::File<'_>,
) -> RevDeckResult<Vec<ParsedSymbol>> {
    let mut symbols = Vec::new();
    let mut seen = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        let address = (symbol.address() != 0).then_some(symbol.address());
        let size = (symbol.size() != 0).then_some(symbol.size());
        let dedupe = (name.to_string(), address.unwrap_or(0), size.unwrap_or(0));
        if !seen.insert(dedupe) {
            continue;
        }
        let key = StableObjectKey::symbol(&artifact_ref.key, name, address.unwrap_or(0), size)?;
        symbols.push(ParsedSymbol {
            object_ref: ObjectRef::new(ObjectKind::Symbol, key),
            name: name.to_string(),
            address,
            size,
            kind: symbol_kind(symbol.kind()).to_string(),
            binding: if symbol.is_global() {
                "global"
            } else {
                "local"
            }
            .to_string(),
        });
    }
    symbols.sort_by(|left, right| {
        left.address
            .unwrap_or(u64::MAX)
            .cmp(&right.address.unwrap_or(u64::MAX))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(symbols)
}

fn collect_strings(
    artifact_ref: &ObjectRef,
    bytes: &[u8],
    mappings: &[SectionMapping],
) -> RevDeckResult<Vec<ParsedString>> {
    let mut strings = Vec::new();
    for span in ascii_spans(bytes) {
        let value = String::from_utf8_lossy(&bytes[span.start..span.end]).to_string();
        let offset = span.start as u64;
        let address = offset_to_address(offset, mappings);
        let key = StableObjectKey::string(&artifact_ref.key, offset, address, &value)?;
        strings.push(ParsedString {
            object_ref: ObjectRef::new(ObjectKind::String, key),
            value,
            address,
            offset,
            length: (span.end - span.start) as u64,
            encoding: "ascii".to_string(),
        });
    }
    for span in utf16le_spans(bytes) {
        let mut code_units = Vec::new();
        for chunk in bytes[span.start..span.end].chunks_exact(2) {
            code_units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        let Ok(value) = String::from_utf16(&code_units) else {
            continue;
        };
        let offset = span.start as u64;
        let address = offset_to_address(offset, mappings);
        let key = StableObjectKey::string(&artifact_ref.key, offset, address, &value)?;
        strings.push(ParsedString {
            object_ref: ObjectRef::new(ObjectKind::String, key),
            value,
            address,
            offset,
            length: (span.end - span.start) as u64,
            encoding: "utf16le".to_string(),
        });
    }
    strings.sort_by_key(|item| item.offset);
    Ok(strings)
}

fn collect_functions(
    artifact_ref: &ObjectRef,
    format: ArtifactFormat,
    entrypoint: Option<u64>,
    symbols: &[ParsedSymbol],
    strings: &[ParsedString],
    imports: &[ParsedImport],
    sections: &[ParsedSection],
) -> RevDeckResult<Vec<ParsedFunction>> {
    let mut functions = BTreeMap::new();
    for symbol in symbols {
        if symbol.kind != "text" && symbol.kind != "unknown" {
            continue;
        }
        let Some(address) = symbol.address else {
            continue;
        };
        if symbol.name.starts_with('$') || symbol.name.contains("@@") {
            continue;
        }
        let size = symbol.size.or(Some(DEFAULT_FUNCTION_SEED_SIZE));
        let key = StableObjectKey::function(&artifact_ref.key, address, size, Some(&symbol.name))?;
        functions.insert(
            (address, symbol.name.clone()),
            ParsedFunction {
                object_ref: ObjectRef::new(ObjectKind::Function, key),
                name: symbol.name.clone(),
                address: Some(address),
                size,
                boundary_source: "symbol".to_string(),
                boundary_confidence: BoundaryConfidence::Symbol.as_str().to_string(),
                frame_pointer: None,
                stack_frame_size: None,
                stack_cleanup_size: None,
                epilogue_kind: None,
                has_frame_epilogue: false,
                stack_slots: Vec::new(),
                calling_convention: None,
                argument_registers: Vec::new(),
                string_count: count_related_strings(address, size, strings),
                call_count: 0,
            },
        );
    }

    if let Some(entrypoint) = entrypoint {
        let has_entry = functions.keys().any(|(address, _)| *address == entrypoint);
        if !has_entry {
            let name = "entrypoint".to_string();
            let size = Some(DEFAULT_FUNCTION_SEED_SIZE);
            let key = StableObjectKey::function(&artifact_ref.key, entrypoint, size, Some(&name))?;
            functions.insert(
                (entrypoint, name.clone()),
                ParsedFunction {
                    object_ref: ObjectRef::new(ObjectKind::Function, key),
                    name,
                    address: Some(entrypoint),
                    size,
                    boundary_source: "entrypoint".to_string(),
                    boundary_confidence: BoundaryConfidence::Entrypoint.as_str().to_string(),
                    frame_pointer: None,
                    stack_frame_size: None,
                    stack_cleanup_size: None,
                    epilogue_kind: None,
                    has_frame_epilogue: false,
                    stack_slots: Vec::new(),
                    calling_convention: None,
                    argument_registers: Vec::new(),
                    string_count: count_related_strings(entrypoint, size, strings),
                    call_count: 0,
                },
            );
        }
    }

    for target in collect_direct_call_targets(sections) {
        let has_target = functions.keys().any(|(address, _)| *address == target);
        if has_target {
            continue;
        }
        let name = format!("sub_{target:016x}");
        let size = Some(DEFAULT_FUNCTION_SEED_SIZE);
        let key = StableObjectKey::function(&artifact_ref.key, target, size, Some(&name))?;
        functions.insert(
            (target, name.clone()),
            ParsedFunction {
                object_ref: ObjectRef::new(ObjectKind::Function, key),
                name,
                address: Some(target),
                size,
                boundary_source: "call_target".to_string(),
                boundary_confidence: BoundaryConfidence::Heuristic.as_str().to_string(),
                frame_pointer: None,
                stack_frame_size: None,
                stack_cleanup_size: None,
                epilogue_kind: None,
                has_frame_epilogue: false,
                stack_slots: Vec::new(),
                calling_convention: None,
                argument_registers: Vec::new(),
                string_count: count_related_strings(target, size, strings),
                call_count: 0,
            },
        );
    }

    if functions.is_empty() {
        for (index, import) in imports.iter().take(4).enumerate() {
            let address = 0x1000 + index as u64 * 0x10;
            let name = format!("import_thunk_{}", import.symbol);
            let size = Some(8);
            let key = StableObjectKey::function(&artifact_ref.key, address, size, Some(&name))?;
            functions.insert(
                (address, name.clone()),
                ParsedFunction {
                    object_ref: ObjectRef::new(ObjectKind::Function, key),
                    name,
                    address: Some(address),
                    size,
                    boundary_source: "import_thunk".to_string(),
                    boundary_confidence: BoundaryConfidence::ImportThunk.as_str().to_string(),
                    frame_pointer: None,
                    stack_frame_size: None,
                    stack_cleanup_size: None,
                    epilogue_kind: None,
                    has_frame_epilogue: false,
                    stack_slots: Vec::new(),
                    calling_convention: None,
                    argument_registers: Vec::new(),
                    string_count: 0,
                    call_count: 1,
                },
            );
        }
    }

    if functions.is_empty() {
        let address = entrypoint.unwrap_or(0);
        let name = "unknown_function_0".to_string();
        let size = Some(DEFAULT_FUNCTION_SEED_SIZE);
        let key = StableObjectKey::function(&artifact_ref.key, address, size, Some(&name))?;
        functions.insert(
            (address, name.clone()),
            ParsedFunction {
                object_ref: ObjectRef::new(ObjectKind::Function, key),
                name,
                address: Some(address),
                size,
                boundary_source: "heuristic".to_string(),
                boundary_confidence: BoundaryConfidence::Heuristic.as_str().to_string(),
                frame_pointer: None,
                stack_frame_size: None,
                stack_cleanup_size: None,
                epilogue_kind: None,
                has_frame_epilogue: false,
                stack_slots: Vec::new(),
                calling_convention: None,
                argument_registers: Vec::new(),
                string_count: 0,
                call_count: 0,
            },
        );
    }

    let mut functions = functions.into_values().collect::<Vec<_>>();
    refine_function_extents(artifact_ref, &mut functions, sections)?;
    annotate_function_native_semantics(&mut functions, format, sections);
    Ok(functions)
}

fn collect_direct_call_targets(sections: &[ParsedSection]) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();
    for section in sections
        .iter()
        .filter(|section| is_executable_section(section))
    {
        let Some(section_address) = section.address else {
            continue;
        };
        for instruction in decode_native_instructions(section_address, &section.bytes) {
            if instruction.flow == InstructionFlow::Call {
                if let Some(target) = instruction.target {
                    if section_contains_address(section, target) {
                        targets.insert(target);
                    }
                }
            }
        }
    }
    targets
}

fn refine_function_extents(
    artifact_ref: &ObjectRef,
    functions: &mut [ParsedFunction],
    sections: &[ParsedSection],
) -> RevDeckResult<()> {
    let starts = functions
        .iter()
        .filter_map(|function| function.address)
        .collect::<Vec<_>>();
    for function in functions {
        let Some(address) = function.address else {
            continue;
        };
        let mut refined_end = function
            .size
            .map(|size| address.saturating_add(size))
            .unwrap_or(address);
        if let Some(next_start) = starts
            .iter()
            .copied()
            .filter(|candidate| *candidate > address)
            .min()
        {
            refined_end = refined_end.min(next_start);
        }
        if let Some(section_end) = section_end_for_address(sections, address) {
            refined_end = refined_end.min(section_end);
        }
        if let Some(terminal_end) = terminal_end_for_function(address, refined_end, sections) {
            refined_end = refined_end.min(terminal_end);
        }
        if refined_end > address {
            function.size = Some(refined_end - address);
            let key = StableObjectKey::function(
                &artifact_ref.key,
                address,
                function.size,
                Some(&function.name),
            )?;
            function.object_ref = ObjectRef::new(ObjectKind::Function, key);
        }
    }
    Ok(())
}

fn annotate_function_native_semantics(
    functions: &mut [ParsedFunction],
    format: ArtifactFormat,
    sections: &[ParsedSection],
) {
    for function in functions {
        let Some(address) = function.address else {
            continue;
        };
        let Some(size) = function.size else {
            continue;
        };
        let bytes = function_bytes(address, size, sections);
        if bytes.is_empty() {
            continue;
        }
        let instructions = decode_native_instructions(address, &bytes);
        let has_frame_pointer = instructions
            .windows(2)
            .next()
            .map(|window| {
                window[0].mnemonic == "push"
                    && window[0].operands == "rbp"
                    && window[1].mnemonic == "mov"
                    && window[1].operands == "rbp,rsp"
            })
            .unwrap_or(false);
        if has_frame_pointer {
            function.frame_pointer = Some("rbp".to_string());
        }
        function.stack_frame_size = instructions.iter().find_map(stack_allocation_size);
        function.stack_cleanup_size = instructions.iter().rev().find_map(stack_cleanup_size);
        function.epilogue_kind = epilogue_kind_for_instructions(&instructions).map(str::to_string);
        function.has_frame_epilogue = function.epilogue_kind.is_some();
        function.stack_slots = stack_slots_for_instructions(&instructions);
        if let Some((calling_convention, registers)) =
            argument_registers_for_instructions(format, &instructions)
        {
            function.calling_convention = Some(calling_convention.to_string());
            function.argument_registers = registers;
        }
    }
}

#[derive(Debug, Clone, Default)]
struct NativeCfgFacts {
    basic_blocks: Vec<ParsedBasicBlock>,
    instructions: Vec<ParsedInstruction>,
    cfg_edges: Vec<ParsedCfgEdge>,
    xrefs: Vec<ParsedXref>,
    function_call_counts: BTreeMap<String, u64>,
    function_string_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct FunctionTarget {
    object_ref: ObjectRef,
}

#[derive(Debug, Clone)]
struct StringTarget {
    object_ref: ObjectRef,
}

#[derive(Debug, Clone)]
struct ImportTarget {
    object_ref: ObjectRef,
}

fn collect_native_cfg(
    artifact_ref: &ObjectRef,
    sections: &[ParsedSection],
    functions: &[ParsedFunction],
    strings: &[ParsedString],
    imports: &[ParsedImport],
) -> RevDeckResult<NativeCfgFacts> {
    let mut facts = NativeCfgFacts::default();
    let function_targets = function_targets_by_start(functions);
    let string_targets = string_targets_by_start(strings);
    let import_targets = import_targets_by_start(imports);
    for function in functions {
        let Some(address) = function.address else {
            continue;
        };
        let bytes = function_bytes(address, function.size.unwrap_or(16), sections);
        if bytes.is_empty() {
            continue;
        }
        let function_facts = scan_function_cfg(
            artifact_ref,
            function,
            address,
            &bytes,
            &function_targets,
            &string_targets,
            &import_targets,
        )?;
        facts.basic_blocks.extend(function_facts.basic_blocks);
        facts.instructions.extend(function_facts.instructions);
        facts.cfg_edges.extend(function_facts.cfg_edges);
        facts.xrefs.extend(function_facts.xrefs);
        for (function_key, count) in function_facts.function_call_counts {
            *facts.function_call_counts.entry(function_key).or_insert(0) += count;
        }
        for (function_key, count) in function_facts.function_string_counts {
            *facts
                .function_string_counts
                .entry(function_key)
                .or_insert(0) += count;
        }
    }
    Ok(facts)
}

fn scan_function_cfg(
    artifact_ref: &ObjectRef,
    function: &ParsedFunction,
    start_address: u64,
    bytes: &[u8],
    function_targets: &BTreeMap<u64, FunctionTarget>,
    string_targets: &BTreeMap<u64, StringTarget>,
    import_targets: &BTreeMap<u64, ImportTarget>,
) -> RevDeckResult<NativeCfgFacts> {
    let decoded = decode_native_instructions(start_address, bytes);
    if decoded.is_empty() {
        return Ok(NativeCfgFacts::default());
    }

    let mut leaders = BTreeSet::from([start_address]);
    let resolved_targets = resolved_control_flow_targets_by_address(&decoded);
    for instruction in &decoded {
        if let Some(target) = instruction
            .target
            .or_else(|| resolved_targets.get(&instruction.address).copied())
        {
            if target >= start_address && target < start_address + bytes.len() as u64 {
                leaders.insert(target);
            }
        }
        if instruction.is_branch() && !instruction.is_unconditional_terminal() {
            let next = instruction.address + instruction.size as u64;
            if next < start_address + bytes.len() as u64 {
                leaders.insert(next);
            }
        }
    }

    let mut blocks_by_start = BTreeMap::new();
    let mut current_block_start = start_address;
    let mut current_block_instructions = Vec::new();
    let mut block_groups: Vec<(u64, Vec<DecodedInstruction>)> = Vec::new();
    for instruction in decoded {
        if instruction.address != current_block_start
            && leaders.contains(&instruction.address)
            && !current_block_instructions.is_empty()
        {
            block_groups.push((current_block_start, current_block_instructions));
            current_block_start = instruction.address;
            current_block_instructions = Vec::new();
        }
        let should_close = instruction.is_terminal();
        current_block_instructions.push(instruction);
        if should_close {
            block_groups.push((current_block_start, current_block_instructions));
            current_block_instructions = Vec::new();
            current_block_start = block_groups
                .last()
                .and_then(|(_, instructions)| instructions.last())
                .map(|instruction| instruction.address + instruction.size as u64)
                .unwrap_or(current_block_start);
        }
    }
    if !current_block_instructions.is_empty() {
        block_groups.push((current_block_start, current_block_instructions));
    }

    let mut facts = NativeCfgFacts::default();
    for (ordinal, (block_start, instructions)) in block_groups.iter().enumerate() {
        let block_end = instructions
            .last()
            .map(|instruction| instruction.address + instruction.size as u64)
            .unwrap_or(*block_start);
        let block_key = StableObjectKey::basic_block(
            &artifact_ref.key,
            &function.object_ref,
            *block_start,
            ordinal as u64,
        )?;
        let block_ref = ObjectRef::new(ObjectKind::BasicBlock, block_key);
        blocks_by_start.insert(*block_start, block_ref.clone());
        facts.basic_blocks.push(ParsedBasicBlock {
            object_ref: block_ref.clone(),
            function: function.object_ref.clone(),
            address: *block_start,
            end_address: block_end,
            size: block_end.saturating_sub(*block_start),
            ordinal: ordinal as u64,
            terminator: instructions
                .last()
                .map(|instruction| instruction.mnemonic.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            confidence: 0.6,
        });

        let mut latest_flag_producer = None;
        let mut latest_flag_condition = None;
        let mut latest_register_writers = BTreeMap::<String, ObjectRef>::new();
        let mut latest_register_constants = BTreeMap::<String, RegisterConstantSource>::new();
        for instruction in instructions {
            let ordinal = facts.instructions.len() as u64;
            let key =
                StableObjectKey::instruction(&artifact_ref.key, instruction.address, ordinal)?;
            let instruction_ref = ObjectRef::new(ObjectKind::Instruction, key);
            let condition_source = if instruction.flow == InstructionFlow::ConditionalBranch {
                latest_flag_producer.clone()
            } else {
                None
            };
            let condition_summary = if instruction.flow == InstructionFlow::ConditionalBranch {
                latest_flag_condition.as_ref().map(|condition| {
                    branch_condition_summary(instruction, condition, &latest_register_constants)
                })
            } else {
                None
            };
            let (register_reads, register_writes) = register_accesses_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
            );
            let register_sources = register_reads
                .iter()
                .filter_map(|register| {
                    latest_register_writers
                        .get(register)
                        .cloned()
                        .map(|source| RegisterSource {
                            register: register.clone(),
                            source,
                        })
                })
                .collect::<Vec<_>>();
            let constant_sources = register_reads
                .iter()
                .filter_map(|register| latest_register_constants.get(register).cloned())
                .collect::<Vec<_>>();
            let mut constant_writes = constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                instruction.data_target,
            );
            constant_writes.extend(copied_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                &constant_sources,
            ));
            constant_writes.extend(imul_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                &constant_sources,
            ));
            constant_writes.extend(cmov_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                latest_flag_condition.as_ref(),
                &latest_register_constants,
            ));
            constant_writes.extend(setcc_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                latest_flag_condition.as_ref(),
                &latest_register_constants,
            ));
            constant_writes.extend(movzx_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                &constant_sources,
            ));
            constant_writes.extend(movsx_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                &constant_sources,
            ));
            constant_writes.extend(movsxd_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                &constant_sources,
            ));
            constant_writes.extend(arithmetic_constant_writes_for_instruction(
                instruction.mnemonic.as_str(),
                &instruction.typed_operands,
                &constant_sources,
            ));
            let resolved_target =
                resolved_control_flow_target(instruction, &constant_sources).or(instruction.target);
            let mut tracked_constant_writes = constant_writes.clone();
            tracked_constant_writes.extend(zero_extended_alias_constant_writes(&constant_writes));
            tracked_constant_writes.extend(low_byte_alias_constant_writes(&constant_writes));
            facts.instructions.push(ParsedInstruction {
                object_ref: instruction_ref.clone(),
                function: function.object_ref.clone(),
                block: block_ref.clone(),
                address: instruction.address,
                size: instruction.size as u64,
                bytes_hex: bytes_hex(&instruction.bytes),
                mnemonic: instruction.mnemonic.clone(),
                operands_text: instruction.operands.clone(),
                typed_operands: instruction.typed_operands.clone(),
                register_reads,
                register_writes: register_writes.clone(),
                register_sources,
                constant_writes: constant_writes.clone(),
                constant_sources,
                target: resolved_target,
                flow_kind: instruction.flow_kind().map(str::to_string),
                data_target: instruction.data_target,
                condition_source,
                condition_summary,
                ordinal,
                confidence: instruction.confidence,
            });
            if is_flag_producer(instruction) {
                latest_flag_producer = Some(instruction_ref.clone());
                latest_flag_condition = Some(condition_from_flag_producer(instruction));
            }
            for register in register_writes.iter() {
                latest_register_writers.insert(register.clone(), instruction_ref.clone());
                latest_register_constants.remove(register);
                if let Some(alias) = zero_extended_alias_register(register) {
                    latest_register_writers.insert(alias.to_string(), instruction_ref.clone());
                    latest_register_constants.remove(alias);
                }
                if let Some(alias) = low_byte_alias_register(register) {
                    latest_register_writers.insert(alias.to_string(), instruction_ref.clone());
                    latest_register_constants.remove(alias);
                }
            }
            for constant_write in tracked_constant_writes {
                latest_register_constants.insert(
                    constant_write.register.clone(),
                    RegisterConstantSource {
                        register: constant_write.register,
                        value: constant_write.value,
                        width_bits: constant_write.width_bits,
                        source: instruction_ref.clone(),
                    },
                );
            }
        }
    }

    append_instruction_xrefs(
        artifact_ref,
        function_targets,
        string_targets,
        import_targets,
        &blocks_by_start,
        &mut facts,
    )?;

    for (block_index, (_block_start, instructions)) in block_groups.iter().enumerate() {
        let Some(source_block) = facts
            .basic_blocks
            .get(block_index)
            .map(|block| block.object_ref.clone())
        else {
            continue;
        };
        let Some(last) = instructions.last() else {
            continue;
        };
        let parsed_last = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == last.address);
        let branch_context = parsed_last.and_then(branch_edge_context);
        if let Some(target) = parsed_last
            .and_then(ParsedInstruction::control_flow_target)
            .or(last.target)
            .and_then(|address| blocks_by_start.get(&address).cloned())
        {
            let known_outcome = branch_context
                .as_ref()
                .and_then(|context| context.known_outcome.as_deref())
                .and_then(|outcome| (outcome == "taken").then(|| "taken".to_string()));
            facts.cfg_edges.push(parsed_cfg_edge(
                source_block.clone(),
                target,
                "branch",
                branch_context
                    .as_ref()
                    .map(|context| context.condition_summary.clone()),
                known_outcome,
            )?);
        }
        if last.flow == InstructionFlow::ConditionalBranch || !last.is_terminal() {
            if let Some(next_block) = facts
                .basic_blocks
                .get(block_index + 1)
                .map(|block| block.object_ref.clone())
            {
                let known_outcome = branch_context
                    .as_ref()
                    .and_then(|context| context.known_outcome.as_deref())
                    .and_then(|outcome| (outcome == "not_taken").then(|| "not_taken".to_string()));
                facts.cfg_edges.push(parsed_cfg_edge(
                    source_block,
                    next_block,
                    "fallthrough",
                    branch_context
                        .as_ref()
                        .map(|context| context.condition_summary.clone()),
                    known_outcome,
                )?);
            }
        }
    }

    Ok(facts)
}

fn parsed_cfg_edge(
    source: ObjectRef,
    target: ObjectRef,
    edge_kind: &str,
    condition_summary: Option<String>,
    known_outcome: Option<String>,
) -> RevDeckResult<ParsedCfgEdge> {
    let key = StableObjectKey::edge(EdgeKind::ControlFlow, &source, &target)?;
    Ok(ParsedCfgEdge {
        edge_ref: ObjectRef::new(ObjectKind::Edge, key),
        source,
        target,
        edge_kind: edge_kind.to_string(),
        condition_summary,
        known_outcome,
        confidence: 0.6,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BranchEdgeContext {
    condition_summary: String,
    known_outcome: Option<String>,
}

fn branch_edge_context(instruction: &ParsedInstruction) -> Option<BranchEdgeContext> {
    let condition_summary = instruction.condition_summary.clone()?;
    let known_outcome = if condition_summary.contains("(known taken)") {
        Some("taken".to_string())
    } else if condition_summary.contains("(known not taken)") {
        Some("not_taken".to_string())
    } else {
        None
    };
    Some(BranchEdgeContext {
        condition_summary,
        known_outcome,
    })
}

fn is_flag_producer(instruction: &DecodedInstruction) -> bool {
    matches!(instruction.mnemonic.as_str(), "cmp" | "test")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FlagCondition {
    mnemonic: String,
    operands_text: String,
    operands: Vec<DecodedOperand>,
}

fn condition_from_flag_producer(instruction: &DecodedInstruction) -> FlagCondition {
    FlagCondition {
        mnemonic: instruction.mnemonic.clone(),
        operands_text: instruction.operands.clone(),
        operands: instruction.typed_operands.clone(),
    }
}

fn branch_condition_summary(
    branch: &DecodedInstruction,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> String {
    if condition.mnemonic == "cmp" {
        if let Some(summary) = cmp_branch_summary(branch.mnemonic.as_str(), condition, constants) {
            return summary;
        }
    }
    if condition.mnemonic == "test" {
        if let Some(summary) = test_branch_summary(branch.mnemonic.as_str(), condition, constants) {
            return summary;
        }
    }
    format!(
        "{} if {} {}",
        branch.mnemonic, condition.mnemonic, condition.operands_text
    )
}

fn cmp_branch_summary(
    branch_mnemonic: &str,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<String> {
    let left = condition.operands.first()?;
    let right = condition.operands.get(1)?;
    let left = operand_summary_text(left)?;
    let right = operand_summary_text(right)?;
    if let Some(expect_sign_set) = sign_flag_branch_expectation(branch_mnemonic) {
        let outcome = cmp_sign_known_outcome(condition, constants)
            .map(|sign_set| branch_outcome_suffix(sign_set == expect_sign_set));
        return Some(format!(
            "{branch_mnemonic} if sign({left} - {right}) is {}{}",
            sign_flag_state_label(expect_sign_set),
            outcome.unwrap_or_default()
        ));
    }
    let relation = match branch_mnemonic {
        "je" => "==",
        "jne" => "!=",
        "ja" => ">",
        "jae" => ">=",
        "jb" => "<",
        "jbe" => "<=",
        "jg" => "> signed",
        "jge" => ">= signed",
        "jl" => "< signed",
        "jle" => "<= signed",
        _ => return None,
    };
    let outcome =
        cmp_known_outcome(branch_mnemonic, condition, constants).map(branch_outcome_suffix);
    Some(format!(
        "{branch_mnemonic} if {left} {relation} {right}{}",
        outcome.unwrap_or_default()
    ))
}

fn test_branch_summary(
    branch_mnemonic: &str,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<String> {
    let left = condition.operands.first()?;
    let right = condition.operands.get(1)?;
    if left.kind == native_decode::OperandKind::Register
        && right.kind == native_decode::OperandKind::Register
        && left.register == right.register
    {
        let register = left.register.as_deref()?;
        let outcome = constants
            .get(register)
            .and_then(|source| match branch_mnemonic {
                "je" => Some(source.value == 0),
                "jne" => Some(source.value != 0),
                "jp" => Some(parity_even(source.value)),
                "jnp" => Some(!parity_even(source.value)),
                "js" => Some(sign_bit_set(
                    source.value,
                    normalized_width_bits(source.width_bits),
                )),
                "jns" => Some(!sign_bit_set(
                    source.value,
                    normalized_width_bits(source.width_bits),
                )),
                _ => None,
            })
            .map(branch_outcome_suffix)
            .unwrap_or_default();
        return match branch_mnemonic {
            "je" => Some(format!("{branch_mnemonic} if {register} == 0{outcome}")),
            "jne" => Some(format!("{branch_mnemonic} if {register} != 0{outcome}")),
            "jp" => Some(format!(
                "{branch_mnemonic} if parity({register}) is even{outcome}"
            )),
            "jnp" => Some(format!(
                "{branch_mnemonic} if parity({register}) is odd{outcome}"
            )),
            "js" => Some(format!("{branch_mnemonic} if {register} < 0{outcome}")),
            "jns" => Some(format!("{branch_mnemonic} if {register} >= 0{outcome}")),
            _ => None,
        };
    }
    let left = operand_summary_text(left)?;
    let right = operand_summary_text(right)?;
    if let Some(expect_sign_set) = sign_flag_branch_expectation(branch_mnemonic) {
        let outcome = test_sign_known_outcome(condition, constants)
            .map(|sign_set| branch_outcome_suffix(sign_set == expect_sign_set));
        return Some(format!(
            "{branch_mnemonic} if sign({left} & {right}) is {}{}",
            sign_flag_state_label(expect_sign_set),
            outcome.unwrap_or_default()
        ));
    }
    match branch_mnemonic {
        "je" => {
            let outcome = test_zero_known_outcome(condition, constants)
                .map(branch_outcome_suffix)
                .unwrap_or_default();
            Some(format!(
                "{branch_mnemonic} if ({left} & {right}) == 0{outcome}"
            ))
        }
        "jne" => {
            let outcome = test_zero_known_outcome(condition, constants)
                .map(|zero| branch_outcome_suffix(!zero))
                .unwrap_or_default();
            Some(format!(
                "{branch_mnemonic} if ({left} & {right}) != 0{outcome}"
            ))
        }
        "jp" => {
            let outcome = test_parity_known_outcome(condition, constants)
                .map(branch_outcome_suffix)
                .unwrap_or_default();
            Some(format!(
                "{branch_mnemonic} if parity({left} & {right}) is even{outcome}"
            ))
        }
        "jnp" => {
            let outcome = test_parity_known_outcome(condition, constants)
                .map(|even| branch_outcome_suffix(!even))
                .unwrap_or_default();
            Some(format!(
                "{branch_mnemonic} if parity({left} & {right}) is odd{outcome}"
            ))
        }
        _ => None,
    }
}

fn cmp_known_outcome(
    branch_mnemonic: &str,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    known_condition_outcome(branch_mnemonic, condition, constants)
}

fn known_condition_outcome(
    mnemonic: &str,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    if condition.mnemonic == "cmp" {
        return cmp_condition_outcome(mnemonic, condition, constants);
    }
    if condition.mnemonic == "test" {
        return test_condition_outcome(mnemonic, condition, constants);
    }
    None
}

fn cmp_condition_outcome(
    mnemonic: &str,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    let width_bits = condition_result_width(condition, constants);
    let mask = width_mask(width_bits);
    let left = condition_operand_value(condition.operands.first()?, constants)? & mask;
    let right = condition_operand_value(condition.operands.get(1)?, constants)? & mask;
    match mnemonic {
        "je" => Some(left == right),
        "jne" => Some(left != right),
        "ja" => Some(left > right),
        "jae" => Some(left >= right),
        "jb" => Some(left < right),
        "jbe" => Some(left <= right),
        "jg" => Some(signed_width_value(left, width_bits) > signed_width_value(right, width_bits)),
        "jge" => {
            Some(signed_width_value(left, width_bits) >= signed_width_value(right, width_bits))
        }
        "jl" => Some(signed_width_value(left, width_bits) < signed_width_value(right, width_bits)),
        "jle" => {
            Some(signed_width_value(left, width_bits) <= signed_width_value(right, width_bits))
        }
        _ => None,
    }
}

fn test_condition_outcome(
    mnemonic: &str,
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    if let Some(expect_sign_set) = sign_flag_branch_expectation(mnemonic) {
        return test_sign_known_outcome(condition, constants)
            .map(|sign_set| sign_set == expect_sign_set);
    }
    match mnemonic {
        "je" => test_zero_known_outcome(condition, constants),
        "jne" => test_zero_known_outcome(condition, constants).map(|zero| !zero),
        "jp" => test_parity_known_outcome(condition, constants),
        "jnp" => test_parity_known_outcome(condition, constants).map(|even| !even),
        _ => None,
    }
}

fn cmp_sign_known_outcome(
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    let left = condition_operand_value(condition.operands.first()?, constants)?;
    let right = condition_operand_value(condition.operands.get(1)?, constants)?;
    let width_bits = condition_result_width(condition, constants);
    let result = left.wrapping_sub(right) & width_mask(width_bits);
    Some(sign_bit_set(result, width_bits))
}

fn test_sign_known_outcome(
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    let (result, width_bits) = test_result_value(condition, constants)?;
    Some(sign_bit_set(result, width_bits))
}

fn test_zero_known_outcome(
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    let (result, _width_bits) = test_result_value(condition, constants)?;
    Some(result == 0)
}

fn test_parity_known_outcome(
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<bool> {
    let (result, _width_bits) = test_result_value(condition, constants)?;
    Some(parity_even(result))
}

fn test_result_value(
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<(u64, u16)> {
    let left = condition_operand_value(condition.operands.first()?, constants)?;
    let right = condition_operand_value(condition.operands.get(1)?, constants)?;
    let width_bits = condition_result_width(condition, constants);
    let result = (left & right) & width_mask(width_bits);
    Some((result, width_bits))
}

fn condition_operand_value(
    operand: &DecodedOperand,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<u64> {
    match operand.kind {
        native_decode::OperandKind::Immediate => operand.value,
        native_decode::OperandKind::Register => {
            let register = operand.register.as_deref()?;
            constants.get(register).map(|source| source.value)
        }
        _ => None,
    }
}

fn condition_result_width(
    condition: &FlagCondition,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> u16 {
    condition
        .operands
        .first()
        .and_then(|operand| operand_known_width_bits(operand, constants))
        .or_else(|| {
            condition
                .operands
                .get(1)
                .and_then(|operand| operand_known_width_bits(operand, constants))
        })
        .unwrap_or(64)
}

fn operand_known_width_bits(
    operand: &DecodedOperand,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Option<u16> {
    operand
        .width_bits
        .or_else(|| {
            let register = operand.register.as_deref()?;
            constants.get(register).and_then(|source| source.width_bits)
        })
        .map(|width_bits| normalized_width_bits(Some(width_bits)))
}

fn normalized_width_bits(width_bits: Option<u16>) -> u16 {
    width_bits.unwrap_or(64).clamp(1, 64)
}

fn width_mask(width_bits: u16) -> u64 {
    if width_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << width_bits) - 1
    }
}

fn sign_bit_set(value: u64, width_bits: u16) -> bool {
    let width_bits = normalized_width_bits(Some(width_bits));
    let sign_bit = 1u64 << (width_bits - 1);
    value & sign_bit != 0
}

fn signed_width_value(value: u64, width_bits: u16) -> i64 {
    let width_bits = normalized_width_bits(Some(width_bits));
    let mask = width_mask(width_bits);
    let value = value & mask;
    if width_bits >= 64 {
        value as i64
    } else if sign_bit_set(value, width_bits) {
        (value | !mask) as i64
    } else {
        value as i64
    }
}

fn parity_even(value: u64) -> bool {
    (value as u8).count_ones() % 2 == 0
}

fn sign_flag_branch_expectation(branch_mnemonic: &str) -> Option<bool> {
    match branch_mnemonic {
        "js" => Some(true),
        "jns" => Some(false),
        _ => None,
    }
}

fn sign_flag_state_label(sign_set: bool) -> &'static str {
    if sign_set {
        "set"
    } else {
        "clear"
    }
}

fn branch_outcome_suffix(taken: bool) -> &'static str {
    if taken {
        " (known taken)"
    } else {
        " (known not taken)"
    }
}

fn operand_summary_text(operand: &DecodedOperand) -> Option<String> {
    match operand.kind {
        native_decode::OperandKind::Register => operand.register.clone(),
        native_decode::OperandKind::Immediate => operand.value.map(|value| format!("0x{value:x}")),
        native_decode::OperandKind::Memory => Some(operand.text.clone()),
        native_decode::OperandKind::RelativeTarget | native_decode::OperandKind::Raw => {
            Some(operand.text.clone())
        }
    }
}

fn function_targets_by_start(functions: &[ParsedFunction]) -> BTreeMap<u64, FunctionTarget> {
    functions
        .iter()
        .filter_map(|function| {
            function.address.map(|address| {
                (
                    address,
                    FunctionTarget {
                        object_ref: function.object_ref.clone(),
                    },
                )
            })
        })
        .collect()
}

fn string_targets_by_start(strings: &[ParsedString]) -> BTreeMap<u64, StringTarget> {
    strings
        .iter()
        .filter_map(|string| {
            string.address.map(|address| {
                (
                    address,
                    StringTarget {
                        object_ref: string.object_ref.clone(),
                    },
                )
            })
        })
        .collect()
}

fn import_targets_by_start(imports: &[ParsedImport]) -> BTreeMap<u64, ImportTarget> {
    imports
        .iter()
        .filter_map(|import| {
            import.address.map(|address| {
                (
                    address,
                    ImportTarget {
                        object_ref: import.object_ref.clone(),
                    },
                )
            })
        })
        .collect()
}

fn append_instruction_xrefs(
    artifact_ref: &ObjectRef,
    functions_by_start: &BTreeMap<u64, FunctionTarget>,
    strings_by_start: &BTreeMap<u64, StringTarget>,
    imports_by_start: &BTreeMap<u64, ImportTarget>,
    blocks_by_start: &BTreeMap<u64, ObjectRef>,
    facts: &mut NativeCfgFacts,
) -> RevDeckResult<()> {
    let mut referenced_strings_by_function = BTreeSet::new();
    for instruction in &facts.instructions {
        for source in &instruction.register_sources {
            push_native_xref(
                artifact_ref,
                &mut facts.xrefs,
                &instruction.object_ref,
                &source.source,
                EdgeKind::References,
                Some(instruction.address),
            )?;
        }
        for source in &instruction.constant_sources {
            push_native_xref(
                artifact_ref,
                &mut facts.xrefs,
                &instruction.object_ref,
                &source.source,
                EdgeKind::References,
                Some(instruction.address),
            )?;
        }

        if let Some(data_target) = instruction_data_target(instruction) {
            if let Some(target) = strings_by_start.get(&data_target) {
                push_native_xref(
                    artifact_ref,
                    &mut facts.xrefs,
                    &instruction.object_ref,
                    &target.object_ref,
                    EdgeKind::References,
                    Some(instruction.address),
                )?;
                push_native_xref(
                    artifact_ref,
                    &mut facts.xrefs,
                    &instruction.function,
                    &target.object_ref,
                    EdgeKind::References,
                    Some(instruction.address),
                )?;
                referenced_strings_by_function.insert((
                    instruction.function.key.to_string(),
                    target.object_ref.key.to_string(),
                ));
            }
        }

        let Some(flow_kind) = instruction.flow_kind.as_deref() else {
            continue;
        };
        match flow_kind {
            "call" => {
                if let Some(target) = instruction
                    .control_flow_target()
                    .and_then(|address| functions_by_start.get(&address))
                {
                    push_native_xref(
                        artifact_ref,
                        &mut facts.xrefs,
                        &instruction.function,
                        &target.object_ref,
                        EdgeKind::Calls,
                        Some(instruction.address),
                    )?;
                    *facts
                        .function_call_counts
                        .entry(instruction.function.key.to_string())
                        .or_insert(0) += 1;
                } else if let Some(target) = instruction_import_slot(instruction)
                    .and_then(|address| imports_by_start.get(&address))
                {
                    push_import_call_xref(
                        artifact_ref,
                        &mut facts.xrefs,
                        &mut facts.function_call_counts,
                        instruction,
                        &target.object_ref,
                    )?;
                }
            }
            "jump" | "conditional_branch" => {
                if flow_kind == "conditional_branch" {
                    if let Some(condition_source) = &instruction.condition_source {
                        push_native_xref(
                            artifact_ref,
                            &mut facts.xrefs,
                            &instruction.object_ref,
                            condition_source,
                            EdgeKind::References,
                            Some(instruction.address),
                        )?;
                    }
                }
                if let Some(target) = instruction_import_slot(instruction)
                    .and_then(|address| imports_by_start.get(&address))
                {
                    push_import_call_xref(
                        artifact_ref,
                        &mut facts.xrefs,
                        &mut facts.function_call_counts,
                        instruction,
                        &target.object_ref,
                    )?;
                } else if let Some(target_block) = instruction
                    .control_flow_target()
                    .and_then(|address| blocks_by_start.get(&address))
                {
                    push_native_xref(
                        artifact_ref,
                        &mut facts.xrefs,
                        &instruction.object_ref,
                        target_block,
                        EdgeKind::References,
                        Some(instruction.address),
                    )?;
                } else if let Some(target) = instruction
                    .control_flow_target()
                    .and_then(|address| functions_by_start.get(&address))
                {
                    push_native_xref(
                        artifact_ref,
                        &mut facts.xrefs,
                        &instruction.object_ref,
                        &target.object_ref,
                        EdgeKind::References,
                        Some(instruction.address),
                    )?;
                }
            }
            _ => {}
        }
    }
    for (function_key, _string_key) in referenced_strings_by_function {
        *facts
            .function_string_counts
            .entry(function_key)
            .or_insert(0) += 1;
    }
    Ok(())
}

impl ParsedInstruction {
    fn control_flow_target(&self) -> Option<u64> {
        self.typed_operands
            .iter()
            .find_map(DecodedOperand::control_flow_target)
            .or(self.target)
    }
}

fn register_accesses_for_operands(operands: &[DecodedOperand]) -> (Vec<String>, Vec<String>) {
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    for operand in operands {
        let registers = operand_registers(operand);
        match operand.role {
            native_decode::OperandRole::Destination => {
                if operand.kind == native_decode::OperandKind::Memory {
                    for register in registers {
                        reads.insert(register);
                    }
                    continue;
                }
                for register in registers {
                    writes.insert(register);
                }
            }
            native_decode::OperandRole::Source
            | native_decode::OperandRole::CallTarget
            | native_decode::OperandRole::BranchTarget
            | native_decode::OperandRole::DataReference => {
                for register in registers {
                    reads.insert(register);
                }
            }
            native_decode::OperandRole::Unknown => {}
        }
    }
    (
        reads.into_iter().collect::<Vec<_>>(),
        writes.into_iter().collect::<Vec<_>>(),
    )
}

fn register_accesses_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
) -> (Vec<String>, Vec<String>) {
    let (mut reads, mut writes) = register_accesses_for_operands(operands);
    let self_xor = self_xor_register(mnemonic, operands);
    if let Some(register) = self_xor.as_ref() {
        reads.retain(|read| read != register);
    }
    if self_xor.is_none() {
        if let Some(register) = in_place_arithmetic_register(mnemonic, operands) {
            insert_sorted_register(&mut reads, register);
        }
    }
    if call_stack_pointer_effect_instruction(mnemonic) {
        insert_sorted_register(&mut reads, "rsp");
        insert_sorted_register(&mut writes, "rsp");
    }
    if mnemonic == "leave" {
        insert_sorted_register(&mut reads, "rbp");
        insert_sorted_register(&mut writes, "rbp");
        insert_sorted_register(&mut writes, "rsp");
    }
    (reads, writes)
}

fn insert_sorted_register(registers: &mut Vec<String>, register: impl Into<String>) {
    let register = register.into();
    if !registers.iter().any(|existing| existing == &register) {
        registers.push(register);
        registers.sort();
    }
}

fn call_stack_pointer_effect_instruction(mnemonic: &str) -> bool {
    matches!(mnemonic, "call" | "push" | "pop" | "ret")
}

fn operand_registers(operand: &DecodedOperand) -> Vec<String> {
    let mut registers = BTreeSet::new();
    if let Some(register) = operand.register.as_deref() {
        registers.insert(register.to_string());
    }
    if let Some(base) = operand.base.as_deref() {
        registers.insert(base.to_string());
    }
    if let Some(index) = operand.index.as_deref() {
        registers.insert(index.to_string());
    }
    registers.into_iter().collect()
}

fn constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    data_target: Option<u64>,
) -> Vec<RegisterConstantWrite> {
    if let Some(register) = self_xor_register(mnemonic, operands) {
        let width_bits = operands
            .iter()
            .find(|operand| {
                operand.role == native_decode::OperandRole::Destination
                    && operand.kind == native_decode::OperandKind::Register
            })
            .and_then(|operand| operand.width_bits)
            .or(Some(64));
        return vec![RegisterConstantWrite {
            register,
            value: 0,
            width_bits,
        }];
    }
    if mnemonic == "lea" {
        let Some(destination) = destination_register_operand(operands) else {
            return Vec::new();
        };
        let Some(register) = destination.register.clone() else {
            return Vec::new();
        };
        let Some(value) = data_target else {
            return Vec::new();
        };
        return vec![RegisterConstantWrite {
            register,
            value,
            width_bits: destination.width_bits.or(Some(64)),
        }];
    }
    if mnemonic != "mov" {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(immediate) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Immediate
    }) else {
        return Vec::new();
    };
    let Some(register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(value) = immediate.value else {
        return Vec::new();
    };
    vec![RegisterConstantWrite {
        register,
        value,
        width_bits: immediate.width_bits,
    }]
}

fn copied_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    constant_sources: &[RegisterConstantSource],
) -> Vec<RegisterConstantWrite> {
    if mnemonic != "mov" {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(source) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Register
    }) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(source_register) = source.register.as_deref() else {
        return Vec::new();
    };
    let Some(source_constant) = constant_sources
        .iter()
        .find(|constant| constant.register == source_register)
    else {
        return Vec::new();
    };
    vec![RegisterConstantWrite {
        register: destination_register,
        value: source_constant.value,
        width_bits: destination.width_bits.or(source_constant.width_bits),
    }]
}

fn imul_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    constant_sources: &[RegisterConstantSource],
) -> Vec<RegisterConstantWrite> {
    if mnemonic != "imul" {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(source) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Register
    }) else {
        return Vec::new();
    };
    let Some(source_register) = source.register.as_deref() else {
        return Vec::new();
    };
    let Some(immediate) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Immediate
    }) else {
        return Vec::new();
    };
    let Some(immediate_value) = immediate.value else {
        return Vec::new();
    };
    let Some(source_constant) = constant_sources
        .iter()
        .find(|constant| constant.register == source_register)
    else {
        return Vec::new();
    };
    let width_bits = destination
        .width_bits
        .or(source.width_bits)
        .or(source_constant.width_bits)
        .map(|width_bits| normalized_width_bits(Some(width_bits)))
        .or(Some(64));
    let mask = width_mask(width_bits.unwrap_or(64));
    let value = source_constant.value.wrapping_mul(immediate_value) & mask;
    vec![RegisterConstantWrite {
        register: destination_register,
        value,
        width_bits,
    }]
}

fn cmov_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    condition: Option<&FlagCondition>,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Vec<RegisterConstantWrite> {
    let Some(condition_suffix) = mnemonic.strip_prefix("cmov") else {
        return Vec::new();
    };
    let Some(condition_mnemonic) = cmov_condition_mnemonic(condition_suffix) else {
        return Vec::new();
    };
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(condition) = condition else {
        return Vec::new();
    };
    let Some(taken) = known_condition_outcome(condition_mnemonic, condition, constants) else {
        return Vec::new();
    };
    let selected_register = if taken {
        operands.iter().find_map(|operand| {
            (operand.role == native_decode::OperandRole::Source
                && operand.kind == native_decode::OperandKind::Register)
                .then_some(operand.register.as_deref())
                .flatten()
        })
    } else {
        Some(destination_register.as_str())
    };
    let Some(selected_register) = selected_register else {
        return Vec::new();
    };
    let Some(source_constant) = constants.get(selected_register) else {
        return Vec::new();
    };
    vec![RegisterConstantWrite {
        register: destination_register,
        value: source_constant.value,
        width_bits: destination.width_bits.or(source_constant.width_bits),
    }]
}

fn cmov_condition_mnemonic(suffix: &str) -> Option<&'static str> {
    match suffix {
        "o" => Some("jo"),
        "no" => Some("jno"),
        "b" => Some("jb"),
        "ae" => Some("jae"),
        "e" => Some("je"),
        "ne" => Some("jne"),
        "be" => Some("jbe"),
        "a" => Some("ja"),
        "s" => Some("js"),
        "ns" => Some("jns"),
        "p" => Some("jp"),
        "np" => Some("jnp"),
        "l" => Some("jl"),
        "ge" => Some("jge"),
        "le" => Some("jle"),
        "g" => Some("jg"),
        _ => None,
    }
}

fn setcc_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    condition: Option<&FlagCondition>,
    constants: &BTreeMap<String, RegisterConstantSource>,
) -> Vec<RegisterConstantWrite> {
    let Some(condition_suffix) = mnemonic.strip_prefix("set") else {
        return Vec::new();
    };
    let Some(condition_mnemonic) = cmov_condition_mnemonic(condition_suffix) else {
        return Vec::new();
    };
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(condition) = condition else {
        return Vec::new();
    };
    let Some(taken) = known_condition_outcome(condition_mnemonic, condition, constants) else {
        return Vec::new();
    };
    vec![RegisterConstantWrite {
        register: destination_register,
        value: u64::from(taken),
        width_bits: destination.width_bits.or(Some(8)),
    }]
}

fn movzx_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    constant_sources: &[RegisterConstantSource],
) -> Vec<RegisterConstantWrite> {
    if mnemonic != "movzx" {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(source) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Register
    }) else {
        return Vec::new();
    };
    let Some(source_register) = source.register.as_deref() else {
        return Vec::new();
    };
    let Some(source_constant) = constant_sources
        .iter()
        .find(|constant| constant.register == source_register)
    else {
        return Vec::new();
    };
    let source_width_bits = normalized_width_bits(source.width_bits.or(source_constant.width_bits));
    vec![RegisterConstantWrite {
        register: destination_register,
        value: source_constant.value & width_mask(source_width_bits),
        width_bits: destination.width_bits.or(Some(32)),
    }]
}

fn movsx_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    constant_sources: &[RegisterConstantSource],
) -> Vec<RegisterConstantWrite> {
    if mnemonic != "movsx" {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(source) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Register
    }) else {
        return Vec::new();
    };
    let Some(source_register) = source.register.as_deref() else {
        return Vec::new();
    };
    let Some(source_constant) = constant_sources
        .iter()
        .find(|constant| constant.register == source_register)
    else {
        return Vec::new();
    };
    let source_width_bits = normalized_width_bits(source.width_bits.or(source_constant.width_bits));
    let destination_width_bits = normalized_width_bits(destination.width_bits.or(Some(32)));
    let value = sign_extend_to_width(
        source_constant.value,
        source_width_bits,
        destination_width_bits,
    );
    vec![RegisterConstantWrite {
        register: destination_register,
        value,
        width_bits: Some(destination_width_bits),
    }]
}

fn sign_extend_to_width(value: u64, source_width_bits: u16, destination_width_bits: u16) -> u64 {
    let source_width_bits = normalized_width_bits(Some(source_width_bits));
    let destination_width_bits = normalized_width_bits(Some(destination_width_bits));
    let source_mask = width_mask(source_width_bits);
    let destination_mask = width_mask(destination_width_bits);
    let value = value & source_mask;
    if sign_bit_set(value, source_width_bits) {
        (value | (!source_mask)) & destination_mask
    } else {
        value & destination_mask
    }
}

fn movsxd_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    constant_sources: &[RegisterConstantSource],
) -> Vec<RegisterConstantWrite> {
    if mnemonic != "movsxd" {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let Some(source) = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Register
    }) else {
        return Vec::new();
    };
    let Some(source_register) = source.register.as_deref() else {
        return Vec::new();
    };
    let Some(source_constant) = constant_sources
        .iter()
        .find(|constant| constant.register == source_register)
    else {
        return Vec::new();
    };
    let source_width_bits = normalized_width_bits(source.width_bits.or(Some(32)));
    let destination_width_bits = normalized_width_bits(destination.width_bits.or(Some(64)));
    vec![RegisterConstantWrite {
        register: destination_register,
        value: sign_extend_to_width(
            source_constant.value,
            source_width_bits,
            destination_width_bits,
        ),
        width_bits: Some(destination_width_bits),
    }]
}

fn arithmetic_constant_writes_for_instruction(
    mnemonic: &str,
    operands: &[DecodedOperand],
    constant_sources: &[RegisterConstantSource],
) -> Vec<RegisterConstantWrite> {
    if !matches!(
        mnemonic,
        "add"
            | "sub"
            | "and"
            | "or"
            | "xor"
            | "inc"
            | "dec"
            | "shl"
            | "shr"
            | "sar"
            | "not"
            | "neg"
    ) {
        return Vec::new();
    }
    let Some(destination) = destination_register_operand(operands) else {
        return Vec::new();
    };
    let Some(destination_register) = destination.register.clone() else {
        return Vec::new();
    };
    let immediate_value = if matches!(mnemonic, "inc" | "dec" | "not" | "neg") {
        1
    } else {
        let Some(immediate) = operands.iter().find(|operand| {
            operand.role == native_decode::OperandRole::Source
                && operand.kind == native_decode::OperandKind::Immediate
        }) else {
            return Vec::new();
        };
        let Some(immediate_value) = immediate.value else {
            return Vec::new();
        };
        immediate_value
    };
    let Some(source_constant) = constant_sources
        .iter()
        .find(|constant| constant.register == destination_register)
    else {
        return Vec::new();
    };
    let width_bits = destination
        .width_bits
        .or(source_constant.width_bits)
        .map(|width_bits| normalized_width_bits(Some(width_bits)))
        .or(Some(64));
    let mask = width_mask(width_bits.unwrap_or(64));
    let value = match mnemonic {
        "add" => source_constant.value.wrapping_add(immediate_value) & mask,
        "sub" => source_constant.value.wrapping_sub(immediate_value) & mask,
        "and" => (source_constant.value & immediate_value) & mask,
        "or" => (source_constant.value | immediate_value) & mask,
        "xor" => (source_constant.value ^ immediate_value) & mask,
        "inc" => source_constant.value.wrapping_add(1) & mask,
        "dec" => source_constant.value.wrapping_sub(1) & mask,
        "shl" => (source_constant.value << (immediate_value & 0x1f)) & mask,
        "shr" => (source_constant.value & mask) >> (immediate_value & 0x1f),
        "sar" => arithmetic_shift_right(source_constant.value, immediate_value, width_bits),
        "not" => (!source_constant.value) & mask,
        "neg" => 0u64.wrapping_sub(source_constant.value) & mask,
        _ => return Vec::new(),
    };
    vec![RegisterConstantWrite {
        register: destination_register,
        value,
        width_bits,
    }]
}

fn zero_extended_alias_constant_writes(
    constant_writes: &[RegisterConstantWrite],
) -> Vec<RegisterConstantWrite> {
    constant_writes
        .iter()
        .filter_map(|constant| {
            if constant.width_bits != Some(32) {
                return None;
            }
            let alias = zero_extended_alias_register(constant.register.as_str())?;
            Some(RegisterConstantWrite {
                register: alias.to_string(),
                value: constant.value & 0xffff_ffff,
                width_bits: Some(64),
            })
        })
        .collect()
}

fn low_byte_alias_constant_writes(
    constant_writes: &[RegisterConstantWrite],
) -> Vec<RegisterConstantWrite> {
    constant_writes
        .iter()
        .filter_map(|constant| {
            if !matches!(constant.width_bits, Some(32) | Some(64)) {
                return None;
            }
            let alias = low_byte_alias_register(constant.register.as_str())?;
            Some(RegisterConstantWrite {
                register: alias.to_string(),
                value: constant.value & 0xff,
                width_bits: Some(8),
            })
        })
        .collect()
}

fn arithmetic_shift_right(value: u64, shift: u64, width_bits: Option<u16>) -> u64 {
    let width_bits = normalized_width_bits(width_bits);
    let mask = width_mask(width_bits);
    let shift = (shift & 0x1f).min((width_bits - 1) as u64);
    let value = value & mask;
    if !sign_bit_set(value, width_bits) {
        return value >> shift;
    }
    let shifted = value >> shift;
    let fill = mask ^ (mask >> shift);
    (shifted | fill) & mask
}

fn zero_extended_alias_register(register: &str) -> Option<&'static str> {
    match register {
        "eax" => Some("rax"),
        "ecx" => Some("rcx"),
        "edx" => Some("rdx"),
        "ebx" => Some("rbx"),
        "esp" => Some("rsp"),
        "ebp" => Some("rbp"),
        "esi" => Some("rsi"),
        "edi" => Some("rdi"),
        "r8d" => Some("r8"),
        "r9d" => Some("r9"),
        "r10d" => Some("r10"),
        "r11d" => Some("r11"),
        "r12d" => Some("r12"),
        "r13d" => Some("r13"),
        "r14d" => Some("r14"),
        "r15d" => Some("r15"),
        _ => None,
    }
}

fn low_byte_alias_register(register: &str) -> Option<&'static str> {
    match register {
        "eax" | "rax" => Some("al"),
        "ecx" | "rcx" => Some("cl"),
        "edx" | "rdx" => Some("dl"),
        "ebx" | "rbx" => Some("bl"),
        "esp" | "rsp" => Some("spl"),
        "ebp" | "rbp" => Some("bpl"),
        "esi" | "rsi" => Some("sil"),
        "edi" | "rdi" => Some("dil"),
        "r8d" | "r8" => Some("r8b"),
        "r9d" | "r9" => Some("r9b"),
        "r10d" | "r10" => Some("r10b"),
        "r11d" | "r11" => Some("r11b"),
        "r12d" | "r12" => Some("r12b"),
        "r13d" | "r13" => Some("r13b"),
        "r14d" | "r14" => Some("r14b"),
        "r15d" | "r15" => Some("r15b"),
        _ => None,
    }
}

fn destination_register_operand(operands: &[DecodedOperand]) -> Option<&DecodedOperand> {
    operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Destination
            && operand.kind == native_decode::OperandKind::Register
    })
}

fn in_place_arithmetic_register(mnemonic: &str, operands: &[DecodedOperand]) -> Option<String> {
    if !matches!(
        mnemonic,
        "add"
            | "sub"
            | "adc"
            | "sbb"
            | "and"
            | "or"
            | "xor"
            | "inc"
            | "dec"
            | "shl"
            | "shr"
            | "sar"
            | "not"
            | "neg"
    ) {
        return None;
    }
    if !matches!(mnemonic, "inc" | "dec" | "not" | "neg") {
        operands.iter().find(|operand| {
            operand.role == native_decode::OperandRole::Source
                && matches!(
                    operand.kind,
                    native_decode::OperandKind::Immediate
                        | native_decode::OperandKind::Register
                        | native_decode::OperandKind::Memory
                )
        })?;
    }
    destination_register_operand(operands)?.register.clone()
}

fn self_xor_register(mnemonic: &str, operands: &[DecodedOperand]) -> Option<String> {
    if mnemonic != "xor" || operands.len() != 2 {
        return None;
    }
    let destination = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Destination
            && operand.kind == native_decode::OperandKind::Register
    })?;
    let source = operands.iter().find(|operand| {
        operand.role == native_decode::OperandRole::Source
            && operand.kind == native_decode::OperandKind::Register
    })?;
    let destination = destination.register.as_deref()?;
    let source = source.register.as_deref()?;
    (destination == source).then(|| destination.to_string())
}

fn instruction_data_target(instruction: &ParsedInstruction) -> Option<u64> {
    instruction
        .typed_operands
        .iter()
        .find_map(DecodedOperand::data_reference_target)
        .or(instruction.data_target)
}

fn resolved_control_flow_target(
    instruction: &DecodedInstruction,
    constant_sources: &[RegisterConstantSource],
) -> Option<u64> {
    if !matches!(
        instruction.flow,
        InstructionFlow::Call | InstructionFlow::Jump
    ) {
        return None;
    }
    let target_register = instruction.typed_operands.iter().find_map(|operand| {
        (matches!(
            operand.role,
            native_decode::OperandRole::CallTarget | native_decode::OperandRole::BranchTarget
        ) && operand.kind == native_decode::OperandKind::Register)
            .then_some(operand.register.as_deref())
            .flatten()
    })?;
    constant_sources
        .iter()
        .find(|constant| constant.register == target_register)
        .map(|constant| constant.value)
}

fn resolved_control_flow_targets_by_address(
    instructions: &[DecodedInstruction],
) -> BTreeMap<u64, u64> {
    let mut resolved_targets = BTreeMap::new();
    let mut latest_register_constants = BTreeMap::<String, RegisterConstantSource>::new();
    for instruction in instructions {
        let (register_reads, register_writes) = register_accesses_for_instruction(
            instruction.mnemonic.as_str(),
            &instruction.typed_operands,
        );
        let constant_sources = register_reads
            .iter()
            .filter_map(|register| latest_register_constants.get(register).cloned())
            .collect::<Vec<_>>();
        if let Some(target) = resolved_control_flow_target(instruction, &constant_sources) {
            resolved_targets.insert(instruction.address, target);
        }
        let mut constant_writes = constant_writes_for_instruction(
            instruction.mnemonic.as_str(),
            &instruction.typed_operands,
            instruction.data_target,
        );
        constant_writes.extend(copied_constant_writes_for_instruction(
            instruction.mnemonic.as_str(),
            &instruction.typed_operands,
            &constant_sources,
        ));
        let mut tracked_constant_writes = constant_writes.clone();
        tracked_constant_writes.extend(zero_extended_alias_constant_writes(&constant_writes));
        tracked_constant_writes.extend(low_byte_alias_constant_writes(&constant_writes));
        for register in register_writes {
            latest_register_constants.remove(&register);
            if let Some(alias) = zero_extended_alias_register(register.as_str()) {
                latest_register_constants.remove(alias);
            }
            if let Some(alias) = low_byte_alias_register(register.as_str()) {
                latest_register_constants.remove(alias);
            }
        }
        for constant_write in tracked_constant_writes {
            latest_register_constants.insert(
                constant_write.register.clone(),
                RegisterConstantSource {
                    register: constant_write.register,
                    value: constant_write.value,
                    width_bits: constant_write.width_bits,
                    source: ObjectRef::artifact("leader-scan", "constant").unwrap(),
                },
            );
        }
    }
    resolved_targets
}

fn instruction_import_slot(instruction: &ParsedInstruction) -> Option<u64> {
    instruction.control_flow_target().or_else(|| {
        instruction
            .typed_operands
            .iter()
            .find_map(DecodedOperand::data_reference_target)
            .or(instruction.data_target)
    })
}

fn push_import_call_xref(
    artifact_ref: &ObjectRef,
    xrefs: &mut Vec<ParsedXref>,
    function_call_counts: &mut BTreeMap<String, u64>,
    instruction: &ParsedInstruction,
    import_ref: &ObjectRef,
) -> RevDeckResult<()> {
    push_native_xref(
        artifact_ref,
        xrefs,
        &instruction.function,
        import_ref,
        EdgeKind::CallsImport,
        Some(instruction.address),
    )?;
    *function_call_counts
        .entry(instruction.function.key.to_string())
        .or_insert(0) += 1;
    Ok(())
}

fn push_native_xref(
    artifact_ref: &ObjectRef,
    xrefs: &mut Vec<ParsedXref>,
    source: &ObjectRef,
    target: &ObjectRef,
    relation: EdgeKind,
    address: Option<u64>,
) -> RevDeckResult<()> {
    let key = StableObjectKey::xref(
        &artifact_ref.key,
        source,
        target,
        relation.as_str(),
        address,
    )?;
    xrefs.push(ParsedXref {
        object_ref: ObjectRef::new(ObjectKind::Xref, key),
        source: source.clone(),
        target: target.clone(),
        relation,
        address,
    });
    Ok(())
}

fn apply_native_function_call_counts(
    functions: &mut [ParsedFunction],
    call_counts: &BTreeMap<String, u64>,
) {
    for function in functions {
        if let Some(call_count) = call_counts.get(function.object_ref.key.as_str()) {
            function.call_count = function.call_count.saturating_add(*call_count);
        }
    }
}

fn apply_native_function_string_counts(
    functions: &mut [ParsedFunction],
    string_counts: &BTreeMap<String, u64>,
) {
    for function in functions {
        if let Some(string_count) = string_counts.get(function.object_ref.key.as_str()) {
            function.string_count = function.string_count.saturating_add(*string_count);
        }
    }
}

fn is_executable_section(section: &ParsedSection) -> bool {
    let flags = section.flags.to_ascii_lowercase();
    section.name.eq_ignore_ascii_case(".text")
        || flags.contains("text")
        || flags.contains("execute")
        || flags.contains("executable")
}

fn section_contains_address(section: &ParsedSection, address: u64) -> bool {
    let Some(section_address) = section.address else {
        return false;
    };
    let section_end = section_address.saturating_add(section.bytes.len() as u64);
    address >= section_address && address < section_end
}

fn section_end_for_address(sections: &[ParsedSection], address: u64) -> Option<u64> {
    sections.iter().find_map(|section| {
        if !section_contains_address(section, address) {
            return None;
        }
        let section_address = section.address?;
        Some(section_address.saturating_add(section.bytes.len() as u64))
    })
}

fn terminal_end_for_function(
    address: u64,
    current_end: u64,
    sections: &[ParsedSection],
) -> Option<u64> {
    if current_end <= address {
        return None;
    }
    let bytes = function_bytes(address, current_end - address, sections);
    if bytes.is_empty() {
        return None;
    }
    decode_native_instructions(address, &bytes)
        .into_iter()
        .find(|instruction| instruction.is_unconditional_terminal())
        .map(|instruction| instruction.address + instruction.size as u64)
        .filter(|terminal_end| *terminal_end > address && *terminal_end <= current_end)
}

fn stack_allocation_size(instruction: &DecodedInstruction) -> Option<u64> {
    if instruction.mnemonic != "sub" || !instruction.operands.starts_with("rsp,") {
        return None;
    }
    instruction
        .typed_operands
        .iter()
        .find(|operand| {
            operand.role == native_decode::OperandRole::Source
                && operand.kind == native_decode::OperandKind::Immediate
        })
        .and_then(|operand| operand.value)
}

fn stack_cleanup_size(instruction: &DecodedInstruction) -> Option<u64> {
    if instruction.mnemonic != "add" || !instruction.operands.starts_with("rsp,") {
        return None;
    }
    instruction
        .typed_operands
        .iter()
        .find(|operand| {
            operand.role == native_decode::OperandRole::Source
                && operand.kind == native_decode::OperandKind::Immediate
        })
        .and_then(|operand| operand.value)
}

fn epilogue_kind_for_instructions(instructions: &[DecodedInstruction]) -> Option<&'static str> {
    let return_index = instructions
        .iter()
        .rposition(|instruction| instruction.flow == InstructionFlow::Return)?;
    let before_return = &instructions[..return_index];
    let tail = before_return.iter().rev().take(3).collect::<Vec<_>>();
    if tail
        .first()
        .is_some_and(|instruction| instruction.mnemonic == "leave")
    {
        return Some("leave");
    }
    if tail.len() >= 2
        && tail[0].mnemonic == "pop"
        && tail[0].operands == "rbp"
        && stack_cleanup_size(tail[1]).is_some()
    {
        return Some("stack-add-pop-rbp");
    }
    if tail
        .first()
        .is_some_and(|instruction| instruction.mnemonic == "pop" && instruction.operands == "rbp")
    {
        return Some("pop-rbp");
    }
    if tail.first().is_some_and(|instruction| {
        stack_cleanup_size(instruction).is_some()
            || (instruction.mnemonic == "mov" && instruction.operands == "rsp,rbp")
    }) {
        return Some("stack-restore");
    }
    None
}

fn argument_registers_for_instructions(
    format: ArtifactFormat,
    instructions: &[DecodedInstruction],
) -> Option<(&'static str, Vec<ArgumentRegisterHint>)> {
    let (calling_convention, candidates) = match format {
        ArtifactFormat::Pe => ("windows-x64", ["rcx", "rdx", "r8", "r9"].as_slice()),
        ArtifactFormat::Elf => (
            "sysv-x64",
            ["rdi", "rsi", "rdx", "rcx", "r8", "r9"].as_slice(),
        ),
        ArtifactFormat::Unknown => return None,
    };
    let mut written = BTreeSet::<&str>::new();
    let mut seen = BTreeSet::<&str>::new();
    let mut hints = Vec::new();
    for instruction in instructions
        .iter()
        .take_while(|instruction| instruction.flow != InstructionFlow::Call)
        .take(16)
    {
        for operand in &instruction.typed_operands {
            let Some(register) = operand.register.as_deref() else {
                continue;
            };
            if !candidates.contains(&register) {
                continue;
            }
            if operand.role == native_decode::OperandRole::Source
                && !written.contains(register)
                && seen.insert(register)
            {
                if let Some(ordinal) = candidates
                    .iter()
                    .position(|candidate| *candidate == register)
                {
                    hints.push(ArgumentRegisterHint {
                        ordinal: ordinal as u8,
                        register: register.to_string(),
                    });
                }
            }
        }
        for operand in &instruction.typed_operands {
            if operand.role == native_decode::OperandRole::Destination {
                if let Some(register) = operand.register.as_deref() {
                    if candidates.contains(&register) {
                        written.insert(register);
                    }
                }
            }
        }
    }
    hints.sort_by_key(|hint| hint.ordinal);
    (!hints.is_empty()).then_some((calling_convention, hints))
}

fn stack_slots_for_instructions(instructions: &[DecodedInstruction]) -> Vec<StackSlot> {
    let mut slots = BTreeMap::<(String, i64), (Option<u16>, BTreeSet<&'static str>)>::new();
    for operand in instructions
        .iter()
        .flat_map(|instruction| instruction.typed_operands.iter())
    {
        if operand.kind != native_decode::OperandKind::Memory {
            continue;
        }
        let Some(base) = operand.base.as_deref() else {
            continue;
        };
        if !matches!(base, "rbp" | "rsp") {
            continue;
        }
        let Some(offset) = operand.displacement else {
            continue;
        };
        let entry = slots
            .entry((base.to_string(), offset))
            .or_insert((operand.width_bits, BTreeSet::new()));
        if entry.0.is_none() {
            entry.0 = operand.width_bits;
        }
        entry.1.insert(stack_slot_access_kind(operand.role));
    }
    slots
        .into_iter()
        .map(|((base, offset), (width_bits, accesses))| StackSlot {
            base,
            offset,
            width_bits,
            accesses: accesses.into_iter().map(str::to_string).collect::<Vec<_>>(),
        })
        .collect()
}

fn stack_slot_access_kind(role: native_decode::OperandRole) -> &'static str {
    match role {
        native_decode::OperandRole::Destination => "write",
        native_decode::OperandRole::Source => "read",
        native_decode::OperandRole::CallTarget => "call_target",
        native_decode::OperandRole::BranchTarget => "branch_target",
        native_decode::OperandRole::DataReference => "address_reference",
        native_decode::OperandRole::Unknown => "unknown",
    }
}

fn function_bytes(address: u64, size: u64, sections: &[ParsedSection]) -> Vec<u8> {
    for section in sections {
        let Some(section_address) = section.address else {
            continue;
        };
        let section_end = section_address.saturating_add(section.bytes.len() as u64);
        if address < section_address || address >= section_end {
            continue;
        }
        let start = (address - section_address) as usize;
        let available = section.bytes.len().saturating_sub(start);
        let length = available.min(size as usize);
        return section.bytes[start..start + length].to_vec();
    }
    Vec::new()
}

fn collect_xrefs(
    artifact_ref: &ObjectRef,
    functions: &[ParsedFunction],
    strings: &[ParsedString],
    imports: &[ParsedImport],
) -> RevDeckResult<Vec<ParsedXref>> {
    let Some(primary_function) = functions.first() else {
        return Ok(Vec::new());
    };
    let mut xrefs = Vec::new();
    for string in strings
        .iter()
        .filter(|value| is_sensitive_string(&value.value))
        .take(8)
    {
        let address = primary_function.address;
        let key = StableObjectKey::xref(
            &artifact_ref.key,
            &primary_function.object_ref,
            &string.object_ref,
            EdgeKind::References.as_str(),
            address,
        )?;
        xrefs.push(ParsedXref {
            object_ref: ObjectRef::new(ObjectKind::Xref, key),
            source: primary_function.object_ref.clone(),
            target: string.object_ref.clone(),
            relation: EdgeKind::References,
            address,
        });
    }
    for import in imports
        .iter()
        .filter(|value| is_dangerous_import(&value.symbol))
        .take(8)
    {
        let address = primary_function.address;
        let key = StableObjectKey::xref(
            &artifact_ref.key,
            &primary_function.object_ref,
            &import.object_ref,
            EdgeKind::CallsImport.as_str(),
            address,
        )?;
        xrefs.push(ParsedXref {
            object_ref: ObjectRef::new(ObjectKind::Xref, key),
            source: primary_function.object_ref.clone(),
            target: import.object_ref.clone(),
            relation: EdgeKind::CallsImport,
            address,
        });
    }
    Ok(xrefs)
}

fn upsert_edge(
    repo: &ObjectRepository<'_>,
    source: &ObjectRef,
    target: &ObjectRef,
    kind: EdgeKind,
    confidence: f64,
    run_id: i64,
    source_label: &str,
) -> Result<(), ImportError> {
    let key = StableObjectKey::edge(kind, source, target)?;
    repo.upsert_edge(&StoredEdge {
        edge_ref: ObjectRef::new(ObjectKind::Edge, key),
        source: source.clone(),
        target: target.clone(),
        kind,
        confidence,
        source_run_id: Some(run_id),
        metadata_json: serde_json::json!({
            "relation": kind.label(),
            "source": source_label
        })
        .to_string(),
    })?;
    Ok(())
}

fn count_related_strings(address: u64, size: Option<u64>, strings: &[ParsedString]) -> u64 {
    let end = address.saturating_add(size.unwrap_or(0));
    strings
        .iter()
        .filter(|string| {
            string
                .address
                .map(|string_address| string_address >= address && string_address <= end)
                .unwrap_or(false)
        })
        .count() as u64
}

fn offset_to_address(offset: u64, mappings: &[SectionMapping]) -> Option<u64> {
    mappings.iter().find_map(|mapping| {
        let end = mapping.offset.saturating_add(mapping.size);
        (offset >= mapping.offset && offset < end)
            .then_some(mapping.address + offset - mapping.offset)
    })
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

fn ascii_spans(bytes: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if is_printable_ascii(byte) {
            start.get_or_insert(index);
        } else if let Some(span_start) = start.take() {
            if index - span_start >= 4 {
                spans.push(Span {
                    start: span_start,
                    end: index,
                });
            }
        }
    }
    if let Some(span_start) = start {
        if bytes.len() - span_start >= 4 {
            spans.push(Span {
                start: span_start,
                end: bytes.len(),
            });
        }
    }
    spans
}

fn utf16le_spans(bytes: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut start = None;
    let mut index = 0;
    while index + 1 < bytes.len() {
        let lo = bytes[index];
        let hi = bytes[index + 1];
        if hi == 0 && is_printable_ascii(lo) {
            start.get_or_insert(index);
        } else if let Some(span_start) = start.take() {
            if index - span_start >= 8 {
                spans.push(Span {
                    start: span_start,
                    end: index,
                });
            }
        }
        index += 2;
    }
    if let Some(span_start) = start {
        if index - span_start >= 8 {
            spans.push(Span {
                start: span_start,
                end: index,
            });
        }
    }
    spans
}

fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}

fn is_sensitive_string(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password", "token", "/bin/sh", "cmd", "admin", "auth", "http",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_dangerous_import(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "system",
        "popen",
        "exec",
        "strcpy",
        "sprintf",
        "gets",
        "createprocess",
        "winexec",
        "shellexecute",
        "loadlibrary",
        "getprocaddress",
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "urldownload",
        "internetopen",
        "regsetvalue",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn artifact_format_for(format: object::BinaryFormat) -> Option<ArtifactFormat> {
    match format {
        object::BinaryFormat::Elf => Some(ArtifactFormat::Elf),
        object::BinaryFormat::Pe => Some(ArtifactFormat::Pe),
        _ => None,
    }
}

fn symbol_kind(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Text => "text",
        SymbolKind::Data => "data",
        SymbolKind::Section => "section",
        SymbolKind::File => "file",
        SymbolKind::Label => "label",
        _ => "unknown",
    }
}

fn diagnostic_from_core(stage: DiagnosticStage, err: RevDeckError) -> AnalysisDiagnostic {
    AnalysisDiagnostic::new(
        DiagnosticSeverity::Error,
        stage,
        "index_model_error",
        err.to_string(),
        true,
    )
    .expect("static diagnostic fields are valid")
}

fn start_analysis_job(
    repo: &AnalysisJobRepository<'_>,
    run_id: Option<i64>,
    artifact_ref: &ObjectRef,
    profile: AnalysisProfile,
    pass_name: &str,
    metadata: serde_json::Value,
) -> Result<AnalysisJobRecord, ImportError> {
    Ok(repo.insert(&NewAnalysisJob {
        analysis_run_id: run_id,
        artifact_key: Some(artifact_ref.key.to_string()),
        pass_name: pass_name.to_string(),
        profile: profile.as_str().to_string(),
        status: "running".to_string(),
        progress_current: 0,
        progress_total: Some(1),
        objects_produced: 0,
        diagnostics_count: 0,
        byte_limit: None,
        function_limit: None,
        time_limit_ms: None,
        metadata_json: metadata.to_string(),
        started_at: OffsetDateTime::now_utc(),
    })?)
}

struct AnalysisJobFinish {
    status: &'static str,
    progress_current: u64,
    progress_total: Option<u64>,
    objects_produced: u64,
    diagnostics_count: u64,
    metadata: serde_json::Value,
}

fn finish_analysis_job(
    repo: &AnalysisJobRepository<'_>,
    job_id: i64,
    update: AnalysisJobFinish,
) -> Result<AnalysisJobRecord, ImportError> {
    Ok(repo.finish(
        job_id,
        &AnalysisJobUpdate {
            status: update.status.to_string(),
            progress_current: update.progress_current,
            progress_total: update.progress_total,
            objects_produced: update.objects_produced,
            diagnostics_count: update.diagnostics_count,
            metadata_json: update.metadata.to_string(),
            finished_at: OffsetDateTime::now_utc(),
        },
    )?)
}

struct CompletedAnalysisJob {
    run_id: Option<i64>,
    pass_name: &'static str,
    status: &'static str,
    objects_produced: u64,
    diagnostics_count: u64,
    metadata: serde_json::Value,
}

fn record_completed_job(
    repo: &AnalysisJobRepository<'_>,
    artifact_ref: &ObjectRef,
    profile: AnalysisProfile,
    job: CompletedAnalysisJob,
) -> Result<AnalysisJobRecord, ImportError> {
    let record = start_analysis_job(
        repo,
        job.run_id,
        artifact_ref,
        profile,
        job.pass_name,
        job.metadata.clone(),
    )?;
    let progress_current = u64::from(job.status != "skipped");
    finish_analysis_job(
        repo,
        record.id,
        AnalysisJobFinish {
            status: job.status,
            progress_current,
            progress_total: Some(1),
            objects_produced: job.objects_produced,
            diagnostics_count: job.diagnostics_count,
            metadata: job.metadata,
        },
    )
}

fn job_metadata(
    mut metadata: serde_json::Value,
    profile: AnalysisProfile,
    pass_name: &'static str,
    diagnostic_snippets: Vec<String>,
    log_snippets: Vec<String>,
) -> serde_json::Value {
    let (lab_id, pass_phase) = pass_name
        .split_once('.')
        .map(|(lab_id, pass_phase)| (lab_id, pass_phase))
        .unwrap_or(("unknown", pass_name));
    let Some(map) = metadata.as_object_mut() else {
        return serde_json::json!({
            "value": metadata,
            "pass_name": pass_name,
            "lab_id": lab_id,
            "pass_phase": pass_phase,
            "parameters": job_parameters(profile),
            "diagnostic_snippets": diagnostic_snippets,
            "log_snippets": log_snippets
        });
    };

    map.entry("pass_name".to_string())
        .or_insert_with(|| serde_json::json!(pass_name));
    map.entry("lab_id".to_string())
        .or_insert_with(|| serde_json::json!(lab_id));
    map.entry("pass_phase".to_string())
        .or_insert_with(|| serde_json::json!(pass_phase));
    map.entry("parameters".to_string())
        .or_insert_with(|| job_parameters(profile));
    if !diagnostic_snippets.is_empty() {
        map.insert(
            "diagnostic_snippets".to_string(),
            serde_json::json!(diagnostic_snippets),
        );
    }
    if !log_snippets.is_empty() {
        map.insert("log_snippets".to_string(), serde_json::json!(log_snippets));
    }
    metadata
}

fn job_parameters(profile: AnalysisProfile) -> serde_json::Value {
    serde_json::json!({
        "profile": profile.as_str(),
        "native_cfg": profile.collects_native_cfg()
    })
}

fn diagnostic_snippets(diagnostics: &[AnalysisDiagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .take(4)
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect()
}

fn native_job_diagnostics(diagnostics: &[AnalysisDiagnostic], status: &str) -> Vec<String> {
    if status != "skipped" {
        return Vec::new();
    }
    diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "pass_skipped_by_profile")
        .take(4)
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect()
}

fn native_job_logs(profile: AnalysisProfile, status: &str, pass_name: &str) -> Vec<String> {
    if status == "skipped" {
        vec![format!(
            "{pass_name} skipped because {} profile does not collect native CFG facts",
            profile.as_str()
        )]
    } else {
        vec![format!(
            "{pass_name} completed with native CFG collection enabled"
        )]
    }
}

fn profile_skipped_diagnostic(
    profile: AnalysisProfile,
    pass: &'static str,
    description: &'static str,
) -> AnalysisDiagnostic {
    AnalysisDiagnostic::new(
        DiagnosticSeverity::Warning,
        DiagnosticStage::IndexEdges,
        "pass_skipped_by_profile",
        format!(
            "analysis profile `{}` skipped {pass}: {description}",
            profile.as_str()
        ),
        true,
    )
    .expect("static diagnostic fields are valid")
}

fn artifact_record(input: ArtifactRecordInput<'_>) -> ArtifactRecord {
    ArtifactRecord {
        object_ref: input.object_ref,
        display_name: input.display_name,
        source_path: input.source_path.display().to_string(),
        stored_path: None,
        sha256: input.sha256.to_string(),
        size: input.size,
        kind: input.kind.as_str().to_string(),
        format: input.format.as_str().to_string(),
        architecture: input.architecture.to_string(),
        import_status: input.status.as_str().to_string(),
        created_at: OffsetDateTime::now_utc(),
    }
}

fn normalize_path(project_root: &Path, path: &Path) -> String {
    let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let root = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    absolute
        .strip_prefix(&root)
        .unwrap_or(&absolute)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("failed to read artifact `{path}`: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Core(#[from] RevDeckError),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl ImportError {
    pub fn structured_message(&self) -> String {
        #[derive(Serialize)]
        struct Structured<'a> {
            error: &'a str,
            recoverable: bool,
        }
        serde_json::to_string(&Structured {
            error: &self.to_string(),
            recoverable: true,
        })
        .unwrap_or_else(|_| self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_decode::{OperandKind, OperandRole};
    use revdeck_db::{
        migrations::{current_version, SCHEMA_VERSION},
        ProjectDatabase,
    };
    use tempfile::tempdir;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn fixture(name: &str) -> PathBuf {
        repo_root().join("fixtures").join("binaries").join(name)
    }

    fn import_fixture(name: &str) -> (tempfile::TempDir, ProjectDatabase, ImportOutcome) {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(repo_root(), fixture(name)),
        )
        .unwrap();
        (temp, project, outcome)
    }

    fn test_function(
        artifact_ref: &ObjectRef,
        address: u64,
        size: Option<u64>,
        name: &str,
    ) -> ParsedFunction {
        ParsedFunction {
            object_ref: ObjectRef::new(
                ObjectKind::Function,
                StableObjectKey::function(&artifact_ref.key, address, size, Some(name)).unwrap(),
            ),
            name: name.to_string(),
            address: Some(address),
            size,
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        }
    }

    #[test]
    fn fixture_minimal_elf() {
        let (_temp, project, outcome) = import_fixture("minimal_elf");
        assert_eq!(
            current_version(project.connection()).unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        assert!(outcome.summary.sections >= 6);
        assert!(outcome.summary.symbols >= 3);
        assert!(outcome.summary.imports >= 1);
        assert!(outcome.summary.strings >= 2);
        assert!(outcome.summary.functions >= 3);

        let index_repo = IndexRepository::new(project.connection());
        assert!(index_repo
            .function_boundary_confidences(&outcome.artifact_ref)
            .unwrap()
            .iter()
            .any(|confidence| confidence == "symbol"));
        let instruction_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))
            .unwrap();
        let block_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM basic_blocks", [], |row| row.get(0))
            .unwrap();
        assert!(instruction_count > 0);
        assert!(block_count > 0);
    }

    #[test]
    fn fixture_stripped_elf() {
        let (_temp, project, outcome) = import_fixture("stripped_elf");
        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        assert_eq!(outcome.summary.imports, 0);
        assert!(outcome.summary.strings >= 2);
        assert!(outcome.summary.functions >= 1);
        let confidences = IndexRepository::new(project.connection())
            .function_boundary_confidences(&outcome.artifact_ref)
            .unwrap();
        assert!(
            confidences.iter().any(|value| value == "entrypoint")
                || confidences.iter().any(|value| value == "heuristic")
        );
    }

    #[test]
    fn fixture_sensitive_imports() {
        let (_temp, project, outcome) = import_fixture("sensitive_imports_elf");
        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        assert!(outcome.summary.imports >= 2);
        assert!(outcome.summary.xrefs >= 4);

        let calls_import: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM edges WHERE kind = 'calls_import'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let references: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM edges WHERE kind = 'references'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let xref_from: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM edges WHERE kind = 'xref_from'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(calls_import >= 2);
        assert!(references >= 2);
        assert!(xref_from >= 4);
    }

    #[test]
    fn scoring_analyzer_run() {
        let (_temp, project, outcome) = import_fixture("sensitive_imports_elf");
        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);

        let run = revdeck_db::AnalysisRunRepository::new(project.connection())
            .get(outcome.run_id)
            .unwrap()
            .unwrap();
        assert_eq!(run.analyzer_id, FUNCTION_RADAR_ANALYZER_ID);
        assert_eq!(run.status, AnalysisRunStatus::Succeeded);

        let reason_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM score_reasons", [], |row| row.get(0))
            .unwrap();
        assert!(reason_count > 0);

        let dangerous_count: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM score_reasons
                WHERE reason_code LIKE 'dangerous_import.%'
                  AND evidence_refs_json LIKE '%\"kind\":\"import\"%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(dangerous_count > 0);
    }

    #[test]
    fn corrupt_artifact_records_failed_run() {
        let (_temp, project, outcome) = import_fixture("corrupt_elf");
        assert_eq!(outcome.status, AnalysisRunStatus::Failed);
        assert_eq!(outcome.summary.diagnostics.len(), 1);
        assert_eq!(outcome.summary.diagnostics[0].code, "binary_parse_failed");

        let run = IndexRepository::new(project.connection())
            .latest_analysis_run(&outcome.artifact_ref)
            .unwrap()
            .unwrap();
        assert_eq!(run.status, AnalysisRunStatus::Failed);
        assert!(run.error_json.unwrap().contains("binary_parse_failed"));
        let reopened = ProjectDatabase::open_existing(&project.info().root_dir);
        assert!(reopened.is_ok());
    }

    #[test]
    fn synthetic_pe_fixture_indexes_sections_strings_and_entrypoint() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("sample.exe");
        fs::write(&fixture_path, synthetic_pe_fixture()).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        assert_eq!(outcome.summary.sections, 2);
        assert!(outcome.summary.strings >= 2);
        assert!(outcome.summary.functions >= 1);
        let block_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM basic_blocks", [], |row| row.get(0))
            .unwrap();
        let instruction_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))
            .unwrap();
        let cfg_edge_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM cfg_edges", [], |row| row.get(0))
            .unwrap();
        assert!(block_count > 0);
        assert!(instruction_count > 0);
        assert!(cfg_edge_count > 0);

        let artifact = ArtifactRepository::new(project.connection())
            .get_artifact(&outcome.artifact_ref)
            .unwrap()
            .unwrap();
        assert_eq!(artifact.format, "pe");
        assert_eq!(artifact.import_status, "indexed");

        let indexed_strings: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM strings
                WHERE value IN ('cmd.exe /c calc', 'admin-token')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexed_strings, 2);
    }

    #[test]
    fn quick_profile_skips_native_cfg_but_keeps_surface_facts() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("quick.exe");
        fs::write(&fixture_path, synthetic_pe_fixture()).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::with_profile(
                temp.path().to_path_buf(),
                fixture_path,
                AnalysisProfile::Quick,
            ),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        assert_eq!(outcome.profile, AnalysisProfile::Quick);
        assert_eq!(outcome.summary.sections, 2);
        assert!(outcome.summary.strings >= 2);
        assert!(outcome.summary.functions >= 1);
        assert!(outcome
            .summary
            .diagnostics
            .iter()
            .any(
                |diagnostic| diagnostic.code == "pass_skipped_by_profile" && diagnostic.recoverable
            ));

        let block_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM basic_blocks", [], |row| row.get(0))
            .unwrap();
        let instruction_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))
            .unwrap();
        let cfg_edge_count: i64 = project
            .connection()
            .query_row("SELECT COUNT(*) FROM cfg_edges", [], |row| row.get(0))
            .unwrap();
        assert_eq!(block_count, 0);
        assert_eq!(instruction_count, 0);
        assert_eq!(cfg_edge_count, 0);

        let native_diagnostics_json: String = project
            .connection()
            .query_row(
                "SELECT diagnostics_json
                FROM analysis_runs
                WHERE analyzer_id = ?1
                ORDER BY id DESC
                LIMIT 1",
                [NATIVE_BINARY_ANALYZER_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert!(native_diagnostics_json.contains("pass_skipped_by_profile"));

        let jobs = revdeck_db::AnalysisJobRepository::new(project.connection())
            .list_recent(20)
            .unwrap();
        let job_statuses = jobs
            .iter()
            .map(|job| (job.pass_name.as_str(), job.status.as_str()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(job_statuses.get("binary.parse"), Some(&"succeeded"));
        assert_eq!(job_statuses.get("binary.surface"), Some(&"succeeded"));
        assert_eq!(job_statuses.get("binary.seed"), Some(&"succeeded"));
        assert_eq!(job_statuses.get("binary.linear"), Some(&"skipped"));
        assert_eq!(job_statuses.get("binary.cfg"), Some(&"skipped"));
        assert_eq!(job_statuses.get("binary.dataflow"), Some(&"skipped"));
        assert_eq!(job_statuses.get("binary.triage"), Some(&"succeeded"));
    }

    #[test]
    fn synthetic_pe_direct_call_targets_create_heuristic_functions() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("call-target.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20b].copy_from_slice(&[
            0xe8, 0x03, 0x00, 0x00, 0x00, // call 0x1008
            0xc3, // ret
            0x90, 0x90, // padding
            0x55, // push rbp
            0xc3, // ret
            0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let entrypoint_address: i64 = project
            .connection()
            .query_row(
                "SELECT virtual_address FROM functions WHERE name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let target_address = entrypoint_address + 8;
        let entrypoint_size: i64 = project
            .connection()
            .query_row(
                "SELECT size FROM functions WHERE virtual_address = ?1",
                [entrypoint_address],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(entrypoint_size, 6);
        let entrypoint_key: String = project
            .connection()
            .query_row(
                "SELECT object_key FROM functions WHERE virtual_address = ?1",
                [entrypoint_address],
                |row| row.get(0),
            )
            .unwrap();
        assert!(entrypoint_key.contains("size=6"));

        let heuristic_functions: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM functions
                WHERE virtual_address = ?1
                  AND boundary_source = 'call_target'
                  AND boundary_confidence = 'heuristic'",
                [target_address],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(heuristic_functions, 1);

        let calls: i64 = project
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM edges
                WHERE kind = 'calls'
                  AND src_object_key IN (SELECT object_key FROM functions WHERE virtual_address = ?1)
                  AND dst_object_key IN (SELECT object_key FROM functions WHERE virtual_address = ?2)",
                [entrypoint_address, target_address],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn synthetic_pe_function_metadata_includes_stack_frame() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("stack-frame.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x21b].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x48, 0x83, 0xec, 0x20, // sub rsp,0x20
            0x48, 0x89, 0xc8, // mov rax,rcx
            0x48, 0x89, 0x45, 0xf8, // mov qword ptr [rbp-0x8],rax
            0x48, 0x8b, 0x45, 0xf8, // mov rax,qword ptr [rbp-0x8]
            0x48, 0x83, 0xc4, 0x20, // add rsp,0x20
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert_eq!(metadata["frame_pointer"].as_str(), Some("rbp"));
        assert_eq!(metadata["stack_frame_size"].as_u64(), Some(0x20));
        assert_eq!(metadata["stack_cleanup_size"].as_u64(), Some(0x20));
        assert_eq!(
            metadata["epilogue_kind"].as_str(),
            Some("stack-add-pop-rbp")
        );
        assert_eq!(metadata["has_frame_epilogue"].as_bool(), Some(true));
        assert_eq!(metadata["calling_convention"].as_str(), Some("windows-x64"));
        assert!(metadata["argument_registers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|register| register["ordinal"].as_u64() == Some(0)
                && register["register"].as_str() == Some("rcx")));
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-8)
                && slot["width_bits"].as_u64() == Some(64)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_stack_slot_immediate_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("stack-slot-imm.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20f].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x2a, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x2a
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_byte_stack_slot_immediate_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("byte-stack-slot-imm.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20c].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_mov_rm8_register_memory_stack_slots() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("mov-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x88, 0x45, 0xff, // mov byte ptr [rbp-0x1],al
            0x8a, 0x4d, 0xff, // mov cl,byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_cmp_test_rm8_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("cmp-test-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x7f, // mov byte ptr [rbp-0x1],0x7f
            0x38, 0x45, 0xff, // cmp byte ptr [rbp-0x1],al
            0x84, 0x4d, 0xff, // test byte ptr [rbp-0x1],cl
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_cmp_test_rm8_immediate_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("cmp-test-rm8-imm-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x216].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x7f, // mov byte ptr [rbp-0x1],0x7f
            0x80, 0x7d, 0xff, 0x7f, // cmp byte ptr [rbp-0x1],0x7f
            0xf6, 0x45, 0xff, 0x80, // test byte ptr [rbp-0x1],0x80
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_word_stack_slot_immediate_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("word-stack-slot-imm.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20e].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x66, 0xc7, 0x45, 0xfe, 0xef, 0xbe, // mov word ptr [rbp-0x2],0xbeef
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-2)
                && slot["width_bits"].as_u64() == Some(16)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_word_stack_slot_register_moves() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("word-stack-slot-register.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x212].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x66, 0x89, 0x45, 0xfe, // mov word ptr [rbp-0x2],ax
            0x66, 0x8b, 0x4d, 0xfe, // mov cx,word ptr [rbp-0x2]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-2)
                && slot["width_bits"].as_u64() == Some(16)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_mov_rm32_register_memory_stack_slots() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("mov-rm32-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x89, 0x45, 0xfc, // mov dword ptr [rbp-0x4],eax
            0x8b, 0x4d, 0xfc, // mov ecx,dword ptr [rbp-0x4]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_movzx_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("movzx-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x212].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x7f, // mov byte ptr [rbp-0x1],0x7f
            0x0f, 0xb6, 0x45, 0xff, // movzx eax,byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_setcc_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("setcc-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20e].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x31, 0xc0, // xor eax,eax
            0x39, 0xc0, // cmp eax,eax
            0x0f, 0x94, 0x45, 0xff, // sete byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_movsx_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("movsx-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x212].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x80, // mov byte ptr [rbp-0x1],0x80
            0x0f, 0xbe, 0x45, 0xff, // movsx eax,byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_movsxd_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("movsxd-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x215].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x80, 0xff, 0xff, 0xff, // mov dword ptr [rbp-0x4],0xffffff80
            0x48, 0x63, 0x45, 0xfc, // movsxd rax,dword ptr [rbp-0x4]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_cmp_test_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("cmp-test-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x217].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x2a, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x2a
            0x39, 0x45, 0xfc, // cmp dword ptr [rbp-0x4],eax
            0x85, 0x4d, 0xfc, // test dword ptr [rbp-0x4],ecx
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_cmovcc_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("cmovcc-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x215].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x2a, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x2a
            0x31, 0xc0, // xor eax,eax
            0x39, 0xc0, // cmp eax,eax
            0x0f, 0x44, 0x45, 0xfc, // cmove eax,dword ptr [rbp-0x4]
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_cmp_test_immediate_stack_slot_reads() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("cmp-test-imm-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x21a].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x2a, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x2a
            0x83, 0x7d, 0xfc, 0x2a, // cmp dword ptr [rbp-0x4],0x2a
            0xf7, 0x45, 0xfc, 0xff, 0x00, 0x00, 0x00, // test dword ptr [rbp-0x4],0xff
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_group1_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("group1-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x217].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x1
            0x83, 0x45, 0xfc, 0x02, // add dword ptr [rbp-0x4],0x2
            0x83, 0x65, 0xfc, 0x0f, // and dword ptr [rbp-0x4],0xf
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_group1_adc_sbb_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("group1-adc-sbb-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x217].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x1
            0x83, 0x55, 0xfc, 0x02, // adc dword ptr [rbp-0x4],0x2
            0x83, 0x5d, 0xfc, 0x01, // sbb dword ptr [rbp-0x4],0x1
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_group1_rm8_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("group1-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x212].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            0x80, 0x45, 0xff, 0x02, // add byte ptr [rbp-0x1],0x2
            0x80, 0x65, 0xff, 0x0f, // and byte ptr [rbp-0x1],0xf
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_group1_rm8_adc_sbb_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("group1-rm8-adc-sbb-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x212].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            0x80, 0x55, 0xff, 0x02, // adc byte ptr [rbp-0x1],0x2
            0x80, 0x5d, 0xff, 0x01, // sbb byte ptr [rbp-0x1],0x1
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_adc_sbb_register_memory_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("adc-sbb-rm32-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x217].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x1
            0x11, 0x45, 0xfc, // adc dword ptr [rbp-0x4],eax
            0x1b, 0x4d, 0xfc, // sbb ecx,dword ptr [rbp-0x4]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_adc_sbb_rm8_register_memory_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("adc-sbb-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            0x10, 0x45, 0xff, // adc byte ptr [rbp-0x1],al
            0x1a, 0x4d, 0xff, // sbb cl,byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_inc_dec_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("inc-dec-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x215].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x1
            0xff, 0x45, 0xfc, // inc dword ptr [rbp-0x4]
            0xff, 0x4d, 0xfc, // dec dword ptr [rbp-0x4]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_inc_dec_rm8_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("inc-dec-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            0xfe, 0x45, 0xff, // inc byte ptr [rbp-0x1]
            0xfe, 0x4d, 0xff, // dec byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_shift_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("shift-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x215].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x08, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x8
            0xc1, 0x65, 0xfc, 0x01, // shl dword ptr [rbp-0x4],0x1
            0xc1, 0x7d, 0xfc, 0x02, // sar dword ptr [rbp-0x4],0x2
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_shift_one_and_cl_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("shift-one-cl-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x213].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x08, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x8
            0xd1, 0x65, 0xfc, // shl dword ptr [rbp-0x4],1
            0xd3, 0x7d, 0xfc, // sar dword ptr [rbp-0x4],cl
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_not_neg_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("not-neg-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x214].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc7, 0x45, 0xfc, 0x08, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x8
            0xf7, 0x55, 0xfc, // not dword ptr [rbp-0x4]
            0xf7, 0x5d, 0xfc, // neg dword ptr [rbp-0x4]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-4)
                && slot["width_bits"].as_u64() == Some(32)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_shift_rm8_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("shift-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x212].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x08, // mov byte ptr [rbp-0x1],0x8
            0xc0, 0x65, 0xff, 0x01, // shl byte ptr [rbp-0x1],0x1
            0xc0, 0x7d, 0xff, 0x02, // sar byte ptr [rbp-0x1],0x2
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_shift_rm8_one_and_cl_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("shift-rm8-one-cl-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x08, // mov byte ptr [rbp-0x1],0x8
            0xd0, 0x65, 0xff, // shl byte ptr [rbp-0x1],1
            0xd2, 0x7d, 0xff, // sar byte ptr [rbp-0x1],cl
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_tracks_not_neg_rm8_stack_slot_writes() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("not-neg-rm8-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x210].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            0xf6, 0x55, 0xff, // not byte ptr [rbp-0x1]
            0xf6, 0x5d, 0xff, // neg byte ptr [rbp-0x1]
            0x5d, // pop rbp
            0xc3, // ret
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-1)
                && slot["width_bits"].as_u64() == Some(8)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("write"))));
    }

    #[test]
    fn synthetic_pe_function_metadata_marks_lea_stack_slots_as_address_references() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("lea-stack-slot.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20e].copy_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp,rsp
            0x48, 0x8d, 0x45, 0xf0, // lea rax,[rbp-0x10]
            0x5d, // pop rbp
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_json: String = project
            .connection()
            .query_row(
                "SELECT objects.metadata_json
                FROM objects
                JOIN functions ON functions.object_key = objects.object_key
                WHERE functions.name = 'entrypoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert!(metadata["stack_slots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| slot["base"].as_str() == Some("rbp")
                && slot["offset"].as_i64() == Some(-0x10)
                && slot["width_bits"].as_u64() == Some(64)
                && slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("address_reference"))
                && !slot["accesses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|access| access.as_str() == Some("read"))));
    }

    #[test]
    fn native_cfg_scanner_splits_conditional_branch() {
        let artifact_ref = ObjectRef::artifact("abc123", "cfg-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(5), Some("branchy")).unwrap(),
        );
        let function = ParsedFunction {
            object_ref: function_ref,
            name: "branchy".to_string(),
            address: Some(0x1000),
            size: Some(5),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x1000,
            &[0x74, 0x02, 0x90, 0xc3, 0xc3],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(facts.basic_blocks.len(), 3);
        assert_eq!(facts.cfg_edges.len(), 2);
        assert!(facts
            .cfg_edges
            .iter()
            .any(|edge| edge.edge_kind == "branch"));
        assert!(facts
            .cfg_edges
            .iter()
            .any(|edge| edge.edge_kind == "fallthrough"));
        assert!(facts
            .xrefs
            .iter()
            .any(|xref| xref.relation == EdgeKind::References));
    }

    #[test]
    fn native_decoder_assigns_instruction_flow_semantics() {
        let instructions = decode_native_instructions(
            0x1000,
            &[
                0xe8, 0x00, 0x00, 0x00, 0x00, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0xff, 0x25, 0x00,
                0x00, 0x00, 0x00, 0x74, 0x02, 0xc3,
            ],
        );

        assert_eq!(instructions[0].flow, InstructionFlow::Call);
        assert_eq!(instructions[0].flow_kind(), Some("call"));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::CallTarget
                && operand.kind == OperandKind::RelativeTarget
                && operand.control_flow_target() == Some(0x1005)
        }));
        assert_eq!(instructions[1].flow, InstructionFlow::Call);
        assert_eq!(instructions[1].data_target, Some(0x100b));
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::CallTarget
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rip")
                && operand.displacement == Some(0)
                && operand.data_reference_target() == Some(0x100b)
                && operand.width_bits == Some(64)
        }));
        assert_eq!(instructions[2].flow, InstructionFlow::Jump);
        assert_eq!(instructions[2].flow_kind(), Some("jump"));
        assert_eq!(instructions[3].flow, InstructionFlow::ConditionalBranch);
        assert_eq!(instructions[3].flow_kind(), Some("conditional_branch"));
        assert_eq!(instructions[4].flow, InstructionFlow::Return);
        assert_eq!(instructions[4].flow_kind(), None);
    }

    #[test]
    fn native_decoder_decodes_stack_cleanup_and_epilogue_instructions() {
        let instructions = decode_native_instructions(
            0x7000,
            &[
                0x48, 0x83, 0xc4, 0x20, // add rsp,0x20
                0x48, 0x81, 0xc4, 0x00, 0x02, 0x00, 0x00, // add rsp,0x200
                0xc9, // leave
                0x5d, // pop rbp
                0xc3, // ret
            ],
        );

        assert_eq!(instructions[0].mnemonic, "add");
        assert_eq!(instructions[0].operands, "rsp,0x20");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rsp")
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x20)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "add");
        assert_eq!(instructions[1].operands, "rsp,0x200");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x200)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[2].mnemonic, "leave");
        assert_eq!(instructions[2].flow, InstructionFlow::None);
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["rbp", "rsp"]);
        assert_eq!(instructions[3].mnemonic, "pop");
        assert_eq!(instructions[3].operands, "rbp");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rbp")
        }));
        assert_eq!(instructions[3].flow, InstructionFlow::None);
        assert_eq!(instructions[4].flow, InstructionFlow::Return);
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);
    }

    #[test]
    fn native_decoder_tracks_call_return_stack_pointer_effects() {
        let instructions = decode_native_instructions(
            0x7100,
            &[
                0xe8, 0x00, 0x00, 0x00, 0x00, // call 0x7105
                0xc3, // ret
            ],
        );

        assert_eq!(instructions[0].mnemonic, "call");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);

        assert_eq!(instructions[1].mnemonic, "ret");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);
    }

    #[test]
    fn native_decoder_decodes_push_immediates_and_ret_stack_cleanup() {
        let instructions = decode_native_instructions(
            0x7110,
            &[
                0x6a, 0xf0, // push -0x10
                0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
                0xc2, 0x20, 0x00, // ret 0x20
            ],
        );

        assert_eq!(instructions[0].mnemonic, "push");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "0xfffffffffffffff0");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0xffff_ffff_ffff_fff0)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);

        assert_eq!(instructions[1].mnemonic, "push");
        assert_eq!(instructions[1].size, 5);
        assert_eq!(instructions[1].operands, "0x12345678");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x1234_5678)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[2].mnemonic, "ret");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "0x20");
        assert_eq!(instructions[2].flow, InstructionFlow::Return);
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x20)
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);
    }

    #[test]
    fn native_decoder_decodes_push_rm64_operands() {
        let instructions = decode_native_instructions(
            0x7120,
            &[
                0xff, 0xf0, // push rax
                0x41, 0xff, 0xf0, // push r8
                0xff, 0x74, 0x24, 0x08, // push qword ptr [rsp+0x8]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "push");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "rax");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rax")
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rax", "rsp"]);
        assert_eq!(writes, vec!["rsp"]);

        assert_eq!(instructions[1].mnemonic, "push");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "r8");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r8", "rsp"]);
        assert_eq!(writes, vec!["rsp"]);

        assert_eq!(instructions[2].mnemonic, "push");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "qword ptr [rsp+0x8]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.displacement == Some(8)
                && operand.width_bits == Some(64)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);
    }

    #[test]
    fn native_decoder_decodes_pop_rm64_operands() {
        let instructions = decode_native_instructions(
            0x7130,
            &[
                0x8f, 0xc0, // pop rax
                0x41, 0x8f, 0xc0, // pop r8
                0x8f, 0x44, 0x24, 0x08, // pop qword ptr [rsp+0x8]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "pop");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "rax");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rax")
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rax", "rsp"]);

        assert_eq!(instructions[1].mnemonic, "pop");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "r8");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["r8", "rsp"]);

        assert_eq!(instructions[2].mnemonic, "pop");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "qword ptr [rsp+0x8]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.displacement == Some(8)
                && operand.width_bits == Some(64)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rsp"]);
    }

    #[test]
    fn native_decoder_decodes_push_pop_register_operands() {
        let instructions = decode_native_instructions(
            0x7010,
            &[
                0x50, // push rax
                0x5b, // pop rbx
                0x41, 0x50, // push r8
                0x41, 0x59, // pop r9
            ],
        );

        assert_eq!(instructions[0].mnemonic, "push");
        assert_eq!(instructions[0].size, 1);
        assert_eq!(instructions[0].operands, "rax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rax", "rsp"]);
        assert_eq!(writes, vec!["rsp"]);

        assert_eq!(instructions[1].mnemonic, "pop");
        assert_eq!(instructions[1].size, 1);
        assert_eq!(instructions[1].operands, "rbx");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["rbx", "rsp"]);

        assert_eq!(instructions[2].mnemonic, "push");
        assert_eq!(instructions[2].size, 2);
        assert_eq!(instructions[2].operands, "r8");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["r8", "rsp"]);
        assert_eq!(writes, vec!["rsp"]);

        assert_eq!(instructions[3].mnemonic, "pop");
        assert_eq!(instructions[3].size, 2);
        assert_eq!(instructions[3].operands, "r9");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["rsp"]);
        assert_eq!(writes, vec!["r9", "rsp"]);
    }

    #[test]
    fn synthetic_pe_instruction_metadata_tracks_push_pop_stack_pointer_effects() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("push-pop-effects.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x204].copy_from_slice(&[
            0x50, // push rax
            0x5b, // pop rbx
            0xc3, // ret
            0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_rows = project
            .connection()
            .prepare(
                "SELECT instructions.mnemonic, objects.metadata_json
                FROM instructions
                JOIN objects ON objects.object_key = instructions.object_key
                WHERE instructions.mnemonic IN ('push', 'pop')
                ORDER BY instructions.address",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(metadata_rows.len(), 2);
        let push_metadata: serde_json::Value = serde_json::from_str(&metadata_rows[0].1).unwrap();
        assert_eq!(metadata_rows[0].0, "push");
        assert_eq!(
            push_metadata["register_reads"],
            serde_json::json!(["rax", "rsp"])
        );
        assert_eq!(push_metadata["register_writes"], serde_json::json!(["rsp"]));

        let pop_metadata: serde_json::Value = serde_json::from_str(&metadata_rows[1].1).unwrap();
        assert_eq!(metadata_rows[1].0, "pop");
        assert_eq!(pop_metadata["register_reads"], serde_json::json!(["rsp"]));
        assert_eq!(
            pop_metadata["register_writes"],
            serde_json::json!(["rbx", "rsp"])
        );
    }

    #[test]
    fn synthetic_pe_instruction_metadata_tracks_call_return_stack_effects() {
        let temp = tempdir().unwrap();
        let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let fixture_path = temp.path().join("call-ret-effects.exe");
        let mut bytes = synthetic_pe_fixture();
        bytes[0x200..0x20a].copy_from_slice(&[
            0xe8, 0x01, 0x00, 0x00, 0x00, // call 0x1006
            0xc3, // ret
            0xc9, // leave
            0xc3, // ret
            0x90, 0x90, // padding
        ]);
        fs::write(&fixture_path, bytes).unwrap();

        let outcome = import_binary(
            project.connection(),
            ImportOptions::new(temp.path().to_path_buf(), fixture_path),
        )
        .unwrap();

        assert_eq!(outcome.status, AnalysisRunStatus::Succeeded);
        let metadata_rows = project
            .connection()
            .prepare(
                "SELECT instructions.mnemonic, objects.metadata_json
                FROM instructions
                JOIN objects ON objects.object_key = instructions.object_key
                WHERE instructions.mnemonic IN ('call', 'leave', 'ret')
                ORDER BY instructions.address",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(metadata_rows.len(), 4);
        let call_metadata: serde_json::Value = serde_json::from_str(&metadata_rows[0].1).unwrap();
        assert_eq!(metadata_rows[0].0, "call");
        assert_eq!(call_metadata["register_reads"], serde_json::json!(["rsp"]));
        assert_eq!(call_metadata["register_writes"], serde_json::json!(["rsp"]));

        let ret_metadata: serde_json::Value = serde_json::from_str(&metadata_rows[1].1).unwrap();
        assert_eq!(metadata_rows[1].0, "ret");
        assert_eq!(ret_metadata["register_reads"], serde_json::json!(["rsp"]));
        assert_eq!(ret_metadata["register_writes"], serde_json::json!(["rsp"]));

        let leave_metadata: serde_json::Value = serde_json::from_str(&metadata_rows[2].1).unwrap();
        assert_eq!(metadata_rows[2].0, "leave");
        assert_eq!(leave_metadata["register_reads"], serde_json::json!(["rbp"]));
        assert_eq!(
            leave_metadata["register_writes"],
            serde_json::json!(["rbp", "rsp"])
        );
    }

    #[test]
    fn native_decoder_decodes_indirect_call_and_jump_operands() {
        let instructions = decode_native_instructions(
            0x1800,
            &[
                0xff, 0xd0, // call rax
                0x41, 0xff, 0xe0, // jmp r8
                0xff, 0x54, 0x24, 0x08, // call qword ptr [rsp+0x8]
                0x49, 0xff, 0x64, 0x24, 0xf0, // jmp qword ptr [r12-0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "call");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].flow, InstructionFlow::Call);
        assert_eq!(instructions[0].operands, "rax");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::CallTarget
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rax")
        }));

        assert_eq!(instructions[1].mnemonic, "jmp");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].flow, InstructionFlow::Jump);
        assert_eq!(instructions[1].operands, "r8");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::BranchTarget
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r8")
        }));

        assert_eq!(instructions[2].mnemonic, "call");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "qword ptr [rsp+0x8]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::CallTarget
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.displacement == Some(8)
        }));

        assert_eq!(instructions[3].mnemonic, "jmp");
        assert_eq!(instructions[3].size, 5);
        assert_eq!(instructions[3].operands, "qword ptr [r12-0x10]");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::BranchTarget
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r12")
                && operand.displacement == Some(-0x10)
        }));
    }

    #[test]
    fn native_decoder_decodes_modrm_sib_memory_operands() {
        let instructions = decode_native_instructions(
            0x2000,
            &[
                0x48, 0x8b, 0x45, 0xf8, // mov rax,qword ptr [rbp-0x8]
                0x48, 0x89, 0x4c, 0x84, 0x20, // mov qword ptr [rsp+rax*4+0x20],rcx
                0x48, 0x8b, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00, // mov rax,qword ptr [0x1234]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "rax,qword ptr [rbp-0x8]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-8)
                && operand.effective_address.is_none()
        }));

        assert_eq!(instructions[1].size, 5);
        assert_eq!(instructions[1].operands, "qword ptr [rsp+rax*4+0x20],rcx");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.index.as_deref() == Some("rax")
                && operand.scale == Some(4)
                && operand.displacement == Some(0x20)
        }));

        assert_eq!(instructions[2].size, 8);
        assert_eq!(instructions[2].operands, "rax,qword ptr [0x1234]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.is_none()
                && operand.index.is_none()
                && operand.displacement == Some(0x1234)
                && operand.data_reference_target() == Some(0x1234)
        }));
    }

    #[test]
    fn native_decoder_decodes_mov_rm64_sign_extended_immediate_memory_destinations() {
        let instructions = decode_native_instructions(
            0x2020,
            &[
                0x48, 0xc7, 0x45, 0xf8, 0xff, 0xff, 0xff, 0xff, // mov qword ptr [rbp-0x8],-1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 8);
        assert_eq!(
            instructions[0].operands,
            "qword ptr [rbp-0x8],0xffffffffffffffff"
        );
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-8)
                && operand.width_bits == Some(64)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0xffff_ffff_ffff_ffff)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_tracks_rip_relative_destination_registers() {
        let instructions = decode_native_instructions(
            0x6000,
            &[
                0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00, // lea rcx,[rip]
                0x4c, 0x8d, 0x0d, 0x04, 0x00, 0x00, 0x00, // lea r9,[rip+0x4]
                0x8b, 0x15, 0x08, 0x00, 0x00, 0x00, // mov edx,[rip+0x8]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "lea");
        assert_eq!(
            instructions[0].operands,
            "rcx,[rip+disp32] -> 0x0000000000006007"
        );
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rcx")
        }));
        assert_eq!(
            register_accesses_for_operands(&instructions[0].typed_operands),
            (vec!["rip".to_string()], vec!["rcx".to_string()])
        );

        assert_eq!(instructions[1].mnemonic, "lea");
        assert_eq!(
            instructions[1].operands,
            "r9,[rip+disp32] -> 0x0000000000006012"
        );
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r9")
        }));
        assert_eq!(
            register_accesses_for_operands(&instructions[1].typed_operands),
            (vec!["rip".to_string()], vec!["r9".to_string()])
        );

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(
            instructions[2].operands,
            "edx,[rip+disp32] -> 0x000000000000601c"
        );
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("edx")
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_lea_r64_memory_operands() {
        let instructions = decode_native_instructions(
            0x6020,
            &[
                0x48, 0x8d, 0x45, 0xf0, // lea rax,[rbp-0x10]
                0x4e, 0x8d, 0x4c, 0x94, 0x20, // lea r9,[rsp+r10*4+0x20]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "lea");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "rax,[rbp-0x10]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rax")
                && operand.width_bits == Some(64)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::DataReference
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-0x10)
                && operand.width_bits == Some(64)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["rax"]);

        assert_eq!(instructions[1].mnemonic, "lea");
        assert_eq!(instructions[1].size, 5);
        assert_eq!(instructions[1].operands, "r9,[rsp+r10*4+0x20]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::DataReference
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.index.as_deref() == Some("r10")
                && operand.scale == Some(4)
                && operand.displacement == Some(0x20)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r10", "rsp"]);
        assert_eq!(writes, vec!["r9"]);
    }

    #[test]
    fn native_decoder_decodes_lea_r32_memory_operands() {
        let instructions = decode_native_instructions(
            0x6030,
            &[
                0x8d, 0x45, 0xf0, // lea eax,[rbp-0x10]
                0x46, 0x8d, 0x4c, 0x94, 0x20, // lea r9d,[rsp+r10*4+0x20]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "lea");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "eax,[rbp-0x10]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::DataReference
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-0x10)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[1].mnemonic, "lea");
        assert_eq!(instructions[1].size, 5);
        assert_eq!(instructions[1].operands, "r9d,[rsp+r10*4+0x20]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::DataReference
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.index.as_deref() == Some("r10")
                && operand.scale == Some(4)
                && operand.displacement == Some(0x20)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r10", "rsp"]);
        assert_eq!(writes, vec!["r9d"]);
    }

    #[test]
    fn native_instruction_register_access_summaries_include_memory_address_registers() {
        let instructions = decode_native_instructions(
            0x2000,
            &[
                0x48, 0x8b, 0x45, 0xf8, // mov rax,qword ptr [rbp-0x8]
                0x48, 0x89, 0x4c, 0x84, 0x20, // mov qword ptr [rsp+rax*4+0x20],rcx
            ],
        );

        let (reads, writes) = register_accesses_for_operands(&instructions[0].typed_operands);
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["rax"]);

        let (reads, writes) = register_accesses_for_operands(&instructions[1].typed_operands);
        assert_eq!(reads, vec!["rax", "rcx", "rsp"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_and_indexer_track_mov_immediate_constants() {
        let instructions = decode_native_instructions(
            0x8000,
            &[
                0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, // mov rax,0x1122334455667788
                0x49, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00, // mov r8,0x2a
                0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax,0x12345678
                0xb9, 0xff, 0x00, 0x00, 0x00, // mov ecx,0xff
                0x41, 0xb8, 0x34, 0x12, 0x00, 0x00, // mov r8d,0x1234
                0x41, 0xbf, 0xef, 0xbe, 0x00, 0x00, // mov r15d,0xbeef
                0xc7, 0xc2, 0x78, 0x56, 0x34, 0x12, // mov edx,0x12345678
                0x41, 0xc7, 0xc1, 0xef, 0xbe, 0x00, 0x00, // mov r9d,0xbeef
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 10);
        assert_eq!(instructions[0].operands, "rax,0x1122334455667788");
        let constants = constant_writes_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
            instructions[0].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "rax".to_string(),
                value: 0x1122_3344_5566_7788,
                width_bits: Some(64),
            }]
        );

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].operands, "r8,0x2a");
        let constants = constant_writes_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
            instructions[1].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r8".to_string(),
                value: 0x2a,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].size, 5);
        assert_eq!(instructions[2].operands, "eax,0x12345678");
        let constants = constant_writes_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
            instructions[2].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x1234_5678,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[3].mnemonic, "mov");
        assert_eq!(instructions[3].operands, "ecx,0xff");
        let constants = constant_writes_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
            instructions[3].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "ecx".to_string(),
                value: 0xff,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[4].mnemonic, "mov");
        assert_eq!(instructions[4].size, 6);
        assert_eq!(instructions[4].operands, "r8d,0x1234");
        let constants = constant_writes_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
            instructions[4].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0x1234,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[5].mnemonic, "mov");
        assert_eq!(instructions[5].operands, "r15d,0xbeef");
        let constants = constant_writes_for_instruction(
            instructions[5].mnemonic.as_str(),
            &instructions[5].typed_operands,
            instructions[5].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r15d".to_string(),
                value: 0xbeef,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[6].mnemonic, "mov");
        assert_eq!(instructions[6].size, 6);
        assert_eq!(instructions[6].operands, "edx,0x12345678");
        let constants = constant_writes_for_instruction(
            instructions[6].mnemonic.as_str(),
            &instructions[6].typed_operands,
            instructions[6].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "edx".to_string(),
                value: 0x1234_5678,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[7].mnemonic, "mov");
        assert_eq!(instructions[7].size, 7);
        assert_eq!(instructions[7].operands, "r9d,0xbeef");
        let constants = constant_writes_for_instruction(
            instructions[7].mnemonic.as_str(),
            &instructions[7].typed_operands,
            instructions[7].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r9d".to_string(),
                value: 0xbeef,
                width_bits: Some(32),
            }]
        );
    }

    #[test]
    fn native_decoder_decodes_32_bit_mov_register_copies() {
        let instructions = decode_native_instructions(
            0x8070,
            &[
                0x89, 0xc8, // mov eax,ecx
                0x8b, 0xd0, // mov edx,eax
                0x41, 0x89, 0xc0, // mov r8d,eax
                0x45, 0x8b, 0xc8, // mov r9d,r8d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "eax,ecx");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["ecx"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ecx")
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].operands, "edx,eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["edx"]);

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "r8d,eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["r8d"]);

        assert_eq!(instructions[3].mnemonic, "mov");
        assert_eq!(instructions[3].operands, "r9d,r8d");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["r8d"]);
        assert_eq!(writes, vec!["r9d"]);
    }

    #[test]
    fn native_decoder_decodes_mov_rm32_register_memory_operands() {
        let instructions = decode_native_instructions(
            0x8078,
            &[
                0x89, 0x45, 0xfc, // mov dword ptr [rbp-0x4],eax
                0x8b, 0x4d, 0xfc, // mov ecx,dword ptr [rbp-0x4]
                0x41, 0x89, 0x48, 0x10, // mov dword ptr [r8+0x10],ecx
                0x41, 0x8b, 0x48, 0x10, // mov ecx,dword ptr [r8+0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4],eax");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "ecx,dword ptr [rbp-0x4]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ecx")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "dword ptr [r8+0x10],ecx");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["ecx", "r8"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "mov");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "ecx,dword ptr [r8+0x10]");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert_eq!(writes, vec!["ecx"]);
    }

    #[test]
    fn native_decoder_decodes_mov_rm8_register_memory_operands() {
        let instructions = decode_native_instructions(
            0x8078,
            &[
                0x88, 0x45, 0xff, // mov byte ptr [rbp-0x1],al
                0x8a, 0x4d, 0xff, // mov cl,byte ptr [rbp-0x1]
                0x41, 0x88, 0x48, 0x10, // mov byte ptr [r8+0x10],cl
                0x41, 0x8a, 0x48, 0x10, // mov cl,byte ptr [r8+0x10]
                0x44, 0x88, 0x48, 0x11, // mov byte ptr [rax+0x11],r9b
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1],al");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("al")
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["al", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "cl,byte ptr [rbp-0x1]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("cl")
                && operand.width_bits == Some(8)
        }));
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["cl"]);

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "byte ptr [r8+0x10],cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "r8"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "mov");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "cl,byte ptr [r8+0x10]");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert_eq!(writes, vec!["cl"]);

        assert_eq!(instructions[4].mnemonic, "mov");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "byte ptr [rax+0x11],r9b");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r9b")
                && operand.width_bits == Some(8)
        }));
    }

    #[test]
    fn native_decoder_decodes_cmp_test_rm8_register_memory_operands() {
        let instructions = decode_native_instructions(
            0x8078,
            &[
                0x38, 0x45, 0xff, // cmp byte ptr [rbp-0x1],al
                0x3a, 0x4d, 0xff, // cmp cl,byte ptr [rbp-0x1]
                0x84, 0x4d, 0xff, // test byte ptr [rbp-0x1],cl
                0x41, 0x38, 0x48, 0x10, // cmp byte ptr [r8+0x10],cl
                0x45, 0x84, 0x48, 0x10, // test byte ptr [r8+0x10],r9b
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1],al");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["al", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "cmp");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "cl,byte ptr [rbp-0x1]");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[2].mnemonic, "test");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "cmp");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "byte ptr [r8+0x10],cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "r8"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[4].mnemonic, "test");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "byte ptr [r8+0x10],r9b");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["r8", "r9b"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_decodes_cmp_test_rm8_immediate_operands() {
        let instructions = decode_native_instructions(
            0x8078,
            &[
                0x80, 0x7d, 0xff, 0x7f, // cmp byte ptr [rbp-0x1],0x7f
                0xf6, 0x45, 0xff, 0x80, // test byte ptr [rbp-0x1],0x80
                0x41, 0x80, 0x78, 0x10, 0x01, // cmp byte ptr [r8+0x10],0x1
                0x41, 0xf6, 0x40, 0x10, 0xff, // test byte ptr [r8+0x10],0xff
                0x40, 0x80, 0xfc, 0x01, // cmp spl,0x1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1],0x7f");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x7f)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "test");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1],0x80");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[2].mnemonic, "cmp");
        assert_eq!(instructions[2].size, 5);
        assert_eq!(instructions[2].operands, "byte ptr [r8+0x10],0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "test");
        assert_eq!(instructions[3].size, 5);
        assert_eq!(instructions[3].operands, "byte ptr [r8+0x10],0xff");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[4].mnemonic, "cmp");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "spl,0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["spl"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_decodes_group1_rm8_immediates() {
        let instructions = decode_native_instructions(
            0x8078,
            &[
                0x80, 0x45, 0xff, 0x02, // add byte ptr [rbp-0x1],0x2
                0x80, 0x6d, 0xff, 0x01, // sub byte ptr [rbp-0x1],0x1
                0x80, 0x65, 0xff, 0x0f, // and byte ptr [rbp-0x1],0xf
                0x80, 0x4d, 0xff, 0x03, // or byte ptr [rbp-0x1],0x3
                0x80, 0x75, 0xff, 0xff, // xor byte ptr [rbp-0x1],0xff
                0x41, 0x80, 0x40, 0x10, 0x02, // add byte ptr [r8+0x10],0x2
                0x40, 0x80, 0xc4, 0x01, // add spl,0x1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "add");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1],0x2");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "sub");
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1],0x1");
        assert_eq!(instructions[2].mnemonic, "and");
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],0xf");
        assert_eq!(instructions[3].mnemonic, "or");
        assert_eq!(instructions[3].operands, "byte ptr [rbp-0x1],0x3");
        assert_eq!(instructions[4].mnemonic, "xor");
        assert_eq!(instructions[4].operands, "byte ptr [rbp-0x1],0xff");

        assert_eq!(instructions[5].mnemonic, "add");
        assert_eq!(instructions[5].size, 5);
        assert_eq!(instructions[5].operands, "byte ptr [r8+0x10],0x2");
        assert!(instructions[5].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[6].mnemonic, "add");
        assert_eq!(instructions[6].size, 4);
        assert_eq!(instructions[6].operands, "spl,0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[6].mnemonic.as_str(),
            &instructions[6].typed_operands,
        );
        assert_eq!(reads, vec!["spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_group1_rm8_adc_sbb_immediates() {
        let instructions = decode_native_instructions(
            0x807c,
            &[
                0x80, 0xd0, 0x05, // adc al,0x5
                0x80, 0xd9, 0x01, // sbb cl,0x1
                0x80, 0x55, 0xff, 0x02, // adc byte ptr [rbp-0x1],0x2
                0x80, 0x5d, 0xff, 0x01, // sbb byte ptr [rbp-0x1],0x1
                0x41, 0x80, 0x50, 0x10, 0x02, // adc byte ptr [r8+0x10],0x2
                0x40, 0x80, 0xd4, 0x01, // adc spl,0x1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "adc");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "al,0x5");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["al"]);
        assert_eq!(writes, vec!["al"]);

        assert_eq!(instructions[1].mnemonic, "sbb");
        assert_eq!(instructions[1].operands, "cl,0x1");

        assert_eq!(instructions[2].mnemonic, "adc");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],0x2");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[3].mnemonic, "sbb");
        assert_eq!(instructions[3].operands, "byte ptr [rbp-0x1],0x1");

        assert_eq!(instructions[4].mnemonic, "adc");
        assert_eq!(instructions[4].size, 5);
        assert_eq!(instructions[4].operands, "byte ptr [r8+0x10],0x2");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[5].mnemonic, "adc");
        assert_eq!(instructions[5].size, 4);
        assert_eq!(instructions[5].operands, "spl,0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[5].mnemonic.as_str(),
            &instructions[5].typed_operands,
        );
        assert_eq!(reads, vec!["spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_adc_sbb_rm8_register_memory_operands() {
        let instructions = decode_native_instructions(
            0x807e,
            &[
                0x10, 0xc8, // adc al,cl
                0x12, 0xc8, // adc cl,al
                0x18, 0x45, 0xff, // sbb byte ptr [rbp-0x1],al
                0x1a, 0x4d, 0xff, // sbb cl,byte ptr [rbp-0x1]
                0x41, 0x10, 0x48, 0x10, // adc byte ptr [r8+0x10],cl
                0x45, 0x1a, 0x48, 0x10, // sbb r9b,byte ptr [r8+0x10]
                0x40, 0x10, 0xcc, // adc spl,cl
            ],
        );

        assert_eq!(instructions[0].mnemonic, "adc");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "al,cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["al", "cl"]);
        assert_eq!(writes, vec!["al"]);

        assert_eq!(instructions[1].mnemonic, "adc");
        assert_eq!(instructions[1].operands, "cl,al");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["al", "cl"]);
        assert_eq!(writes, vec!["cl"]);

        assert_eq!(instructions[2].mnemonic, "sbb");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],al");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["al", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "sbb");
        assert_eq!(instructions[3].size, 3);
        assert_eq!(instructions[3].operands, "cl,byte ptr [rbp-0x1]");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "rbp"]);
        assert_eq!(writes, vec!["cl"]);

        assert_eq!(instructions[4].mnemonic, "adc");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "byte ptr [r8+0x10],cl");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[5].mnemonic, "sbb");
        assert_eq!(instructions[5].size, 4);
        assert_eq!(instructions[5].operands, "r9b,byte ptr [r8+0x10]");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[5].mnemonic.as_str(),
            &instructions[5].typed_operands,
        );
        assert_eq!(reads, vec!["r8", "r9b"]);
        assert_eq!(writes, vec!["r9b"]);

        assert_eq!(instructions[6].mnemonic, "adc");
        assert_eq!(instructions[6].size, 3);
        assert_eq!(instructions[6].operands, "spl,cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[6].mnemonic.as_str(),
            &instructions[6].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_mov_rm32_immediate_memory_destinations() {
        let instructions = decode_native_instructions(
            0x8078,
            &[
                0xc7, 0x45, 0xfc, 0x2a, 0x00, 0x00, 0x00, // mov dword ptr [rbp-0x4],0x2a
                0x41, 0xc7, 0x40, 0x10, 0xef, 0xbe, 0x00,
                0x00, // mov dword ptr [r8+0x10],0xbeef
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 7);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4],0x2a");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].size, 8);
        assert_eq!(instructions[1].operands, "dword ptr [r8+0x10],0xbeef");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_decodes_mov_rm8_immediate_destinations() {
        let instructions = decode_native_instructions(
            0x807a,
            &[
                0xc6, 0xc0, 0x7f, // mov al,0x7f
                0x41, 0xc6, 0xc0, 0x80, // mov r8b,0x80
                0xc6, 0x45, 0xff, 0x01, // mov byte ptr [rbp-0x1],0x1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "al,0x7f");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("al")
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "r8b,0x80");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r8b")
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],0x1");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_decodes_mov_rm16_immediate_destinations() {
        let instructions = decode_native_instructions(
            0x807c,
            &[
                0x66, 0xc7, 0xc0, 0x34, 0x12, // mov ax,0x1234
                0x66, 0xc7, 0x45, 0xfe, 0xef, 0xbe, // mov word ptr [rbp-0x2],0xbeef
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 5);
        assert_eq!(instructions[0].operands, "ax,0x1234");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ax")
                && operand.width_bits == Some(16)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x1234)
                && operand.width_bits == Some(16)
        }));

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].size, 6);
        assert_eq!(instructions[1].operands, "word ptr [rbp-0x2],0xbeef");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-2)
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_decodes_mov_rm16_register_and_memory_forms() {
        let instructions = decode_native_instructions(
            0x8082,
            &[
                0x66, 0x89, 0xc8, // mov ax,cx
                0x66, 0x8b, 0xc8, // mov cx,ax
                0x66, 0x89, 0x45, 0xfe, // mov word ptr [rbp-0x2],ax
                0x66, 0x8b, 0x4d, 0xfe, // mov cx,word ptr [rbp-0x2]
                0x66, 0x41, 0x89, 0xc8, // mov r8w,cx
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "ax,cx");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ax")
                && operand.width_bits == Some(16)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("cx")
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["cx"]);
        assert_eq!(writes, vec!["ax"]);

        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "cx,ax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["ax"]);
        assert_eq!(writes, vec!["cx"]);

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "word ptr [rbp-0x2],ax");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-2)
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["ax", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "mov");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "cx,word ptr [rbp-0x2]");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-2)
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["cx"]);

        assert_eq!(instructions[4].mnemonic, "mov");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "r8w,cx");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r8w")
                && operand.width_bits == Some(16)
        }));
    }

    #[test]
    fn native_decoder_decodes_32_bit_group1_immediates() {
        let instructions = decode_native_instructions(
            0x8080,
            &[
                0x83, 0xc0, 0x05, // add eax,0x5
                0x81, 0xe9, 0x78, 0x56, 0x34, 0x12, // sub ecx,0x12345678
                0x41, 0x83, 0xc0, 0x02, // add r8d,0x2
                0x41, 0x83, 0xe9, 0x01, // sub r9d,0x1
                0x83, 0xe0, 0xf0, // and eax,-0x10
                0x83, 0xc9, 0x03, // or ecx,0x3
                0x41, 0x81, 0xf0, 0xff, 0x00, 0x00, 0x00, // xor r8d,0xff
            ],
        );

        assert_eq!(instructions[0].mnemonic, "add");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "eax,0x5");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x5)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "sub");
        assert_eq!(instructions[1].size, 6);
        assert_eq!(instructions[1].operands, "ecx,0x12345678");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["ecx"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "add");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "r8d,0x2");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["r8d"]);
        assert_eq!(writes, vec!["r8d"]);

        assert_eq!(instructions[3].mnemonic, "sub");
        assert_eq!(instructions[3].operands, "r9d,0x1");

        assert_eq!(instructions[4].mnemonic, "and");
        assert_eq!(instructions[4].operands, "eax,0xfffffffffffffff0");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[5].mnemonic, "or");
        assert_eq!(instructions[5].operands, "ecx,0x3");

        assert_eq!(instructions[6].mnemonic, "xor");
        assert_eq!(instructions[6].size, 7);
        assert_eq!(instructions[6].operands, "r8d,0xff");
    }

    #[test]
    fn native_decoder_decodes_32_bit_group1_memory_immediates() {
        let instructions = decode_native_instructions(
            0x8086,
            &[
                0x83, 0x45, 0xfc, 0x02, // add dword ptr [rbp-0x4],0x2
                0x83, 0x6d, 0xfc, 0x01, // sub dword ptr [rbp-0x4],0x1
                0x83, 0x65, 0xfc, 0x0f, // and dword ptr [rbp-0x4],0xf
                0x83, 0x4d, 0xfc, 0x03, // or dword ptr [rbp-0x4],0x3
                0x81, 0x75, 0xfc, 0xff, 0x00, 0x00, 0x00, // xor dword ptr [rbp-0x4],0xff
                0x41, 0x83, 0x40, 0x10, 0x02, // add dword ptr [r8+0x10],0x2
            ],
        );

        assert_eq!(instructions[0].mnemonic, "add");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4],0x2");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "sub");
        assert_eq!(instructions[1].operands, "dword ptr [rbp-0x4],0x1");
        assert_eq!(instructions[2].mnemonic, "and");
        assert_eq!(instructions[2].operands, "dword ptr [rbp-0x4],0xf");
        assert_eq!(instructions[3].mnemonic, "or");
        assert_eq!(instructions[3].operands, "dword ptr [rbp-0x4],0x3");
        assert_eq!(instructions[4].mnemonic, "xor");
        assert_eq!(instructions[4].size, 7);
        assert_eq!(instructions[4].operands, "dword ptr [rbp-0x4],0xff");
        assert_eq!(instructions[5].mnemonic, "add");
        assert_eq!(instructions[5].size, 5);
        assert_eq!(instructions[5].operands, "dword ptr [r8+0x10],0x2");
        assert!(instructions[5].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_32_bit_group1_adc_sbb_immediates() {
        let instructions = decode_native_instructions(
            0x8088,
            &[
                0x83, 0xd0, 0x05, // adc eax,0x5
                0x81, 0xd9, 0x78, 0x56, 0x34, 0x12, // sbb ecx,0x12345678
                0x83, 0x55, 0xfc, 0x02, // adc dword ptr [rbp-0x4],0x2
                0x83, 0x5d, 0xfc, 0x01, // sbb dword ptr [rbp-0x4],0x1
                0x41, 0x83, 0x50, 0x10, 0x02, // adc dword ptr [r8+0x10],0x2
            ],
        );

        assert_eq!(instructions[0].mnemonic, "adc");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "eax,0x5");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x5)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "sbb");
        assert_eq!(instructions[1].size, 6);
        assert_eq!(instructions[1].operands, "ecx,0x12345678");

        assert_eq!(instructions[2].mnemonic, "adc");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "dword ptr [rbp-0x4],0x2");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "sbb");
        assert_eq!(instructions[3].operands, "dword ptr [rbp-0x4],0x1");

        assert_eq!(instructions[4].mnemonic, "adc");
        assert_eq!(instructions[4].size, 5);
        assert_eq!(instructions[4].operands, "dword ptr [r8+0x10],0x2");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_32_bit_adc_sbb_register_memory_operands() {
        let instructions = decode_native_instructions(
            0x808a,
            &[
                0x11, 0xc8, // adc eax,ecx
                0x13, 0xc8, // adc ecx,eax
                0x19, 0x45, 0xfc, // sbb dword ptr [rbp-0x4],eax
                0x1b, 0x4d, 0xfc, // sbb ecx,dword ptr [rbp-0x4]
                0x41, 0x11, 0x48, 0x10, // adc dword ptr [r8+0x10],ecx
                0x45, 0x1b, 0x48, 0x10, // sbb r9d,dword ptr [r8+0x10]
                0x49, 0x11, 0x48, 0x10, // adc qword ptr [r8+0x10],rcx
            ],
        );

        assert_eq!(instructions[0].mnemonic, "adc");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "eax,ecx");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax", "ecx"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[1].mnemonic, "adc");
        assert_eq!(instructions[1].operands, "ecx,eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["eax", "ecx"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "sbb");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "dword ptr [rbp-0x4],eax");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["eax", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "sbb");
        assert_eq!(instructions[3].size, 3);
        assert_eq!(instructions[3].operands, "ecx,dword ptr [rbp-0x4]");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["ecx", "rbp"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[4].mnemonic, "adc");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "dword ptr [r8+0x10],ecx");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[5].mnemonic, "sbb");
        assert_eq!(instructions[5].size, 4);
        assert_eq!(instructions[5].operands, "r9d,dword ptr [r8+0x10]");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[5].mnemonic.as_str(),
            &instructions[5].typed_operands,
        );
        assert_eq!(reads, vec!["r8", "r9d"]);
        assert_eq!(writes, vec!["r9d"]);

        assert_eq!(instructions[6].mnemonic, "adc");
        assert_eq!(instructions[6].size, 4);
        assert_eq!(instructions[6].operands, "qword ptr [r8+0x10],rcx");
        assert!(instructions[6].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(64)
        }));
    }

    #[test]
    fn native_decoder_decodes_32_bit_imul_immediates() {
        let instructions = decode_native_instructions(
            0x8088,
            &[
                0x6b, 0xc1, 0x05, // imul eax,ecx,5
                0x69, 0xd0, 0x78, 0x56, 0x34, 0x12, // imul edx,eax,0x12345678
                0x45, 0x6b, 0xc1, 0xfb, // imul r8d,r9d,-5
            ],
        );

        assert_eq!(instructions[0].mnemonic, "imul");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "eax,ecx,0x5");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["ecx"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ecx")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x5)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "imul");
        assert_eq!(instructions[1].size, 6);
        assert_eq!(instructions[1].operands, "edx,eax,0x12345678");

        assert_eq!(instructions[2].mnemonic, "imul");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "r8d,r9d,0xfffffffffffffffb");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["r9d"]);
        assert_eq!(writes, vec!["r8d"]);
    }

    #[test]
    fn native_decoder_decodes_32_bit_cmovcc_registers() {
        let instructions = decode_native_instructions(
            0x808c,
            &[
                0x0f, 0x44, 0xc1, // cmove eax,ecx
                0x45, 0x0f, 0x45, 0xc1, // cmovne r8d,r9d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmove");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "eax,ecx");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["ecx"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ecx")
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[1].mnemonic, "cmovne");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "r8d,r9d");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r9d"]);
        assert_eq!(writes, vec!["r8d"]);
    }

    #[test]
    fn native_decoder_decodes_32_bit_cmovcc_memory_sources() {
        let instructions = decode_native_instructions(
            0x8090,
            &[
                0x0f, 0x44, 0x45, 0xfc, // cmove eax,dword ptr [rbp-0x4]
                0x0f, 0x45, 0x4d, 0xfc, // cmovne ecx,dword ptr [rbp-0x4]
                0x41, 0x0f, 0x44, 0x50, 0x10, // cmove edx,dword ptr [r8+0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmove");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "eax,dword ptr [rbp-0x4]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[1].mnemonic, "cmovne");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "ecx,dword ptr [rbp-0x4]");

        assert_eq!(instructions[2].mnemonic, "cmove");
        assert_eq!(instructions[2].size, 5);
        assert_eq!(instructions[2].operands, "edx,dword ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_setcc_and_movzx_r32_rm8_registers() {
        let instructions = decode_native_instructions(
            0x8092,
            &[
                0x0f, 0x94, 0xc0, // sete al
                0x0f, 0xb6, 0xc0, // movzx eax,al
                0x41, 0x0f, 0x95, 0xc0, // setne r8b
                0x45, 0x0f, 0xb6, 0xc8, // movzx r9d,r8b
            ],
        );

        assert_eq!(instructions[0].mnemonic, "sete");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "al");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert!(reads.is_empty());
        assert_eq!(writes, vec!["al"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("al")
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "movzx");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "eax,al");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["al"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[2].mnemonic, "setne");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "r8b");

        assert_eq!(instructions[3].mnemonic, "movzx");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "r9d,r8b");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["r8b"]);
        assert_eq!(writes, vec!["r9d"]);
    }

    #[test]
    fn native_decoder_decodes_setcc_rm8_memory_operands() {
        let instructions = decode_native_instructions(
            0x8096,
            &[
                0x0f, 0x94, 0x45, 0xff, // sete byte ptr [rbp-0x1]
                0x0f, 0x95, 0x5d, 0xff, // setne byte ptr [rbp-0x1]
                0x41, 0x0f, 0x94, 0x40, 0x10, // sete byte ptr [r8+0x10]
                0x40, 0x0f, 0x94, 0xc4, // sete spl
            ],
        );

        assert_eq!(instructions[0].mnemonic, "sete");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "setne");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1]");

        assert_eq!(instructions[2].mnemonic, "sete");
        assert_eq!(instructions[2].size, 5);
        assert_eq!(instructions[2].operands, "byte ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[3].mnemonic, "sete");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "spl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert!(reads.is_empty());
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_movzx_r32_memory_sources() {
        let instructions = decode_native_instructions(
            0x8096,
            &[
                0x0f, 0xb6, 0x45, 0xff, // movzx eax,byte ptr [rbp-0x1]
                0x0f, 0xb7, 0x4d, 0xfe, // movzx ecx,word ptr [rbp-0x2]
                0x41, 0x0f, 0xb6, 0x50, 0x10, // movzx edx,byte ptr [r8+0x10]
                0x45, 0x0f, 0xb7, 0xc8, // movzx r9d,r8w
            ],
        );

        assert_eq!(instructions[0].mnemonic, "movzx");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "eax,byte ptr [rbp-0x1]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[1].mnemonic, "movzx");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "ecx,word ptr [rbp-0x2]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-2)
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "movzx");
        assert_eq!(instructions[2].size, 5);
        assert_eq!(instructions[2].operands, "edx,byte ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert_eq!(writes, vec!["edx"]);

        assert_eq!(instructions[3].mnemonic, "movzx");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "r9d,r8w");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r8w")
                && operand.width_bits == Some(16)
        }));
    }

    #[test]
    fn native_decoder_decodes_movsx_r32_rm8_registers() {
        let instructions = decode_native_instructions(
            0x8098,
            &[
                0x0f, 0xbe, 0xc8, // movsx ecx,al
                0x45, 0x0f, 0xbe, 0xc8, // movsx r9d,r8b
            ],
        );

        assert_eq!(instructions[0].mnemonic, "movsx");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "ecx,al");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["al"]);
        assert_eq!(writes, vec!["ecx"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ecx")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("al")
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "movsx");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "r9d,r8b");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r8b"]);
        assert_eq!(writes, vec!["r9d"]);
    }

    #[test]
    fn native_decoder_decodes_movsx_r32_memory_sources() {
        let instructions = decode_native_instructions(
            0x809a,
            &[
                0x0f, 0xbe, 0x45, 0xff, // movsx eax,byte ptr [rbp-0x1]
                0x0f, 0xbf, 0x4d, 0xfe, // movsx ecx,word ptr [rbp-0x2]
                0x41, 0x0f, 0xbe, 0x50, 0x10, // movsx edx,byte ptr [r8+0x10]
                0x45, 0x0f, 0xbf, 0xc8, // movsx r9d,r8w
            ],
        );

        assert_eq!(instructions[0].mnemonic, "movsx");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "eax,byte ptr [rbp-0x1]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[1].mnemonic, "movsx");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "ecx,word ptr [rbp-0x2]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-2)
                && operand.width_bits == Some(16)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "movsx");
        assert_eq!(instructions[2].size, 5);
        assert_eq!(instructions[2].operands, "edx,byte ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert_eq!(writes, vec!["edx"]);

        assert_eq!(instructions[3].mnemonic, "movsx");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "r9d,r8w");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r8w")
                && operand.width_bits == Some(16)
        }));
    }

    #[test]
    fn native_decoder_decodes_movsxd_r64_rm32_registers() {
        let instructions = decode_native_instructions(
            0x809c,
            &[
                0x48, 0x63, 0xc0, // movsxd rax,eax
                0x4d, 0x63, 0xc8, // movsxd r9,r8d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "movsxd");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "rax,eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["rax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rax")
                && operand.width_bits.is_none()
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[1].mnemonic, "movsxd");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "r9,r8d");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r8d"]);
        assert_eq!(writes, vec!["r9"]);
    }

    #[test]
    fn native_decoder_decodes_movsxd_r64_memory_sources() {
        let instructions = decode_native_instructions(
            0x809e,
            &[
                0x48, 0x63, 0x45, 0xfc, // movsxd rax,dword ptr [rbp-0x4]
                0x4d, 0x63, 0x48, 0x10, // movsxd r9,dword ptr [r8+0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "movsxd");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "rax,dword ptr [rbp-0x4]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert_eq!(writes, vec!["rax"]);

        assert_eq!(instructions[1].mnemonic, "movsxd");
        assert_eq!(instructions[1].size, 4);
        assert_eq!(instructions[1].operands, "r9,dword ptr [r8+0x10]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["r8"]);
        assert_eq!(writes, vec!["r9"]);
    }

    #[test]
    fn native_decoder_decodes_32_bit_inc_dec_registers() {
        let instructions = decode_native_instructions(
            0x8090,
            &[
                0xff, 0xc0, // inc eax
                0xff, 0xc9, // dec ecx
                0x41, 0xff, 0xc0, // inc r8d
                0x41, 0xff, 0xc9, // dec r9d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "inc");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[1].mnemonic, "dec");
        assert_eq!(instructions[1].operands, "ecx");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["ecx"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "inc");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "r8d");

        assert_eq!(instructions[3].mnemonic, "dec");
        assert_eq!(instructions[3].operands, "r9d");
    }

    #[test]
    fn native_decoder_decodes_32_bit_inc_dec_memory_operands() {
        let instructions = decode_native_instructions(
            0x8091,
            &[
                0xff, 0x45, 0xfc, // inc dword ptr [rbp-0x4]
                0xff, 0x4d, 0xfc, // dec dword ptr [rbp-0x4]
                0x41, 0xff, 0x40, 0x10, // inc dword ptr [r8+0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "inc");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "dec");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "dword ptr [rbp-0x4]");

        assert_eq!(instructions[2].mnemonic, "inc");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "dword ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_inc_dec_rm8_memory_operands() {
        let instructions = decode_native_instructions(
            0x8098,
            &[
                0xfe, 0x45, 0xff, // inc byte ptr [rbp-0x1]
                0xfe, 0x4d, 0xff, // dec byte ptr [rbp-0x1]
                0x41, 0xfe, 0x40, 0x10, // inc byte ptr [r8+0x10]
                0x40, 0xfe, 0xc4, // inc spl
            ],
        );

        assert_eq!(instructions[0].mnemonic, "inc");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "dec");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1]");

        assert_eq!(instructions[2].mnemonic, "inc");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "byte ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[3].mnemonic, "inc");
        assert_eq!(instructions[3].size, 3);
        assert_eq!(instructions[3].operands, "spl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_32_bit_shift_immediates() {
        let instructions = decode_native_instructions(
            0x80a0,
            &[
                0xc1, 0xe0, 0x01, // shl eax,1
                0xc1, 0xe9, 0x04, // shr ecx,4
                0x41, 0xc1, 0xe0, 0x03, // shl r8d,3
                0x41, 0xc1, 0xe9, 0x02, // shr r9d,2
                0xc1, 0xf8, 0x01, // sar eax,1
                0x41, 0xc1, 0xf8, 0x04, // sar r8d,4
            ],
        );

        assert_eq!(instructions[0].mnemonic, "shl");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "eax,0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(1)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "shr");
        assert_eq!(instructions[1].operands, "ecx,0x4");

        assert_eq!(instructions[2].mnemonic, "shl");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "r8d,0x3");

        assert_eq!(instructions[3].mnemonic, "shr");
        assert_eq!(instructions[3].operands, "r9d,0x2");

        assert_eq!(instructions[4].mnemonic, "sar");
        assert_eq!(instructions[4].operands, "eax,0x1");

        assert_eq!(instructions[5].mnemonic, "sar");
        assert_eq!(instructions[5].size, 4);
        assert_eq!(instructions[5].operands, "r8d,0x4");
    }

    #[test]
    fn native_decoder_decodes_32_bit_shift_memory_immediates() {
        let instructions = decode_native_instructions(
            0x80a6,
            &[
                0xc1, 0x65, 0xfc, 0x01, // shl dword ptr [rbp-0x4],0x1
                0xc1, 0x6d, 0xfc, 0x04, // shr dword ptr [rbp-0x4],0x4
                0xc1, 0x7d, 0xfc, 0x02, // sar dword ptr [rbp-0x4],0x2
                0x41, 0xc1, 0x60, 0x10, 0x03, // shl dword ptr [r8+0x10],0x3
            ],
        );

        assert_eq!(instructions[0].mnemonic, "shl");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4],0x1");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "shr");
        assert_eq!(instructions[1].operands, "dword ptr [rbp-0x4],0x4");
        assert_eq!(instructions[2].mnemonic, "sar");
        assert_eq!(instructions[2].operands, "dword ptr [rbp-0x4],0x2");
        assert_eq!(instructions[3].mnemonic, "shl");
        assert_eq!(instructions[3].size, 5);
        assert_eq!(instructions[3].operands, "dword ptr [r8+0x10],0x3");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_32_bit_shift_one_and_cl_counts() {
        let instructions = decode_native_instructions(
            0x80aa,
            &[
                0xd1, 0xe0, // shl eax,0x1
                0xd3, 0xe9, // shr ecx,cl
                0xd3, 0xf8, // sar eax,cl
                0xd1, 0x65, 0xfc, // shl dword ptr [rbp-0x4],0x1
                0xd3, 0x7d, 0xfc, // sar dword ptr [rbp-0x4],cl
                0x41, 0xd1, 0x60, 0x10, // shl dword ptr [r8+0x10],0x1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "shl");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "eax,0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(1)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "shr");
        assert_eq!(instructions[1].size, 2);
        assert_eq!(instructions[1].operands, "ecx,cl");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("cl")
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "ecx"]);
        assert_eq!(writes, vec!["ecx"]);

        assert_eq!(instructions[2].mnemonic, "sar");
        assert_eq!(instructions[2].operands, "eax,cl");

        assert_eq!(instructions[3].mnemonic, "shl");
        assert_eq!(instructions[3].size, 3);
        assert_eq!(instructions[3].operands, "dword ptr [rbp-0x4],0x1");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[4].mnemonic, "sar");
        assert_eq!(instructions[4].operands, "dword ptr [rbp-0x4],cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[5].mnemonic, "shl");
        assert_eq!(instructions[5].size, 4);
        assert_eq!(instructions[5].operands, "dword ptr [r8+0x10],0x1");
        assert!(instructions[5].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_shift_rm8_memory_immediates() {
        let instructions = decode_native_instructions(
            0x80aa,
            &[
                0xc0, 0x65, 0xff, 0x01, // shl byte ptr [rbp-0x1],0x1
                0xc0, 0x6d, 0xff, 0x04, // shr byte ptr [rbp-0x1],0x4
                0xc0, 0x7d, 0xff, 0x02, // sar byte ptr [rbp-0x1],0x2
                0x41, 0xc0, 0x60, 0x10, 0x03, // shl byte ptr [r8+0x10],0x3
                0x40, 0xc0, 0xe4, 0x01, // shl spl,0x1
            ],
        );

        assert_eq!(instructions[0].mnemonic, "shl");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1],0x1");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "shr");
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1],0x4");
        assert_eq!(instructions[2].mnemonic, "sar");
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],0x2");

        assert_eq!(instructions[3].mnemonic, "shl");
        assert_eq!(instructions[3].size, 5);
        assert_eq!(instructions[3].operands, "byte ptr [r8+0x10],0x3");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[4].mnemonic, "shl");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "spl,0x1");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_shift_rm8_one_and_cl_counts() {
        let instructions = decode_native_instructions(
            0x80ae,
            &[
                0xd0, 0x65, 0xff, // shl byte ptr [rbp-0x1],0x1
                0xd2, 0x6d, 0xff, // shr byte ptr [rbp-0x1],cl
                0xd2, 0x7d, 0xff, // sar byte ptr [rbp-0x1],cl
                0x41, 0xd0, 0x60, 0x10, // shl byte ptr [r8+0x10],0x1
                0x40, 0xd2, 0xe4, // shl spl,cl
            ],
        );

        assert_eq!(instructions[0].mnemonic, "shl");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1],0x1");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "shr");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1],cl");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("cl")
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[2].mnemonic, "sar");
        assert_eq!(instructions[2].operands, "byte ptr [rbp-0x1],cl");

        assert_eq!(instructions[3].mnemonic, "shl");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "byte ptr [r8+0x10],0x1");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[4].mnemonic, "shl");
        assert_eq!(instructions[4].size, 3);
        assert_eq!(instructions[4].operands, "spl,cl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["cl", "spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_decoder_decodes_32_bit_not_neg_registers() {
        let instructions = decode_native_instructions(
            0x80b0,
            &[
                0xf7, 0xd0, // not eax
                0xf7, 0xd9, // neg ecx
                0x41, 0xf7, 0xd0, // not r8d
                0x41, 0xf7, 0xd9, // neg r9d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "not");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax"]);
        assert_eq!(writes, vec!["eax"]);

        assert_eq!(instructions[1].mnemonic, "neg");
        assert_eq!(instructions[1].operands, "ecx");

        assert_eq!(instructions[2].mnemonic, "not");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "r8d");

        assert_eq!(instructions[3].mnemonic, "neg");
        assert_eq!(instructions[3].operands, "r9d");
    }

    #[test]
    fn native_decoder_decodes_32_bit_not_neg_memory_operands() {
        let instructions = decode_native_instructions(
            0x80b4,
            &[
                0xf7, 0x55, 0xfc, // not dword ptr [rbp-0x4]
                0xf7, 0x5d, 0xfc, // neg dword ptr [rbp-0x4]
                0x41, 0xf7, 0x50, 0x10, // not dword ptr [r8+0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "not");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "neg");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "dword ptr [rbp-0x4]");

        assert_eq!(instructions[2].mnemonic, "not");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "dword ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));
    }

    #[test]
    fn native_decoder_decodes_not_neg_rm8_memory_operands() {
        let instructions = decode_native_instructions(
            0x80b4,
            &[
                0xf6, 0x55, 0xff, // not byte ptr [rbp-0x1]
                0xf6, 0x5d, 0xff, // neg byte ptr [rbp-0x1]
                0x41, 0xf6, 0x50, 0x10, // not byte ptr [r8+0x10]
                0x40, 0xf6, 0xd4, // not spl
            ],
        );

        assert_eq!(instructions[0].mnemonic, "not");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "byte ptr [rbp-0x1]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-1)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "neg");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "byte ptr [rbp-0x1]");

        assert_eq!(instructions[2].mnemonic, "not");
        assert_eq!(instructions[2].size, 4);
        assert_eq!(instructions[2].operands, "byte ptr [r8+0x10]");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[3].mnemonic, "not");
        assert_eq!(instructions[3].size, 3);
        assert_eq!(instructions[3].operands, "spl");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert_eq!(reads, vec!["spl"]);
        assert_eq!(writes, vec!["spl"]);
    }

    #[test]
    fn native_indexer_tracks_lea_data_target_constants() {
        let instructions = decode_native_instructions(
            0x8020,
            &[
                0x48, 0x8d, 0x0d, 0x2a, 0x00, 0x00, 0x00, // lea rcx,[rip+0x2a]
                0x4c, 0x8d, 0x0d, 0x20, 0x00, 0x00, 0x00, // lea r9,[rip+0x20]
                0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, // mov rax,[rip+0x10]
            ],
        );

        assert_eq!(instructions[0].mnemonic, "lea");
        assert_eq!(instructions[0].data_target, Some(0x8051));
        let constants = constant_writes_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
            instructions[0].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "rcx".to_string(),
                value: 0x8051,
                width_bits: Some(64),
            }]
        );

        assert_eq!(instructions[1].mnemonic, "lea");
        assert_eq!(instructions[1].data_target, Some(0x804e));
        let constants = constant_writes_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
            instructions[1].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r9".to_string(),
                value: 0x804e,
                width_bits: Some(64),
            }]
        );

        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[2].data_target, Some(0x8045));
        assert!(constant_writes_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
            instructions[2].data_target,
        )
        .is_empty());
    }

    #[test]
    fn native_decoder_and_indexer_track_self_xor_zero_constants() {
        let instructions = decode_native_instructions(
            0x8010,
            &[
                0x48, 0x31, 0xc0, // xor rax,rax
                0x4d, 0x33, 0xc0, // xor r8,r8
                0x31, 0xc0, // xor eax,eax
                0x45, 0x31, 0xc0, // xor r8d,r8d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "xor");
        assert_eq!(instructions[0].operands, "rax,rax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert!(reads.is_empty());
        assert_eq!(writes, vec!["rax"]);
        let constants = constant_writes_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
            instructions[0].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "rax".to_string(),
                value: 0,
                width_bits: Some(64),
            }]
        );

        assert_eq!(instructions[1].mnemonic, "xor");
        assert_eq!(instructions[1].operands, "r8,r8");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert!(reads.is_empty());
        assert_eq!(writes, vec!["r8"]);
        let constants = constant_writes_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
            instructions[1].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r8".to_string(),
                value: 0,
                width_bits: Some(64),
            }]
        );

        assert_eq!(instructions[2].mnemonic, "xor");
        assert_eq!(instructions[2].operands, "eax,eax");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert!(reads.is_empty());
        assert_eq!(writes, vec!["eax"]);
        let constants = constant_writes_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
            instructions[2].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0,
                width_bits: Some(32),
            }]
        );

        assert_eq!(instructions[3].mnemonic, "xor");
        assert_eq!(instructions[3].operands, "r8d,r8d");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
        );
        assert!(reads.is_empty());
        assert_eq!(writes, vec!["r8d"]);
        let constants = constant_writes_for_instruction(
            instructions[3].mnemonic.as_str(),
            &instructions[3].typed_operands,
            instructions[3].data_target,
        );
        assert_eq!(
            constants,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0,
                width_bits: Some(32),
            }]
        );
    }

    #[test]
    fn native_decoder_decodes_rex_extended_registers() {
        let instructions = decode_native_instructions(
            0x3000,
            &[
                0x4e, 0x8b, 0x4c, 0x94, 0x10, // mov r9,qword ptr [rsp+r10*4+0x10]
                0x49, 0x89, 0x4c, 0x24, 0xf0, // mov qword ptr [r12-0x10],rcx
            ],
        );

        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].operands, "r9,qword ptr [rsp+r10*4+0x10]");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r9")
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rsp")
                && operand.index.as_deref() == Some("r10")
                && operand.scale == Some(4)
                && operand.displacement == Some(0x10)
        }));

        assert_eq!(instructions[1].operands, "qword ptr [r12-0x10],rcx");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Destination
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r12")
                && operand.displacement == Some(-0x10)
        }));
    }

    #[test]
    fn native_decoder_decodes_cmp_and_test_typed_operands() {
        let instructions = decode_native_instructions(
            0x4000,
            &[
                0x4c, 0x39, 0x4d, 0xf8, // cmp qword ptr [rbp-0x8],r9
                0x4f, 0x3b, 0x4c, 0x94, 0x20, // cmp r9,qword ptr [r12+r10*4+0x20]
                0x4c, 0x85, 0xc9, // test rcx,r9
                0x39, 0xc8, // cmp eax,ecx
                0x3b, 0xd8, // cmp ebx,eax
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[0].operands, "qword ptr [rbp-0x8],r9");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-8)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r9")
        }));

        assert_eq!(instructions[1].mnemonic, "cmp");
        assert_eq!(instructions[1].operands, "r9,qword ptr [r12+r10*4+0x20]");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r12")
                && operand.index.as_deref() == Some("r10")
                && operand.scale == Some(4)
                && operand.displacement == Some(0x20)
        }));

        assert_eq!(instructions[2].mnemonic, "test");
        assert_eq!(instructions[2].operands, "rcx,r9");
        assert!(instructions[2].typed_operands.iter().all(|operand| {
            operand.role == OperandRole::Source && operand.kind == OperandKind::Register
        }));
        assert!(instructions[2]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("r9")));

        assert_eq!(instructions[3].mnemonic, "cmp");
        assert_eq!(instructions[3].size, 2);
        assert_eq!(instructions[3].operands, "eax,ecx");
        assert!(instructions[3].typed_operands.iter().all(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[3]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("eax")));
        assert!(instructions[3]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("ecx")));

        assert_eq!(instructions[4].mnemonic, "cmp");
        assert_eq!(instructions[4].operands, "ebx,eax");
        assert!(instructions[4]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("ebx")));
        assert!(instructions[4]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("eax")));
    }

    #[test]
    fn native_decoder_decodes_32_bit_test_register_operands() {
        let instructions = decode_native_instructions(
            0x4100,
            &[
                0x85, 0xc0, // test eax,eax
                0x85, 0xd1, // test ecx,edx
            ],
        );

        assert_eq!(instructions[0].mnemonic, "test");
        assert_eq!(instructions[0].size, 2);
        assert_eq!(instructions[0].operands, "eax,eax");
        assert!(instructions[0].typed_operands.iter().all(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0]
            .typed_operands
            .iter()
            .all(|operand| operand.register.as_deref() == Some("eax")));

        assert_eq!(instructions[1].mnemonic, "test");
        assert_eq!(instructions[1].operands, "ecx,edx");
        assert!(instructions[1]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("ecx")));
        assert!(instructions[1]
            .typed_operands
            .iter()
            .any(|operand| operand.register.as_deref() == Some("edx")));
    }

    #[test]
    fn native_decoder_decodes_32_bit_cmp_and_test_memory_operands() {
        let instructions = decode_native_instructions(
            0x4108,
            &[
                0x39, 0x45, 0xfc, // cmp dword ptr [rbp-0x4],eax
                0x3b, 0x4d, 0xfc, // cmp ecx,dword ptr [rbp-0x4]
                0x85, 0x55, 0xfc, // test dword ptr [rbp-0x4],edx
                0x41, 0x39, 0x48, 0x10, // cmp dword ptr [r8+0x10],ecx
                0x45, 0x85, 0x48, 0x10, // test dword ptr [r8+0x10],r9d
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[0].size, 3);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4],eax");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["eax", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "cmp");
        assert_eq!(instructions[1].size, 3);
        assert_eq!(instructions[1].operands, "ecx,dword ptr [rbp-0x4]");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[1].mnemonic.as_str(),
            &instructions[1].typed_operands,
        );
        assert_eq!(reads, vec!["ecx", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[2].mnemonic, "test");
        assert_eq!(instructions[2].size, 3);
        assert_eq!(instructions[2].operands, "dword ptr [rbp-0x4],edx");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["edx", "rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "cmp");
        assert_eq!(instructions[3].size, 4);
        assert_eq!(instructions[3].operands, "dword ptr [r8+0x10],ecx");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[4].mnemonic, "test");
        assert_eq!(instructions[4].size, 4);
        assert_eq!(instructions[4].operands, "dword ptr [r8+0x10],r9d");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[4].mnemonic.as_str(),
            &instructions[4].typed_operands,
        );
        assert_eq!(reads, vec!["r8", "r9d"]);
        assert!(writes.is_empty());
    }

    #[test]
    fn native_decoder_decodes_32_bit_cmp_and_test_memory_immediates() {
        let instructions = decode_native_instructions(
            0x4118,
            &[
                0x83, 0x7d, 0xfc, 0x2a, // cmp dword ptr [rbp-0x4],0x2a
                0x81, 0x7d, 0xfc, 0x78, 0x56, 0x34,
                0x12, // cmp dword ptr [rbp-0x4],0x12345678
                0xf7, 0x45, 0xfc, 0xff, 0x00, 0x00, 0x00, // test dword ptr [rbp-0x4],0xff
                0x41, 0x83, 0x78, 0x10, 0xfb, // cmp dword ptr [r8+0x10],-5
                0x41, 0xf7, 0x40, 0x10, 0x03, 0x00, 0x00,
                0x00, // test dword ptr [r8+0x10],0x3
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "dword ptr [rbp-0x4],0x2a");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-4)
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x2a)
                && operand.width_bits == Some(8)
        }));
        let (reads, writes) = register_accesses_for_instruction(
            instructions[0].mnemonic.as_str(),
            &instructions[0].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[1].mnemonic, "cmp");
        assert_eq!(instructions[1].size, 7);
        assert_eq!(instructions[1].operands, "dword ptr [rbp-0x4],0x12345678");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x12345678)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[2].mnemonic, "test");
        assert_eq!(instructions[2].size, 7);
        assert_eq!(instructions[2].operands, "dword ptr [rbp-0x4],0xff");
        let (reads, writes) = register_accesses_for_instruction(
            instructions[2].mnemonic.as_str(),
            &instructions[2].typed_operands,
        );
        assert_eq!(reads, vec!["rbp"]);
        assert!(writes.is_empty());

        assert_eq!(instructions[3].mnemonic, "cmp");
        assert_eq!(instructions[3].size, 5);
        assert_eq!(
            instructions[3].operands,
            "dword ptr [r8+0x10],0xfffffffffffffffb"
        );
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r8")
                && operand.displacement == Some(0x10)
        }));

        assert_eq!(instructions[4].mnemonic, "test");
        assert_eq!(instructions[4].size, 8);
        assert_eq!(instructions[4].operands, "dword ptr [r8+0x10],0x3");
    }

    #[test]
    fn native_decoder_decodes_cmp_and_test_immediate_operands() {
        let instructions = decode_native_instructions(
            0x5000,
            &[
                0x48, 0x83, 0xf8, 0x7f, // cmp rax,0x7f
                0x48, 0x81, 0x7d, 0xf8, 0x78, 0x56, 0x34,
                0x12, // cmp qword ptr [rbp-0x8],0x12345678
                0x49, 0xf7, 0x44, 0x24, 0xf0, 0xff, 0x00, 0x00,
                0x00, // test qword ptr [r12-0x10],0xff
                0x83, 0xf8, 0x2a, // cmp eax,0x2a
                0x81, 0xfa, 0x78, 0x56, 0x34, 0x12, // cmp edx,0x12345678
                0xf7, 0xc1, 0x03, 0x00, 0x00, 0x00, // test ecx,0x3
                0x41, 0x83, 0xf8, 0xfb, // cmp r8d,-5
            ],
        );

        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[0].size, 4);
        assert_eq!(instructions[0].operands, "rax,0x7f");
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("rax")
        }));
        assert!(instructions[0].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x7f)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[1].mnemonic, "cmp");
        assert_eq!(instructions[1].size, 8);
        assert_eq!(instructions[1].operands, "qword ptr [rbp-0x8],0x12345678");
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("rbp")
                && operand.displacement == Some(-8)
        }));
        assert!(instructions[1].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x12345678)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[2].mnemonic, "test");
        assert_eq!(instructions[2].size, 9);
        assert_eq!(instructions[2].operands, "qword ptr [r12-0x10],0xff");
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Memory
                && operand.base.as_deref() == Some("r12")
                && operand.displacement == Some(-0x10)
        }));
        assert!(instructions[2].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0xff)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[3].mnemonic, "cmp");
        assert_eq!(instructions[3].size, 3);
        assert_eq!(instructions[3].operands, "eax,0x2a");
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("eax")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[3].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x2a)
                && operand.width_bits == Some(8)
        }));

        assert_eq!(instructions[4].mnemonic, "cmp");
        assert_eq!(instructions[4].size, 6);
        assert_eq!(instructions[4].operands, "edx,0x12345678");
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("edx")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[4].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x12345678)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[5].mnemonic, "test");
        assert_eq!(instructions[5].size, 6);
        assert_eq!(instructions[5].operands, "ecx,0x3");
        assert!(instructions[5].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("ecx")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[5].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0x3)
                && operand.width_bits == Some(32)
        }));

        assert_eq!(instructions[6].mnemonic, "cmp");
        assert_eq!(instructions[6].size, 4);
        assert_eq!(instructions[6].operands, "r8d,0xfffffffffffffffb");
        assert!(instructions[6].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Register
                && operand.register.as_deref() == Some("r8d")
                && operand.width_bits == Some(32)
        }));
        assert!(instructions[6].typed_operands.iter().any(|operand| {
            operand.role == OperandRole::Source
                && operand.kind == OperandKind::Immediate
                && operand.value == Some(0xffff_ffff_ffff_fffb)
                && operand.width_bits == Some(8)
        }));
    }

    #[test]
    fn native_conditional_branches_reference_recent_flag_producer() {
        let artifact_ref = ObjectRef::artifact("abc123", "condition-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(11), Some("branchy"))
                .unwrap(),
        );
        let function = ParsedFunction {
            object_ref: function_ref,
            name: "branchy".to_string(),
            address: Some(0x1000),
            size: Some(11),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x1000,
            &[
                0x48, 0x39, 0xc8, // cmp rax,rcx
                0x74, 0x01, // je 0x1006
                0x90, // nop
                0xc3, // ret
                0x48, 0x85, 0xc0, // test rax,rax
                0x75, 0xf6, // jne 0x1000
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x1000)
            .expect("cmp instruction should be present");
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x1003)
            .expect("je instruction should be present");
        assert_eq!(je.condition_source.as_ref(), Some(&cmp.object_ref));
        assert_eq!(je.condition_summary.as_deref(), Some("je if rax == rcx"));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == je.object_ref
                && xref.target == cmp.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x1003)
        }));

        let test = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x1007)
            .expect("test instruction should be present");
        let jne = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x100a)
            .expect("jne instruction should be present");
        assert_eq!(jne.condition_source.as_ref(), Some(&test.object_ref));
        assert_eq!(jne.condition_summary.as_deref(), Some("jne if rax != 0"));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == jne.object_ref
                && xref.target == test.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x100a)
        }));
    }

    #[test]
    fn native_conditional_branch_references_immediate_flag_producer() {
        let artifact_ref = ObjectRef::artifact("abc123", "condition-immediate-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x5000, Some(8), Some("branchy_imm"))
                .unwrap(),
        );
        let function = ParsedFunction {
            object_ref: function_ref,
            name: "branchy_imm".to_string(),
            address: Some(0x5000),
            size: Some(8),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5000,
            &[
                0x48, 0x83, 0xf8, 0x7f, // cmp rax,0x7f
                0x74, 0x01, // je 0x5007
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5000)
            .expect("cmp instruction should be present");
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5004)
            .expect("je instruction should be present");
        assert_eq!(je.condition_source.as_ref(), Some(&cmp.object_ref));
        assert_eq!(je.condition_summary.as_deref(), Some("je if rax == 0x7f"));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == je.object_ref
                && xref.target == cmp.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x5004)
        }));
    }

    #[test]
    fn native_conditional_branch_summary_marks_known_constant_outcomes() {
        let artifact_ref = ObjectRef::artifact("abc123", "condition-known-fixture").unwrap();
        let not_taken_function = test_function(&artifact_ref, 0x5100, Some(16), "known_not_taken");
        let not_taken_facts = scan_function_cfg(
            &artifact_ref,
            &not_taken_function,
            0x5100,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x83, 0xf8, 0x2a, // cmp rax,0x2a
                0x75, 0x01, // jne 0x5111
            ],
            &function_targets_by_start(std::slice::from_ref(&not_taken_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let jne_not_taken = not_taken_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x510e)
            .expect("not-taken jne should be present");
        assert_eq!(
            jne_not_taken.condition_summary.as_deref(),
            Some("jne if rax != 0x2a (known not taken)")
        );

        let taken_function = test_function(&artifact_ref, 0x5120, Some(16), "known_taken");
        let taken_facts = scan_function_cfg(
            &artifact_ref,
            &taken_function,
            0x5120,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x83, 0xf8, 0x7f, // cmp rax,0x7f
                0x75, 0x01, // jne 0x5131
            ],
            &function_targets_by_start(std::slice::from_ref(&taken_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let jne_taken = taken_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x512e)
            .expect("taken jne should be present");
        assert_eq!(
            jne_taken.condition_summary.as_deref(),
            Some("jne if rax != 0x7f (known taken)")
        );

        let zero_function = test_function(&artifact_ref, 0x5140, Some(8), "known_zero");
        let zero_facts = scan_function_cfg(
            &artifact_ref,
            &zero_function,
            0x5140,
            &[
                0x48, 0x31, 0xc9, // xor rcx,rcx
                0x48, 0x85, 0xc9, // test rcx,rcx
                0x75, 0x00, // jne 0x5148
            ],
            &function_targets_by_start(std::slice::from_ref(&zero_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let zero_jne_not_taken = zero_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5146)
            .expect("jne should be present");
        assert_eq!(
            zero_jne_not_taken.condition_summary.as_deref(),
            Some("jne if rcx != 0 (known not taken)")
        );
    }

    #[test]
    fn native_32_bit_constant_writes_propagate_zero_extended_aliases() {
        let artifact_ref = ObjectRef::artifact("abc123", "zero-extended-alias-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5160, Some(14), "zero_extended_alias");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5160,
            &[
                0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,0x2a
                0x48, 0x83, 0xf8, 0x2a, // cmp rax,0x2a
                0x74, 0x01, // je 0x516c
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5160)
            .expect("mov instruction should be present");
        assert_eq!(
            writer.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x2a,
                width_bits: Some(32),
            }]
        );
        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5165)
            .expect("cmp instruction should be present");
        assert!(cmp.constant_sources.iter().any(|source| {
            source.register == "rax" && source.value == 0x2a && source.source == writer.object_ref
        }));
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5169)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rax == 0x2a (known taken)")
        );
    }

    #[test]
    fn native_32_bit_test_self_branches_use_known_zero_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "test32-known-zero-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5170, Some(10), "test32_known_zero");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5170,
            &[
                0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
                0x85, 0xc0, // test eax,eax
                0x74, 0x01, // je 0x517a
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let test = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5175)
            .expect("test instruction should be present");
        assert_eq!(test.operands_text, "eax,eax");
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5177)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if eax == 0 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_xor_zero_aliases_feed_64_bit_conditions() {
        let artifact_ref = ObjectRef::artifact("abc123", "xor32-zero-alias-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5178, Some(8), "xor32_zero_alias");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5178,
            &[
                0x31, 0xc0, // xor eax,eax
                0x48, 0x85, 0xc0, // test rax,rax
                0x74, 0x01, // je 0x5180
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5178)
            .expect("xor instruction should be present");
        assert_eq!(
            writer.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0,
                width_bits: Some(32),
            }]
        );
        let test = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x517a)
            .expect("test instruction should be present");
        assert!(test.constant_sources.iter().any(|source| {
            source.register == "rax" && source.value == 0 && source.source == writer.object_ref
        }));
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x517d)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rax == 0 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_cmp_immediate_branches_use_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "cmp32-known-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x517c, Some(12), "cmp32_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x517c,
            &[
                0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,0x2a
                0x83, 0xf8, 0x2a, // cmp eax,0x2a
                0x74, 0x01, // je 0x5186
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5181)
            .expect("cmp instruction should be present");
        assert_eq!(cmp.operands_text, "eax,0x2a");
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5184)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if eax == 0x2a (known taken)")
        );
    }

    #[test]
    fn native_32_bit_cmp_register_branches_use_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "cmp32-register-known-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5188, Some(17), "cmp32_register_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5188,
            &[
                0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,0x2a
                0xb9, 0x2a, 0x00, 0x00, 0x00, // mov ecx,0x2a
                0x39, 0xc8, // cmp eax,ecx
                0x74, 0x01, // je 0x5196
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5192)
            .expect("cmp instruction should be present");
        assert_eq!(cmp.operands_text, "eax,ecx");
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5194)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if eax == ecx (known taken)")
        );
    }

    #[test]
    fn native_32_bit_mov_register_copies_propagate_alias_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "mov32-copy-alias-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x51a0, Some(15), "mov32_copy_alias");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x51a0,
            &[
                0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,0x2a
                0x89, 0xc1, // mov ecx,eax
                0x48, 0x83, 0xf9, 0x2a, // cmp rcx,0x2a
                0x74, 0x01, // je 0x51ae
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let source = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51a0)
            .expect("source mov instruction should be present");
        let copy = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51a5)
            .expect("copy mov instruction should be present");
        assert_eq!(copy.operands_text, "ecx,eax");
        assert!(copy.constant_sources.iter().any(|constant| {
            constant.register == "eax"
                && constant.value == 0x2a
                && constant.source == source.object_ref
        }));
        assert_eq!(
            copy.constant_writes,
            vec![RegisterConstantWrite {
                register: "ecx".to_string(),
                value: 0x2a,
                width_bits: Some(32),
            }]
        );
        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51a7)
            .expect("cmp instruction should be present");
        assert!(cmp.constant_sources.iter().any(|constant| {
            constant.register == "rcx"
                && constant.value == 0x2a
                && constant.source == copy.object_ref
        }));
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51ab)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rcx == 0x2a (known taken)")
        );
    }

    #[test]
    fn native_32_bit_mov_rm_immediates_propagate_alias_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "mov32-rm-imm-alias-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x51b0, Some(14), "mov32_rm_imm_alias");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x51b0,
            &[
                0xc7, 0xc2, 0x2a, 0x00, 0x00, 0x00, // mov edx,0x2a
                0x48, 0x83, 0xfa, 0x2a, // cmp rdx,0x2a
                0x74, 0x01, // je 0x51bd
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51b0)
            .expect("mov instruction should be present");
        assert_eq!(
            writer.constant_writes,
            vec![RegisterConstantWrite {
                register: "edx".to_string(),
                value: 0x2a,
                width_bits: Some(32),
            }]
        );
        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51b6)
            .expect("cmp instruction should be present");
        assert!(cmp.constant_sources.iter().any(|constant| {
            constant.register == "rdx"
                && constant.value == 0x2a
                && constant.source == writer.object_ref
        }));
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51ba)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rdx == 0x2a (known taken)")
        );
    }

    #[test]
    fn native_32_bit_add_sub_immediates_fold_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "arith32-immediate-fixture").unwrap();
        let add_function = test_function(&artifact_ref, 0x51c0, Some(15), "add32_known");
        let add_facts = scan_function_cfg(
            &artifact_ref,
            &add_function,
            0x51c0,
            &[
                0xb8, 0x20, 0x00, 0x00, 0x00, // mov eax,0x20
                0x83, 0xc0, 0x22, // add eax,0x22
                0x48, 0x83, 0xf8, 0x42, // cmp rax,0x42
                0x74, 0x01, // je 0x51cf
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&add_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let add = add_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51c5)
            .expect("add instruction should be present");
        assert!(add
            .constant_sources
            .iter()
            .any(|constant| { constant.register == "eax" && constant.value == 0x20 }));
        assert_eq!(
            add.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x42,
                width_bits: Some(32),
            }]
        );
        let je = add_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51cc)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rax == 0x42 (known taken)")
        );

        let sub_function = test_function(&artifact_ref, 0x51d0, Some(16), "sub32_known");
        let sub_facts = scan_function_cfg(
            &artifact_ref,
            &sub_function,
            0x51d0,
            &[
                0x41, 0xb8, 0x50, 0x00, 0x00, 0x00, // mov r8d,0x50
                0x41, 0x83, 0xe8, 0x10, // sub r8d,0x10
                0x49, 0x83, 0xf8, 0x40, // cmp r8,0x40
                0x74, 0x01, // je 0x51e1
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&sub_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let sub = sub_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51d6)
            .expect("sub instruction should be present");
        assert_eq!(
            sub.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0x40,
                width_bits: Some(32),
            }]
        );
        let je = sub_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51de)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8 == 0x40 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_bitwise_immediates_fold_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "bitwise32-immediate-fixture").unwrap();
        let mask_function = test_function(&artifact_ref, 0x51f0, Some(16), "and32_known");
        let mask_facts = scan_function_cfg(
            &artifact_ref,
            &mask_function,
            0x51f0,
            &[
                0xb8, 0xaf, 0x00, 0x00, 0x00, // mov eax,0xaf
                0x83, 0xe0, 0xf0, // and eax,-0x10
                0xf7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // test eax,0xf
                0x74, 0x01, // je 0x5200
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&mask_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let and = mask_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51f5)
            .expect("and instruction should be present");
        assert_eq!(
            and.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0xa0,
                width_bits: Some(32),
            }]
        );
        let je = mask_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51fe)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if (eax & 0xf) == 0 (known taken)")
        );

        let xor_function = test_function(&artifact_ref, 0x5210, Some(17), "xor32_known");
        let xor_facts = scan_function_cfg(
            &artifact_ref,
            &xor_function,
            0x5210,
            &[
                0x41, 0xb8, 0xff, 0x00, 0x00, 0x00, // mov r8d,0xff
                0x41, 0x81, 0xf0, 0xff, 0x00, 0x00, 0x00, // xor r8d,0xff
                0x49, 0x83, 0xf8, 0x00, // cmp r8,0
                0x74, 0x01, // je 0x5222
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&xor_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let xor = xor_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5216)
            .expect("xor instruction should be present");
        assert_eq!(
            xor.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0,
                width_bits: Some(32),
            }]
        );
        let je = xor_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5221)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8 == 0x0 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_inc_dec_registers_fold_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "incdec32-fixture").unwrap();
        let inc_function = test_function(&artifact_ref, 0x5230, Some(13), "inc32_known");
        let inc_facts = scan_function_cfg(
            &artifact_ref,
            &inc_function,
            0x5230,
            &[
                0xb8, 0x41, 0x00, 0x00, 0x00, // mov eax,0x41
                0xff, 0xc0, // inc eax
                0x48, 0x83, 0xf8, 0x42, // cmp rax,0x42
                0x74, 0x01, // je 0x523e
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&inc_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let inc = inc_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5235)
            .expect("inc instruction should be present");
        assert!(inc
            .constant_sources
            .iter()
            .any(|constant| constant.register == "eax" && constant.value == 0x41));
        assert_eq!(
            inc.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x42,
                width_bits: Some(32),
            }]
        );
        let je = inc_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x523b)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rax == 0x42 (known taken)")
        );

        let dec_function = test_function(&artifact_ref, 0x5240, Some(14), "dec32_known");
        let dec_facts = scan_function_cfg(
            &artifact_ref,
            &dec_function,
            0x5240,
            &[
                0x41, 0xb8, 0x43, 0x00, 0x00, 0x00, // mov r8d,0x43
                0x41, 0xff, 0xc8, // dec r8d
                0x49, 0x83, 0xf8, 0x42, // cmp r8,0x42
                0x74, 0x01, // je 0x524f
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&dec_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let dec = dec_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5246)
            .expect("dec instruction should be present");
        assert_eq!(
            dec.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0x42,
                width_bits: Some(32),
            }]
        );
        let je = dec_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x524d)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8 == 0x42 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_shift_immediates_fold_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "shift32-fixture").unwrap();
        let shl_function = test_function(&artifact_ref, 0x5260, Some(14), "shl32_known");
        let shl_facts = scan_function_cfg(
            &artifact_ref,
            &shl_function,
            0x5260,
            &[
                0xb8, 0x21, 0x00, 0x00, 0x00, // mov eax,0x21
                0xc1, 0xe0, 0x01, // shl eax,1
                0x48, 0x83, 0xf8, 0x42, // cmp rax,0x42
                0x74, 0x01, // je 0x526f
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&shl_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let shl = shl_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5265)
            .expect("shl instruction should be present");
        assert_eq!(
            shl.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x42,
                width_bits: Some(32),
            }]
        );
        let je = shl_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x526c)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rax == 0x42 (known taken)")
        );

        let shr_function = test_function(&artifact_ref, 0x5270, Some(15), "shr32_known");
        let shr_facts = scan_function_cfg(
            &artifact_ref,
            &shr_function,
            0x5270,
            &[
                0x41, 0xb8, 0x80, 0x00, 0x00, 0x00, // mov r8d,0x80
                0x41, 0xc1, 0xe8, 0x01, // shr r8d,1
                0x49, 0x83, 0xf8, 0x40, // cmp r8,0x40
                0x74, 0x01, // je 0x5280
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&shr_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let shr = shr_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5276)
            .expect("shr instruction should be present");
        assert_eq!(
            shr.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0x40,
                width_bits: Some(32),
            }]
        );
        let je = shr_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x527e)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8 == 0x40 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_sar_immediates_fold_signed_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "sar32-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5290, Some(14), "sar32_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5290,
            &[
                0xb8, 0xfc, 0xff, 0xff, 0xff, // mov eax,0xfffffffc
                0xc1, 0xf8, 0x01, // sar eax,1
                0x85, 0xc0, // test eax,eax
                0x78, 0x01, // js 0x529d
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let sar = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5295)
            .expect("sar instruction should be present");
        assert_eq!(
            sar.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0xffff_fffe,
                width_bits: Some(32),
            }]
        );
        let js = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x529a)
            .expect("js instruction should be present");
        assert_eq!(
            js.condition_summary.as_deref(),
            Some("js if eax < 0 (known taken)")
        );
    }

    #[test]
    fn native_32_bit_not_neg_registers_fold_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "notneg32-fixture").unwrap();
        let not_function = test_function(&artifact_ref, 0x52a0, Some(14), "not32_known");
        let not_facts = scan_function_cfg(
            &artifact_ref,
            &not_function,
            0x52a0,
            &[
                0xb8, 0xf0, 0xff, 0xff, 0xff, // mov eax,0xfffffff0
                0xf7, 0xd0, // not eax
                0xf7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // test eax,0xf
                0x75, 0x01, // jne 0x52af
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&not_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let not = not_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52a5)
            .expect("not instruction should be present");
        assert_eq!(
            not.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x0f,
                width_bits: Some(32),
            }]
        );
        let jne = not_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52ad)
            .expect("jne instruction should be present");
        assert_eq!(
            jne.condition_summary.as_deref(),
            Some("jne if (eax & 0xf) != 0 (known taken)")
        );

        let neg_function = test_function(&artifact_ref, 0x52b0, Some(15), "neg32_known");
        let neg_facts = scan_function_cfg(
            &artifact_ref,
            &neg_function,
            0x52b0,
            &[
                0x41, 0xb8, 0x05, 0x00, 0x00, 0x00, // mov r8d,5
                0x41, 0xf7, 0xd8, // neg r8d
                0x41, 0x83, 0xf8, 0xfb, // cmp r8d,-5
                0x74, 0x01, // je 0x52bf
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&neg_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let neg = neg_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52b6)
            .expect("neg instruction should be present");
        assert_eq!(
            neg.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0xffff_fffb,
                width_bits: Some(32),
            }]
        );
        let je = neg_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52bd)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8d == 0xfffffffffffffffb (known taken)")
        );
    }

    #[test]
    fn native_32_bit_imul_immediates_fold_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "imul32-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x52c0, Some(17), "imul32_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x52c0,
            &[
                0x41, 0xb9, 0x07, 0x00, 0x00, 0x00, // mov r9d,7
                0x45, 0x6b, 0xc1, 0xfb, // imul r8d,r9d,-5
                0x41, 0x83, 0xf8, 0xdd, // cmp r8d,-35
                0x74, 0x01, // je 0x52d0
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let imul = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52c6)
            .expect("imul instruction should be present");
        assert_eq!(imul.operands_text, "r8d,r9d,0xfffffffffffffffb");
        assert_eq!(
            imul.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0xffff_ffdd,
                width_bits: Some(32),
            }]
        );
        let cmp = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52ca)
            .expect("cmp instruction should be present");
        assert!(cmp.constant_sources.iter().any(|source| {
            source.register == "r8d"
                && source.value == 0xffff_ffdd
                && source.source == imul.object_ref
        }));
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52ce)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8d == 0xffffffffffffffdd (known taken)")
        );
    }

    #[test]
    fn native_32_bit_cmovcc_registers_select_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "cmov32-fixture").unwrap();
        let taken_function = test_function(&artifact_ref, 0x52d0, Some(20), "cmov32_taken");
        let taken_facts = scan_function_cfg(
            &artifact_ref,
            &taken_function,
            0x52d0,
            &[
                0xb8, 0x11, 0x00, 0x00, 0x00, // mov eax,0x11
                0xb9, 0x22, 0x00, 0x00, 0x00, // mov ecx,0x22
                0x83, 0xf8, 0x11, // cmp eax,0x11
                0x0f, 0x44, 0xc1, // cmove eax,ecx
                0x83, 0xf8, 0x22, // cmp eax,0x22
                0x74, 0x00, // je 0x52e4
            ],
            &function_targets_by_start(std::slice::from_ref(&taken_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let cmove = taken_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52dd)
            .expect("cmove instruction should be present");
        assert_eq!(
            cmove.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 0x22,
                width_bits: Some(32),
            }]
        );
        let je = taken_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x52e3)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if eax == 0x22 (known taken)")
        );

        let not_taken_function = test_function(&artifact_ref, 0x52f0, Some(21), "cmov32_not_taken");
        let not_taken_facts = scan_function_cfg(
            &artifact_ref,
            &not_taken_function,
            0x52f0,
            &[
                0x41, 0xb8, 0x11, 0x00, 0x00, 0x00, // mov r8d,0x11
                0x41, 0xb9, 0x22, 0x00, 0x00, 0x00, // mov r9d,0x22
                0x41, 0x83, 0xf8, 0x33, // cmp r8d,0x33
                0x45, 0x0f, 0x44, 0xc1, // cmove r8d,r9d
                0x41, 0x83, 0xf8, 0x11, // cmp r8d,0x11
                0x74, 0x00, // je 0x5305
            ],
            &function_targets_by_start(std::slice::from_ref(&not_taken_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let cmove = not_taken_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5300)
            .expect("cmove instruction should be present");
        assert_eq!(
            cmove.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8d".to_string(),
                value: 0x11,
                width_bits: Some(32),
            }]
        );
        let je = not_taken_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5308)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r8d == 0x11 (known taken)")
        );
    }

    #[test]
    fn native_setcc_and_movzx_fold_known_boolean_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "setcc-movzx-fixture").unwrap();
        let true_function = test_function(&artifact_ref, 0x5310, Some(18), "setcc_true");
        let true_facts = scan_function_cfg(
            &artifact_ref,
            &true_function,
            0x5310,
            &[
                0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,0x2a
                0x83, 0xf8, 0x2a, // cmp eax,0x2a
                0x0f, 0x94, 0xc0, // sete al
                0x0f, 0xb6, 0xc0, // movzx eax,al
                0x83, 0xf8, 0x01, // cmp eax,1
                0x74, 0x00, // je 0x5322
            ],
            &function_targets_by_start(std::slice::from_ref(&true_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let sete = true_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5318)
            .expect("sete instruction should be present");
        assert_eq!(
            sete.constant_writes,
            vec![RegisterConstantWrite {
                register: "al".to_string(),
                value: 1,
                width_bits: Some(8),
            }]
        );
        let movzx = true_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x531b)
            .expect("movzx instruction should be present");
        assert_eq!(
            movzx.constant_writes,
            vec![RegisterConstantWrite {
                register: "eax".to_string(),
                value: 1,
                width_bits: Some(32),
            }]
        );
        let je = true_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5321)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if eax == 0x1 (known taken)")
        );

        let false_function = test_function(&artifact_ref, 0x5330, Some(24), "setcc_false");
        let false_facts = scan_function_cfg(
            &artifact_ref,
            &false_function,
            0x5330,
            &[
                0x41, 0xb8, 0x2a, 0x00, 0x00, 0x00, // mov r8d,0x2a
                0x41, 0x83, 0xf8, 0x2a, // cmp r8d,0x2a
                0x41, 0x0f, 0x95, 0xc0, // setne r8b
                0x45, 0x0f, 0xb6, 0xc8, // movzx r9d,r8b
                0x41, 0x83, 0xf9, 0x00, // cmp r9d,0
                0x74, 0x00, // je 0x5348
            ],
            &function_targets_by_start(std::slice::from_ref(&false_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let setne = false_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x533a)
            .expect("setne instruction should be present");
        assert_eq!(
            setne.constant_writes,
            vec![RegisterConstantWrite {
                register: "r8b".to_string(),
                value: 0,
                width_bits: Some(8),
            }]
        );
        let movzx = false_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x533e)
            .expect("movzx instruction should be present");
        assert_eq!(
            movzx.constant_writes,
            vec![RegisterConstantWrite {
                register: "r9d".to_string(),
                value: 0,
                width_bits: Some(32),
            }]
        );
        let je = false_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5346)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if r9d == 0x0 (known taken)")
        );
    }

    #[test]
    fn native_movsx_r32_rm8_sign_extends_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "movsx8-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5350, Some(23), "movsx8_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5350,
            &[
                0xb8, 0x80, 0x00, 0x00, 0x00, // mov eax,0x80
                0x0f, 0xbe, 0xc8, // movsx ecx,al
                0x83, 0xf9, 0x80, // cmp ecx,-128
                0x74, 0x01, // je 0x535e
                0x41, 0xb8, 0x7f, 0x00, 0x00, 0x00, // mov r8d,0x7f
                0x45, 0x0f, 0xbe, 0xc8, // movsx r9d,r8b
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let movsx_negative = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5355)
            .expect("negative movsx instruction should be present");
        assert_eq!(
            movsx_negative.constant_writes,
            vec![RegisterConstantWrite {
                register: "ecx".to_string(),
                value: 0xffff_ff80,
                width_bits: Some(32),
            }]
        );
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x535b)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if ecx == 0xffffffffffffff80 (known taken)")
        );
        let movsx_positive = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5363)
            .expect("positive movsx instruction should be present");
        assert_eq!(
            movsx_positive.constant_writes,
            vec![RegisterConstantWrite {
                register: "r9d".to_string(),
                value: 0x7f,
                width_bits: Some(32),
            }]
        );
    }

    #[test]
    fn native_movsxd_r64_rm32_sign_extends_known_constants() {
        let artifact_ref = ObjectRef::artifact("abc123", "movsxd-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x5370, Some(20), "movsxd_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x5370,
            &[
                0xb8, 0x80, 0xff, 0xff, 0xff, // mov eax,0xffffff80
                0x48, 0x63, 0xc0, // movsxd rax,eax
                0x48, 0x83, 0xf8, 0x80, // cmp rax,-128
                0x74, 0x01, // je 0x537f
                0x41, 0xb8, 0x7f, 0x00, 0x00, 0x00, // mov r8d,0x7f
                0x4d, 0x63, 0xc8, // movsxd r9,r8d
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let negative = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5375)
            .expect("negative movsxd instruction should be present");
        assert_eq!(
            negative.constant_writes,
            vec![RegisterConstantWrite {
                register: "rax".to_string(),
                value: 0xffff_ffff_ffff_ff80,
                width_bits: Some(64),
            }]
        );
        let je = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x537c)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if rax == 0xffffffffffffff80 (known taken)")
        );
        let positive = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5384)
            .expect("positive movsxd instruction should be present");
        assert_eq!(
            positive.constant_writes,
            vec![RegisterConstantWrite {
                register: "r9".to_string(),
                value: 0x7f,
                width_bits: Some(64),
            }]
        );
    }

    #[test]
    fn native_sign_flag_branches_summarize_known_test_outcomes() {
        let artifact_ref = ObjectRef::artifact("abc123", "sign-branch-fixture").unwrap();
        let negative_function =
            test_function(&artifact_ref, 0x5180, Some(17), "known_negative_sign");
        let negative_facts = scan_function_cfg(
            &artifact_ref,
            &negative_function,
            0x5180,
            &[
                0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov rax,-1
                0x48, 0x85, 0xc0, // test rax,rax
                0x78, 0x01, // js 0x5190
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&negative_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let js = negative_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x518d)
            .expect("js instruction should be present");
        assert_eq!(
            js.condition_summary.as_deref(),
            Some("js if rax < 0 (known taken)")
        );
        let negative_entry = negative_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x5180)
            .expect("entry block should be present");
        let negative_target = negative_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x5190)
            .expect("branch target block should be present");
        let negative_branch = negative_facts
            .cfg_edges
            .iter()
            .find(|edge| {
                edge.edge_kind == "branch"
                    && edge.source == negative_entry.object_ref
                    && edge.target == negative_target.object_ref
            })
            .expect("known sign branch edge should be present");
        assert_eq!(
            negative_branch.condition_summary.as_deref(),
            Some("js if rax < 0 (known taken)")
        );
        assert_eq!(negative_branch.known_outcome.as_deref(), Some("taken"));

        let non_negative_function =
            test_function(&artifact_ref, 0x51a0, Some(15), "known_non_negative_sign");
        let non_negative_facts = scan_function_cfg(
            &artifact_ref,
            &non_negative_function,
            0x51a0,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x85, 0xc0, // test rax,rax
                0x79, 0x00, // jns 0x51af
            ],
            &function_targets_by_start(std::slice::from_ref(&non_negative_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let jns = non_negative_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51ad)
            .expect("jns instruction should be present");
        assert_eq!(
            jns.condition_summary.as_deref(),
            Some("jns if rax >= 0 (known taken)")
        );
    }

    #[test]
    fn native_test_bitmask_branches_summarize_known_outcomes() {
        let artifact_ref = ObjectRef::artifact("abc123", "test-bitmask-fixture").unwrap();
        let mask_function = test_function(&artifact_ref, 0x51c0, Some(22), "known_bitmask");
        let mask_facts = scan_function_cfg(
            &artifact_ref,
            &mask_function,
            0x51c0,
            &[
                0x48, 0xb8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x8
                0x48, 0xf7, 0xc0, 0x08, 0x00, 0x00, 0x00, // test rax,0x8
                0x74, 0x01, // je 0x51d4
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&mask_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let je = mask_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51d1)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if (rax & 0x8) == 0 (known not taken)")
        );
        let entry = mask_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x51c0)
            .expect("entry block should be present");
        let fallthrough = mask_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x51d3)
            .expect("fallthrough block should be present");
        let fallthrough_edge = mask_facts
            .cfg_edges
            .iter()
            .find(|edge| {
                edge.edge_kind == "fallthrough"
                    && edge.source == entry.object_ref
                    && edge.target == fallthrough.object_ref
            })
            .expect("known bitmask fallthrough edge should be present");
        assert_eq!(fallthrough_edge.known_outcome.as_deref(), Some("not_taken"));

        let parity_function = test_function(&artifact_ref, 0x51e0, Some(22), "known_parity");
        let parity_facts = scan_function_cfg(
            &artifact_ref,
            &parity_function,
            0x51e0,
            &[
                0x48, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x3
                0x48, 0xf7, 0xc0, 0x03, 0x00, 0x00, 0x00, // test rax,0x3
                0x7a, 0x01, // jp 0x51f4
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&parity_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let jp = parity_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x51f1)
            .expect("jp instruction should be present");
        assert_eq!(
            jp.condition_summary.as_deref(),
            Some("jp if parity(rax & 0x3) is even (known taken)")
        );
    }

    #[test]
    fn native_32_bit_test_immediate_branches_summarize_known_outcomes() {
        let artifact_ref = ObjectRef::artifact("abc123", "test32-immediate-fixture").unwrap();
        let mask_function = test_function(&artifact_ref, 0x5240, Some(14), "test32_bitmask");
        let mask_facts = scan_function_cfg(
            &artifact_ref,
            &mask_function,
            0x5240,
            &[
                0xb8, 0x08, 0x00, 0x00, 0x00, // mov eax,0x8
                0xf7, 0xc0, 0x08, 0x00, 0x00, 0x00, // test eax,0x8
                0x74, 0x01, // je 0x524f
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&mask_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let test = mask_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x5245)
            .expect("test instruction should be present");
        assert_eq!(test.operands_text, "eax,0x8");
        let je = mask_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x524b)
            .expect("je instruction should be present");
        assert_eq!(
            je.condition_summary.as_deref(),
            Some("je if (eax & 0x8) == 0 (known not taken)")
        );

        let parity_function = test_function(&artifact_ref, 0x5260, Some(14), "test32_parity");
        let parity_facts = scan_function_cfg(
            &artifact_ref,
            &parity_function,
            0x5260,
            &[
                0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax,0x3
                0xf7, 0xc0, 0x03, 0x00, 0x00, 0x00, // test eax,0x3
                0x7a, 0x01, // jp 0x526f
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&parity_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let jp = parity_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x526b)
            .expect("jp instruction should be present");
        assert_eq!(
            jp.condition_summary.as_deref(),
            Some("jp if parity(eax & 0x3) is even (known taken)")
        );
    }

    #[test]
    fn native_cfg_edges_preserve_condition_summary_and_known_outcome() {
        let artifact_ref = ObjectRef::artifact("abc123", "cfg-outcome-fixture").unwrap();
        let taken_function = test_function(&artifact_ref, 0x5200, Some(18), "cfg_taken");
        let taken_facts = scan_function_cfg(
            &artifact_ref,
            &taken_function,
            0x5200,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x83, 0xf8, 0x7f, // cmp rax,0x7f
                0x75, 0x01, // jne 0x5211
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&taken_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let taken_entry = taken_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x5200)
            .expect("entry block should be present");
        let taken_target = taken_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x5211)
            .expect("branch target block should be present");
        let taken_branch = taken_facts
            .cfg_edges
            .iter()
            .find(|edge| {
                edge.edge_kind == "branch"
                    && edge.source == taken_entry.object_ref
                    && edge.target == taken_target.object_ref
            })
            .expect("taken branch edge should be present");
        assert_eq!(
            taken_branch.condition_summary.as_deref(),
            Some("jne if rax != 0x7f (known taken)")
        );
        assert_eq!(taken_branch.known_outcome.as_deref(), Some("taken"));

        let not_taken_function = test_function(&artifact_ref, 0x5220, Some(18), "cfg_not_taken");
        let not_taken_facts = scan_function_cfg(
            &artifact_ref,
            &not_taken_function,
            0x5220,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x83, 0xf8, 0x2a, // cmp rax,0x2a
                0x75, 0x01, // jne 0x5231
                0x90, // nop
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&not_taken_function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let not_taken_entry = not_taken_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x5220)
            .expect("entry block should be present");
        let not_taken_fallthrough = not_taken_facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x5230)
            .expect("fallthrough block should be present");
        let fallthrough_edge = not_taken_facts
            .cfg_edges
            .iter()
            .find(|edge| {
                edge.edge_kind == "fallthrough"
                    && edge.source == not_taken_entry.object_ref
                    && edge.target == not_taken_fallthrough.object_ref
            })
            .expect("known not-taken fallthrough edge should be present");
        assert_eq!(
            fallthrough_edge.condition_summary.as_deref(),
            Some("jne if rax != 0x2a (known not taken)")
        );
        assert_eq!(fallthrough_edge.known_outcome.as_deref(), Some("not_taken"));
    }

    #[test]
    fn native_cfg_scanner_closes_indirect_jump_without_static_target_xref() {
        let artifact_ref = ObjectRef::artifact("abc123", "indirect-jump-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x6000, Some(4), Some("dispatch"))
                .unwrap(),
        );
        let function = ParsedFunction {
            object_ref: function_ref,
            name: "dispatch".to_string(),
            address: Some(0x6000),
            size: Some(4),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x6000,
            &[
                0x90, // nop
                0xff, 0xe0, // jmp rax
                0xc3, // ret, unreachable from the closed indirect jump block
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(facts.basic_blocks.len(), 2);
        assert_eq!(facts.basic_blocks[0].address, 0x6000);
        assert_eq!(facts.basic_blocks[0].end_address, 0x6003);
        assert_eq!(facts.basic_blocks[0].terminator, "jmp");
        assert!(facts.cfg_edges.is_empty());
        assert!(facts.xrefs.iter().all(|xref| xref.address != Some(0x6001)));
    }

    #[test]
    fn native_indirect_call_register_uses_known_constant_target() {
        let artifact_ref = ObjectRef::artifact("abc123", "indirect-call-known-fixture").unwrap();
        let caller = test_function(&artifact_ref, 0x7400, Some(12), "caller");
        let callee = test_function(&artifact_ref, 0x7500, Some(1), "callee");
        let functions = vec![caller.clone(), callee.clone()];
        let facts = scan_function_cfg(
            &artifact_ref,
            &caller,
            0x7400,
            &[
                0x48, 0xb8, 0x00, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x7500
                0xff, 0xd0, // call rax
            ],
            &function_targets_by_start(&functions),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let call = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x740a)
            .expect("indirect call should be indexed");
        assert_eq!(call.target, Some(0x7500));
        assert!(call.constant_sources.iter().any(|source| {
            source.register == "rax" && source.value == 0x7500 && source.source != call.object_ref
        }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == caller.object_ref
                && xref.target == callee.object_ref
                && xref.relation == EdgeKind::Calls
                && xref.address == Some(0x740a)
        }));
        assert_eq!(
            facts
                .function_call_counts
                .get(caller.object_ref.key.to_string().as_str())
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn native_indirect_jump_register_uses_known_constant_block_target() {
        let artifact_ref = ObjectRef::artifact("abc123", "indirect-jump-known-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x7600, Some(12), "dispatch_known");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x7600,
            &[
                0x41, 0xb8, 0x0a, 0x76, 0x00, 0x00, // mov r8d,0x760a
                0x41, 0xff, 0xe0, // jmp r8
                0x90, // nop, unreachable
                0xc3, // ret target
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let jump = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x7606)
            .expect("indirect jump should be indexed");
        assert_eq!(jump.target, Some(0x760a));
        let target_block = facts
            .basic_blocks
            .iter()
            .find(|block| block.address == 0x760a)
            .expect("known jump target block should be present");
        assert!(facts.cfg_edges.iter().any(|edge| {
            edge.edge_kind == "branch"
                && edge.source == jump.block
                && edge.target == target_block.object_ref
        }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == jump.object_ref
                && xref.target == target_block.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x7606)
        }));
    }

    #[test]
    fn native_register_reads_reference_latest_local_writer() {
        let artifact_ref = ObjectRef::artifact("abc123", "register-def-use-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x7000, Some(7), Some("regflow")).unwrap(),
        );
        let function = ParsedFunction {
            object_ref: function_ref,
            name: "regflow".to_string(),
            address: Some(0x7000),
            size: Some(7),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x7000,
            &[
                0x48, 0x89, 0xc8, // mov rax,rcx
                0x48, 0x89, 0xc2, // mov rdx,rax
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x7000)
            .expect("writer instruction should be present");
        let reader = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x7003)
            .expect("reader instruction should be present");
        assert!(reader
            .register_sources
            .iter()
            .any(|source| { source.register == "rax" && source.source == writer.object_ref }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == reader.object_ref
                && xref.target == writer.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x7003)
        }));
    }

    #[test]
    fn native_zero_extended_register_writes_reference_alias_readers() {
        let artifact_ref = ObjectRef::artifact("abc123", "register-alias-def-use-fixture").unwrap();
        let function = test_function(&artifact_ref, 0x7100, Some(9), "regalias");
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x7100,
            &[
                0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,0x2a
                0x48, 0x89, 0xc2, // mov rdx,rax
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x7100)
            .expect("32-bit writer instruction should be present");
        let reader = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x7105)
            .expect("64-bit reader instruction should be present");
        assert!(reader
            .register_sources
            .iter()
            .any(|source| { source.register == "rax" && source.source == writer.object_ref }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == reader.object_ref
                && xref.target == writer.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x7105)
        }));
    }

    #[test]
    fn native_constant_reads_reference_latest_local_constant_writer() {
        let artifact_ref = ObjectRef::artifact("abc123", "constant-flow-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x7200, Some(17), Some("constflow"))
                .unwrap(),
        );
        let function = ParsedFunction {
            object_ref: function_ref,
            name: "constflow".to_string(),
            address: Some(0x7200),
            size: Some(17),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let facts = scan_function_cfg(
            &artifact_ref,
            &function,
            0x7200,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x89, 0xc2, // mov rdx,rax
                0x48, 0x31, 0xc0, // xor rax,rax
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&function)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        let writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x7200)
            .expect("constant writer instruction should be present");
        let reader = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x720a)
            .expect("constant reader instruction should be present");
        assert!(reader.constant_sources.iter().any(|source| {
            source.register == "rax" && source.value == 0x2a && source.source == writer.object_ref
        }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == reader.object_ref
                && xref.target == writer.object_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x720a)
        }));
        assert_eq!(
            reader.constant_writes,
            vec![RegisterConstantWrite {
                register: "rdx".to_string(),
                value: 0x2a,
                width_bits: Some(64),
            }]
        );

        let copy_chain = test_function(&artifact_ref, 0x7300, Some(17), "copy_chain");
        let copy_facts = scan_function_cfg(
            &artifact_ref,
            &copy_chain,
            0x7300,
            &[
                0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x2a
                0x48, 0x89, 0xc2, // mov rdx,rax
                0x48, 0x89, 0xd1, // mov rcx,rdx
                0xc3, // ret
            ],
            &function_targets_by_start(std::slice::from_ref(&copy_chain)),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let second_copy = copy_facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x730d)
            .expect("second copy should be present");
        assert_eq!(
            second_copy.constant_writes,
            vec![RegisterConstantWrite {
                register: "rcx".to_string(),
                value: 0x2a,
                width_bits: Some(64),
            }]
        );

        let zero_writer = facts
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x720d)
            .expect("zero idiom instruction should be present");
        assert_eq!(
            zero_writer.constant_writes,
            vec![RegisterConstantWrite {
                register: "rax".to_string(),
                value: 0,
                width_bits: Some(64),
            }]
        );
    }

    #[test]
    fn native_instruction_calls_create_function_xrefs_and_call_counts() {
        let artifact_ref = ObjectRef::artifact("abc123", "call-fixture").unwrap();
        let caller_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(6), Some("caller")).unwrap(),
        );
        let callee_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1005, Some(1), Some("callee")).unwrap(),
        );
        let caller = ParsedFunction {
            object_ref: caller_ref.clone(),
            name: "caller".to_string(),
            address: Some(0x1000),
            size: Some(6),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let callee = ParsedFunction {
            object_ref: callee_ref.clone(),
            name: "callee".to_string(),
            address: Some(0x1005),
            size: Some(1),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        };
        let functions = vec![caller.clone(), callee];
        let facts = scan_function_cfg(
            &artifact_ref,
            &caller,
            0x1000,
            &[0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3],
            &function_targets_by_start(&functions),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == caller_ref
                && xref.target == callee_ref
                && xref.relation == EdgeKind::Calls
                && xref.address == Some(0x1000)
        }));
        assert_eq!(
            facts.function_call_counts.get(caller_ref.key.as_str()),
            Some(&1)
        );
    }

    #[test]
    fn native_cfg_collection_merges_instruction_xrefs_and_call_counts() {
        let artifact_ref = ObjectRef::artifact("abc123", "native-merge-fixture").unwrap();
        let caller_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(6), Some("caller")).unwrap(),
        );
        let callee_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1005, Some(1), Some("callee")).unwrap(),
        );
        let functions = vec![
            ParsedFunction {
                object_ref: caller_ref.clone(),
                name: "caller".to_string(),
                address: Some(0x1000),
                size: Some(6),
                boundary_source: "test".to_string(),
                boundary_confidence: "symbol".to_string(),
                frame_pointer: None,
                stack_frame_size: None,
                stack_cleanup_size: None,
                epilogue_kind: None,
                has_frame_epilogue: false,
                stack_slots: Vec::new(),
                calling_convention: None,
                argument_registers: Vec::new(),
                string_count: 0,
                call_count: 0,
            },
            ParsedFunction {
                object_ref: callee_ref.clone(),
                name: "callee".to_string(),
                address: Some(0x1005),
                size: Some(1),
                boundary_source: "test".to_string(),
                boundary_confidence: "symbol".to_string(),
                frame_pointer: None,
                stack_frame_size: None,
                stack_cleanup_size: None,
                epilogue_kind: None,
                has_frame_epilogue: false,
                stack_slots: Vec::new(),
                calling_convention: None,
                argument_registers: Vec::new(),
                string_count: 0,
                call_count: 0,
            },
        ];
        let sections = vec![ParsedSection {
            object_ref: ObjectRef::new(
                ObjectKind::Section,
                StableObjectKey::section(&artifact_ref.key, ".text", 0x1000, 6).unwrap(),
            ),
            name: ".text".to_string(),
            address: Some(0x1000),
            offset: Some(0),
            size: 6,
            flags: "Text".to_string(),
            bytes: vec![0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3],
        }];

        let facts = collect_native_cfg(&artifact_ref, &sections, &functions, &[], &[]).unwrap();

        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == caller_ref
                && xref.target == callee_ref
                && xref.relation == EdgeKind::Calls
        }));
        assert_eq!(
            facts.function_call_counts.get(caller_ref.key.as_str()),
            Some(&1)
        );
    }

    #[test]
    fn native_cfg_collection_creates_rip_relative_string_xrefs() {
        let artifact_ref = ObjectRef::artifact("abc123", "rip-string-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(8), Some("loader")).unwrap(),
        );
        let string_ref = ObjectRef::new(
            ObjectKind::String,
            StableObjectKey::string(&artifact_ref.key, 0x100, Some(0x1007), "admin").unwrap(),
        );
        let functions = vec![ParsedFunction {
            object_ref: function_ref.clone(),
            name: "loader".to_string(),
            address: Some(0x1000),
            size: Some(8),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        }];
        let strings = vec![ParsedString {
            object_ref: string_ref.clone(),
            value: "admin".to_string(),
            address: Some(0x1007),
            offset: 0x100,
            length: 5,
            encoding: "ascii".to_string(),
        }];
        let sections = vec![ParsedSection {
            object_ref: ObjectRef::new(
                ObjectKind::Section,
                StableObjectKey::section(&artifact_ref.key, ".text", 0x1000, 8).unwrap(),
            ),
            name: ".text".to_string(),
            address: Some(0x1000),
            offset: Some(0),
            size: 8,
            flags: "Text".to_string(),
            bytes: vec![0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3],
        }];

        let facts =
            collect_native_cfg(&artifact_ref, &sections, &functions, &strings, &[]).unwrap();

        assert!(facts.instructions.iter().any(|instruction| {
            instruction.mnemonic == "lea" && instruction.data_target == Some(0x1007)
        }));
        let lea = facts
            .instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "lea")
            .expect("lea instruction should be indexed");
        assert!(lea.register_writes.iter().any(|register| register == "rax"));
        assert!(facts.instructions.iter().any(|instruction| {
            instruction.mnemonic == "lea"
                && instruction.typed_operands.iter().any(|operand| {
                    operand.role == OperandRole::DataReference
                        && operand.kind == OperandKind::Memory
                        && operand.data_reference_target() == Some(0x1007)
                })
        }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == function_ref
                && xref.target == string_ref
                && xref.relation == EdgeKind::References
                && xref.address == Some(0x1000)
        }));
        assert_eq!(
            facts.function_string_counts.get(function_ref.key.as_str()),
            Some(&1)
        );
    }

    #[test]
    fn synthetic_pe_imports_include_iat_slot_addresses() {
        let artifact_ref = ObjectRef::artifact("abc123", "pe-import-fixture").unwrap();
        let bytes = synthetic_pe_with_import_fixture();
        let file = object::File::parse(&*bytes).unwrap();
        let imports = collect_imports(&artifact_ref, &file, &bytes).unwrap();

        let exit_process = imports
            .iter()
            .find(|import| import.symbol == "ExitProcess")
            .expect("synthetic PE import should be indexed");
        assert_eq!(exit_process.module.as_deref(), Some("kernel32.dll"));
        assert_eq!(exit_process.address, Some(0x140002080));
    }

    #[test]
    fn native_calls_to_import_slots_create_calls_import_xrefs() {
        let artifact_ref = ObjectRef::artifact("abc123", "native-import-call-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(6), Some("caller")).unwrap(),
        );
        let import_ref = ObjectRef::new(
            ObjectKind::Import,
            StableObjectKey::import(&artifact_ref.key, Some("kernel32.dll"), "ExitProcess", None)
                .unwrap(),
        );
        let functions = vec![ParsedFunction {
            object_ref: function_ref.clone(),
            name: "caller".to_string(),
            address: Some(0x1000),
            size: Some(6),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        }];
        let imports = vec![ParsedImport {
            object_ref: import_ref.clone(),
            module: Some("kernel32.dll".to_string()),
            symbol: "ExitProcess".to_string(),
            address: Some(0x1005),
        }];
        let sections = vec![ParsedSection {
            object_ref: ObjectRef::new(
                ObjectKind::Section,
                StableObjectKey::section(&artifact_ref.key, ".text", 0x1000, 6).unwrap(),
            ),
            name: ".text".to_string(),
            address: Some(0x1000),
            offset: Some(0),
            size: 6,
            flags: "Text".to_string(),
            bytes: vec![0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3],
        }];

        let facts =
            collect_native_cfg(&artifact_ref, &sections, &functions, &[], &imports).unwrap();

        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == function_ref
                && xref.target == import_ref
                && xref.relation == EdgeKind::CallsImport
                && xref.address == Some(0x1000)
        }));
        assert_eq!(
            facts.function_call_counts.get(function_ref.key.as_str()),
            Some(&1)
        );
    }

    #[test]
    fn native_indirect_iat_calls_create_calls_import_xrefs() {
        let artifact_ref =
            ObjectRef::artifact("abc123", "native-indirect-import-call-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x1000, Some(7), Some("caller")).unwrap(),
        );
        let import_ref = ObjectRef::new(
            ObjectKind::Import,
            StableObjectKey::import(&artifact_ref.key, Some("kernel32.dll"), "ExitProcess", None)
                .unwrap(),
        );
        let functions = vec![ParsedFunction {
            object_ref: function_ref.clone(),
            name: "caller".to_string(),
            address: Some(0x1000),
            size: Some(7),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        }];
        let imports = vec![ParsedImport {
            object_ref: import_ref.clone(),
            module: Some("kernel32.dll".to_string()),
            symbol: "ExitProcess".to_string(),
            address: Some(0x1006),
        }];
        let sections = vec![ParsedSection {
            object_ref: ObjectRef::new(
                ObjectKind::Section,
                StableObjectKey::section(&artifact_ref.key, ".text", 0x1000, 7).unwrap(),
            ),
            name: ".text".to_string(),
            address: Some(0x1000),
            offset: Some(0),
            size: 7,
            flags: "Text".to_string(),
            bytes: vec![0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0xc3],
        }];

        let facts =
            collect_native_cfg(&artifact_ref, &sections, &functions, &[], &imports).unwrap();

        assert!(facts.instructions.iter().any(|instruction| {
            instruction.mnemonic == "call"
                && instruction.data_target == Some(0x1006)
                && instruction.typed_operands.iter().any(|operand| {
                    operand.role == OperandRole::CallTarget
                        && operand.kind == OperandKind::Memory
                        && operand.data_reference_target() == Some(0x1006)
                })
        }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == function_ref
                && xref.target == import_ref
                && xref.relation == EdgeKind::CallsImport
                && xref.address == Some(0x1000)
        }));
        assert_eq!(
            facts.function_call_counts.get(function_ref.key.as_str()),
            Some(&1)
        );
    }

    #[test]
    fn native_iat_jump_thunks_create_calls_import_xrefs() {
        let artifact_ref = ObjectRef::artifact("abc123", "native-import-thunk-fixture").unwrap();
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(
                &artifact_ref.key,
                0x1000,
                Some(6),
                Some("ExitProcess$thunk"),
            )
            .unwrap(),
        );
        let import_ref = ObjectRef::new(
            ObjectKind::Import,
            StableObjectKey::import(&artifact_ref.key, Some("kernel32.dll"), "ExitProcess", None)
                .unwrap(),
        );
        let functions = vec![ParsedFunction {
            object_ref: function_ref.clone(),
            name: "ExitProcess$thunk".to_string(),
            address: Some(0x1000),
            size: Some(6),
            boundary_source: "test".to_string(),
            boundary_confidence: "symbol".to_string(),
            frame_pointer: None,
            stack_frame_size: None,
            stack_cleanup_size: None,
            epilogue_kind: None,
            has_frame_epilogue: false,
            stack_slots: Vec::new(),
            calling_convention: None,
            argument_registers: Vec::new(),
            string_count: 0,
            call_count: 0,
        }];
        let imports = vec![ParsedImport {
            object_ref: import_ref.clone(),
            module: Some("kernel32.dll".to_string()),
            symbol: "ExitProcess".to_string(),
            address: Some(0x1006),
        }];
        let sections = vec![ParsedSection {
            object_ref: ObjectRef::new(
                ObjectKind::Section,
                StableObjectKey::section(&artifact_ref.key, ".text", 0x1000, 6).unwrap(),
            ),
            name: ".text".to_string(),
            address: Some(0x1000),
            offset: Some(0),
            size: 6,
            flags: "Text".to_string(),
            bytes: vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00],
        }];

        let facts =
            collect_native_cfg(&artifact_ref, &sections, &functions, &[], &imports).unwrap();

        assert!(facts.instructions.iter().any(|instruction| {
            instruction.mnemonic == "jmp"
                && instruction.data_target == Some(0x1006)
                && instruction.typed_operands.iter().any(|operand| {
                    operand.role == OperandRole::BranchTarget
                        && operand.kind == OperandKind::Memory
                        && operand.data_reference_target() == Some(0x1006)
                })
        }));
        assert!(facts.xrefs.iter().any(|xref| {
            xref.source == function_ref
                && xref.target == import_ref
                && xref.relation == EdgeKind::CallsImport
                && xref.address == Some(0x1000)
        }));
        assert_eq!(
            facts.function_call_counts.get(function_ref.key.as_str()),
            Some(&1)
        );
    }

    fn synthetic_pe_fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        put_u16(&mut bytes, 0x00, 0x5a4d);
        put_u32(&mut bytes, 0x3c, 0x80);
        put_u32(&mut bytes, 0x80, 0x0000_4550);
        put_u16(&mut bytes, 0x84, 0x8664);
        put_u16(&mut bytes, 0x86, 2);
        put_u16(&mut bytes, 0x94, 0xf0);
        put_u16(&mut bytes, 0x96, 0x0022);

        let optional = 0x98;
        put_u16(&mut bytes, optional, 0x20b);
        bytes[optional + 2] = 14;
        put_u32(&mut bytes, optional + 4, 0x200);
        put_u32(&mut bytes, optional + 16, 0x1000);
        put_u32(&mut bytes, optional + 20, 0x1000);
        put_u64(&mut bytes, optional + 24, 0x140000000);
        put_u32(&mut bytes, optional + 32, 0x1000);
        put_u32(&mut bytes, optional + 36, 0x200);
        put_u16(&mut bytes, optional + 48, 6);
        put_u32(&mut bytes, optional + 56, 0x3000);
        put_u32(&mut bytes, optional + 60, 0x200);
        put_u16(&mut bytes, optional + 68, 3);
        put_u64(&mut bytes, optional + 72, 0x100000);
        put_u64(&mut bytes, optional + 80, 0x1000);
        put_u64(&mut bytes, optional + 88, 0x100000);
        put_u64(&mut bytes, optional + 96, 0x1000);
        put_u32(&mut bytes, optional + 108, 16);

        let text = 0x188;
        put_section(
            &mut bytes,
            SectionSpec {
                offset: text,
                name: b".text",
                virtual_size: 0x40,
                virtual_address: 0x1000,
                raw_size: 0x200,
                raw_pointer: 0x200,
                characteristics: 0x6000_0020,
            },
        );
        let rdata = text + 40;
        put_section(
            &mut bytes,
            SectionSpec {
                offset: rdata,
                name: b".rdata",
                virtual_size: 0x80,
                virtual_address: 0x2000,
                raw_size: 0x200,
                raw_pointer: 0x400,
                characteristics: 0x4000_0040,
            },
        );

        bytes[0x200..0x205].copy_from_slice(&[0x74, 0x02, 0x90, 0xc3, 0xc3]);
        bytes[0x400..0x40f].copy_from_slice(b"cmd.exe /c calc");
        bytes[0x420..0x42b].copy_from_slice(b"admin-token");
        bytes
    }

    fn synthetic_pe_with_import_fixture() -> Vec<u8> {
        let mut bytes = synthetic_pe_fixture();
        put_u32(&mut bytes, 0x1b0 + 8, 0x100);
        bytes[0x400..0x500].fill(0);
        put_u32(&mut bytes, 0x400, 0x2040);
        put_u32(&mut bytes, 0x404, 0);
        put_u32(&mut bytes, 0x408, 0);
        put_u32(&mut bytes, 0x40c, 0x2030);
        put_u32(&mut bytes, 0x410, 0x2080);
        bytes[0x430..0x43c].copy_from_slice(b"kernel32.dll");
        put_u64(&mut bytes, 0x440, 0x2060);
        put_u64(&mut bytes, 0x448, 0);
        put_u16(&mut bytes, 0x460, 0);
        bytes[0x462..0x46d].copy_from_slice(b"ExitProcess");
        put_u64(&mut bytes, 0x480, 0x2060);
        put_u64(&mut bytes, 0x488, 0);
        put_u32(&mut bytes, 0x98 + 112 + 8, 0x2000);
        put_u32(&mut bytes, 0x98 + 112 + 12, 0x100);
        bytes
    }

    struct SectionSpec<'name> {
        offset: usize,
        name: &'name [u8],
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_pointer: u32,
        characteristics: u32,
    }

    fn put_section(bytes: &mut [u8], section: SectionSpec<'_>) {
        bytes[section.offset..section.offset + section.name.len()].copy_from_slice(section.name);
        put_u32(bytes, section.offset + 8, section.virtual_size);
        put_u32(bytes, section.offset + 12, section.virtual_address);
        put_u32(bytes, section.offset + 16, section.raw_size);
        put_u32(bytes, section.offset + 20, section.raw_pointer);
        put_u32(bytes, section.offset + 36, section.characteristics);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
