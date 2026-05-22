use anyhow::Context;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use revdeck_core::{
    pre_export_validation, render_json_bundle, render_markdown, AnalysisJobDetail, AnalysisJobRow,
    AnalysisJobsSummary, CommandDiagnostic, CommandDiagnosticKind, CommandExecutor, CommandOutcome,
    CommandParser, CommandResolver, CommandState, ExportFormat, Finding, FindingEvidence,
    FindingSeverity, FindingStatus, FunctionRadarFilter, FunctionRadarViewModel, FunctionScore,
    GraphEdgeDetail, GraphLabViewModel, InspectorViewModel, NavigationEntry, NavigationLens,
    ObjectGraphQuery, ObjectKind, ObjectRef, ObjectRelation, ObjectSearch, ObjectSummary,
    QueryError, RelationDirection, RelationFilter, ResolvedCommand, StableObjectKey,
    TraversalOptions, TriageBoardViewModel, WORKSPACE_LENSES,
};
use revdeck_db::{
    AnalysisJobRecord, AnalysisJobRepository, ArtifactRepository, FindingRepository,
    IndexRepository, MemoryRepository, ObjectQueryRepository, ProjectDatabase, RadarRepository,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
    time::Duration,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneFocus {
    Workspace,
    Main,
    Inspector,
}

const PANE_FOCUS_ORDER: [PaneFocus; 3] =
    [PaneFocus::Workspace, PaneFocus::Main, PaneFocus::Inspector];
const GRAPH_LAB_MAX_DEPTH: usize = 2;
const GRAPH_LAB_MAX_NODES: usize = 64;
const GRAPH_LAB_ACTIVE_FILTER: RelationFilter = RelationFilter::All;

#[derive(Debug, Clone)]
pub struct WorkspaceSnapshot {
    pub overview: revdeck_core::OverviewViewModel,
    pub triage: TriageBoardViewModel,
    pub radar: FunctionRadarViewModel,
    pub scores: Vec<FunctionScore>,
    pub functions: Vec<ObjectSummary>,
    pub strings: Vec<ObjectSummary>,
    pub imports: Vec<ObjectSummary>,
    pub diff_deltas: Vec<ObjectSummary>,
    pub trace_items: Vec<ObjectSummary>,
    pub firmware_files: Vec<ObjectSummary>,
    pub crash_items: Vec<ObjectSummary>,
    pub protocol_items: Vec<ObjectSummary>,
    pub annotations: Vec<ObjectSummary>,
    pub findings: Vec<Finding>,
    pub analysis_jobs: Vec<AnalysisJobRow>,
    pub analysis_jobs_summary: AnalysisJobsSummary,
    pub objects: BTreeMap<ObjectRef, ObjectSummary>,
    pub relations_by_object: BTreeMap<ObjectRef, Vec<ObjectRelation>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersistSessionSummary {
    pub annotations: usize,
    pub findings: usize,
    pub exports: usize,
}

impl WorkspaceSnapshot {
    pub fn empty() -> Self {
        let overview = revdeck_core::OverviewViewModel::new(None, "No project loaded", "closed");
        let triage = TriageBoardViewModel::from_overview_and_scores(&overview, &[]);
        let radar = FunctionRadarViewModel::from_scores(None, &[], &FunctionRadarFilter::default());
        Self {
            overview,
            triage,
            radar,
            scores: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            imports: Vec::new(),
            diff_deltas: Vec::new(),
            trace_items: Vec::new(),
            firmware_files: Vec::new(),
            crash_items: Vec::new(),
            protocol_items: Vec::new(),
            annotations: Vec::new(),
            findings: Vec::new(),
            analysis_jobs: Vec::new(),
            analysis_jobs_summary: AnalysisJobsSummary::default(),
            objects: BTreeMap::new(),
            relations_by_object: BTreeMap::new(),
        }
    }

    pub fn load_from_project(project: &ProjectDatabase) -> anyhow::Result<Self> {
        let connection = project.connection();
        let query = ObjectQueryRepository::new(connection);
        let artifacts = query
            .search_objects(&ObjectSearch::new(Some(ObjectKind::Artifact), "").with_limit(32))
            .map_err(|err| anyhow::anyhow!(err))?;
        let Some(artifact_summary) = artifacts.first().cloned() else {
            return Ok(Self::empty());
        };
        let artifact_ref = artifact_summary.object_ref.clone();
        let artifact = ArtifactRepository::new(connection)
            .get_artifact(&artifact_ref)
            .context("failed to load artifact metadata")?;
        let index_repo = IndexRepository::new(connection);
        let finding_repo = FindingRepository::new(connection);
        let findings = finding_repo
            .list_findings()
            .context("failed to load findings")?;
        let scores = RadarRepository::new(connection)
            .load_function_scores(&artifact_ref)
            .context("failed to load Function Radar scores")?;
        let radar = FunctionRadarViewModel::from_scores(
            Some(artifact_ref.clone()),
            &scores,
            &FunctionRadarFilter {
                include_zero_score: true,
                ..FunctionRadarFilter::default()
            },
        );
        let analysis_status = index_repo
            .latest_analysis_run(&artifact_ref)
            .context("failed to load latest analysis run")?
            .map(|run| run.status);
        let section_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::Section)
            .context("failed to count sections")? as usize;
        let function_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::Function)
            .context("failed to count functions")? as usize;
        let string_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::String)
            .context("failed to count strings")? as usize;
        let import_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::Import)
            .context("failed to count imports")? as usize;
        let artifact_label = artifact
            .as_ref()
            .map(|artifact| artifact.display_name.clone())
            .or_else(|| artifact_summary.display_name.clone())
            .unwrap_or_else(|| artifact_ref.key.to_string());
        let import_status = artifact
            .as_ref()
            .map(|artifact| artifact.import_status.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let mut overview = revdeck_core::OverviewViewModel::new(
            Some(artifact_ref.clone()),
            artifact_label,
            import_status,
        )
        .with_counts(
            section_count,
            function_count,
            string_count,
            import_count,
            findings.len(),
        )
        .with_top_functions(&scores, 5);
        overview.analysis_status = analysis_status;
        overview
            .degraded_indexing_warnings
            .extend(radar.warnings.iter().cloned());
        let triage = TriageBoardViewModel::from_overview_and_scores(&overview, &scores);
        let analysis_jobs = AnalysisJobRepository::new(connection)
            .list_recent_for_artifact(&artifact_ref, 50)
            .context("failed to load artifact analysis jobs")?
            .into_iter()
            .map(|record| analysis_job_row_from_record(&record))
            .collect::<Vec<_>>();
        let analysis_jobs_summary = AnalysisJobsSummary::from_rows(&analysis_jobs);

        let functions = search_kind(&query, ObjectKind::Function, 500)?;
        let basic_blocks = search_kind(&query, ObjectKind::BasicBlock, 1000)?;
        let instructions = search_kind(&query, ObjectKind::Instruction, 1000)?;
        let strings = search_kind(&query, ObjectKind::String, 500)?;
        let imports = search_kind(&query, ObjectKind::Import, 500)?;
        let diff_deltas = search_kind(&query, ObjectKind::DiffDelta, 500)?;
        let trace_sessions = search_kind(&query, ObjectKind::TraceSession, 200)?;
        let trace_events = search_kind(&query, ObjectKind::TraceEvent, 1000)?;
        let trace_items = trace_sessions
            .iter()
            .cloned()
            .chain(trace_events.iter().cloned())
            .collect::<Vec<_>>();
        let firmware_files = search_kind(&query, ObjectKind::FirmwareFile, 1000)?;
        let crash_reports = search_kind(&query, ObjectKind::CrashReport, 200)?;
        let crash_frames = search_kind(&query, ObjectKind::CrashFrame, 1000)?;
        let crash_items = crash_reports
            .iter()
            .cloned()
            .chain(crash_frames.iter().cloned())
            .collect::<Vec<_>>();
        let protocol_samples = search_kind(&query, ObjectKind::ProtocolSample, 200)?;
        let protocol_messages = search_kind(&query, ObjectKind::ProtocolMessage, 500)?;
        let protocol_fields = search_kind(&query, ObjectKind::ProtocolField, 1000)?;
        let protocol_items = protocol_samples
            .iter()
            .cloned()
            .chain(protocol_messages.iter().cloned())
            .chain(protocol_fields.iter().cloned())
            .collect::<Vec<_>>();
        let annotations = search_kind(&query, ObjectKind::Annotation, 500)?;
        let finding_objects = search_kind(&query, ObjectKind::Finding, 500)?;

        let mut objects = BTreeMap::new();
        for object in artifacts
            .into_iter()
            .chain(functions.iter().cloned())
            .chain(basic_blocks.into_iter())
            .chain(instructions.into_iter())
            .chain(strings.iter().cloned())
            .chain(imports.iter().cloned())
            .chain(diff_deltas.iter().cloned())
            .chain(trace_items.iter().cloned())
            .chain(firmware_files.iter().cloned())
            .chain(crash_items.iter().cloned())
            .chain(protocol_items.iter().cloned())
            .chain(annotations.iter().cloned())
            .chain(finding_objects.into_iter())
        {
            objects.insert(object.object_ref.clone(), object);
        }

        let mut relation_targets = objects.keys().cloned().collect::<BTreeSet<_>>();
        for score in &scores {
            relation_targets.insert(score.function_ref.clone());
            for reason in &score.reasons {
                relation_targets.extend(reason.evidence_refs.iter().cloned());
            }
        }
        let mut relations_by_object = BTreeMap::new();
        for object_ref in relation_targets {
            let relations = query
                .relations(&object_ref, RelationDirection::Both, None)
                .map_err(|err| anyhow::anyhow!(err))?;
            if !relations.is_empty() {
                relations_by_object.insert(object_ref, relations);
            }
        }

        Ok(Self {
            overview,
            triage,
            radar,
            scores,
            functions,
            strings,
            imports,
            diff_deltas,
            trace_items,
            firmware_files,
            crash_items,
            protocol_items,
            annotations,
            findings,
            analysis_jobs,
            analysis_jobs_summary,
            objects,
            relations_by_object,
        })
    }

    pub fn demo() -> Self {
        use revdeck_core::{EdgeKind, FunctionScoreInput, RadarEvidence, StableObjectKeyBuilder};

        let artifact = ObjectRef::artifact("abc123", "fixtures/sensitive_imports_elf")
            .expect("demo artifact ref");
        let function = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, 0x401000, Some(128), Some("main"))
                .expect("demo function ref"),
        );
        let import = ObjectRef::new(
            ObjectKind::Import,
            StableObjectKey::import(&artifact.key, Some("libc.so.6"), "system", None)
                .expect("demo import ref"),
        );
        let string = ObjectRef::new(
            ObjectKind::String,
            StableObjectKey::string(&artifact.key, 0x200, Some(0x402000), "admin password")
                .expect("demo string ref"),
        );
        let mut input = FunctionScoreInput::new(artifact.clone(), function.clone(), "main");
        input.virtual_address = Some(0x401000);
        input.size = Some(128);
        input.boundary_source = "symbol".to_string();
        input.boundary_confidence = "symbol".to_string();
        input.entrypoint = Some(0x401000);
        input.call_count = 2;
        input.string_count = 1;
        input.called_imports.push(RadarEvidence::new(
            import.clone(),
            "libc.so.6!system",
            "system",
        ));
        input.referenced_strings.push(RadarEvidence::new(
            string.clone(),
            "admin password",
            "admin password",
        ));
        let scores = revdeck_core::score_functions(vec![input]);
        let radar = FunctionRadarViewModel::from_scores(
            Some(artifact.clone()),
            &scores,
            &FunctionRadarFilter {
                include_zero_score: true,
                ..FunctionRadarFilter::default()
            },
        );
        let overview = revdeck_core::OverviewViewModel::new(
            Some(artifact.clone()),
            "sensitive_imports_elf",
            "indexed",
        )
        .with_counts(3, 1, 1, 1, 0)
        .with_top_functions(&scores, 5);
        let triage = TriageBoardViewModel::from_overview_and_scores(&overview, &scores);
        let mut function_summary = summary(function.clone(), "main", Some(0x401000), Some(128));
        function_summary.metadata_json = serde_json::json!({
            "boundary_source": "symbol",
            "boundary_confidence": "symbol",
            "frame_pointer": "rbp",
            "stack_frame_size": 32,
            "stack_cleanup_size": 32,
            "epilogue_kind": "stack-add-pop-rbp",
            "has_frame_epilogue": true,
            "calling_convention": "windows-x64",
            "argument_registers": [
                {"ordinal": 0, "register": "rcx"}
            ],
            "stack_slots": [
                {"base": "rbp", "offset": -8, "width_bits": 64, "accesses": ["read", "write"]}
            ]
        })
        .to_string();
        let functions = vec![function_summary];
        let strings = vec![summary(
            string.clone(),
            "admin password",
            Some(0x402000),
            Some(14),
        )];
        let imports = vec![summary(import.clone(), "system", None, None)];
        let diff_delta = ObjectRef::lab_object(
            ObjectKind::DiffDelta,
            Some(&artifact.key),
            "diff",
            "object/changed/demo-auth-gate",
        )
        .expect("demo diff delta ref");
        let mut diff_delta_summary = summary(diff_delta.clone(), "changed object main", None, None);
        diff_delta_summary.metadata_json = serde_json::json!({
            "lab_id": "diff",
            "change": "changed",
            "entity_kind": "object",
            "match_key": "function:address:0000000000401000",
            "before": function.to_string(),
            "after": function.to_string(),
            "before_label": "main before",
            "after_label": "main after",
            "command_previews": [
                format!(":open {function}"),
                format!(":finding link <finding> {function} evidence")
            ]
        })
        .to_string();
        let diff_deltas = vec![diff_delta_summary];
        let trace_session = ObjectRef::lab_object(
            ObjectKind::TraceSession,
            Some(&artifact.key),
            "trace",
            "session/demo-auth",
        )
        .expect("demo trace session ref");
        let mut trace_session_summary = summary(
            trace_session.clone(),
            "Trace session demo-auth",
            None,
            Some(2),
        );
        trace_session_summary.metadata_json = serde_json::json!({
            "lab_id": "trace",
            "session_id": "demo-auth",
            "event_count": 2,
            "thread_count": 1,
            "source_path": "fixtures/traces/minimal.jsonl",
            "command_previews": [
                format!(":open {trace_session}"),
                format!(":xrefs {trace_session}")
            ]
        })
        .to_string();
        let trace_event = ObjectRef::lab_object(
            ObjectKind::TraceEvent,
            Some(&artifact.key),
            "trace",
            "session/demo-auth/event/call-main",
        )
        .expect("demo trace event ref");
        let mut trace_event_summary = summary(
            trace_event.clone(),
            "main call auth gate",
            Some(0x401000),
            None,
        );
        trace_event_summary.metadata_json = serde_json::json!({
            "lab_id": "trace",
            "session": trace_session.to_string(),
            "event_id": "call-main",
            "event_index": 0,
            "thread_id": "main",
            "event_kind": "call",
            "timestamp_ns": 100,
            "function": "main",
            "address": 0x401000_u64,
            "message": "auth gate reached",
            "correlated": function.to_string(),
            "command_previews": [
                format!(":open {function}"),
                format!(":finding link <finding> {trace_event} evidence")
            ]
        })
        .to_string();
        let trace_items = vec![trace_session_summary, trace_event_summary];
        let firmware_file = ObjectRef::lab_object(
            ObjectKind::FirmwareFile,
            Some(&artifact.key),
            "firmware",
            "file/etc/passwd",
        )
        .expect("demo firmware file ref");
        let mut firmware_file_summary =
            summary(firmware_file.clone(), "etc/passwd", None, Some(96));
        firmware_file_summary.metadata_json = serde_json::json!({
            "lab_id": "firmware",
            "firmware": artifact.to_string(),
            "path": "etc/passwd",
            "parent_path": "etc",
            "source_path": "fixtures/firmware/router-root/etc/passwd",
            "sha256": "demo-passwd-sha256",
            "size": 96,
            "file_type": "text",
            "executable": false,
            "command_previews": [
                format!(":open {firmware_file}"),
                format!(":finding link <finding> {firmware_file} evidence")
            ]
        })
        .to_string();
        let nested_artifact =
            ObjectRef::artifact("demoelf", "fixtures/firmware/router-root/bin/httpd.elf")
                .expect("demo nested artifact ref");
        let firmware_binary_file = ObjectRef::lab_object(
            ObjectKind::FirmwareFile,
            Some(&artifact.key),
            "firmware",
            "file/bin/httpd.elf",
        )
        .expect("demo firmware binary file ref");
        let mut firmware_binary_file_summary = summary(
            firmware_binary_file.clone(),
            "bin/httpd.elf",
            None,
            Some(16),
        );
        firmware_binary_file_summary.metadata_json = serde_json::json!({
            "lab_id": "firmware",
            "firmware": artifact.to_string(),
            "path": "bin/httpd.elf",
            "parent_path": "bin",
            "source_path": "fixtures/firmware/router-root/bin/httpd.elf",
            "sha256": "demo-elf-sha256",
            "size": 16,
            "file_type": "elf",
            "executable": true,
            "nested_artifact": nested_artifact.to_string(),
            "command_previews": [
                format!(":open {firmware_binary_file}"),
                format!(":finding link <finding> {firmware_binary_file} evidence")
            ]
        })
        .to_string();
        let mut firmware_binary_summary =
            summary(nested_artifact.clone(), "bin/httpd.elf", None, Some(16));
        firmware_binary_summary.metadata_json = serde_json::json!({
            "lab_id": "firmware",
            "parent_artifact": artifact.to_string(),
            "path": "bin/httpd.elf",
            "sha256": "demo-elf-sha256",
            "file_type": "elf"
        })
        .to_string();
        let firmware_files = vec![firmware_file_summary, firmware_binary_file_summary];
        let crash_report = ObjectRef::lab_object(
            ObjectKind::CrashReport,
            Some(&artifact.key),
            "crash",
            "report/asan-uaf-001",
        )
        .expect("demo crash report ref");
        let mut crash_report_summary = summary(
            crash_report.clone(),
            "ASAN heap-use-after-free in main",
            Some(0x401000),
            Some(2),
        );
        crash_report_summary.metadata_json = serde_json::json!({
            "lab_id": "crash",
            "crash_id": "asan-uaf-001",
            "source_path": "fixtures/crashes/asan_uaf.json",
            "sanitizer": "asan",
            "crash_class": "heap-use-after-free",
            "signal": "SIGABRT",
            "message": "heap-use-after-free in request handler",
            "signature": "asan|heap-use-after-free|SIGABRT|main|main>parse_request",
            "frame_count": 2,
            "correlated_frame_count": 1,
            "diagnostics": [],
            "command_previews": [
                format!(":open {crash_report}"),
                format!(":xrefs {crash_report}"),
                format!(":finding link <finding> {crash_report} evidence")
            ]
        })
        .to_string();
        let crash_frame = ObjectRef::lab_object(
            ObjectKind::CrashFrame,
            Some(&artifact.key),
            "crash",
            &format!("report/{}/frame/0", crash_report.key.as_str()),
        )
        .expect("demo crash frame ref");
        let mut crash_frame_summary = summary(
            crash_frame.clone(),
            "#0 main @ 0x401000",
            Some(0x401000),
            None,
        );
        crash_frame_summary.metadata_json = serde_json::json!({
            "lab_id": "crash",
            "report": crash_report.to_string(),
            "frame_index": 0,
            "module": "firmware.elf",
            "function": "main",
            "address": 0x401000_u64,
            "offset": 0x10_u64,
            "source_location": "main.c:42",
            "confidence": "reported",
            "correlated": function.to_string(),
            "command_previews": [
                format!(":open {function}"),
                format!(":finding link <finding> {crash_frame} evidence")
            ]
        })
        .to_string();
        let crash_frame_two = ObjectRef::lab_object(
            ObjectKind::CrashFrame,
            Some(&artifact.key),
            "crash",
            &format!("report/{}/frame/1", crash_report.key.as_str()),
        )
        .expect("demo crash frame two ref");
        let mut crash_frame_two_summary = summary(
            crash_frame_two.clone(),
            "#1 parse_request @ 0x401040",
            Some(0x401040),
            None,
        );
        crash_frame_two_summary.metadata_json = serde_json::json!({
            "lab_id": "crash",
            "report": crash_report.to_string(),
            "frame_index": 1,
            "module": "firmware.elf",
            "function": "parse_request",
            "address": 0x401040_u64,
            "source_location": "http.c:88",
            "confidence": "reported",
            "command_previews": [
                format!(":open {crash_frame_two}"),
                format!(":finding link <finding> {crash_frame_two} evidence")
            ]
        })
        .to_string();
        let crash_items = vec![
            crash_report_summary,
            crash_frame_summary,
            crash_frame_two_summary,
        ];
        let protocol_sample = ObjectRef::lab_object(
            ObjectKind::ProtocolSample,
            Some(&artifact.key),
            "protocol",
            "sample/demo-login",
        )
        .expect("demo protocol sample ref");
        let mut protocol_sample_summary = summary(
            protocol_sample.clone(),
            "Protocol sample demo-login",
            None,
            Some(3),
        );
        protocol_sample_summary.metadata_json = serde_json::json!({
            "lab_id": "protocol",
            "sample_id": "demo-login",
            "source_path": "fixtures/protocol/login_handshake.json",
            "schema_hypothesis": "login request: opcode, length, ascii credential",
            "message_count": 1,
            "field_count": 3,
            "correlated_field_count": 1,
            "diagnostics": [],
            "command_previews": [
                format!(":open {protocol_sample}"),
                format!(":xrefs {protocol_sample}"),
                format!(":finding link <finding> {protocol_sample} evidence")
            ]
        })
        .to_string();
        let protocol_message = ObjectRef::lab_object(
            ObjectKind::ProtocolMessage,
            Some(&artifact.key),
            "protocol",
            "sample/demo-login/message/client-hello",
        )
        .expect("demo protocol message ref");
        let mut protocol_message_summary = summary(
            protocol_message.clone(),
            "client_to_server client-hello fields=3",
            None,
            Some(16),
        );
        protocol_message_summary.metadata_json = serde_json::json!({
            "lab_id": "protocol",
            "sample": protocol_sample.to_string(),
            "message_id": "client-hello",
            "message_index": 0,
            "direction": "client_to_server",
            "payload_len": 16,
            "field_count": 3,
            "schema_hypothesis": "opcode plus credential string",
            "payload_hex": "010e61646d696e2070617373776f7264",
            "command_previews": [
                format!(":open {protocol_message}"),
                format!(":xrefs {protocol_message}"),
                format!(":finding link <finding> {protocol_message} evidence")
            ]
        })
        .to_string();
        let protocol_opcode = ObjectRef::lab_object(
            ObjectKind::ProtocolField,
            Some(&artifact.key),
            "protocol",
            "message/client-hello/field/0",
        )
        .expect("demo protocol opcode field ref");
        let mut protocol_opcode_summary =
            summary(protocol_opcode.clone(), "opcode off=0 len=1", None, Some(1));
        protocol_opcode_summary.metadata_json = serde_json::json!({
            "lab_id": "protocol",
            "sample": protocol_sample.to_string(),
            "message": protocol_message.to_string(),
            "field_index": 0,
            "name": "opcode",
            "byte_offset": 0,
            "byte_length": 1,
            "field_type": "integer",
            "confidence": "annotated",
            "entropy": 0.0,
            "printable_ratio": 0.0,
            "integer_value": 1,
            "string_hint": null,
            "value_hex": "01",
            "command_previews": [
                format!(":open {protocol_opcode}"),
                format!(":finding link <finding> {protocol_opcode} evidence")
            ]
        })
        .to_string();
        let protocol_length = ObjectRef::lab_object(
            ObjectKind::ProtocolField,
            Some(&artifact.key),
            "protocol",
            "message/client-hello/field/1",
        )
        .expect("demo protocol length field ref");
        let mut protocol_length_summary = summary(
            protocol_length.clone(),
            "credential_len off=1 len=1",
            None,
            Some(1),
        );
        protocol_length_summary.metadata_json = serde_json::json!({
            "lab_id": "protocol",
            "sample": protocol_sample.to_string(),
            "message": protocol_message.to_string(),
            "field_index": 1,
            "name": "credential_len",
            "byte_offset": 1,
            "byte_length": 1,
            "field_type": "integer",
            "confidence": "annotated",
            "entropy": 0.0,
            "printable_ratio": 0.0,
            "integer_value": 14,
            "string_hint": null,
            "value_hex": "0e",
            "command_previews": [
                format!(":open {protocol_length}"),
                format!(":finding link <finding> {protocol_length} evidence")
            ]
        })
        .to_string();
        let protocol_credential = ObjectRef::lab_object(
            ObjectKind::ProtocolField,
            Some(&artifact.key),
            "protocol",
            "message/client-hello/field/2",
        )
        .expect("demo protocol credential field ref");
        let mut protocol_credential_summary = summary(
            protocol_credential.clone(),
            "credential off=2 len=14",
            None,
            Some(14),
        );
        protocol_credential_summary.metadata_json = serde_json::json!({
            "lab_id": "protocol",
            "sample": protocol_sample.to_string(),
            "message": protocol_message.to_string(),
            "field_index": 2,
            "name": "credential",
            "byte_offset": 2,
            "byte_length": 14,
            "field_type": "string",
            "confidence": "annotated",
            "entropy": 3.32,
            "printable_ratio": 1.0,
            "integer_value": null,
            "string_hint": "admin password",
            "value_hex": "61646d696e2070617373776f7264",
            "correlated": string.to_string(),
            "command_previews": [
                format!(":open {string}"),
                format!(":finding link <finding> {protocol_credential} evidence")
            ]
        })
        .to_string();
        let protocol_items = vec![
            protocol_sample_summary,
            protocol_message_summary,
            protocol_opcode_summary,
            protocol_length_summary,
            protocol_credential_summary,
        ];
        let mut objects = BTreeMap::new();
        for object in [
            summary(artifact.clone(), "sensitive_imports_elf", None, None),
            functions[0].clone(),
            strings[0].clone(),
            imports[0].clone(),
            diff_deltas[0].clone(),
            trace_items[0].clone(),
            trace_items[1].clone(),
            firmware_files[0].clone(),
            firmware_files[1].clone(),
            firmware_binary_summary,
            crash_items[0].clone(),
            crash_items[1].clone(),
            crash_items[2].clone(),
            protocol_items[0].clone(),
            protocol_items[1].clone(),
            protocol_items[2].clone(),
            protocol_items[3].clone(),
            protocol_items[4].clone(),
        ] {
            objects.insert(object.object_ref.clone(), object);
        }
        let edge_ref = ObjectRef::new(
            ObjectKind::Edge,
            StableObjectKeyBuilder::new(ObjectKind::Edge)
                .component("edge_kind", EdgeKind::CallsImport.as_str())
                .and_then(|builder| builder.component("source", function.key.as_str()))
                .and_then(|builder| builder.component("target", import.key.as_str()))
                .and_then(|builder| builder.finish())
                .expect("demo edge ref"),
        );
        let relation = ObjectRelation {
            edge_ref,
            source: function.clone(),
            target: import,
            kind: EdgeKind::CallsImport,
            confidence: 1.0,
            metadata_json: "{}".to_string(),
        };
        let mut relations_by_object = BTreeMap::new();
        let diff_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::DiffersFrom.as_str())
                    .and_then(|builder| builder.component("source", diff_delta.key.as_str()))
                    .and_then(|builder| builder.component("target", function.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo diff edge ref"),
            ),
            source: diff_delta.clone(),
            target: function.clone(),
            kind: EdgeKind::DiffersFrom,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"diff","side":"after"}"#.to_string(),
        };
        let trace_timeline_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Timeline.as_str())
                    .and_then(|builder| builder.component("source", trace_session.key.as_str()))
                    .and_then(|builder| builder.component("target", trace_event.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo trace timeline edge ref"),
            ),
            source: trace_session.clone(),
            target: trace_event.clone(),
            kind: EdgeKind::Timeline,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"trace","thread_id":"main","event_index":0}"#.to_string(),
        };
        let trace_correlation_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Correlates.as_str())
                    .and_then(|builder| builder.component("source", trace_event.key.as_str()))
                    .and_then(|builder| builder.component("target", function.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo trace correlation edge ref"),
            ),
            source: trace_event.clone(),
            target: function.clone(),
            kind: EdgeKind::Correlates,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"trace","address":4198400,"function":"main"}"#.to_string(),
        };
        let firmware_contains_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", artifact.key.as_str()))
                    .and_then(|builder| builder.component("target", firmware_file.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo firmware contains edge ref"),
            ),
            source: artifact.clone(),
            target: firmware_file.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"firmware","path":"etc/passwd","file_type":"text"}"#
                .to_string(),
        };
        let firmware_binary_contains_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", artifact.key.as_str()))
                    .and_then(|builder| {
                        builder.component("target", firmware_binary_file.key.as_str())
                    })
                    .and_then(|builder| builder.finish())
                    .expect("demo firmware binary contains edge ref"),
            ),
            source: artifact.clone(),
            target: firmware_binary_file.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"firmware","path":"bin/httpd.elf","file_type":"elf"}"#
                .to_string(),
        };
        let firmware_derived_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::DerivedFrom.as_str())
                    .and_then(|builder| builder.component("source", nested_artifact.key.as_str()))
                    .and_then(|builder| {
                        builder.component("target", firmware_binary_file.key.as_str())
                    })
                    .and_then(|builder| builder.finish())
                    .expect("demo firmware derived edge ref"),
            ),
            source: nested_artifact.clone(),
            target: firmware_binary_file.clone(),
            kind: EdgeKind::DerivedFrom,
            confidence: 1.0,
            metadata_json:
                r#"{"lab_id":"firmware","path":"bin/httpd.elf","sha256":"demo-elf-sha256"}"#
                    .to_string(),
        };
        let crash_contains_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", crash_report.key.as_str()))
                    .and_then(|builder| builder.component("target", crash_frame.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo crash contains edge ref"),
            ),
            source: crash_report.clone(),
            target: crash_frame.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"crash","frame_index":0}"#.to_string(),
        };
        let crash_contains_relation_two = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", crash_report.key.as_str()))
                    .and_then(|builder| builder.component("target", crash_frame_two.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo crash contains edge two ref"),
            ),
            source: crash_report.clone(),
            target: crash_frame_two.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"crash","frame_index":1}"#.to_string(),
        };
        let crash_correlation_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Correlates.as_str())
                    .and_then(|builder| builder.component("source", crash_frame.key.as_str()))
                    .and_then(|builder| builder.component("target", function.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo crash correlation edge ref"),
            ),
            source: crash_frame.clone(),
            target: function.clone(),
            kind: EdgeKind::Correlates,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"crash","address":4198400,"function":"main"}"#.to_string(),
        };
        let protocol_sample_message_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", protocol_sample.key.as_str()))
                    .and_then(|builder| builder.component("target", protocol_message.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo protocol sample contains message edge ref"),
            ),
            source: protocol_sample.clone(),
            target: protocol_message.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json:
                r#"{"lab_id":"protocol","message_index":0,"direction":"client_to_server"}"#
                    .to_string(),
        };
        let protocol_message_opcode_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", protocol_message.key.as_str()))
                    .and_then(|builder| builder.component("target", protocol_opcode.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo protocol opcode contains edge ref"),
            ),
            source: protocol_message.clone(),
            target: protocol_opcode.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"protocol","field_index":0,"name":"opcode"}"#.to_string(),
        };
        let protocol_message_length_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", protocol_message.key.as_str()))
                    .and_then(|builder| builder.component("target", protocol_length.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo protocol length contains edge ref"),
            ),
            source: protocol_message.clone(),
            target: protocol_length.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"protocol","field_index":1,"name":"credential_len"}"#
                .to_string(),
        };
        let protocol_message_credential_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::Contains.as_str())
                    .and_then(|builder| builder.component("source", protocol_message.key.as_str()))
                    .and_then(|builder| {
                        builder.component("target", protocol_credential.key.as_str())
                    })
                    .and_then(|builder| builder.finish())
                    .expect("demo protocol credential contains edge ref"),
            ),
            source: protocol_message.clone(),
            target: protocol_credential.clone(),
            kind: EdgeKind::Contains,
            confidence: 1.0,
            metadata_json: r#"{"lab_id":"protocol","field_index":2,"name":"credential"}"#
                .to_string(),
        };
        let protocol_credential_string_relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKeyBuilder::new(ObjectKind::Edge)
                    .component("edge_kind", EdgeKind::References.as_str())
                    .and_then(|builder| {
                        builder.component("source", protocol_credential.key.as_str())
                    })
                    .and_then(|builder| builder.component("target", string.key.as_str()))
                    .and_then(|builder| builder.finish())
                    .expect("demo protocol string reference edge ref"),
            ),
            source: protocol_credential.clone(),
            target: string.clone(),
            kind: EdgeKind::References,
            confidence: 0.85,
            metadata_json:
                r#"{"lab_id":"protocol","string_hint":"admin password","field_name":"credential"}"#
                    .to_string(),
        };
        relations_by_object.insert(function.clone(), vec![relation]);
        relations_by_object.insert(diff_delta, vec![diff_relation]);
        relations_by_object.insert(trace_session, vec![trace_timeline_relation.clone()]);
        relations_by_object.insert(
            trace_event,
            vec![trace_timeline_relation, trace_correlation_relation],
        );
        relations_by_object.insert(firmware_file, vec![firmware_contains_relation]);
        relations_by_object.insert(
            firmware_binary_file,
            vec![firmware_binary_contains_relation, firmware_derived_relation],
        );
        relations_by_object.insert(
            crash_report,
            vec![crash_contains_relation.clone(), crash_contains_relation_two],
        );
        relations_by_object.insert(
            crash_frame,
            vec![crash_contains_relation, crash_correlation_relation],
        );
        relations_by_object.insert(crash_frame_two, Vec::new());
        relations_by_object.insert(
            protocol_sample,
            vec![protocol_sample_message_relation.clone()],
        );
        relations_by_object.insert(
            protocol_message,
            vec![
                protocol_sample_message_relation,
                protocol_message_opcode_relation.clone(),
                protocol_message_length_relation.clone(),
                protocol_message_credential_relation.clone(),
            ],
        );
        relations_by_object.insert(protocol_opcode, vec![protocol_message_opcode_relation]);
        relations_by_object.insert(protocol_length, vec![protocol_message_length_relation]);
        relations_by_object.insert(
            protocol_credential,
            vec![
                protocol_message_credential_relation,
                protocol_credential_string_relation,
            ],
        );
        let analysis_jobs = vec![
            AnalysisJobRow {
                id: 5,
                analysis_run_id: Some(2),
                artifact_key: Some(artifact.key.to_string()),
                pass_name: "binary.triage".to_string(),
                profile: "quick".to_string(),
                status: "succeeded".to_string(),
                progress: "1/1".to_string(),
                objects_produced: 1,
                diagnostics_count: 0,
                byte_limit: Some(4096),
                function_limit: Some(500),
                time_limit_ms: Some(1000),
                started_at: "2026-05-13T00:05:00Z".to_string(),
                finished_at: Some("2026-05-13T00:05:01Z".to_string()),
                updated_at: "2026-05-13T00:05:01Z".to_string(),
                metadata_summary: "functions=1 profile=quick".to_string(),
                metadata_items: AnalysisJobDetail::from_metadata_json(
                    r#"{"functions":1,"parameters":{"profile":"quick","function_limit":500},"log_snippets":["scored 1 functions for triage"]}"#,
                )
                .metadata_items,
                parameter_items: AnalysisJobDetail::from_metadata_json(
                    r#"{"parameters":{"profile":"quick","function_limit":500}}"#,
                )
                .parameter_items,
                diagnostic_snippets: Vec::new(),
                log_snippets: vec!["scored 1 functions for triage".to_string()],
            },
            AnalysisJobRow {
                id: 4,
                analysis_run_id: Some(1),
                artifact_key: Some(artifact.key.to_string()),
                pass_name: "binary.dataflow".to_string(),
                profile: "quick".to_string(),
                status: "skipped".to_string(),
                progress: "0/?".to_string(),
                objects_produced: 0,
                diagnostics_count: 1,
                byte_limit: None,
                function_limit: Some(500),
                time_limit_ms: None,
                started_at: "2026-05-13T00:04:00Z".to_string(),
                finished_at: Some("2026-05-13T00:04:00Z".to_string()),
                updated_at: "2026-05-13T00:04:00Z".to_string(),
                metadata_summary: "instructions=0 profile=quick".to_string(),
                metadata_items: vec![revdeck_core::AnalysisJobDetailItem {
                    key: "instructions".to_string(),
                    value: "0".to_string(),
                }],
                parameter_items: vec![
                    revdeck_core::AnalysisJobDetailItem {
                        key: "profile".to_string(),
                        value: "quick".to_string(),
                    },
                    revdeck_core::AnalysisJobDetailItem {
                        key: "native_cfg".to_string(),
                        value: "false".to_string(),
                    },
                ],
                diagnostic_snippets: vec![
                    "pass_skipped_by_profile: quick profile skipped native CFG".to_string(),
                ],
                log_snippets: vec![
                    "dataflow skipped because quick profile does not collect native CFG facts"
                        .to_string(),
                ],
            },
            AnalysisJobRow {
                id: 3,
                analysis_run_id: Some(1),
                artifact_key: Some(artifact.key.to_string()),
                pass_name: "binary.cfg".to_string(),
                profile: "quick".to_string(),
                status: "skipped".to_string(),
                progress: "0/?".to_string(),
                objects_produced: 0,
                diagnostics_count: 1,
                byte_limit: None,
                function_limit: Some(500),
                time_limit_ms: None,
                started_at: "2026-05-13T00:03:00Z".to_string(),
                finished_at: Some("2026-05-13T00:03:00Z".to_string()),
                updated_at: "2026-05-13T00:03:00Z".to_string(),
                metadata_summary: "basic_blocks=0 profile=quick".to_string(),
                metadata_items: vec![revdeck_core::AnalysisJobDetailItem {
                    key: "basic_blocks".to_string(),
                    value: "0".to_string(),
                }],
                parameter_items: vec![revdeck_core::AnalysisJobDetailItem {
                    key: "profile".to_string(),
                    value: "quick".to_string(),
                }],
                diagnostic_snippets: vec![
                    "pass_skipped_by_profile: quick profile skipped native CFG".to_string(),
                ],
                log_snippets: vec![
                    "cfg skipped because quick profile does not collect native CFG facts"
                        .to_string(),
                ],
            },
            AnalysisJobRow {
                id: 2,
                analysis_run_id: Some(1),
                artifact_key: Some(artifact.key.to_string()),
                pass_name: "binary.linear".to_string(),
                profile: "quick".to_string(),
                status: "skipped".to_string(),
                progress: "0/?".to_string(),
                objects_produced: 0,
                diagnostics_count: 1,
                byte_limit: None,
                function_limit: Some(500),
                time_limit_ms: None,
                started_at: "2026-05-13T00:02:00Z".to_string(),
                finished_at: Some("2026-05-13T00:02:00Z".to_string()),
                updated_at: "2026-05-13T00:02:00Z".to_string(),
                metadata_summary: "instructions=0 profile=quick".to_string(),
                metadata_items: vec![revdeck_core::AnalysisJobDetailItem {
                    key: "instructions".to_string(),
                    value: "0".to_string(),
                }],
                parameter_items: vec![revdeck_core::AnalysisJobDetailItem {
                    key: "profile".to_string(),
                    value: "quick".to_string(),
                }],
                diagnostic_snippets: vec![
                    "pass_skipped_by_profile: quick profile skipped native CFG".to_string(),
                ],
                log_snippets: vec![
                    "linear skipped because quick profile does not collect native CFG facts"
                        .to_string(),
                ],
            },
            AnalysisJobRow {
                id: 1,
                analysis_run_id: Some(1),
                artifact_key: Some(artifact.key.to_string()),
                pass_name: "binary.parse".to_string(),
                profile: "quick".to_string(),
                status: "succeeded".to_string(),
                progress: "1/1".to_string(),
                objects_produced: 1,
                diagnostics_count: 0,
                byte_limit: Some(4096),
                function_limit: Some(500),
                time_limit_ms: Some(1000),
                started_at: "2026-05-13T00:00:00Z".to_string(),
                finished_at: Some("2026-05-13T00:00:01Z".to_string()),
                updated_at: "2026-05-13T00:00:01Z".to_string(),
                metadata_summary: "format=elf profile=quick".to_string(),
                metadata_items: vec![
                    revdeck_core::AnalysisJobDetailItem {
                        key: "format".to_string(),
                        value: "elf".to_string(),
                    },
                    revdeck_core::AnalysisJobDetailItem {
                        key: "architecture".to_string(),
                        value: "x86_64".to_string(),
                    },
                ],
                parameter_items: vec![revdeck_core::AnalysisJobDetailItem {
                    key: "profile".to_string(),
                    value: "quick".to_string(),
                }],
                diagnostic_snippets: Vec::new(),
                log_snippets: vec!["parsed elf x86_64 artifact".to_string()],
            },
        ];
        let analysis_jobs_summary = AnalysisJobsSummary::from_rows(&analysis_jobs);
        Self {
            overview,
            triage,
            radar,
            scores,
            functions,
            strings,
            imports,
            diff_deltas,
            trace_items,
            firmware_files,
            crash_items,
            protocol_items,
            annotations: Vec::new(),
            findings: Vec::new(),
            analysis_jobs,
            analysis_jobs_summary,
            objects,
            relations_by_object,
        }
    }

    pub fn rows_for_lens(&self, lens: NavigationLens) -> Vec<ObjectRef> {
        match lens {
            NavigationLens::Overview | NavigationLens::BinaryMap => {
                self.overview.artifact.iter().cloned().collect()
            }
            NavigationLens::TriageBoard => self
                .triage
                .rows
                .iter()
                .map(|row| row.target.clone())
                .collect(),
            NavigationLens::FunctionRadar => self
                .radar
                .rows
                .iter()
                .map(|row| row.function_ref.clone())
                .collect(),
            NavigationLens::Functions => self
                .functions
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Strings => self
                .strings
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Imports => self
                .imports
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Diff => self
                .diff_deltas
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Trace => self
                .trace_items
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Firmware => self
                .firmware_files
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Crash => self
                .crash_items
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Protocol => self
                .protocol_items
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Notes => self
                .annotations
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Findings => self
                .findings
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Jobs | NavigationLens::Inspector | NavigationLens::LocalGraph => {
                Vec::new()
            }
        }
    }

    pub fn object_label(&self, object_ref: &ObjectRef) -> String {
        self.objects
            .get(object_ref)
            .map(|object| object.label().to_string())
            .or_else(|| {
                self.findings
                    .iter()
                    .find(|finding| finding.object_ref == *object_ref)
                    .map(|finding| finding.title.clone())
            })
            .unwrap_or_else(|| short_ref(object_ref))
    }

    pub fn score_for(&self, object_ref: &ObjectRef) -> Option<&FunctionScore> {
        self.scores
            .iter()
            .find(|score| score.function_ref == *object_ref)
    }

    pub fn inspector_for(&self, selected: Option<&ObjectRef>) -> Option<InspectorViewModel> {
        let selected = selected?;
        if let Some(score) = self.score_for(selected) {
            Some(InspectorViewModel::for_function(score))
        } else {
            Some(InspectorViewModel::for_object(
                selected.clone(),
                self.object_label(selected),
            ))
        }
    }

    pub fn selected_job(&self, cursor: usize) -> Option<&AnalysisJobRow> {
        self.analysis_jobs.get(cursor)
    }

    pub fn relations_for(&self, selected: &ObjectRef) -> &[ObjectRelation] {
        self.relations_by_object
            .get(selected)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn relations_for_selected(&self, selected: Option<&ObjectRef>) -> &[ObjectRelation] {
        selected
            .and_then(|object_ref| self.relations_by_object.get(object_ref))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn local_graph_traversal(
        &self,
        root: &ObjectRef,
        relation_filter: RelationFilter,
        max_depth: usize,
        max_nodes: usize,
    ) -> Option<revdeck_core::LocalTraversal> {
        self.local_traversal(
            &TraversalOptions::new(root.clone())
                .with_direction(RelationDirection::Both)
                .with_relation_filter(relation_filter)
                .with_max_depth(max_depth)
                .with_max_nodes(max_nodes),
        )
        .ok()
    }

    pub fn local_graph_model(
        &self,
        root: &ObjectRef,
        relation_filter: RelationFilter,
        max_depth: usize,
        max_nodes: usize,
    ) -> Option<GraphLabViewModel> {
        let traversal = self.local_graph_traversal(root, relation_filter, max_depth, max_nodes)?;
        Some(GraphLabViewModel::from_traversal(
            &traversal,
            relation_filter,
            max_nodes,
            |object_ref| self.object_label(object_ref),
        ))
    }
}

impl ObjectGraphQuery for WorkspaceSnapshot {
    fn get_object(&self, object_ref: &ObjectRef) -> Result<Option<ObjectSummary>, QueryError> {
        Ok(self.objects.get(object_ref).cloned())
    }

    fn search_objects(&self, search: &ObjectSearch) -> Result<Vec<ObjectSummary>, QueryError> {
        let term = search.term.to_ascii_lowercase();
        let mut matches = self
            .objects
            .values()
            .filter(|object| {
                search
                    .kind
                    .map_or(true, |kind| object.object_ref.kind == kind)
            })
            .filter(|object| {
                term.is_empty()
                    || object
                        .display_name
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains(&term)
                    || object
                        .object_ref
                        .key
                        .as_str()
                        .to_ascii_lowercase()
                        .contains(&term)
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.object_ref
                .kind
                .cmp(&right.object_ref.kind)
                .then_with(|| left.label().cmp(right.label()))
                .then_with(|| left.object_ref.key.cmp(&right.object_ref.key))
        });
        matches.truncate(search.limit);
        Ok(matches)
    }

    fn relations(
        &self,
        object_ref: &ObjectRef,
        direction: RelationDirection,
        edge_kind: Option<revdeck_core::EdgeKind>,
    ) -> Result<Vec<ObjectRelation>, QueryError> {
        let mut seen_edges = BTreeSet::new();
        let mut matches = Vec::new();
        for relations in self.relations_by_object.values() {
            for relation in relations {
                if !seen_edges.insert(relation.edge_ref.clone()) {
                    continue;
                }
                if edge_kind.map_or(false, |kind| relation.kind != kind) {
                    continue;
                }
                let direction_matches = match direction {
                    RelationDirection::Outgoing => relation.source == *object_ref,
                    RelationDirection::Incoming => relation.target == *object_ref,
                    RelationDirection::Both => {
                        relation.source == *object_ref || relation.target == *object_ref
                    }
                };
                if direction_matches {
                    matches.push(relation.clone());
                }
            }
        }
        matches.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.target.cmp(&right.target))
                .then_with(|| left.edge_ref.cmp(&right.edge_ref))
        });
        Ok(matches)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiAction {
    SwitchLens(NavigationLens),
    NextLens,
    PreviousLens,
    FocusNextPane,
    FocusPreviousPane,
    FocusRightPane,
    FocusLeftPane,
    FocusPane(PaneFocus),
    NextRow,
    PreviousRow,
    ActivateSelection,
    NavigateTo(ObjectRef),
    NavigateToReasonEvidence {
        reason_index: usize,
        evidence_index: usize,
    },
    Back,
    Forward,
    ToggleHelp,
    ToggleCommandDeck,
    EnterCommandMode,
    ExitCommandMode,
    PushCommandChar(char),
    BackspaceCommand,
    Quit,
}

#[derive(Debug, Clone)]
pub struct TuiShellState {
    pub selected: Option<ObjectRef>,
    pub active_lens: NavigationLens,
    pub focus: PaneFocus,
    pub nav_index: usize,
    pub main_cursor: usize,
    pub inspector_cursor: usize,
    pub inspector_scroll: u16,
    pub command_mode: bool,
    pub command_input: String,
    pub command_state: CommandState,
    pub status_line: String,
    pub last_error: Option<CommandDiagnostic>,
    pub show_help: bool,
    pub show_command_deck: bool,
    pub should_quit: bool,
}

impl Default for TuiShellState {
    fn default() -> Self {
        Self {
            selected: None,
            active_lens: NavigationLens::Overview,
            focus: PaneFocus::Main,
            nav_index: 0,
            main_cursor: 0,
            inspector_cursor: 0,
            inspector_scroll: 0,
            command_mode: false,
            command_input: String::new(),
            command_state: CommandState::default(),
            status_line: "ready".to_string(),
            last_error: None,
            show_help: false,
            show_command_deck: false,
            should_quit: false,
        }
    }
}

impl TuiShellState {
    pub fn from_snapshot(snapshot: &WorkspaceSnapshot) -> Self {
        let mut state = Self::default();
        state.sync_selection_from_cursor(snapshot);
        state
    }

    pub fn apply_action(
        &mut self,
        action: TuiAction,
        snapshot: &WorkspaceSnapshot,
    ) -> Result<Option<CommandOutcome>, CommandDiagnostic> {
        match action {
            TuiAction::SwitchLens(lens) => {
                self.switch_lens(lens, snapshot);
                Ok(None)
            }
            TuiAction::NextLens => {
                let next = (self.nav_index + 1) % WORKSPACE_LENSES.len();
                self.switch_lens(WORKSPACE_LENSES[next], snapshot);
                Ok(None)
            }
            TuiAction::PreviousLens => {
                let next = if self.nav_index == 0 {
                    WORKSPACE_LENSES.len() - 1
                } else {
                    self.nav_index - 1
                };
                self.switch_lens(WORKSPACE_LENSES[next], snapshot);
                Ok(None)
            }
            TuiAction::FocusNextPane => {
                self.focus_next_pane(1);
                Ok(None)
            }
            TuiAction::FocusPreviousPane => {
                self.focus_next_pane(-1);
                Ok(None)
            }
            TuiAction::FocusRightPane => {
                self.focus_directional(1);
                Ok(None)
            }
            TuiAction::FocusLeftPane => {
                self.focus_directional(-1);
                Ok(None)
            }
            TuiAction::FocusPane(focus) => {
                self.focus_pane(focus);
                Ok(None)
            }
            TuiAction::NextRow => {
                self.move_active_cursor(snapshot, 1);
                Ok(None)
            }
            TuiAction::PreviousRow => {
                self.move_active_cursor(snapshot, -1);
                Ok(None)
            }
            TuiAction::ActivateSelection => {
                match self.focus {
                    PaneFocus::Workspace => self.focus_pane(PaneFocus::Main),
                    PaneFocus::Main => {
                        if self.active_lens == NavigationLens::Jobs {
                            self.focus_pane(PaneFocus::Inspector);
                            return Ok(None);
                        }
                        if self.active_lens == NavigationLens::LocalGraph {
                            if let Some(target) = graph_target_at_cursor(self, snapshot) {
                                self.navigate_to(target, snapshot);
                            }
                            return Ok(None);
                        }
                        if let Some(selected) = self.selected.clone() {
                            self.navigate_to(selected, snapshot);
                        }
                    }
                    PaneFocus::Inspector => {
                        if let Some(target) = inspector_target_at_cursor(self, snapshot) {
                            self.navigate_to(target, snapshot);
                        }
                    }
                }
                Ok(None)
            }
            TuiAction::NavigateTo(object_ref) => {
                self.navigate_to(object_ref, snapshot);
                Ok(None)
            }
            TuiAction::NavigateToReasonEvidence {
                reason_index,
                evidence_index,
            } => {
                let selected = self.selected.as_ref().ok_or_else(|| {
                    CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        "no current object is selected",
                    )
                })?;
                let score = snapshot.score_for(selected).ok_or_else(|| {
                    CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        "selected object has no Function Radar score",
                    )
                })?;
                let target = score
                    .reasons
                    .get(reason_index)
                    .and_then(|reason| reason.evidence_refs.get(evidence_index))
                    .cloned()
                    .ok_or_else(|| {
                        CommandDiagnostic::new(
                            CommandDiagnosticKind::Unresolved,
                            "score reason evidence target is missing",
                        )
                    })?;
                self.navigate_to(target, snapshot);
                Ok(None)
            }
            TuiAction::Back => {
                let outcome =
                    CommandExecutor::execute(&mut self.command_state, ResolvedCommand::Back)?;
                self.sync_from_command_state();
                self.status_line = "history back".to_string();
                Ok(Some(outcome))
            }
            TuiAction::Forward => {
                let outcome =
                    CommandExecutor::execute(&mut self.command_state, ResolvedCommand::Forward)?;
                self.sync_from_command_state();
                self.status_line = "history forward".to_string();
                Ok(Some(outcome))
            }
            TuiAction::ToggleHelp => {
                self.show_command_deck = false;
                self.show_help = !self.show_help;
                self.status_line = if self.show_help {
                    "help overlay opened".to_string()
                } else {
                    "help overlay closed".to_string()
                };
                Ok(None)
            }
            TuiAction::ToggleCommandDeck => {
                self.show_help = false;
                self.show_command_deck = !self.show_command_deck;
                self.status_line = if self.show_command_deck {
                    "command deck opened".to_string()
                } else {
                    "command deck closed".to_string()
                };
                Ok(None)
            }
            TuiAction::EnterCommandMode => {
                self.show_help = false;
                self.show_command_deck = false;
                self.command_mode = true;
                self.command_input.clear();
                Ok(None)
            }
            TuiAction::ExitCommandMode => {
                self.command_mode = false;
                self.command_input.clear();
                Ok(None)
            }
            TuiAction::PushCommandChar(ch) => {
                self.command_input.push(ch);
                Ok(None)
            }
            TuiAction::BackspaceCommand => {
                self.command_input.pop();
                Ok(None)
            }
            TuiAction::Quit => {
                self.should_quit = true;
                Ok(None)
            }
        }
    }

    pub fn submit_command(
        &mut self,
        input: &str,
        query: &dyn ObjectGraphQuery,
    ) -> Result<CommandOutcome, CommandDiagnostic> {
        let ast = CommandParser::parse(input)?;
        let resolved = CommandResolver::new(query).resolve(ast, &self.command_state)?;
        let outcome = CommandExecutor::execute(&mut self.command_state, resolved)?;
        self.sync_after_outcome(&outcome);
        self.command_mode = false;
        self.command_input.clear();
        self.last_error = None;
        Ok(outcome)
    }

    pub fn handle_key_event(
        &mut self,
        key: KeyEvent,
        snapshot: &WorkspaceSnapshot,
        query: &dyn ObjectGraphQuery,
    ) -> Result<(), CommandDiagnostic> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.apply_action(TuiAction::Quit, snapshot)?;
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
            self.apply_action(TuiAction::ToggleCommandDeck, snapshot)?;
            return Ok(());
        }
        if self.command_mode {
            match key.code {
                KeyCode::Esc => {
                    self.apply_action(TuiAction::ExitCommandMode, snapshot)?;
                }
                KeyCode::Enter => {
                    let input = self.command_input.clone();
                    if let Err(err) = self.submit_command(&input, query) {
                        self.status_line = err.message.clone();
                        self.last_error = Some(err.clone());
                        return Err(err);
                    }
                }
                KeyCode::Backspace => {
                    self.apply_action(TuiAction::BackspaceCommand, snapshot)?;
                }
                KeyCode::Char(ch) => {
                    self.apply_action(TuiAction::PushCommandChar(ch), snapshot)?;
                }
                _ => {}
            }
            return Ok(());
        }

        if self.show_help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('q') => {
                    self.apply_action(TuiAction::ToggleHelp, snapshot)?;
                }
                _ => {
                    self.status_line = "help overlay open; press ?/h/Esc to close".to_string();
                }
            }
            return Ok(());
        }
        if self.show_command_deck {
            match key.code {
                KeyCode::Esc | KeyCode::Char('p') | KeyCode::Char('q') => {
                    self.apply_action(TuiAction::ToggleCommandDeck, snapshot)?;
                }
                KeyCode::Char(':') => {
                    self.apply_action(TuiAction::EnterCommandMode, snapshot)?;
                }
                _ => {
                    self.status_line = "command deck open; press p/Esc to close".to_string();
                }
            }
            return Ok(());
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.apply_action(TuiAction::Quit, snapshot)?;
            }
            KeyCode::Char('g') => self.switch_lens(NavigationLens::TriageBoard, snapshot),
            KeyCode::Char('G') => self.switch_lens(NavigationLens::LocalGraph, snapshot),
            KeyCode::Char('J') => self.switch_lens(NavigationLens::Jobs, snapshot),
            KeyCode::Char('D') => self.switch_lens(NavigationLens::Diff, snapshot),
            KeyCode::Char('T') => self.switch_lens(NavigationLens::Trace, snapshot),
            KeyCode::Char('W') => self.switch_lens(NavigationLens::Firmware, snapshot),
            KeyCode::Char('C') => self.switch_lens(NavigationLens::Crash, snapshot),
            KeyCode::Char('P') => self.switch_lens(NavigationLens::Protocol, snapshot),
            KeyCode::Char('?') | KeyCode::Char('h') => {
                self.apply_action(TuiAction::ToggleHelp, snapshot)?;
            }
            KeyCode::Char('p') => {
                self.apply_action(TuiAction::ToggleCommandDeck, snapshot)?;
            }
            KeyCode::Char(':') => {
                self.apply_action(TuiAction::EnterCommandMode, snapshot)?;
            }
            KeyCode::Tab => {
                self.apply_action(TuiAction::FocusNextPane, snapshot)?;
            }
            KeyCode::BackTab => {
                self.apply_action(TuiAction::FocusPreviousPane, snapshot)?;
            }
            KeyCode::Right => {
                self.apply_action(TuiAction::FocusRightPane, snapshot)?;
            }
            KeyCode::Left => {
                self.apply_action(TuiAction::FocusLeftPane, snapshot)?;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.apply_action(TuiAction::NextRow, snapshot)?;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.apply_action(TuiAction::PreviousRow, snapshot)?;
            }
            KeyCode::Enter => {
                self.apply_action(TuiAction::ActivateSelection, snapshot)?;
            }
            KeyCode::Backspace | KeyCode::Char('[') => {
                if let Err(err) = self.apply_action(TuiAction::Back, snapshot) {
                    self.status_line = err.message.clone();
                    self.last_error = Some(err);
                }
            }
            KeyCode::Char(']') => {
                if let Err(err) = self.apply_action(TuiAction::Forward, snapshot) {
                    self.status_line = err.message.clone();
                    self.last_error = Some(err);
                }
            }
            KeyCode::Char('o') => self.switch_lens(NavigationLens::Overview, snapshot),
            KeyCode::Char('b') => self.switch_lens(NavigationLens::BinaryMap, snapshot),
            KeyCode::Char('r') => self.switch_lens(NavigationLens::FunctionRadar, snapshot),
            KeyCode::Char('f') => self.switch_lens(NavigationLens::Functions, snapshot),
            KeyCode::Char('s') => self.switch_lens(NavigationLens::Strings, snapshot),
            KeyCode::Char('i') => self.switch_lens(NavigationLens::Imports, snapshot),
            KeyCode::Char('n') => self.switch_lens(NavigationLens::Notes, snapshot),
            KeyCode::Char('F') => self.switch_lens(NavigationLens::Findings, snapshot),
            _ => {}
        }
        Ok(())
    }

    pub fn persist_session_to_project(
        &self,
        project: &ProjectDatabase,
    ) -> anyhow::Result<PersistSessionSummary> {
        let now = OffsetDateTime::now_utc();
        self.persist_session_to_connection(
            project.connection(),
            project.info().root_dir.as_path(),
            now,
        )
    }

    pub fn persist_session_to_connection(
        &self,
        connection: &rusqlite::Connection,
        project_root: &Path,
        now: OffsetDateTime,
    ) -> anyhow::Result<PersistSessionSummary> {
        let mut summary = PersistSessionSummary::default();
        let memory = MemoryRepository::new(connection);
        for (object_ref, tags) in &self.command_state.tags {
            for tag in tags {
                memory
                    .upsert_tag(object_ref, tag, now, now)
                    .context("failed to persist tag")?;
                summary.annotations += 1;
            }
        }
        for (object_ref, notes) in &self.command_state.notes {
            for note in notes {
                memory
                    .upsert_note(object_ref, note, now, now, Vec::new())
                    .context("failed to persist note")?;
                summary.annotations += 1;
            }
        }
        for (object_ref, renamed_to) in &self.command_state.renames {
            memory
                .upsert_rename(object_ref, renamed_to, now, now)
                .context("failed to persist rename")?;
            summary.annotations += 1;
        }
        for (object_ref, status) in &self.command_state.statuses {
            memory
                .upsert_status(object_ref, status, now, now)
                .context("failed to persist status")?;
            summary.annotations += 1;
        }

        let finding_repo = FindingRepository::new(connection);
        for draft in self.command_state.findings.values() {
            let severity = draft
                .severity
                .parse::<FindingSeverity>()
                .map_err(|err| anyhow::anyhow!(err))?;
            let evidence = self
                .command_state
                .finding_links
                .iter()
                .filter(|link| link.finding == draft.object_ref)
                .enumerate()
                .map(|(index, link)| {
                    FindingEvidence::new(
                        link.evidence.clone(),
                        link.role.clone(),
                        index as u64,
                        "linked from TUI session",
                        None,
                    )
                })
                .collect::<Vec<_>>();
            let finding = Finding {
                object_ref: draft.object_ref.clone(),
                title: draft.title.clone(),
                severity,
                status: FindingStatus::Draft,
                summary: draft.title.clone(),
                body: String::new(),
                tags: Vec::new(),
                evidence,
                created_at: now,
                updated_at: now,
            };
            finding_repo
                .upsert_finding(&finding)
                .context("failed to persist finding")?;
            summary.findings += 1;
        }

        for request in &self.command_state.export_requests {
            let context = finding_repo
                .export_context(now)
                .context("failed to load export context")?;
            pre_export_validation(&context).map_err(|err| {
                anyhow::anyhow!(
                    "{}",
                    serde_json::to_string_pretty(&err.report).unwrap_or_else(|_| err.to_string())
                )
            })?;
            let rendered = match request.format {
                ExportFormat::Markdown => render_markdown(&context),
                ExportFormat::Json => {
                    render_json_bundle(&context).context("failed to render JSON report")?
                }
            };
            let path = project_root.join(&request.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create export directory {}", parent.display())
                })?;
            }
            std::fs::write(&path, rendered)
                .with_context(|| format!("failed to write export {}", path.display()))?;
            summary.exports += 1;
        }

        Ok(summary)
    }

    fn switch_lens(&mut self, lens: NavigationLens, snapshot: &WorkspaceSnapshot) {
        self.active_lens = lens;
        if let Some(index) = WORKSPACE_LENSES
            .iter()
            .position(|candidate| *candidate == lens)
        {
            self.nav_index = index;
        }
        self.main_cursor = 0;
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
        self.command_state.current_lens = lens;
        self.sync_selection_from_cursor(snapshot);
        self.status_line = format!("lens {}", lens_label(lens));
    }

    fn focus_next_pane(&mut self, delta: isize) {
        let index = PANE_FOCUS_ORDER
            .iter()
            .position(|candidate| *candidate == self.focus)
            .unwrap_or(0) as isize;
        let next = (index + delta).rem_euclid(PANE_FOCUS_ORDER.len() as isize) as usize;
        self.focus_pane(PANE_FOCUS_ORDER[next]);
    }

    fn focus_directional(&mut self, delta: isize) {
        if delta > 0 {
            if self.focus == PaneFocus::Inspector {
                self.focus_pane(PaneFocus::Inspector);
            } else {
                self.focus_next_pane(1);
            }
        } else if self.focus == PaneFocus::Workspace {
            self.focus_pane(PaneFocus::Workspace);
        } else {
            self.focus_next_pane(-1);
        }
    }

    fn focus_pane(&mut self, focus: PaneFocus) {
        self.focus = focus;
        if self.focus != PaneFocus::Inspector {
            self.inspector_scroll = 0;
        }
        self.status_line = format!("focus {}", pane_focus_label(focus));
    }

    fn move_active_cursor(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        match self.focus {
            PaneFocus::Workspace => self.move_workspace_lens(snapshot, delta),
            PaneFocus::Main => self.move_row(snapshot, delta),
            PaneFocus::Inspector => self.move_inspector(snapshot, delta),
        }
    }

    fn move_workspace_lens(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        let len = WORKSPACE_LENSES.len() as isize;
        let next = (self.nav_index as isize + delta).rem_euclid(len) as usize;
        self.switch_lens(WORKSPACE_LENSES[next], snapshot);
    }

    fn move_row(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        if self.active_lens == NavigationLens::Jobs {
            if snapshot.analysis_jobs.is_empty() {
                self.main_cursor = 0;
                self.selected = None;
                self.command_state.current_object = None;
                self.inspector_cursor = 0;
                self.inspector_scroll = 0;
                return;
            }
            let len = snapshot.analysis_jobs.len() as isize;
            self.main_cursor = (self.main_cursor as isize + delta).rem_euclid(len) as usize;
            self.selected = None;
            self.command_state.current_object = None;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        if self.active_lens == NavigationLens::LocalGraph {
            let Some(selected) = self.selected.as_ref() else {
                self.main_cursor = 0;
                self.command_state.current_object = None;
                self.inspector_cursor = 0;
                self.inspector_scroll = 0;
                return;
            };
            let len = graph_row_count(snapshot, selected) as isize;
            if len == 0 {
                self.main_cursor = 0;
            } else {
                self.main_cursor = (self.main_cursor as isize + delta).rem_euclid(len) as usize;
            }
            self.command_state.current_object = self.selected.clone();
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let rows = snapshot.rows_for_lens(self.active_lens);
        if rows.is_empty() {
            self.main_cursor = 0;
            self.selected = None;
            self.command_state.current_object = None;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let len = rows.len() as isize;
        let next = (self.main_cursor as isize + delta).rem_euclid(len) as usize;
        self.main_cursor = next;
        self.selected = rows.get(next).cloned();
        self.command_state.current_object = self.selected.clone();
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
    }

    fn move_inspector(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        let indices = inspector_focusable_indices(self, snapshot);
        if indices.is_empty() {
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let next = if let Some(current) = indices
            .iter()
            .position(|index| *index == self.inspector_cursor)
        {
            (current as isize + delta).rem_euclid(indices.len() as isize) as usize
        } else if delta >= 0 {
            0
        } else {
            indices.len() - 1
        };
        self.inspector_cursor = indices[next];
        self.inspector_scroll = self.inspector_cursor.saturating_sub(1) as u16;
    }

    fn sync_selection_from_cursor(&mut self, snapshot: &WorkspaceSnapshot) {
        if self.active_lens == NavigationLens::LocalGraph && self.selected.is_some() {
            if let Some(selected) = self.selected.as_ref() {
                let len = graph_row_count(snapshot, selected);
                if len == 0 {
                    self.main_cursor = 0;
                } else if self.main_cursor >= len {
                    self.main_cursor = len - 1;
                }
            }
            self.command_state.current_object = self.selected.clone();
            self.command_state.current_lens = self.active_lens;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        if self.active_lens == NavigationLens::Jobs {
            if snapshot.analysis_jobs.is_empty() {
                self.main_cursor = 0;
            } else if self.main_cursor >= snapshot.analysis_jobs.len() {
                self.main_cursor = snapshot.analysis_jobs.len() - 1;
            }
            self.selected = None;
            self.command_state.current_object = None;
            self.command_state.current_lens = self.active_lens;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let rows = snapshot.rows_for_lens(self.active_lens);
        if rows.is_empty() {
            self.main_cursor = 0;
            self.selected = None;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
        } else {
            if self.main_cursor >= rows.len() {
                self.main_cursor = rows.len() - 1;
            }
            self.selected = rows.get(self.main_cursor).cloned();
        }
        self.command_state.current_object = self.selected.clone();
        self.command_state.current_lens = self.active_lens;
    }

    fn navigate_to(&mut self, object_ref: ObjectRef, snapshot: &WorkspaceSnapshot) {
        let lens = NavigationLens::for_object_kind(object_ref.kind);
        self.command_state
            .navigation
            .navigate_to(NavigationEntry::new(lens, object_ref.clone()));
        self.command_state.current_lens = lens;
        self.command_state.current_object = Some(object_ref.clone());
        self.active_lens = lens;
        if let Some(index) = WORKSPACE_LENSES
            .iter()
            .position(|candidate| *candidate == lens)
        {
            self.nav_index = index;
        }
        self.selected = Some(object_ref.clone());
        self.main_cursor = cursor_for_selection(snapshot, lens, &object_ref).unwrap_or(0);
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
        self.status_line = format!("opened {}", short_ref(&object_ref));
    }

    fn sync_after_outcome(&mut self, outcome: &CommandOutcome) {
        match outcome {
            CommandOutcome::SearchResults(matches) => {
                self.main_cursor = 0;
                self.status_line = format!("{} search results", matches.len());
            }
            CommandOutcome::Xrefs(relations) => {
                self.status_line = format!("{} relations", relations.len());
            }
            CommandOutcome::Navigated(object_ref) | CommandOutcome::Mutated(object_ref) => {
                self.selected = Some(object_ref.clone());
                self.active_lens = self.command_state.current_lens;
                if let Some(index) = WORKSPACE_LENSES
                    .iter()
                    .position(|candidate| *candidate == self.active_lens)
                {
                    self.nav_index = index;
                }
                self.inspector_cursor = 0;
                self.inspector_scroll = 0;
                self.status_line = format!("updated {}", short_ref(object_ref));
            }
            CommandOutcome::FindingCreated(object_ref) => {
                self.selected = Some(object_ref.clone());
                self.active_lens = NavigationLens::Findings;
                self.nav_index = WORKSPACE_LENSES
                    .iter()
                    .position(|candidate| *candidate == NavigationLens::Findings)
                    .unwrap_or(self.nav_index);
                self.inspector_cursor = 0;
                self.inspector_scroll = 0;
                self.status_line = format!("finding draft {}", short_ref(object_ref));
            }
            CommandOutcome::FindingLinked(link) => {
                self.status_line = format!(
                    "linked {} -> {}",
                    short_ref(&link.finding),
                    short_ref(&link.evidence)
                );
            }
            CommandOutcome::ExportRequested(request) => {
                self.status_line = format!(
                    "export queued {} {}",
                    export_format_label(&request.format),
                    request.path
                );
            }
            CommandOutcome::Help(topic) => {
                self.status_line = topic
                    .as_ref()
                    .map(|topic| format!("help {topic}"))
                    .unwrap_or_else(|| {
                        "help: find xrefs open tag note rename status finding export".to_string()
                    });
            }
        }
    }

    fn sync_from_command_state(&mut self) {
        self.selected = self.command_state.current_object.clone();
        self.active_lens = self.command_state.current_lens;
        if let Some(index) = WORKSPACE_LENSES
            .iter()
            .position(|candidate| *candidate == self.active_lens)
        {
            self.nav_index = index;
        }
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
    }
}

pub fn run_project_tui(project_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let project = ProjectDatabase::open_existing(project_dir.as_ref()).with_context(|| {
        format!(
            "failed to open project at {}",
            project_dir.as_ref().display()
        )
    })?;
    let snapshot = WorkspaceSnapshot::load_from_project(&project)?;
    let mut app = TuiShellState::from_snapshot(&snapshot);
    let query = ObjectQueryRepository::new(project.connection());

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    let result = run_terminal_app(&mut terminal, &mut app, &snapshot, &query);
    let restore_result = restore_terminal(&mut terminal);
    result.and(restore_result)?;
    let summary = app.persist_session_to_project(&project)?;
    if summary.annotations > 0 || summary.findings > 0 || summary.exports > 0 {
        println!(
            "persisted annotations={} findings={} exports={}",
            summary.annotations, summary.findings, summary.exports
        );
    }
    Ok(())
}

pub fn run_terminal_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiShellState,
    snapshot: &WorkspaceSnapshot,
    query: &dyn ObjectGraphQuery,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| render_workspace(frame, app, snapshot))?;
        if app.should_quit {
            return Ok(());
        }
        if event::poll(Duration::from_millis(200)).context("failed to poll terminal events")? {
            if let Event::Key(key) = event::read().context("failed to read terminal event")? {
                if key.kind == KeyEventKind::Press {
                    let _ = app.handle_key_event(key, snapshot, query);
                }
            }
        }
    }
}

pub fn render_workspace(frame: &mut Frame<'_>, app: &TuiShellState, snapshot: &WorkspaceSnapshot) {
    let area = frame.size();
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(5),
        ])
        .split(area);
    render_header(frame, vertical[0], app, snapshot);
    if vertical[1].height < 10 || vertical[1].width < 72 {
        render_stacked_body(frame, vertical[1], app, snapshot);
    } else {
        render_three_pane_body(frame, vertical[1], app, snapshot);
    }
    render_command_bar(frame, vertical[2], app, snapshot);
    if app.show_help {
        render_help_overlay(frame, area, app, snapshot);
    }
    if app.show_command_deck {
        render_command_deck_overlay(frame, area, app, snapshot);
    }
}

fn render_header(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    let analysis_status = snapshot
        .overview
        .analysis_status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let jobs_summary = cockpit_jobs_summary(&snapshot.analysis_jobs_summary);
    let line = Line::from(vec![
        Span::styled(
            " RevDeck ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            snapshot.overview.artifact_label.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  |  analysis={} import={} {}  |  view={} focus={}  funcs={} strings={} imports={} findings={}  |  selected={}",
            analysis_status,
            snapshot.overview.import_status,
            jobs_summary,
            lens_label(app.active_lens),
            pane_focus_label(app.focus),
            snapshot.overview.function_count,
            snapshot.overview.string_count,
            snapshot.overview.import_count,
            snapshot.overview.finding_count,
            truncate(&selected, 34)
        )),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .title("Cockpit")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn cockpit_jobs_summary(summary: &AnalysisJobsSummary) -> String {
    if summary.total == 0 {
        return "jobs=0".to_string();
    }

    let mut parts = vec![format!("jobs={}", summary.total)];
    if summary.running > 0 {
        parts.push(format!("running={}", summary.running));
    }
    if summary.failed > 0 {
        parts.push(format!("failed={}", summary.failed));
    }
    if summary.skipped > 0 {
        parts.push(format!("skipped={}", summary.skipped));
    }
    if let Some(latest) = &summary.latest {
        parts.push(format!("latest={}:{}", latest.pass_name, latest.status));
    }

    parts.join(" ")
}

fn render_help_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let width = area.width.saturating_sub(8).min(92);
    let height = area.height.saturating_sub(2).min(25);
    if width < 44 || height < 12 {
        return;
    }
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let overlay = Rect {
        x,
        y,
        width,
        height,
    };
    let lines = help_overlay_lines(app, snapshot);
    frame.render_widget(Clear, overlay);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Command Deck - ? / h closes")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta)),
            )
            .wrap(Wrap { trim: true }),
        overlay,
    );
}

fn render_command_deck_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let width = area.width.saturating_sub(10).min(88);
    let height = area.height.saturating_sub(4).min(22);
    if width < 48 || height < 12 {
        return;
    }
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let overlay = Rect {
        x,
        y,
        width,
        height,
    };
    frame.render_widget(Clear, overlay);
    frame.render_widget(
        Paragraph::new(command_deck_lines(app, snapshot))
            .block(
                Block::default()
                    .title("Command Deck - p / Esc closes, : edits command")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: true }),
        overlay,
    );
}

fn render_three_pane_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(20),
            Constraint::Min(40),
            Constraint::Length(32),
        ])
        .split(area);
    render_workspace_nav(frame, chunks[0], app);
    render_main_view(frame, chunks[1], app, snapshot);
    render_inspector(frame, chunks[2], app, snapshot);
}

fn render_stacked_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(5),
        ])
        .split(area);
    render_workspace_nav(frame, chunks[0], app);
    render_main_view(frame, chunks[1], app, snapshot);
    render_inspector(frame, chunks[2], app, snapshot);
}

fn render_workspace_nav(frame: &mut Frame<'_>, area: Rect, app: &TuiShellState) {
    let items = WORKSPACE_LENSES
        .iter()
        .enumerate()
        .map(|(index, lens)| {
            let marker = if index == app.nav_index { ">>" } else { "  " };
            let badge = lens_badge(*lens);
            ListItem::new(format!("{marker} {badge:<3} {}", lens_label(*lens))).style(
                if app.focus == PaneFocus::Workspace && index == app.nav_index {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else if index == app.nav_index {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            focused_block(app, PaneFocus::Workspace, "Workspace - lenses".to_string())
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_main_view(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    match app.active_lens {
        NavigationLens::Overview => render_overview(frame, area, app, snapshot),
        NavigationLens::TriageBoard => render_triage_board(frame, area, app, snapshot),
        NavigationLens::Jobs => render_analysis_jobs(frame, area, app, snapshot),
        NavigationLens::BinaryMap => render_binary_map(frame, area, app, snapshot),
        NavigationLens::FunctionRadar => render_function_radar(frame, area, app, snapshot),
        NavigationLens::Functions => {
            render_object_list(frame, area, "Functions", &snapshot.functions, app)
        }
        NavigationLens::Strings => {
            render_object_list(frame, area, "Strings", &snapshot.strings, app)
        }
        NavigationLens::Imports => {
            render_object_list(frame, area, "Imports", &snapshot.imports, app)
        }
        NavigationLens::Diff => render_diff_lab(frame, area, app, snapshot),
        NavigationLens::Trace => render_trace_lab(frame, area, app, snapshot),
        NavigationLens::Firmware => render_firmware_lab(frame, area, app, snapshot),
        NavigationLens::Crash => render_crash_lab(frame, area, app, snapshot),
        NavigationLens::Protocol => render_protocol_lab(frame, area, app, snapshot),
        NavigationLens::Notes => render_notes(frame, area, app, snapshot),
        NavigationLens::Findings => render_findings(frame, area, app, snapshot),
        NavigationLens::LocalGraph => render_local_graph(frame, area, app, snapshot),
        NavigationLens::Inspector => render_inspector(frame, area, app, snapshot),
    }
}

fn render_triage_board(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let rows = snapshot
        .triage
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(row.priority.clone()),
                Cell::from(truncate(&row.title, 30)),
                Cell::from(truncate(&snapshot.object_label(&row.target), 16)),
                Cell::from(truncate(&row.rationale, 32)),
                Cell::from(truncate(&row.command_hints.join(" | "), 22)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(31),
            Constraint::Length(17),
            Constraint::Min(16),
            Constraint::Length(23),
        ],
    )
    .header(
        Row::new(vec!["prio", "next action", "target", "why", "commands"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::TriageBoard)
            .title(format!(
                "Main View - Triage Board | {} leads | findings gap: {} | {}",
                snapshot.triage.high_score_count,
                if snapshot.triage.finding_gap {
                    "yes"
                } else {
                    "no"
                },
                lens_help(NavigationLens::TriageBoard)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let overview = &snapshot.overview;
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(overview.artifact_label.clone()),
        ]),
        Line::from(format!("Status: {}", overview.import_status)),
        Line::from(format!(
            "Sections: {}  Functions: {}  Strings: {}  Imports: {}  Findings: {}",
            overview.section_count,
            overview.function_count,
            overview.string_count,
            overview.import_count,
            overview.finding_count
        )),
        Line::from(""),
        Line::from("Top Function Radar"),
    ];
    for row in &overview.top_functions {
        lines.push(Line::from(format!(
            "{:>3}  {:<24} {}",
            row.score,
            truncate(&row.name, 24),
            row.reason_labels.join(", ")
        )));
    }
    if !overview.degraded_indexing_warnings.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Warnings"));
        for warning in &overview.degraded_indexing_warnings {
            lines.push(Line::from(format!("- {warning}")));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::Overview).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_binary_map(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let lines = vec![
        Line::from(format!("Artifact: {}", snapshot.overview.artifact_label)),
        Line::from(format!(
            "Import status: {}",
            snapshot.overview.import_status
        )),
        Line::from(format!("Sections: {}", snapshot.overview.section_count)),
        Line::from(format!("Functions: {}", snapshot.overview.function_count)),
        Line::from(format!("Strings: {}", snapshot.overview.string_count)),
        Line::from(format!("Imports: {}", snapshot.overview.import_count)),
        Line::from(""),
        Line::from("Binary Map is backed by the shared object graph."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::BinaryMap).borders(Borders::ALL)),
        area,
    );
}

fn render_function_radar(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let rows = snapshot
        .radar
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(row.score.to_string()),
                Cell::from(truncate(&row.name, 22)),
                Cell::from(row.address.clone()),
                Cell::from(
                    row.size
                        .map(|size| size.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(row.call_count.to_string()),
                Cell::from(row.string_count.to_string()),
                Cell::from(truncate(&row.boundary_confidence, 12)),
                Cell::from(truncate(&row.reason_labels.join(", "), 30)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(24),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(12),
            Constraint::Min(16),
        ],
    )
    .header(
        Row::new(vec![
            "score", "function", "address", "size", "calls", "strings", "boundary", "reasons",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::FunctionRadar)
            .title(format!(
                "Main View - Function Radar ({}/{}) | {}",
                snapshot.radar.visible_functions,
                snapshot.radar.total_functions,
                lens_help(NavigationLens::FunctionRadar)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_analysis_jobs(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    if snapshot.analysis_jobs.is_empty() {
        let lines = vec![
            Line::from("No analysis jobs recorded"),
            Line::from("This read-only lens shows recent pass status for the active artifact."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(main_view_block(app, NavigationLens::Jobs).borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows = snapshot
        .analysis_jobs
        .iter()
        .enumerate()
        .map(|(index, job)| {
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(truncate(&job.pass_name, 16)),
                Cell::from(truncate(&job.status, 10)),
                Cell::from(truncate(&job.profile, 9)),
                Cell::from(job.progress.clone()),
                Cell::from(job.objects_produced.to_string()),
                Cell::from(job.diagnostics_count.to_string()),
                Cell::from(truncate(&job.started_at, 20)),
                Cell::from(
                    job.finished_at
                        .as_deref()
                        .map(|finished_at| truncate(finished_at, 20))
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(truncate(&job.metadata_summary, 24)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let summary = &snapshot.analysis_jobs_summary;
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Min(12),
        ],
    )
    .header(
        Row::new(vec![
            "pass", "status", "profile", "progress", "objects", "diag", "started", "finished",
            "metadata",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::Jobs)
            .title(format!(
                "Main View - Analysis Jobs | jobs={} running={} failed={} skipped={} | {}",
                summary.total,
                summary.running,
                summary.failed,
                summary.skipped,
                lens_help(NavigationLens::Jobs)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_object_list(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    objects: &[ObjectSummary],
    app: &TuiShellState,
) {
    let items = objects
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let address = object
                .address
                .map(|address| format!("0x{address:016x}"))
                .unwrap_or_else(|| "-".to_string());
            let text = format!(
                "{:>3}  {:<18} {:<20} {}",
                index,
                object.object_ref.kind,
                address,
                object.label()
            );
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(text).style(style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            main_view_block(app, app.active_lens)
                .title(format!(
                    "Main View - {title} | {}",
                    lens_help(app.active_lens)
                ))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_diff_lab(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    if snapshot.diff_deltas.is_empty() {
        let lines = vec![
            Line::from("Diff Lab"),
            Line::from("No persisted diff deltas yet."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(main_view_block(app, NavigationLens::Diff).borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows = snapshot
        .diff_deltas
        .iter()
        .enumerate()
        .map(|(index, delta)| {
            let metadata = parsed_metadata(&delta.metadata_json);
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(diff_metadata_str(metadata.as_ref(), "change")),
                Cell::from(diff_metadata_str(metadata.as_ref(), "entity_kind")),
                Cell::from(truncate(
                    &diff_metadata_str(metadata.as_ref(), "before_label"),
                    20,
                )),
                Cell::from(truncate(
                    &diff_metadata_str(metadata.as_ref(), "after_label"),
                    20,
                )),
                Cell::from(truncate(delta.label(), 34)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(22),
            Constraint::Length(22),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(vec!["change", "entity", "before", "after", "delta"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::Diff)
            .title(format!(
                "Main View - Diff Lab | deltas={} | {}",
                snapshot.diff_deltas.len(),
                lens_help(NavigationLens::Diff)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_trace_lab(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    if snapshot.trace_items.is_empty() {
        let lines = vec![
            Line::from("Trace Lab"),
            Line::from("No imported trace sessions yet."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(main_view_block(app, NavigationLens::Trace).borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows = snapshot
        .trace_items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let metadata = parsed_metadata(&item.metadata_json);
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            let (thread, event, time, target, summary) = match item.object_ref.kind {
                ObjectKind::TraceSession => (
                    diff_metadata_str(metadata.as_ref(), "session_id"),
                    format!(
                        "{} events",
                        diff_metadata_str(metadata.as_ref(), "event_count")
                    ),
                    format!(
                        "{} threads",
                        diff_metadata_str(metadata.as_ref(), "thread_count")
                    ),
                    diff_metadata_str(metadata.as_ref(), "source_path"),
                    item.label().to_string(),
                ),
                ObjectKind::TraceEvent => (
                    diff_metadata_str(metadata.as_ref(), "thread_id"),
                    diff_metadata_str(metadata.as_ref(), "event_kind"),
                    diff_metadata_str(metadata.as_ref(), "timestamp_ns"),
                    trace_target_label(snapshot, metadata.as_ref()),
                    item.label().to_string(),
                ),
                _ => (
                    "-".to_string(),
                    item.object_ref.kind.to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    item.label().to_string(),
                ),
            };
            Row::new(vec![
                Cell::from(item.object_ref.kind.to_string()),
                Cell::from(truncate(&thread, 14)),
                Cell::from(truncate(&event, 14)),
                Cell::from(truncate(&time, 14)),
                Cell::from(truncate(&target, 24)),
                Cell::from(truncate(&summary, 38)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Length(15),
            Constraint::Length(15),
            Constraint::Length(15),
            Constraint::Length(25),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(vec!["kind", "thread", "event", "time", "target", "summary"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::Trace)
            .title(format!(
                "Main View - Trace Lab | items={} | {}",
                snapshot.trace_items.len(),
                lens_help(NavigationLens::Trace)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_firmware_lab(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    if snapshot.firmware_files.is_empty() {
        let lines = vec![
            Line::from("Firmware Lab"),
            Line::from("No firmware file inventory imported yet."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(main_view_block(app, NavigationLens::Firmware).borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows = snapshot
        .firmware_files
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let metadata = parsed_metadata(&item.metadata_json);
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            let path = diff_metadata_str(metadata.as_ref(), "path");
            let file_type = diff_metadata_str(metadata.as_ref(), "file_type");
            let size = diff_metadata_str(metadata.as_ref(), "size");
            let executable = diff_metadata_str(metadata.as_ref(), "executable");
            let nested = metadata
                .as_ref()
                .and_then(|metadata| diff_metadata_ref(metadata, "nested_artifact"))
                .map(|target| truncate(&snapshot.object_label(&target), 20))
                .unwrap_or_else(|| "-".to_string());
            let sha256 = diff_metadata_str(metadata.as_ref(), "sha256");
            Row::new(vec![
                Cell::from(truncate(&path, 32)),
                Cell::from(truncate(&file_type, 10)),
                Cell::from(truncate(&size, 10)),
                Cell::from(truncate(&executable, 6)),
                Cell::from(nested),
                Cell::from(truncate(&sha256, 18)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(33),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(7),
            Constraint::Length(21),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(vec!["path", "type", "size", "exec", "nested", "sha256"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::Firmware)
            .title(format!(
                "Main View - Firmware Lab | files={} | {}",
                snapshot.firmware_files.len(),
                lens_help(NavigationLens::Firmware)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_crash_lab(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    if snapshot.crash_items.is_empty() {
        let lines = vec![
            Line::from("Crash Lab"),
            Line::from("No crash reports imported yet."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(main_view_block(app, NavigationLens::Crash).borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows = snapshot
        .crash_items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let metadata = parsed_metadata(&item.metadata_json);
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            let (class, signal, frames, top, signature) = match item.object_ref.kind {
                ObjectKind::CrashReport => (
                    diff_metadata_str(metadata.as_ref(), "crash_class"),
                    diff_metadata_str(metadata.as_ref(), "signal"),
                    format!(
                        "{} frames / {} linked",
                        diff_metadata_str(metadata.as_ref(), "frame_count"),
                        diff_metadata_str(metadata.as_ref(), "correlated_frame_count")
                    ),
                    item.label().to_string(),
                    diff_metadata_str(metadata.as_ref(), "signature"),
                ),
                ObjectKind::CrashFrame => (
                    "stack frame".to_string(),
                    format!("#{}", diff_metadata_str(metadata.as_ref(), "frame_index")),
                    diff_metadata_str(metadata.as_ref(), "module"),
                    trace_target_label(snapshot, metadata.as_ref()),
                    item.label().to_string(),
                ),
                _ => (
                    item.object_ref.kind.to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    item.label().to_string(),
                ),
            };
            Row::new(vec![
                Cell::from(item.object_ref.kind.to_string()),
                Cell::from(truncate(&class, 24)),
                Cell::from(truncate(&signal, 10)),
                Cell::from(truncate(&frames, 18)),
                Cell::from(truncate(&top, 24)),
                Cell::from(truncate(&signature, 34)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Length(25),
            Constraint::Length(11),
            Constraint::Length(19),
            Constraint::Length(25),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(vec![
            "kind",
            "class",
            "signal",
            "frames",
            "top",
            "signature",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::Crash)
            .title(format!(
                "Main View - Crash Lab | items={} | {}",
                snapshot.crash_items.len(),
                lens_help(NavigationLens::Crash)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_protocol_lab(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    if snapshot.protocol_items.is_empty() {
        let lines = vec![
            Line::from("Protocol Lab"),
            Line::from("No protocol samples imported yet."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(main_view_block(app, NavigationLens::Protocol).borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows = snapshot
        .protocol_items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let metadata = parsed_metadata(&item.metadata_json);
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            let (name, range, signal, schema, evidence) = match item.object_ref.kind {
                ObjectKind::ProtocolSample => (
                    diff_metadata_str(metadata.as_ref(), "sample_id"),
                    format!(
                        "{} messages / {} fields",
                        diff_metadata_str(metadata.as_ref(), "message_count"),
                        diff_metadata_str(metadata.as_ref(), "field_count")
                    ),
                    format!(
                        "{} linked",
                        diff_metadata_str(metadata.as_ref(), "correlated_field_count")
                    ),
                    diff_metadata_str(metadata.as_ref(), "schema_hypothesis"),
                    diff_metadata_str(metadata.as_ref(), "source_path"),
                ),
                ObjectKind::ProtocolMessage => (
                    diff_metadata_str(metadata.as_ref(), "message_id"),
                    format!(
                        "{} bytes / {} fields",
                        diff_metadata_str(metadata.as_ref(), "payload_len"),
                        diff_metadata_str(metadata.as_ref(), "field_count")
                    ),
                    diff_metadata_str(metadata.as_ref(), "direction"),
                    diff_metadata_str(metadata.as_ref(), "schema_hypothesis"),
                    diff_metadata_str(metadata.as_ref(), "payload_hex"),
                ),
                ObjectKind::ProtocolField => (
                    diff_metadata_str(metadata.as_ref(), "name"),
                    format!(
                        "off {} len {}",
                        diff_metadata_str(metadata.as_ref(), "byte_offset"),
                        diff_metadata_str(metadata.as_ref(), "byte_length")
                    ),
                    format!(
                        "{} e={}",
                        diff_metadata_str(metadata.as_ref(), "field_type"),
                        diff_metadata_str(metadata.as_ref(), "entropy")
                    ),
                    diff_metadata_str(metadata.as_ref(), "string_hint"),
                    trace_target_label(snapshot, metadata.as_ref()),
                ),
                _ => (
                    item.label().to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                ),
            };
            Row::new(vec![
                Cell::from(item.object_ref.kind.to_string()),
                Cell::from(truncate(&name, 22)),
                Cell::from(truncate(&range, 22)),
                Cell::from(truncate(&signal, 18)),
                Cell::from(truncate(&schema, 32)),
                Cell::from(truncate(&evidence, 28)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(23),
            Constraint::Length(23),
            Constraint::Length(19),
            Constraint::Length(33),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(vec![
            "kind",
            "id/name",
            "range",
            "signal",
            "schema/hint",
            "evidence",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::Protocol)
            .title(format!(
                "Main View - Protocol Lab | items={} | {}",
                snapshot.protocol_items.len(),
                lens_help(NavigationLens::Protocol)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn parsed_metadata(metadata_json: &str) -> Option<serde_json::Value> {
    serde_json::from_str(metadata_json).ok()
}

fn diff_metadata_str(metadata: Option<&serde_json::Value>, key: &str) -> String {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(diff_metadata_value_str)
        .unwrap_or_else(|| "-".to_string())
}

fn diff_metadata_value_str(value: &serde_json::Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    if value.is_number() || value.is_boolean() {
        return Some(value.to_string());
    }
    None
}

fn diff_metadata_ref(metadata: &serde_json::Value, key: &str) -> Option<ObjectRef> {
    let value = metadata.get(key)?;
    if let Some(text) = value.as_str() {
        return text.parse().ok();
    }
    object_ref_from_json_value(value)
}

fn trace_target_label(
    snapshot: &WorkspaceSnapshot,
    metadata: Option<&serde_json::Value>,
) -> String {
    let Some(metadata) = metadata else {
        return "-".to_string();
    };
    if let Some(target) = diff_metadata_ref(metadata, "correlated") {
        return snapshot.object_label(&target);
    }
    let function = diff_metadata_str(Some(metadata), "function");
    if function != "-" {
        return function;
    }
    let address = diff_metadata_str(Some(metadata), "address");
    if address != "-" {
        return format!("0x{:x}", address.parse::<u64>().unwrap_or_default());
    }
    "-".to_string()
}

fn trace_metadata_ref(metadata: &serde_json::Value, key: &str) -> Option<ObjectRef> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok())
}

fn render_notes(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let mut lines = snapshot
        .annotations
        .iter()
        .map(|annotation| {
            Line::from(format!(
                "{}  {}",
                annotation.object_ref.kind,
                annotation.label()
            ))
        })
        .collect::<Vec<_>>();
    if !app.command_state.notes.is_empty()
        || !app.command_state.tags.is_empty()
        || !app.command_state.statuses.is_empty()
        || !app.command_state.renames.is_empty()
    {
        lines.push(Line::from(""));
        lines.push(Line::from("Session Memory"));
    }
    for (object_ref, tags) in &app.command_state.tags {
        lines.push(Line::from(format!(
            "tag {} = {}",
            short_ref(object_ref),
            tags.join(", ")
        )));
    }
    for (object_ref, notes) in &app.command_state.notes {
        for note in notes {
            lines.push(Line::from(format!(
                "note {} = {}",
                short_ref(object_ref),
                note
            )));
        }
    }
    for (object_ref, renamed) in &app.command_state.renames {
        lines.push(Line::from(format!(
            "rename {} = {}",
            short_ref(object_ref),
            renamed
        )));
    }
    for (object_ref, status) in &app.command_state.statuses {
        lines.push(Line::from(format!(
            "status {} = {}",
            short_ref(object_ref),
            status
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from("No notes yet."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::Notes).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_findings(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let mut lines = snapshot
        .findings
        .iter()
        .map(|finding| {
            Line::from(format!(
                "{} [{}] {}",
                finding.severity, finding.status, finding.title
            ))
        })
        .collect::<Vec<_>>();
    for draft in app.command_state.findings.values() {
        lines.push(Line::from(format!(
            "{} [draft] {}",
            draft.severity, draft.title
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from("No findings yet."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::Findings).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_local_graph(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let mut lines = Vec::new();
    lines.push(Line::from("Graph Lab"));
    if !app.command_state.last_xrefs.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Command Xrefs"));
        for relation in &app.command_state.last_xrefs {
            lines.push(Line::from(relation_line(relation, snapshot)));
        }
    }
    if let Some(selected) = &app.selected {
        if let Some(model) = snapshot.local_graph_model(
            selected,
            GRAPH_LAB_ACTIVE_FILTER,
            GRAPH_LAB_MAX_DEPTH,
            GRAPH_LAB_MAX_NODES,
        ) {
            let traversal = snapshot.local_graph_traversal(
                selected,
                GRAPH_LAB_ACTIVE_FILTER,
                GRAPH_LAB_MAX_DEPTH,
                GRAPH_LAB_MAX_NODES,
            );
            lines.push(Line::from(format!("Root: {}", model.root_label)));
            let filters = model
                .relation_filters
                .iter()
                .map(|filter| {
                    if filter.active {
                        format!("[{} {}]", filter.id, filter.relation_count)
                    } else {
                        format!("{} {}", filter.id, filter.relation_count)
                    }
                })
                .collect::<Vec<_>>()
                .join("  ");
            lines.push(Line::from(format!("relation filter: {filters}")));
            if let Some(notice) = &model.limit_notice {
                lines.push(Line::from(notice.clone()));
            }

            lines.push(Line::from(""));
            lines.push(Line::from("Path Rows"));
            for (index, row) in model.path_rows.iter().enumerate() {
                let marker = if app.focus == PaneFocus::Main && app.main_cursor == index {
                    ">"
                } else {
                    " "
                };
                lines.push(Line::from(format!("{marker} P{index:<2} {}", row.summary)));
                lines.push(Line::from(format!("    :open {}", short_ref(&row.target))));
            }

            lines.push(Line::from(""));
            lines.push(Line::from("Selected Edge"));
            let edge_offset = model.path_rows.len();
            if let Some(traversal) = traversal {
                for (index, relation) in traversal.relations.iter().enumerate() {
                    let row_index = edge_offset + index;
                    let marker = if app.focus == PaneFocus::Main && app.main_cursor == row_index {
                        ">"
                    } else {
                        " "
                    };
                    lines.push(Line::from(format!(
                        "{marker} E{index:<2} {}",
                        relation_line(relation, snapshot)
                    )));
                }
            }
            if model.edge_details.is_empty() {
                lines.push(Line::from("  no edges from this root"));
            }
        }
    } else {
        lines.push(Line::from("No object selected."));
    }
    if lines.len() == 1 {
        lines.push(Line::from("No local relations loaded."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::LocalGraph).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_inspector(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let lines = inspector_lines(app, snapshot)
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            let is_selected = app.focus == PaneFocus::Inspector
                && item.target.is_some()
                && index == app.inspector_cursor;
            if is_selected {
                item.line
                    .style(Style::default().fg(Color::Black).bg(Color::Cyan))
            } else {
                item.line
            }
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.inspector_scroll, 0))
            .block(
                focused_block(
                    app,
                    PaneFocus::Inspector,
                    "Inspector - Up/Down evidence, Enter jump".to_string(),
                )
                .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_command_bar(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let prompt = if app.command_mode {
        format!("Command: :{}", app.command_input)
    } else {
        "Command: p deck  :find string password  :xrefs current  :tag suspicious  :export json report.json"
            .to_string()
    };
    let status = if let Some(error) = &app.last_error {
        format!("Status: {:?}: {}", error.kind, error.message)
    } else {
        format!("Status: {}", app.status_line)
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(prompt),
            Line::from(format!(
                "Trail: {} > {} > {}",
                lens_badge(app.active_lens),
                pane_focus_label(app.focus),
                app.selected
                    .as_ref()
                    .map(|object_ref| truncate(&snapshot.object_label(object_ref), 34))
                    .unwrap_or_else(|| "none".to_string())
            )),
            Line::from(status),
            Line::from(context_help(app, snapshot)),
        ])
        .block(
            Block::default()
                .title("Command / Status")
                .borders(Borders::ALL),
        ),
        area,
    );
}

#[derive(Debug, Clone)]
struct InspectorLine {
    line: Line<'static>,
    target: Option<ObjectRef>,
}

impl InspectorLine {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            line: Line::from(text.into()),
            target: None,
        }
    }

    fn jump(text: impl Into<String>, target: ObjectRef) -> Self {
        Self {
            line: Line::from(text.into()),
            target: Some(target),
        }
    }
}

fn inspector_lines(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<InspectorLine> {
    let mut lines = Vec::new();
    if app.active_lens == NavigationLens::Jobs {
        append_job_inspector_lines(&mut lines, snapshot.selected_job(app.main_cursor));
        return lines;
    }
    if app.active_lens == NavigationLens::LocalGraph {
        if let Some(edge) = selected_graph_edge_detail(app, snapshot) {
            append_graph_edge_inspector_lines(&mut lines, &edge);
        }
    }
    if let Some(inspector) = snapshot.inspector_for(app.selected.as_ref()) {
        lines.push(InspectorLine::plain(format!(
            "Selected: {}",
            inspector.title
        )));
        lines.push(InspectorLine::plain(format!(
            "Ref: {}",
            short_ref(&inspector.selected)
        )));
        if let Some(address) = inspector.address {
            lines.push(InspectorLine::plain(format!("Address: {address}")));
        }
        if let Some(size) = inspector.size {
            lines.push(InspectorLine::plain(format!("Size: {size}")));
        }
        if let Some(score) = inspector.radar_score {
            lines.push(InspectorLine::plain(format!("Radar score: {score}")));
        }
        if let Some(confidence) = inspector.boundary_confidence {
            lines.push(InspectorLine::plain(format!("Boundary: {confidence}")));
        }
        if let Some(source) = inspector.boundary_source {
            lines.push(InspectorLine::plain(format!("Boundary source: {source}")));
        }
        if let Some(selected) = app.selected.as_ref() {
            append_native_function_lines(&mut lines, snapshot, selected);
            append_native_instruction_lines(&mut lines, snapshot, selected);
            append_diff_delta_lines(&mut lines, snapshot, selected);
            append_trace_lines(&mut lines, snapshot, selected);
            append_firmware_file_lines(&mut lines, snapshot, selected);
            append_crash_lines(&mut lines, snapshot, selected);
            append_protocol_lines(&mut lines, snapshot, selected);
        }
        if !inspector.score_reasons.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Score Reasons"));
            for reason in inspector.score_reasons.iter().take(5) {
                lines.push(InspectorLine::plain(format!(
                    "+{} {}",
                    reason.contribution, reason.label
                )));
                for (evidence_ref, evidence_label) in reason
                    .evidence_refs
                    .iter()
                    .zip(reason.evidence_labels.iter())
                    .take(2)
                {
                    lines.push(InspectorLine::jump(
                        format!("  > evidence {evidence_label}"),
                        evidence_ref.clone(),
                    ));
                }
            }
        }
        append_session_memory_lines(&mut lines, app, &inspector.selected);
        let relations = snapshot.relations_for(&inspector.selected);
        if !relations.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Backlinks / Relations"));
            for relation in relations.iter().take(4) {
                lines.push(InspectorLine::jump(
                    format!("> {}", relation_line(relation, snapshot)),
                    relation_jump_target(relation, &inspector.selected),
                ));
            }
        }
        if !inspector.warnings.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Warnings"));
            for warning in inspector.warnings {
                lines.push(InspectorLine::plain(format!("- {warning}")));
            }
        }
    } else {
        lines.push(InspectorLine::plain("No object selected."));
    }

    lines
}

fn append_graph_edge_inspector_lines(lines: &mut Vec<InspectorLine>, edge: &GraphEdgeDetail) {
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Selected Edge"));
    lines.push(InspectorLine::plain(edge.title.clone()));
    lines.push(InspectorLine::jump(
        format!("Source: {}", edge.source_label),
        edge.source.clone(),
    ));
    lines.push(InspectorLine::jump(
        format!("Target: {}", edge.target_label),
        edge.target.clone(),
    ));
    lines.push(InspectorLine::plain(format!("Kind: {}", edge.kind.label())));
    lines.push(InspectorLine::plain(format!(
        "Confidence: {:.2}",
        edge.confidence
    )));
    if !edge.metadata_items.is_empty() {
        lines.push(InspectorLine::plain("Metadata"));
        for item in edge.metadata_items.iter().take(6) {
            lines.push(InspectorLine::plain(format!("{}={}", item.key, item.value)));
        }
    }
    if !edge.command_previews.is_empty() {
        lines.push(InspectorLine::plain("Finding link preview"));
        for preview in edge.command_previews.iter().take(3) {
            lines.push(InspectorLine::plain(preview.clone()));
        }
    }
}

fn append_job_inspector_lines(
    lines: &mut Vec<InspectorLine>,
    selected_job: Option<&AnalysisJobRow>,
) {
    let Some(job) = selected_job else {
        lines.push(InspectorLine::plain("No job selected."));
        return;
    };

    lines.push(InspectorLine::plain(format!(
        "Job Inspector: {} [{}]",
        job.pass_name, job.status
    )));
    lines.push(InspectorLine::plain(format!("Job ID: {}", job.id)));
    if let Some(run_id) = job.analysis_run_id {
        lines.push(InspectorLine::plain(format!("Run ID: {run_id}")));
    }
    if let Some(artifact_key) = &job.artifact_key {
        lines.push(InspectorLine::plain(format!(
            "Artifact: {}",
            truncate(artifact_key, 72)
        )));
    }
    lines.push(InspectorLine::plain(format!("Profile: {}", job.profile)));
    lines.push(InspectorLine::plain(format!("Progress: {}", job.progress)));
    lines.push(InspectorLine::plain(format!(
        "Objects: {}  Diagnostics: {}",
        job.objects_produced, job.diagnostics_count
    )));
    lines.push(InspectorLine::plain(format!("Started: {}", job.started_at)));
    if let Some(finished_at) = &job.finished_at {
        lines.push(InspectorLine::plain(format!("Finished: {finished_at}")));
    } else {
        lines.push(InspectorLine::plain("Finished: running"));
    }
    lines.push(InspectorLine::plain(format!("Updated: {}", job.updated_at)));
    append_job_limits(lines, job);
    append_job_detail_items(lines, "Metadata", &job.metadata_items);
    append_job_detail_items(lines, "Parameters", &job.parameter_items);
    append_job_snippets(lines, "Diagnostics", &job.diagnostic_snippets);
    append_job_snippets(lines, "Logs", &job.log_snippets);
    append_job_state_guidance(lines, job);
}

fn append_diff_delta_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::DiffDelta {
        return;
    }

    let Some(summary) = snapshot.objects.get(selected).or_else(|| {
        snapshot
            .diff_deltas
            .iter()
            .find(|delta| delta.object_ref == *selected)
    }) else {
        return;
    };
    let Some(metadata) = parsed_metadata(&summary.metadata_json) else {
        return;
    };

    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Diff Delta"));
    lines.push(InspectorLine::plain(format!(
        "Change: {}",
        diff_metadata_str(Some(&metadata), "change")
    )));
    lines.push(InspectorLine::plain(format!(
        "Entity: {}",
        diff_metadata_str(Some(&metadata), "entity_kind")
    )));
    let match_key = diff_metadata_str(Some(&metadata), "match_key");
    if match_key != "-" {
        lines.push(InspectorLine::plain(format!("Match: {match_key}")));
    }

    append_diff_ref_line(
        lines,
        snapshot,
        &metadata,
        "Before",
        "before",
        "before_label",
    );
    append_diff_ref_line(lines, snapshot, &metadata, "After", "after", "after_label");

    if let Some(previews) = metadata
        .get("command_previews")
        .and_then(serde_json::Value::as_array)
    {
        let rendered = previews
            .iter()
            .filter_map(serde_json::Value::as_str)
            .take(4)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Command Previews"));
            for preview in rendered {
                lines.push(InspectorLine::plain(preview.to_string()));
            }
        }
    }
}

fn append_diff_ref_line(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    metadata: &serde_json::Value,
    label: &str,
    ref_key: &str,
    label_key: &str,
) {
    let display = diff_metadata_str(Some(metadata), label_key);
    if let Some(target) = diff_metadata_ref(metadata, ref_key) {
        let display = if display == "-" {
            snapshot.object_label(&target)
        } else {
            display
        };
        lines.push(InspectorLine::jump(format!("{label}: {display}"), target));
    } else if display != "-" {
        lines.push(InspectorLine::plain(format!("{label}: {display}")));
    }
}

fn append_trace_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::TraceSession && selected.kind != ObjectKind::TraceEvent {
        return;
    }

    let Some(summary) = snapshot.objects.get(selected).or_else(|| {
        snapshot
            .trace_items
            .iter()
            .find(|item| item.object_ref == *selected)
    }) else {
        return;
    };
    let Some(metadata) = parsed_metadata(&summary.metadata_json) else {
        return;
    };

    lines.push(InspectorLine::plain(""));
    match selected.kind {
        ObjectKind::TraceSession => {
            lines.push(InspectorLine::plain("Trace Session"));
            append_trace_value_line(lines, &metadata, "Session", "session_id");
            append_trace_value_line(lines, &metadata, "Events", "event_count");
            append_trace_value_line(lines, &metadata, "Threads", "thread_count");
            append_trace_value_line(lines, &metadata, "Source", "source_path");
            append_trace_diagnostics(lines, &metadata);
            append_trace_command_previews(lines, &metadata);
        }
        ObjectKind::TraceEvent => {
            lines.push(InspectorLine::plain("Trace Event"));
            append_trace_value_line(lines, &metadata, "Thread", "thread_id");
            append_trace_value_line(lines, &metadata, "Kind", "event_kind");
            append_trace_value_line(lines, &metadata, "Time ns", "timestamp_ns");
            append_trace_value_line(lines, &metadata, "Function", "function");
            if let Some(address) = metadata.get("address").and_then(serde_json::Value::as_u64) {
                lines.push(InspectorLine::plain(format!("Address: 0x{address:x}")));
            }
            append_trace_value_line(lines, &metadata, "Message", "message");
            if let Some(session) = trace_metadata_ref(&metadata, "session") {
                lines.push(InspectorLine::jump(
                    format!("Session: {}", snapshot.object_label(&session)),
                    session,
                ));
            }
            if let Some(correlated) = trace_metadata_ref(&metadata, "correlated") {
                lines.push(InspectorLine::jump(
                    format!("Correlated: {}", snapshot.object_label(&correlated)),
                    correlated,
                ));
            }
            append_trace_command_previews(lines, &metadata);
        }
        _ => {}
    }
}

fn append_firmware_file_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::FirmwareFile {
        return;
    }

    let Some(summary) = snapshot.objects.get(selected).or_else(|| {
        snapshot
            .firmware_files
            .iter()
            .find(|item| item.object_ref == *selected)
    }) else {
        return;
    };
    let Some(metadata) = parsed_metadata(&summary.metadata_json) else {
        return;
    };

    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Firmware File"));
    append_trace_value_line(lines, &metadata, "Path", "path");
    append_trace_value_line(lines, &metadata, "Type", "file_type");
    append_trace_value_line(lines, &metadata, "Size", "size");
    append_trace_value_line(lines, &metadata, "Executable", "executable");
    append_trace_value_line(lines, &metadata, "SHA256", "sha256");
    append_trace_value_line(lines, &metadata, "Source", "source_path");
    if let Some(firmware) = diff_metadata_ref(&metadata, "firmware") {
        lines.push(InspectorLine::jump(
            format!("Firmware: {}", snapshot.object_label(&firmware)),
            firmware,
        ));
    }
    if let Some(nested) = diff_metadata_ref(&metadata, "nested_artifact") {
        lines.push(InspectorLine::jump(
            format!("Nested artifact: {}", snapshot.object_label(&nested)),
            nested,
        ));
    }
    append_trace_command_previews(lines, &metadata);
}

fn append_crash_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::CrashReport && selected.kind != ObjectKind::CrashFrame {
        return;
    }

    let Some(summary) = snapshot.objects.get(selected).or_else(|| {
        snapshot
            .crash_items
            .iter()
            .find(|item| item.object_ref == *selected)
    }) else {
        return;
    };
    let Some(metadata) = parsed_metadata(&summary.metadata_json) else {
        return;
    };

    lines.push(InspectorLine::plain(""));
    match selected.kind {
        ObjectKind::CrashReport => {
            lines.push(InspectorLine::plain("Crash Report"));
            append_trace_value_line(lines, &metadata, "Crash ID", "crash_id");
            append_trace_value_line(lines, &metadata, "Sanitizer", "sanitizer");
            append_trace_value_line(lines, &metadata, "Class", "crash_class");
            append_trace_value_line(lines, &metadata, "Signal", "signal");
            append_trace_value_line(lines, &metadata, "Message", "message");
            append_trace_value_line(lines, &metadata, "Signature", "signature");
            append_trace_value_line(lines, &metadata, "Frames", "frame_count");
            append_trace_value_line(lines, &metadata, "Correlated", "correlated_frame_count");
            append_trace_value_line(lines, &metadata, "Source", "source_path");
            append_trace_diagnostics(lines, &metadata);
            append_trace_command_previews(lines, &metadata);
        }
        ObjectKind::CrashFrame => {
            lines.push(InspectorLine::plain("Crash Frame"));
            append_trace_value_line(lines, &metadata, "Index", "frame_index");
            append_trace_value_line(lines, &metadata, "Module", "module");
            append_trace_value_line(lines, &metadata, "Function", "function");
            if let Some(address) = metadata.get("address").and_then(serde_json::Value::as_u64) {
                lines.push(InspectorLine::plain(format!("Address: 0x{address:x}")));
            }
            if let Some(offset) = metadata.get("offset").and_then(serde_json::Value::as_u64) {
                lines.push(InspectorLine::plain(format!("Offset: 0x{offset:x}")));
            }
            append_trace_value_line(lines, &metadata, "Source", "source_location");
            append_trace_value_line(lines, &metadata, "Confidence", "confidence");
            if let Some(report) = trace_metadata_ref(&metadata, "report") {
                lines.push(InspectorLine::jump(
                    format!("Report: {}", snapshot.object_label(&report)),
                    report,
                ));
            }
            if let Some(correlated) = trace_metadata_ref(&metadata, "correlated") {
                lines.push(InspectorLine::jump(
                    format!("Correlated: {}", snapshot.object_label(&correlated)),
                    correlated,
                ));
            }
            append_trace_command_previews(lines, &metadata);
        }
        _ => {}
    }
}

fn append_protocol_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::ProtocolSample
        && selected.kind != ObjectKind::ProtocolMessage
        && selected.kind != ObjectKind::ProtocolField
    {
        return;
    }

    let Some(summary) = snapshot.objects.get(selected).or_else(|| {
        snapshot
            .protocol_items
            .iter()
            .find(|item| item.object_ref == *selected)
    }) else {
        return;
    };
    let Some(metadata) = parsed_metadata(&summary.metadata_json) else {
        return;
    };

    lines.push(InspectorLine::plain(""));
    match selected.kind {
        ObjectKind::ProtocolSample => {
            lines.push(InspectorLine::plain("Protocol Sample"));
            append_trace_value_line(lines, &metadata, "Sample", "sample_id");
            append_trace_value_line(lines, &metadata, "Messages", "message_count");
            append_trace_value_line(lines, &metadata, "Fields", "field_count");
            append_trace_value_line(lines, &metadata, "Correlated", "correlated_field_count");
            append_trace_value_line(lines, &metadata, "Schema hypothesis", "schema_hypothesis");
            append_trace_value_line(lines, &metadata, "Source", "source_path");
            append_trace_diagnostics(lines, &metadata);
            append_trace_command_previews(lines, &metadata);
        }
        ObjectKind::ProtocolMessage => {
            lines.push(InspectorLine::plain("Protocol Message"));
            append_trace_value_line(lines, &metadata, "Message", "message_id");
            append_trace_value_line(lines, &metadata, "Index", "message_index");
            append_trace_value_line(lines, &metadata, "Direction", "direction");
            append_trace_value_line(lines, &metadata, "Payload bytes", "payload_len");
            append_trace_value_line(lines, &metadata, "Fields", "field_count");
            append_trace_value_line(lines, &metadata, "Schema hypothesis", "schema_hypothesis");
            append_trace_value_line(lines, &metadata, "Payload hex", "payload_hex");
            if let Some(sample) = trace_metadata_ref(&metadata, "sample") {
                lines.push(InspectorLine::jump(
                    format!("Sample: {}", snapshot.object_label(&sample)),
                    sample,
                ));
            }
            append_trace_command_previews(lines, &metadata);
        }
        ObjectKind::ProtocolField => {
            lines.push(InspectorLine::plain("Protocol Field"));
            append_trace_value_line(lines, &metadata, "Name", "name");
            append_trace_value_line(lines, &metadata, "Index", "field_index");
            append_trace_value_line(lines, &metadata, "Offset", "byte_offset");
            append_trace_value_line(lines, &metadata, "Length", "byte_length");
            append_trace_value_line(lines, &metadata, "Type", "field_type");
            append_trace_value_line(lines, &metadata, "Confidence", "confidence");
            append_trace_value_line(lines, &metadata, "Entropy", "entropy");
            append_trace_value_line(lines, &metadata, "Printable", "printable_ratio");
            append_trace_value_line(lines, &metadata, "Integer", "integer_value");
            append_trace_value_line(lines, &metadata, "String hint", "string_hint");
            append_trace_value_line(lines, &metadata, "Value hex", "value_hex");
            if let Some(message) = trace_metadata_ref(&metadata, "message") {
                lines.push(InspectorLine::jump(
                    format!("Message: {}", snapshot.object_label(&message)),
                    message,
                ));
            }
            if let Some(sample) = trace_metadata_ref(&metadata, "sample") {
                lines.push(InspectorLine::jump(
                    format!("Sample: {}", snapshot.object_label(&sample)),
                    sample,
                ));
            }
            if let Some(correlated) = trace_metadata_ref(&metadata, "correlated") {
                lines.push(InspectorLine::jump(
                    format!("Correlated: {}", snapshot.object_label(&correlated)),
                    correlated,
                ));
            }
            append_trace_command_previews(lines, &metadata);
        }
        _ => {}
    }
}

fn append_trace_value_line(
    lines: &mut Vec<InspectorLine>,
    metadata: &serde_json::Value,
    label: &str,
    key: &str,
) {
    let value = diff_metadata_str(Some(metadata), key);
    if value != "-" && value != "null" {
        lines.push(InspectorLine::plain(format!("{label}: {value}")));
    }
}

fn append_trace_diagnostics(lines: &mut Vec<InspectorLine>, metadata: &serde_json::Value) {
    let Some(diagnostics) = metadata
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    if diagnostics.is_empty() {
        return;
    }
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Diagnostics"));
    for diagnostic in diagnostics
        .iter()
        .filter_map(serde_json::Value::as_str)
        .take(4)
    {
        lines.push(InspectorLine::plain(format!("- {diagnostic}")));
    }
}

fn append_trace_command_previews(lines: &mut Vec<InspectorLine>, metadata: &serde_json::Value) {
    let Some(previews) = metadata
        .get("command_previews")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    let rendered = previews
        .iter()
        .filter_map(serde_json::Value::as_str)
        .take(4)
        .collect::<Vec<_>>();
    if rendered.is_empty() {
        return;
    }
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Command Previews"));
    for preview in rendered {
        lines.push(InspectorLine::plain(preview.to_string()));
    }
}

fn append_job_limits(lines: &mut Vec<InspectorLine>, job: &AnalysisJobRow) {
    if job.byte_limit.is_none() && job.function_limit.is_none() && job.time_limit_ms.is_none() {
        return;
    }

    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Limits"));
    if let Some(byte_limit) = job.byte_limit {
        lines.push(InspectorLine::plain(format!("Byte limit: {byte_limit}")));
    }
    if let Some(function_limit) = job.function_limit {
        lines.push(InspectorLine::plain(format!(
            "Function limit: {function_limit}"
        )));
    }
    if let Some(time_limit_ms) = job.time_limit_ms {
        lines.push(InspectorLine::plain(format!(
            "Time limit ms: {time_limit_ms}"
        )));
    }
}

fn append_job_detail_items(
    lines: &mut Vec<InspectorLine>,
    title: &str,
    items: &[revdeck_core::AnalysisJobDetailItem],
) {
    if items.is_empty() {
        return;
    }

    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain(title));
    for item in items.iter().take(8) {
        lines.push(InspectorLine::plain(format!(
            "- {}: {}",
            item.key, item.value
        )));
    }
}

fn append_job_snippets(lines: &mut Vec<InspectorLine>, title: &str, snippets: &[String]) {
    if snippets.is_empty() {
        return;
    }

    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain(title));
    for snippet in snippets.iter().take(4) {
        lines.push(InspectorLine::plain(format!("- {snippet}")));
    }
}

fn append_job_state_guidance(lines: &mut Vec<InspectorLine>, job: &AnalysisJobRow) {
    match job.status.to_ascii_lowercase().as_str() {
        "failed" => {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain(
                "State: failed - review diagnostics and logs before continuing triage.",
            ));
        }
        "skipped" => {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain(
                "State: skipped - profile or precondition degradation, not a destructive action.",
            ));
        }
        "running" | "queued" => {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain(
                "State: in progress at snapshot load; live refresh is deferred.",
            ));
        }
        _ => {}
    }
}

fn append_native_function_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::Function {
        return;
    }
    let Some(summary) = snapshot.objects.get(selected) else {
        return;
    };
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&summary.metadata_json) else {
        return;
    };
    let frame_pointer = metadata
        .get("frame_pointer")
        .and_then(serde_json::Value::as_str);
    let stack_frame_size = metadata
        .get("stack_frame_size")
        .and_then(serde_json::Value::as_u64);
    let stack_cleanup_size = metadata
        .get("stack_cleanup_size")
        .and_then(serde_json::Value::as_u64);
    let epilogue_kind = metadata
        .get("epilogue_kind")
        .and_then(serde_json::Value::as_str);
    let has_frame_epilogue = metadata
        .get("has_frame_epilogue")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let calling_convention = metadata
        .get("calling_convention")
        .and_then(serde_json::Value::as_str);
    let argument_registers = metadata
        .get("argument_registers")
        .and_then(serde_json::Value::as_array);
    if frame_pointer.is_none()
        && stack_frame_size.is_none()
        && stack_cleanup_size.is_none()
        && epilogue_kind.is_none()
        && calling_convention.is_none()
        && argument_registers.map(Vec::is_empty).unwrap_or(true)
        && !has_frame_epilogue
    {
        return;
    }
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Native Function"));
    if let Some(frame_pointer) = frame_pointer {
        lines.push(InspectorLine::plain(format!(
            "Frame pointer: {frame_pointer}"
        )));
    }
    if let Some(stack_frame_size) = stack_frame_size {
        lines.push(InspectorLine::plain(format!(
            "Stack frame: {stack_frame_size} bytes"
        )));
    }
    if let Some(stack_cleanup_size) = stack_cleanup_size {
        lines.push(InspectorLine::plain(format!(
            "Stack cleanup: {stack_cleanup_size} bytes"
        )));
    }
    if let Some(epilogue_kind) = epilogue_kind {
        lines.push(InspectorLine::plain(format!("Epilogue: {epilogue_kind}")));
    } else if has_frame_epilogue {
        lines.push(InspectorLine::plain("Epilogue: detected"));
    }
    if let Some(calling_convention) = calling_convention {
        lines.push(InspectorLine::plain(format!("ABI: {calling_convention}")));
    }
    if let Some(argument_registers) = argument_registers {
        let rendered = argument_registers
            .iter()
            .filter_map(render_argument_register)
            .take(6)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain(format!(
                "Args: {}",
                rendered.join(", ")
            )));
        }
    }
    if let Some(slots) = metadata
        .get("stack_slots")
        .and_then(serde_json::Value::as_array)
    {
        let rendered = slots
            .iter()
            .filter_map(render_stack_slot)
            .take(4)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain("Stack slots"));
            for slot in rendered {
                lines.push(InspectorLine::plain(format!("- {slot}")));
            }
        }
    }
}

fn render_argument_register(value: &serde_json::Value) -> Option<String> {
    let ordinal = value
        .get("ordinal")
        .and_then(serde_json::Value::as_u64)?
        .saturating_add(1);
    let register = value.get("register").and_then(serde_json::Value::as_str)?;
    Some(format!("arg{ordinal}: {register}"))
}

fn render_stack_slot(value: &serde_json::Value) -> Option<String> {
    let base = value.get("base").and_then(serde_json::Value::as_str)?;
    let offset = value.get("offset").and_then(serde_json::Value::as_i64)?;
    let text = if offset < 0 {
        format!("{base}-0x{:x}", offset.unsigned_abs())
    } else if offset == 0 {
        base.to_string()
    } else {
        format!("{base}+0x{offset:x}")
    };
    let mut details = Vec::new();
    if let Some(width_bits) = value.get("width_bits").and_then(serde_json::Value::as_u64) {
        details.push(format!("{width_bits}-bit"));
    }
    if let Some(accesses) = value.get("accesses").and_then(serde_json::Value::as_array) {
        let rendered = accesses
            .iter()
            .filter_map(serde_json::Value::as_str)
            .take(4)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            details.push(rendered.join("/"));
        }
    }
    if details.is_empty() {
        Some(text)
    } else {
        Some(format!("{text} ({})", details.join(", ")))
    }
}

fn append_native_instruction_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::Instruction {
        return;
    }
    let Some(summary) = snapshot.objects.get(selected) else {
        return;
    };
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&summary.metadata_json) else {
        return;
    };
    let mnemonic = metadata
        .get("mnemonic")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let operands = metadata
        .get("operands")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Native Instruction"));
    lines.push(InspectorLine::plain(format!(
        "Decoded: {} {}",
        mnemonic, operands
    )));
    if let Some(flow_kind) = metadata
        .get("flow_kind")
        .and_then(serde_json::Value::as_str)
    {
        lines.push(InspectorLine::plain(format!("Flow: {flow_kind}")));
    }
    if let Some(target) = metadata.get("target").and_then(serde_json::Value::as_u64) {
        lines.push(InspectorLine::plain(format!("Target: 0x{target:016x}")));
    }
    if let Some(data_target) = metadata
        .get("data_target")
        .and_then(serde_json::Value::as_u64)
    {
        lines.push(InspectorLine::plain(format!(
            "Data target: 0x{data_target:016x}"
        )));
    }
    if let Some(condition_summary) = metadata
        .get("condition_summary")
        .and_then(serde_json::Value::as_str)
    {
        lines.push(InspectorLine::plain(format!(
            "Condition: {condition_summary}"
        )));
    }
    if let Some(condition_source) = metadata
        .get("condition_source")
        .and_then(object_ref_from_json_value)
    {
        lines.push(InspectorLine::jump(
            format!(
                "Condition source: {}",
                snapshot.object_label(&condition_source)
            ),
            condition_source,
        ));
    }
    if let Some(reads) = render_string_array(metadata.get("register_reads")) {
        lines.push(InspectorLine::plain(format!("Reads: {reads}")));
    }
    if let Some(writes) = render_string_array(metadata.get("register_writes")) {
        lines.push(InspectorLine::plain(format!("Writes: {writes}")));
    }
    if let Some(constants) = metadata
        .get("constant_writes")
        .and_then(serde_json::Value::as_array)
        .map(|values| render_constant_writes(values))
        .filter(|value| !value.is_empty())
    {
        lines.push(InspectorLine::plain(format!("Constants: {constants}")));
    }
    if let Some(sources) = metadata
        .get("constant_sources")
        .and_then(serde_json::Value::as_array)
    {
        for source in sources.iter().filter_map(render_constant_source).take(3) {
            lines.push(source);
        }
    }
    if let Some(sources) = metadata
        .get("register_sources")
        .and_then(serde_json::Value::as_array)
    {
        for source in sources.iter().filter_map(render_register_source).take(3) {
            lines.push(source);
        }
    }
    if let Some(operands) = metadata
        .get("typed_operands")
        .and_then(serde_json::Value::as_array)
    {
        let rendered = operands
            .iter()
            .filter_map(render_typed_operand)
            .take(3)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain("Operands"));
            for operand in rendered {
                lines.push(InspectorLine::plain(format!("- {operand}")));
            }
        }
    }
}

fn render_string_array(value: Option<&serde_json::Value>) -> Option<String> {
    let rendered = value?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .take(8)
        .collect::<Vec<_>>();
    (!rendered.is_empty()).then(|| rendered.join(", "))
}

fn render_constant_writes(values: &[serde_json::Value]) -> String {
    values
        .iter()
        .filter_map(|value| {
            let register = value.get("register").and_then(serde_json::Value::as_str)?;
            let constant = value.get("value").and_then(serde_json::Value::as_u64)?;
            Some(format!("{register}=0x{constant:x}"))
        })
        .take(4)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_register_source(value: &serde_json::Value) -> Option<InspectorLine> {
    let register = value.get("register").and_then(serde_json::Value::as_str)?;
    let source = value.get("source").and_then(object_ref_from_json_value)?;
    Some(InspectorLine::jump(
        format!("Register source {register}"),
        source,
    ))
}

fn render_constant_source(value: &serde_json::Value) -> Option<InspectorLine> {
    let register = value.get("register").and_then(serde_json::Value::as_str)?;
    let constant = value.get("value").and_then(serde_json::Value::as_u64)?;
    let source = value.get("source").and_then(object_ref_from_json_value)?;
    Some(InspectorLine::jump(
        format!("Constant source {register}=0x{constant:x}"),
        source,
    ))
}

fn object_ref_from_json_value(value: &serde_json::Value) -> Option<ObjectRef> {
    serde_json::from_value(value.clone()).ok()
}

fn render_typed_operand(value: &serde_json::Value) -> Option<String> {
    let role = value.get("role").and_then(serde_json::Value::as_str)?;
    let kind = value.get("kind").and_then(serde_json::Value::as_str)?;
    let text = value.get("text").and_then(serde_json::Value::as_str)?;
    Some(format!("{role} {kind} {text}"))
}

fn append_session_memory_lines(
    lines: &mut Vec<InspectorLine>,
    app: &TuiShellState,
    object_ref: &ObjectRef,
) {
    if let Some(tags) = app.command_state.tags.get(object_ref) {
        lines.push(InspectorLine::plain(""));
        lines.push(InspectorLine::plain(format!("Tags: {}", tags.join(", "))));
    }
    if let Some(status) = app.command_state.statuses.get(object_ref) {
        lines.push(InspectorLine::plain(format!("Status: {status}")));
    }
    if let Some(rename) = app.command_state.renames.get(object_ref) {
        lines.push(InspectorLine::plain(format!("Rename: {rename}")));
    }
    if let Some(notes) = app.command_state.notes.get(object_ref) {
        lines.push(InspectorLine::plain("Notes"));
        for note in notes {
            lines.push(InspectorLine::plain(format!("- {note}")));
        }
    }
}

fn inspector_focusable_indices(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<usize> {
    inspector_lines(app, snapshot)
        .iter()
        .enumerate()
        .filter(|(_, line)| line.target.is_some())
        .map(|(index, _)| index)
        .collect()
}

fn inspector_target_at_cursor(
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) -> Option<ObjectRef> {
    inspector_lines(app, snapshot)
        .into_iter()
        .enumerate()
        .find(|(index, item)| *index == app.inspector_cursor && item.target.is_some())
        .and_then(|(_, item)| item.target)
}

fn graph_model_for_app(
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) -> Option<GraphLabViewModel> {
    let root = app.selected.as_ref()?;
    snapshot.local_graph_model(
        root,
        GRAPH_LAB_ACTIVE_FILTER,
        GRAPH_LAB_MAX_DEPTH,
        GRAPH_LAB_MAX_NODES,
    )
}

fn graph_row_count(snapshot: &WorkspaceSnapshot, root: &ObjectRef) -> usize {
    snapshot
        .local_graph_model(
            root,
            GRAPH_LAB_ACTIVE_FILTER,
            GRAPH_LAB_MAX_DEPTH,
            GRAPH_LAB_MAX_NODES,
        )
        .map(|model| model.path_rows.len() + model.edge_details.len())
        .unwrap_or(0)
}

fn graph_target_at_cursor(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Option<ObjectRef> {
    let model = graph_model_for_app(app, snapshot)?;
    if let Some(path_row) = model.path_rows.get(app.main_cursor) {
        return Some(path_row.target.clone());
    }
    let edge_index = app.main_cursor.checked_sub(model.path_rows.len())?;
    let edge = model.edge_details.get(edge_index)?;
    Some(edge.target.clone())
}

fn selected_graph_edge_detail(
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) -> Option<GraphEdgeDetail> {
    let model = graph_model_for_app(app, snapshot)?;
    let edge_index = app.main_cursor.checked_sub(model.path_rows.len())?;
    model.edge_details.get(edge_index).cloned()
}

fn relation_jump_target(relation: &ObjectRelation, selected: &ObjectRef) -> ObjectRef {
    if relation.source == *selected {
        relation.target.clone()
    } else {
        relation.source.clone()
    }
}

fn cursor_for_selection(
    snapshot: &WorkspaceSnapshot,
    lens: NavigationLens,
    selected: &ObjectRef,
) -> Option<usize> {
    snapshot
        .rows_for_lens(lens)
        .iter()
        .position(|candidate| candidate == selected)
}

fn restore_terminal<W: io::Write>(
    terminal: &mut Terminal<CrosstermBackend<W>>,
) -> anyhow::Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")
}

fn search_kind(
    query: &dyn ObjectGraphQuery,
    kind: ObjectKind,
    limit: usize,
) -> anyhow::Result<Vec<ObjectSummary>> {
    query
        .search_objects(&ObjectSearch::new(Some(kind), "").with_limit(limit))
        .map_err(|err| anyhow::anyhow!(err))
}

fn analysis_job_row_from_record(record: &AnalysisJobRecord) -> AnalysisJobRow {
    let detail = AnalysisJobDetail::from_metadata_json(&record.metadata_json);
    AnalysisJobRow {
        id: record.id,
        analysis_run_id: record.analysis_run_id,
        artifact_key: record.artifact_key.clone(),
        pass_name: record.pass_name.clone(),
        profile: record.profile.clone(),
        status: record.status.clone(),
        progress: format_job_progress(record.progress_current, record.progress_total),
        objects_produced: record.objects_produced,
        diagnostics_count: record.diagnostics_count,
        byte_limit: record.byte_limit,
        function_limit: record.function_limit,
        time_limit_ms: record.time_limit_ms,
        started_at: format_job_time(record.started_at),
        finished_at: record.finished_at.map(format_job_time),
        updated_at: format_job_time(record.updated_at),
        metadata_summary: detail.summary(),
        metadata_items: detail.metadata_items,
        parameter_items: detail.parameter_items,
        diagnostic_snippets: detail.diagnostic_snippets,
        log_snippets: detail.log_snippets,
    }
}

fn format_job_progress(current: u64, total: Option<u64>) -> String {
    match total {
        Some(total) => format!("{current}/{total}"),
        None => format!("{current}/?"),
    }
}

fn format_job_time(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

fn summary(
    object_ref: ObjectRef,
    display_name: &str,
    address: Option<u64>,
    size: Option<u64>,
) -> ObjectSummary {
    ObjectSummary {
        object_ref,
        artifact_key: None,
        display_name: Some(display_name.to_string()),
        address,
        size,
        metadata_json: "{}".to_string(),
    }
}

fn relation_line(relation: &ObjectRelation, snapshot: &WorkspaceSnapshot) -> String {
    if is_condition_source_relation(relation, snapshot) {
        return format!(
            "Condition source: {} depends on {}",
            snapshot.object_label(&relation.source),
            snapshot.object_label(&relation.target)
        );
    }
    if relation.kind == revdeck_core::EdgeKind::ControlFlow {
        if let Some(line) = control_flow_relation_line(relation, snapshot) {
            return line;
        }
    }
    format!(
        "{}: {} -> {}",
        relation.kind.label(),
        snapshot.object_label(&relation.source),
        snapshot.object_label(&relation.target)
    )
}

fn control_flow_relation_line(
    relation: &ObjectRelation,
    snapshot: &WorkspaceSnapshot,
) -> Option<String> {
    let metadata = serde_json::from_str::<serde_json::Value>(&relation.metadata_json).ok()?;
    let edge_kind = metadata
        .get("cfg_edge_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("edge");
    let condition = metadata
        .get("condition_summary")
        .and_then(serde_json::Value::as_str);
    let outcome = metadata
        .get("known_outcome")
        .and_then(serde_json::Value::as_str);
    let mut label = format!(
        "Control flow {edge_kind}: {} -> {}",
        snapshot.object_label(&relation.source),
        snapshot.object_label(&relation.target)
    );
    if let Some(outcome) = outcome {
        label.push_str(&format!(" ({})", outcome.replace('_', " ")));
    }
    if let Some(condition) = condition {
        label.push_str(&format!(" | {condition}"));
    }
    Some(label)
}

fn is_condition_source_relation(relation: &ObjectRelation, snapshot: &WorkspaceSnapshot) -> bool {
    relation.kind == revdeck_core::EdgeKind::References
        && relation.source.kind == ObjectKind::Instruction
        && relation.target.kind == ObjectKind::Instruction
        && snapshot
            .objects
            .get(&relation.source)
            .and_then(|summary| {
                serde_json::from_str::<serde_json::Value>(&summary.metadata_json).ok()
            })
            .and_then(|metadata| metadata.get("condition_source").cloned())
            .and_then(|value| object_ref_from_json_value(&value))
            .as_ref()
            == Some(&relation.target)
}

fn focused_block<'a>(app: &TuiShellState, focus: PaneFocus, title: String) -> Block<'a> {
    let style = if app.focus == focus {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::default().title(title).border_style(style)
}

fn main_view_block<'a>(app: &TuiShellState, lens: NavigationLens) -> Block<'a> {
    focused_block(
        app,
        PaneFocus::Main,
        format!("Main View - {} | {}", lens_label(lens), lens_help(lens)),
    )
}

fn lens_badge(lens: NavigationLens) -> &'static str {
    lens.badge()
}

fn pane_focus_label(focus: PaneFocus) -> &'static str {
    match focus {
        PaneFocus::Workspace => "Workspace",
        PaneFocus::Main => "Main View",
        PaneFocus::Inspector => "Inspector",
    }
}

fn lens_label(lens: NavigationLens) -> &'static str {
    lens.label()
}

fn lens_help(lens: NavigationLens) -> &'static str {
    lens.help()
}

fn focus_help(focus: PaneFocus) -> &'static str {
    match focus {
        PaneFocus::Workspace => "Up/Down switches lenses; Enter moves into Main View",
        PaneFocus::Main => "Up/Down moves rows; Enter opens selected object",
        PaneFocus::Inspector => "Up/Down selects evidence or relations; Enter jumps",
    }
}

fn lens_next_step(lens: NavigationLens) -> &'static str {
    lens.next_step()
}

fn help_overlay_lines(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<Line<'static>> {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    let analysis_status = snapshot
        .overview
        .analysis_status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    vec![
        Line::from(vec![
            Span::styled(
                "RevDeck cockpit",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {}  analysis={} import={}",
                snapshot.overview.artifact_label, analysis_status, snapshot.overview.import_status
            )),
        ]),
        Line::from(format!(
            "View: {} ({})",
            lens_label(app.active_lens),
            lens_help(app.active_lens)
        )),
        Line::from(format!(
            "Focus: {} - {}",
            pane_focus_label(app.focus),
            focus_help(app.focus)
        )),
        Line::from(format!("Selected: {}", truncate(&selected, 72))),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("Tab/Shift+Tab panes; Left/Right columns; Up/Down or j/k moves; Enter opens or jumps."),
        Line::from("Lenses: g triage, G graph, D diff, T trace, W firmware, C crash, P protocol, J jobs, o overview, b binary, r radar, f functions, s strings, i imports, n notes, F findings."),
        Line::from("History: [ back, ] forward. Commands: p deck, : command mode. Quit: q or Esc outside help."),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Commands",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(":find string password    :find import system    :xrefs current    :open current"),
        Line::from(":tag current suspicious  :note current reviewed path  :rename current name  :status current reviewed"),
        Line::from(":finding new high title  :finding link <finding> current evidence"),
        Line::from(":export markdown report.md  :export json report.json"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Current next step",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(lens_next_step(app.active_lens)),
    ]
}

fn command_deck_lines(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<Line<'static>> {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    let selected_ref = app
        .selected
        .as_ref()
        .map(short_ref)
        .unwrap_or_else(|| "none".to_string());
    let mut lines = vec![
        Line::from(vec![Span::styled(
            "Commands",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(":open current              navigate to selected object"),
        Line::from(":xrefs current             load local relations into Graph Lab"),
        Line::from(":find string <term>        search strings"),
        Line::from(":find import <term>        search imports"),
        Line::from(":tag current <tag>         add analysis memory"),
        Line::from(":note current <text>       add analyst note"),
        Line::from(":finding new high <title>  create finding draft"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Current Object",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("selected: {}", truncate(&selected, 64))),
        Line::from(format!("ref: {selected_ref}")),
        Line::from("preview: G opens Graph Lab, D opens Diff Lab, T opens Trace Lab, W opens Firmware Lab, C opens Crash Lab, P opens Protocol Lab, Enter opens, :xrefs current loads relations"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Recent / Context",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!(
            "view={} focus={} exports={} findings={} session-tags={}",
            lens_label(app.active_lens),
            pane_focus_label(app.focus),
            app.command_state.export_requests.len(),
            app.command_state.findings.len(),
            app.command_state.tags.len()
        )),
    ];
    if snapshot
        .relations_for_selected(app.selected.as_ref())
        .is_empty()
    {
        lines.push(Line::from("relations: none loaded for selected object"));
    } else {
        lines.push(Line::from(format!(
            "relations: {} local edges available",
            snapshot.relations_for_selected(app.selected.as_ref()).len()
        )));
    }
    lines
}

fn context_help(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> String {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    format!(
        "Focus: {} | View: {} | Selected: {} | ? help, p deck, Tab/Shift+Tab panes, Left/Right columns, Up/Down move, Enter open/jump, : commands, g triage, G graph, D diff, T trace, W firmware, C crash, P protocol, J jobs, q quit",
        pane_focus_label(app.focus),
        lens_label(app.active_lens),
        truncate(&selected, 28)
    )
}

fn export_format_label(format: &ExportFormat) -> &'static str {
    match format {
        ExportFormat::Markdown => "markdown",
        ExportFormat::Json => "json",
    }
}

fn short_ref(object_ref: &ObjectRef) -> String {
    let key = object_ref.key.as_str();
    let key = truncate(key, 40);
    format!("{}:{key}", object_ref.kind)
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value
        .chars()
        .take(limit.saturating_sub(1))
        .collect::<String>()
        + "."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use ratatui::backend::TestBackend;
    use revdeck_core::{InMemoryObjectGraph, ObjectKind};

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<Vec<_>>()
            .join("")
    }

    fn graph(snapshot: &WorkspaceSnapshot) -> InMemoryObjectGraph {
        let mut graph = InMemoryObjectGraph::new();
        for object in snapshot.objects.values() {
            graph.insert_object(object.clone());
        }
        for relations in snapshot.relations_by_object.values() {
            for relation in relations {
                graph
                    .insert_relation(
                        relation.source.clone(),
                        relation.target.clone(),
                        relation.kind,
                    )
                    .unwrap();
            }
        }
        graph
    }

    #[test]
    fn reducer_navigation() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);

        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        let function = app.selected.clone().unwrap();
        app.apply_action(TuiAction::ActivateSelection, &snapshot)
            .unwrap();
        app.apply_action(
            TuiAction::NavigateToReasonEvidence {
                reason_index: 0,
                evidence_index: 0,
            },
            &snapshot,
        )
        .unwrap();

        assert_ne!(app.selected.as_ref(), Some(&function));
        assert!(matches!(
            app.selected.as_ref().map(|item| item.kind),
            Some(ObjectKind::Import | ObjectKind::String | ObjectKind::Artifact)
        ));
        assert!(app.command_state.navigation.len() >= 2);
    }

    #[test]
    fn reducer_command_results() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);
        let function = snapshot.radar.rows[0].function_ref.clone();

        app.submit_command(&format!("open {function}"), &graph)
            .unwrap();
        app.submit_command("tag current suspicious", &graph)
            .unwrap();
        app.submit_command("note current review command path", &graph)
            .unwrap();
        app.submit_command("finding new high command execution", &graph)
            .unwrap();
        app.submit_command("export json report.json", &graph)
            .unwrap();

        assert_eq!(
            app.command_state.tags.get(&function).unwrap(),
            &vec!["suspicious".to_string()]
        );
        assert!(app
            .command_state
            .notes
            .get(&function)
            .unwrap()
            .iter()
            .any(|note| note.contains("command path")));
        assert_eq!(app.command_state.findings.len(), 1);
        assert_eq!(app.command_state.export_requests.len(), 1);
        assert!(app.status_line.contains("export queued"));
    }

    #[test]
    fn render_workspace_three_pane() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Workspace"));
        assert!(text.contains("Cockpit"));
        assert!(text.contains("RevDeck"));
        assert!(text.contains("Main View"));
        assert!(text.contains("Inspector"));
        assert!(text.contains("Command / Status"));
        assert!(text.contains("Function Radar"));
    }

    #[test]
    fn render_help_overlay_with_current_context() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        app.apply_action(TuiAction::ToggleHelp, &snapshot).unwrap();
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Command Deck"));
        assert!(text.contains("RevDeck cockpit"));
        assert!(text.contains("Current next step"));
        assert!(text.contains(":finding new high title"));
    }

    #[test]
    fn triage_board_renders_prioritized_next_actions() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::TriageBoard),
            &snapshot,
        )
        .unwrap();
        let selected = app.selected.clone().unwrap();
        let backend = TestBackend::new(140, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Triage Board"));
        assert!(text.contains("Dangerous import path"));
        assert!(text.contains(":xrefs current"));
        assert_eq!(selected, snapshot.triage.rows[0].target);
    }

    #[test]
    fn render_small_terminal_fallback() {
        let snapshot = WorkspaceSnapshot::demo();
        let app = TuiShellState::from_snapshot(&snapshot);
        let backend = TestBackend::new(54, 12);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Command / Status"));
        assert!(text.contains("Workspace"));
    }

    #[test]
    fn function_radar_inspector_snapshot() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        let backend = TestBackend::new(120, 42);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Dangerous import"));
        assert!(text.contains("Sensitive string"));
        assert!(text.contains("Boundary"));
        assert!(text.contains("Boundary source"));
        assert!(text.contains("Native Function"));
        assert!(text.contains("Frame pointer: rbp"));
        assert!(text.contains("Stack frame: 32 bytes"));
        assert!(text.contains("Stack cleanup: 32 bytes"));
        assert!(text.contains("Epilogue: stack-add-pop-rbp"));
        assert!(text.contains("ABI: windows-x64"));
        assert!(text.contains("Args: arg1: rcx"));
        assert!(text.contains("arg1: rcx"));
        assert!(text.contains("Stack slots"));
        assert!(text.contains("rbp-0x8"));
        assert!(text.contains("read/write"));
        assert!(text.contains("evidence"));
    }

    #[test]
    fn tab_and_arrows_move_between_panes_without_switching_lens() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.focus, PaneFocus::Inspector);
        assert_eq!(app.active_lens, NavigationLens::Overview);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        app.handle_key_event(
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.focus, PaneFocus::Workspace);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.active_lens, NavigationLens::TriageBoard);
    }

    #[test]
    fn non_press_key_events_are_ignored() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);
        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        app.handle_key_event(key, &snapshot, &graph).unwrap();
        let after_press = app.main_cursor;

        let release =
            KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        app.handle_key_event(release, &snapshot, &graph).unwrap();

        assert_eq!(app.main_cursor, after_press);
    }

    #[test]
    fn help_overlay_traps_navigation_until_closed() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert!(app.show_help);
        let cursor = app.main_cursor;

        app.handle_key_event(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.main_cursor, cursor);
        assert!(app.show_help);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert!(!app.show_help);
        assert!(!app.should_quit);
    }

    #[test]
    fn right_pane_can_select_and_open_evidence() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
            .unwrap();
        let function = app.selected.clone().unwrap();

        app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
        app.apply_action(TuiAction::ActivateSelection, &snapshot)
            .unwrap();

        assert_ne!(app.selected.as_ref(), Some(&function));
        assert!(matches!(
            app.selected.as_ref().map(|item| item.kind),
            Some(ObjectKind::Import | ObjectKind::String)
        ));
    }
}
