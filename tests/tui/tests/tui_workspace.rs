use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use revdeck_core::{
    AnalysisJobRow, AnalysisJobsSummary, EdgeKind, InMemoryObjectGraph, NavigationLens, ObjectKind,
    ObjectRef, ObjectRelation, ObjectSummary, StableObjectKey, StableObjectKeyBuilder,
};
use revdeck_db::{FindingRepository, MemoryRepository, ProjectDatabase};
use revdeck_index::AnalysisProfile;
use revdeck_tui::{render_workspace, PaneFocus, TuiAction, TuiShellState, WorkspaceSnapshot};
use time::macros::datetime;

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

fn test_summary(
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

fn test_job(pass_name: &str, status: &str, progress: &str) -> AnalysisJobRow {
    let diagnostic_snippets = if status == "failed" {
        vec!["index_model_error: failed to persist cfg".to_string()]
    } else if status == "skipped" {
        vec!["pass_skipped_by_profile: quick skipped native CFG".to_string()]
    } else {
        Vec::new()
    };
    let log_snippets = if status == "running" {
        vec!["job was still running at snapshot load".to_string()]
    } else {
        vec![format!("{pass_name} {status}")]
    };
    AnalysisJobRow {
        id: 1,
        analysis_run_id: Some(1),
        artifact_key: Some("artifact:test".to_string()),
        pass_name: pass_name.to_string(),
        profile: "quick".to_string(),
        status: status.to_string(),
        progress: progress.to_string(),
        objects_produced: 1,
        diagnostics_count: 0,
        started_at: "2026-05-13T00:00:00Z".to_string(),
        finished_at: Some("2026-05-13T00:00:01Z".to_string()),
        updated_at: "2026-05-13T00:00:01Z".to_string(),
        metadata_summary: "profile=quick".to_string(),
        parameter_items: vec![revdeck_core::AnalysisJobDetailItem {
            key: "profile".to_string(),
            value: "quick".to_string(),
        }],
        diagnostic_snippets,
        log_snippets,
        ..AnalysisJobRow::default()
    }
}

fn snapshot_with_jobs(jobs: Vec<AnalysisJobRow>) -> WorkspaceSnapshot {
    let mut snapshot = WorkspaceSnapshot::empty();
    snapshot.analysis_jobs = jobs;
    snapshot.analysis_jobs_summary = AnalysisJobsSummary::from_rows(&snapshot.analysis_jobs);
    snapshot
}

fn condition_source_snapshot() -> WorkspaceSnapshot {
    let mut snapshot = WorkspaceSnapshot::demo();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("demo artifact should exist");
    let cmp = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x401000, 0).unwrap(),
    );
    let branch = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x401003, 1).unwrap(),
    );
    let cmp_summary = ObjectSummary {
        object_ref: cmp.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("401000: cmp rax,rcx".to_string()),
        address: Some(0x401000),
        size: Some(3),
        metadata_json: r#"{"native_analyzer":true,"mnemonic":"cmp","operands":"rax,rcx","typed_operands":[{"role":"source","kind":"register","text":"rax","register":"rax"},{"role":"source","kind":"register","text":"rcx","register":"rcx"}],"register_reads":["rax","rcx"],"register_writes":[],"flow_kind":null}"#.to_string(),
    };
    let condition_source = format!(
        r#"{{"kind":"{}","key":"{}"}}"#,
        cmp.kind.as_str(),
        cmp.key.as_str()
    );
    let branch_summary = ObjectSummary {
        object_ref: branch.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("401003: je 0x401006".to_string()),
        address: Some(0x401003),
        size: Some(2),
        metadata_json: format!(
            r#"{{"native_analyzer":true,"mnemonic":"je","operands":"0x0000000000401006","typed_operands":[{{"role":"branch_target","kind":"relative_target","text":"0x0000000000401006","value":4198406}}],"register_reads":["rax"],"register_writes":[],"register_sources":[{{"register":"rax","source":{condition_source}}}],"flow_kind":"conditional_branch","target":4198406,"condition_source":{condition_source},"condition_summary":"je if rax == rcx"}}"#
        ),
    };
    let edge_ref = ObjectRef::new(
        ObjectKind::Edge,
        StableObjectKeyBuilder::new(ObjectKind::Edge)
            .component("edge_kind", EdgeKind::References.as_str())
            .unwrap()
            .component("source", branch.key.as_str())
            .unwrap()
            .component("target", cmp.key.as_str())
            .unwrap()
            .finish()
            .unwrap(),
    );
    let relation = ObjectRelation {
        edge_ref,
        source: branch.clone(),
        target: cmp.clone(),
        kind: EdgeKind::References,
        confidence: 1.0,
        metadata_json: "{}".to_string(),
    };
    snapshot.objects.insert(cmp.clone(), cmp_summary);
    snapshot.objects.insert(branch.clone(), branch_summary);
    snapshot.relations_by_object.insert(branch, vec![relation]);
    snapshot
}

fn constant_write_snapshot() -> (WorkspaceSnapshot, ObjectRef) {
    let mut snapshot = WorkspaceSnapshot::demo();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("demo artifact should exist");
    let instruction = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x401020, 2).unwrap(),
    );
    let summary = ObjectSummary {
        object_ref: instruction.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("401020: mov rax,0x2a".to_string()),
        address: Some(0x401020),
        size: Some(10),
        metadata_json: r#"{"native_analyzer":true,"mnemonic":"mov","operands":"rax,0x2a","typed_operands":[{"role":"destination","kind":"register","text":"rax","register":"rax"},{"role":"source","kind":"immediate","text":"0x2a","value":42,"width_bits":64}],"register_reads":[],"register_writes":["rax"],"register_sources":[],"constant_writes":[{"register":"rax","value":42,"width_bits":64}],"flow_kind":null}"#.to_string(),
    };
    snapshot.objects.insert(instruction.clone(), summary);
    (snapshot, instruction)
}

fn zero_idiom_snapshot() -> (WorkspaceSnapshot, ObjectRef) {
    let mut snapshot = WorkspaceSnapshot::demo();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("demo artifact should exist");
    let instruction = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x401030, 3).unwrap(),
    );
    let summary = ObjectSummary {
        object_ref: instruction.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("401030: xor rax,rax".to_string()),
        address: Some(0x401030),
        size: Some(3),
        metadata_json: r#"{"native_analyzer":true,"mnemonic":"xor","operands":"rax,rax","typed_operands":[{"role":"destination","kind":"register","text":"rax","register":"rax"},{"role":"source","kind":"register","text":"rax","register":"rax"}],"register_reads":[],"register_writes":["rax"],"register_sources":[],"constant_writes":[{"register":"rax","value":0,"width_bits":64}],"flow_kind":null}"#.to_string(),
    };
    snapshot.objects.insert(instruction.clone(), summary);
    (snapshot, instruction)
}

fn lea_constant_snapshot() -> (WorkspaceSnapshot, ObjectRef) {
    let mut snapshot = WorkspaceSnapshot::demo();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("demo artifact should exist");
    let instruction = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x401040, 4).unwrap(),
    );
    let summary = ObjectSummary {
        object_ref: instruction.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("401040: lea rcx,[rip+disp32]".to_string()),
        address: Some(0x401040),
        size: Some(7),
        metadata_json: r#"{"native_analyzer":true,"mnemonic":"lea","operands":"rcx,[rip+disp32] -> 0x0000000000401080","typed_operands":[{"role":"destination","kind":"register","text":"rcx","register":"rcx"},{"role":"data_reference","kind":"memory","text":"[rip+disp32] -> 0x0000000000401080","base":"rip","displacement":57,"effective_address":4198528,"width_bits":64}],"register_reads":["rip"],"register_writes":["rcx"],"register_sources":[],"constant_writes":[{"register":"rcx","value":4198528,"width_bits":64}],"data_target":4198528,"flow_kind":null}"#.to_string(),
    };
    snapshot.objects.insert(instruction.clone(), summary);
    (snapshot, instruction)
}

fn constant_source_snapshot() -> (WorkspaceSnapshot, ObjectRef) {
    let mut snapshot = WorkspaceSnapshot::demo();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("demo artifact should exist");
    let writer = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x401050, 5).unwrap(),
    );
    let reader = ObjectRef::new(
        ObjectKind::Instruction,
        StableObjectKey::instruction(&artifact.key, 0x40105a, 6).unwrap(),
    );
    let writer_summary = ObjectSummary {
        object_ref: writer.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("401050: mov rax,0x2a".to_string()),
        address: Some(0x401050),
        size: Some(10),
        metadata_json: r#"{"native_analyzer":true,"mnemonic":"mov","operands":"rax,0x2a","typed_operands":[{"role":"destination","kind":"register","text":"rax","register":"rax","width_bits":64},{"role":"source","kind":"immediate","text":"0x2a","value":42,"width_bits":64}],"register_reads":[],"register_writes":["rax"],"register_sources":[],"constant_writes":[{"register":"rax","value":42,"width_bits":64}],"constant_sources":[],"flow_kind":null}"#.to_string(),
    };
    let source = format!(
        r#"{{"kind":"{}","key":"{}"}}"#,
        writer.kind.as_str(),
        writer.key.as_str()
    );
    let reader_summary = ObjectSummary {
        object_ref: reader.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("40105a: mov rdx,rax".to_string()),
        address: Some(0x40105a),
        size: Some(3),
        metadata_json: format!(
            r#"{{"native_analyzer":true,"mnemonic":"mov","operands":"rdx,rax","typed_operands":[{{"role":"destination","kind":"register","text":"rdx","register":"rdx","width_bits":64}},{{"role":"source","kind":"register","text":"rax","register":"rax","width_bits":64}}],"register_reads":["rax"],"register_writes":["rdx"],"register_sources":[],"constant_writes":[],"constant_sources":[{{"register":"rax","value":42,"width_bits":64,"source":{source}}}],"flow_kind":null}}"#
        ),
    };
    let edge_ref = ObjectRef::new(
        ObjectKind::Edge,
        StableObjectKeyBuilder::new(ObjectKind::Edge)
            .component("edge_kind", EdgeKind::References.as_str())
            .unwrap()
            .component("source", reader.key.as_str())
            .unwrap()
            .component("target", writer.key.as_str())
            .unwrap()
            .finish()
            .unwrap(),
    );
    let relation = ObjectRelation {
        edge_ref,
        source: reader.clone(),
        target: writer.clone(),
        kind: EdgeKind::References,
        confidence: 1.0,
        metadata_json: "{}".to_string(),
    };
    snapshot.objects.insert(writer, writer_summary);
    snapshot.objects.insert(reader.clone(), reader_summary);
    snapshot
        .relations_by_object
        .insert(reader.clone(), vec![relation]);
    (snapshot, reader)
}

fn control_flow_outcome_snapshot() -> (WorkspaceSnapshot, ObjectRef) {
    let mut snapshot = WorkspaceSnapshot::demo();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("demo artifact should exist");
    let function = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, 0x402000, Some(18), Some("branchy")).unwrap(),
    );
    let source_block = ObjectRef::new(
        ObjectKind::BasicBlock,
        StableObjectKey::basic_block(&artifact.key, &function, 0x402000, 0).unwrap(),
    );
    let target_block = ObjectRef::new(
        ObjectKind::BasicBlock,
        StableObjectKey::basic_block(&artifact.key, &function, 0x402011, 1).unwrap(),
    );
    let edge_ref = ObjectRef::new(
        ObjectKind::Edge,
        StableObjectKey::edge(EdgeKind::ControlFlow, &source_block, &target_block).unwrap(),
    );
    let relation = ObjectRelation {
        edge_ref,
        source: source_block.clone(),
        target: target_block.clone(),
        kind: EdgeKind::ControlFlow,
        confidence: 0.6,
        metadata_json: r#"{"relation":"CONTROL_FLOW","cfg_edge_kind":"branch","condition_summary":"jne if rax != 0x7f (known taken)","known_outcome":"taken","source":"native_cfg"}"#.to_string(),
    };
    snapshot.objects.insert(
        function.clone(),
        test_summary(function, "branchy", Some(0x402000), Some(18)),
    );
    snapshot.objects.insert(
        source_block.clone(),
        test_summary(
            source_block.clone(),
            "block 402000",
            Some(0x402000),
            Some(16),
        ),
    );
    snapshot.objects.insert(
        target_block.clone(),
        test_summary(target_block, "block 402011", Some(0x402011), Some(1)),
    );
    snapshot
        .relations_by_object
        .insert(source_block.clone(), vec![relation]);
    (snapshot, source_block)
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
    let backend = TestBackend::new(120, 42);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Workspace"));
    assert!(text.contains("Main View"));
    assert!(text.contains("Inspector"));
    assert!(text.contains("Command / Status"));
    assert!(text.contains("Function Radar"));
}

#[test]
fn render_help_overlay() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::ToggleHelp, &snapshot).unwrap();
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Command Deck"));
    assert!(text.contains("Navigation"));
    assert!(text.contains("D diff"));
    assert!(text.contains(":find string password"));
    assert!(text.contains("Current next step"));
}

#[test]
fn diff_lab_renders_demo_deltas_and_inspector_links() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Diff), &snapshot)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Diff);
    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::DiffDelta)
    );

    let backend = TestBackend::new(180, 38);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Diff Lab"));
    assert!(text.contains("changed"));
    assert!(text.contains("object"));
    assert!(text.contains("main before"));
    assert!(text.contains("main after"));
    assert!(text.contains("Diff Delta"));
    assert!(text.contains("Before: main"));
    assert!(text.contains("After: main"));
    assert!(text.contains("Command Previews"));
    assert!(text.contains(":finding link <finding>"));
}

#[test]
fn trace_lab_renders_demo_timeline_and_inspector_links() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Trace), &snapshot)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Trace);
    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::TraceSession)
    );

    let backend = TestBackend::new(180, 38);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Trace Lab"));
    assert!(text.contains("demo-auth"));
    assert!(text.contains("2 events"));
    assert!(text.contains("Trace Session"));
    assert!(text.contains("Session: demo-auth"));
    assert!(text.contains("Threads: 1"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::TraceEvent)
    );
    assert!(text.contains("Trace Event"));
    assert!(text.contains("Thread: main"));
    assert!(text.contains("Kind: call"));
    assert!(text.contains("main call auth gate"));
    assert!(text.contains("auth gate reached"));
    assert!(text.contains("Correlated: main"));
    assert!(text.contains(":finding link <finding>"));
}

#[test]
fn firmware_lab_renders_demo_inventory_and_inspector_links() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Firmware), &snapshot)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Firmware);
    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::FirmwareFile)
    );

    let backend = TestBackend::new(180, 38);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Firmware Lab"));
    assert!(text.contains("etc/passwd"));
    assert!(text.contains("text"));
    assert!(text.contains("Firmware File"));
    assert!(text.contains("Path: etc/passwd"));
    assert!(text.contains("Source:"));
    assert!(text.contains(":finding link <finding>"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("bin/httpd.elf"));
    assert!(text.contains("elf"));
    assert!(text.contains("Executable: true"));
    assert!(text.contains("Nested artifact: bin/httpd.elf"));
}

#[test]
fn crash_lab_renders_demo_reports_frames_and_inspector_links() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Crash), &snapshot)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Crash);
    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::CrashReport)
    );

    let backend = TestBackend::new(180, 38);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Crash Lab"));
    assert!(text.contains("heap-use-after-free"));
    assert!(text.contains("SIGABRT"));
    assert!(text.contains("Crash Report"));
    assert!(text.contains("Crash ID: asan-uaf-001"));
    assert!(text.contains("Signature:"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::CrashFrame)
    );
    assert!(text.contains("Crash Frame"));
    assert!(text.contains("Function: main"));
    assert!(text.contains("Address: 0x401000"));
    assert!(text.contains("Correlated: main"));
    assert!(text.contains(":finding link <finding>"));
}

#[test]
fn protocol_lab_renders_demo_messages_fields_and_inspector_links() {
    let snapshot = WorkspaceSnapshot::demo();
    let graph = graph(&snapshot);
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.handle_key_event(
        KeyEvent::new(KeyCode::Char('P'), KeyModifiers::NONE),
        &snapshot,
        &graph,
    )
    .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Protocol);
    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::ProtocolSample)
    );

    let backend = TestBackend::new(180, 52);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Protocol Lab"));
    assert!(text.contains("demo-login"));
    assert!(text.contains("Protocol Sample"));
    assert!(text.contains("Schema hypothesis"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::ProtocolMessage)
    );
    assert!(text.contains("Protocol Message"));
    assert!(text.contains("client-hello"));
    assert!(text.contains("Payload hex"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert_eq!(
        app.selected.as_ref().map(|object_ref| object_ref.kind),
        Some(ObjectKind::ProtocolField)
    );
    assert!(text.contains("Protocol Field"));
    assert!(text.contains("Name: credential"));
    assert!(text.contains("String hint: admin password"));
    assert!(text.contains("Correlated: admin password"));
    assert!(text.contains(":finding link <finding>"));
}

#[test]
fn graph_lab_shortcut_preserves_selection_and_renders_relations() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    let graph = graph(&snapshot);
    app.apply_action(
        TuiAction::SwitchLens(NavigationLens::FunctionRadar),
        &snapshot,
    )
    .unwrap();
    let function = app.selected.clone().unwrap();

    app.handle_key_event(
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE),
        &snapshot,
        &graph,
    )
    .unwrap();

    assert_eq!(app.active_lens, NavigationLens::LocalGraph);
    assert_eq!(app.selected.as_ref(), Some(&function));

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Graph Lab"));
    assert!(text.contains("relation filter"));
    assert!(text.contains("Path Rows"));
    assert!(text.contains("Selected Edge"));
    assert!(text.contains("Local Relations"));
    assert!(text.contains("CALLS_IMPORT"));
}

#[test]
fn graph_lab_cursor_selects_edge_detail_for_inspector() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(
        TuiAction::SwitchLens(NavigationLens::FunctionRadar),
        &snapshot,
    )
    .unwrap();
    let root = app.selected.clone().unwrap();
    app.apply_action(TuiAction::SwitchLens(NavigationLens::LocalGraph), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();

    assert_eq!(app.selected.as_ref(), Some(&root));

    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Selected Edge"));
    assert!(text.contains("Source: main"));
    assert!(text.contains("Target: system"));
    assert!(text.contains("Confidence: 1.00"));
    assert!(text.contains("Finding link preview"));
    assert!(text.contains(":finding link <finding>"));
}

#[test]
fn inspector_and_graph_lab_render_condition_source() {
    let snapshot = condition_source_snapshot();
    let cmp = snapshot
        .objects
        .values()
        .find(|summary| {
            summary.object_ref.kind == ObjectKind::Instruction && summary.address == Some(0x401000)
        })
        .map(|summary| summary.object_ref.clone())
        .expect("cmp instruction should exist");
    let branch = snapshot
        .objects
        .values()
        .find(|summary| {
            summary.object_ref.kind == ObjectKind::Instruction && summary.address == Some(0x401003)
        })
        .map(|summary| summary.object_ref.clone())
        .expect("branch instruction should exist");
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::NavigateTo(cmp), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();

    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Native Instruction"));
    assert!(text.contains("Reads: rax, rcx"));

    app.apply_action(TuiAction::NavigateTo(branch.clone()), &snapshot)
        .unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Condition: je if rax == rcx"));
    assert!(text.contains("Condition source"));
    assert!(text.contains("Register source rax"));
    assert!(text.contains("401000: cmp"));
    assert!(text.contains("conditional_branch"));

    app.apply_action(TuiAction::SwitchLens(NavigationLens::LocalGraph), &snapshot)
        .unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Condition source"));
    assert!(text.contains("401003: je"));
    assert!(text.contains("401000: cmp"));
}

#[test]
fn graph_lab_renders_control_flow_condition_outcomes() {
    let (snapshot, source_block) = control_flow_outcome_snapshot();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::NavigateTo(source_block), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::SwitchLens(NavigationLens::LocalGraph), &snapshot)
        .unwrap();

    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Control flow branch"));
    assert!(text.contains("block 402000"));
    assert!(text.contains("block 402011"));
    assert!(text.contains("(taken)"));
    assert!(text.contains("jne if rax"));
    assert!(text.contains("(known taken)"));
}

#[test]
fn instruction_inspector_renders_constant_writes() {
    let (snapshot, instruction) = constant_write_snapshot();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::NavigateTo(instruction), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();

    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Native Instruction"));
    assert!(text.contains("Writes: rax"));
    assert!(text.contains("Constants: rax=0x2a"));
}

#[test]
fn instruction_inspector_renders_zero_idiom_constants() {
    let (snapshot, instruction) = zero_idiom_snapshot();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::NavigateTo(instruction), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();

    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Native Instruction"));
    assert!(!text.contains("Reads: rax"));
    assert!(text.contains("Writes: rax"));
    assert!(text.contains("Constants: rax=0x0"));
}

#[test]
fn instruction_inspector_renders_lea_address_constants() {
    let (snapshot, instruction) = lea_constant_snapshot();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::NavigateTo(instruction), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();

    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Native Instruction"));
    assert!(text.contains("Data target"));
    assert!(text.contains("0000000000401080"));
    assert!(text.contains("Writes: rcx"));
    assert!(text.contains("Constants: rcx=0x401080"));
}

#[test]
fn instruction_inspector_renders_constant_sources() {
    let (snapshot, instruction) = constant_source_snapshot();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::NavigateTo(instruction), &snapshot)
        .unwrap();
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();

    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Native Instruction"));
    assert!(text.contains("Reads: rax"));
    assert!(text.contains("Writes: rdx"));
    assert!(text.contains("Constant source rax=0x2a"));
}

#[test]
fn command_deck_overlay_traps_navigation_until_closed() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    let graph = graph(&snapshot);
    let lens = app.active_lens;

    app.handle_key_event(
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE),
        &snapshot,
        &graph,
    )
    .unwrap();
    assert!(app.show_command_deck);

    app.handle_key_event(
        KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        &snapshot,
        &graph,
    )
    .unwrap();
    assert_eq!(app.active_lens, lens);

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    assert!(text.contains("Command Deck"));
    assert!(text.contains("Current Object"));
    assert!(text.contains(":xrefs current"));

    app.handle_key_event(
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        &snapshot,
        &graph,
    )
    .unwrap();
    assert!(!app.show_command_deck);
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

    assert!(text.contains("Cockpit"));
    assert!(text.contains("Command / Status"));
    assert!(text.contains("Workspace"));
}

#[test]
fn jobs_lens_renders_demo_history_as_read_only() {
    let snapshot = WorkspaceSnapshot::demo();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Jobs);
    assert!(app.selected.is_none());
    for _ in 0..4 {
        app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    }
    assert!(app.selected.is_none());
    assert_eq!(app.main_cursor, 4);
    app.apply_action(TuiAction::ActivateSelection, &snapshot)
        .unwrap();
    assert_eq!(app.active_lens, NavigationLens::Jobs);
    assert!(app.selected.is_none());
    assert_eq!(app.focus, PaneFocus::Inspector);

    let backend = TestBackend::new(180, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Analysis Jobs"));
    assert!(text.contains("triage"));
    assert!(text.contains("succeeded"));
    assert!(text.contains("cfg"));
    assert!(text.contains("skipped"));
    assert!(text.contains("0/?"));
    assert!(text.contains("objects"));
    assert!(text.contains("diag"));
    assert!(text.contains("Job Inspector"));
    assert!(text.contains("parse"));
    assert!(text.contains("Parameters"));
    assert!(text.contains("profile"));
}

#[test]
fn jobs_lens_empty_state_is_stable() {
    let snapshot = WorkspaceSnapshot::empty();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();
    let backend = TestBackend::new(90, 18);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("No analysis jobs recorded"));
    assert!(text.contains("read-only lens"));
    assert!(text.contains("jobs=0"));
}

#[test]
fn jobs_lens_selected_inspector_distinguishes_failed_skipped_and_running() {
    let snapshot = snapshot_with_jobs(vec![
        test_job("binary.triage", "failed", "1/1"),
        test_job("binary.cfg", "skipped", "0/?"),
        test_job("binary.parse", "running", "0/?"),
    ]);
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();
    let backend = TestBackend::new(180, 40);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let failed_text = buffer_text(&terminal);
    assert!(failed_text.contains("Job Inspector"));
    assert!(failed_text.contains("triage"));
    assert!(failed_text.contains("index_model_error"));
    assert!(failed_text.contains("State: failed"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let skipped_text = buffer_text(&terminal);
    assert!(skipped_text.contains("cfg"));
    assert!(skipped_text.contains("pass_skipped_by_profile"));
    assert!(skipped_text.contains("State: skipped"));

    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let running_text = buffer_text(&terminal);
    assert!(running_text.contains("parse"));
    assert!(running_text.contains("snapshot load"));
    assert!(running_text.contains("live refresh"));
}

#[test]
fn cockpit_jobs_summary_counts_skipped_as_neutral() {
    let snapshot = snapshot_with_jobs(vec![
        test_job("binary.parse", "running", "0/?"),
        test_job("binary.cfg", "skipped", "0/?"),
        test_job("binary.triage", "failed", "1/1"),
    ]);
    assert_eq!(snapshot.analysis_jobs_summary.running, 1);
    assert_eq!(snapshot.analysis_jobs_summary.skipped, 1);
    assert_eq!(snapshot.analysis_jobs_summary.failed, 1);

    let app = TuiShellState::from_snapshot(&snapshot);
    let backend = TestBackend::new(150, 18);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("jobs=3"));
    assert!(text.contains("running=1"));
    assert!(text.contains("failed=1"));
    assert!(text.contains("skipped=1"));
    assert!(text.contains("latest=binary.parse:running"));
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

#[test]
fn project_snapshot_loads_native_cfg_objects_for_graph_lab() {
    let temp = tempfile::tempdir().unwrap();
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("binaries")
        .join("minimal_elf");
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::import_binary(
        project.connection(),
        revdeck_index::ImportOptions::new(temp.path().to_path_buf(), binary),
    )
    .unwrap();

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    assert!(snapshot
        .objects
        .keys()
        .any(|object_ref| object_ref.kind == ObjectKind::BasicBlock));
    assert!(snapshot
        .objects
        .keys()
        .any(|object_ref| object_ref.kind == ObjectKind::Instruction));
    assert!(snapshot.relations_by_object.values().any(|relations| {
        relations
            .iter()
            .any(|relation| relation.target.kind == ObjectKind::BasicBlock)
    }));
    assert!(snapshot.relations_by_object.values().any(|relations| {
        relations
            .iter()
            .any(|relation| relation.target.kind == ObjectKind::Instruction)
    }));
}

#[test]
fn project_snapshot_loads_artifact_scoped_analysis_jobs() {
    let temp = tempfile::tempdir().unwrap();
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("binaries")
        .join("minimal_elf");
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::import_binary(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();

    assert!(snapshot
        .analysis_jobs
        .iter()
        .any(|job| job.pass_name == "binary.parse" && job.status == "succeeded"));
    assert!(snapshot
        .analysis_jobs
        .iter()
        .any(|job| job.pass_name == "binary.triage" && job.status == "succeeded"));
    assert!(snapshot
        .analysis_jobs
        .iter()
        .any(|job| job.pass_name == "binary.linear" && job.status == "skipped"));
    assert!(snapshot
        .analysis_jobs
        .iter()
        .any(|job| job.pass_name == "binary.cfg" && job.status == "skipped"));
    assert!(snapshot
        .analysis_jobs
        .iter()
        .any(|job| job.pass_name == "binary.dataflow" && job.status == "skipped"));
    assert_eq!(snapshot.analysis_jobs_summary.failed, 0);
    assert_eq!(snapshot.analysis_jobs_summary.skipped, 3);
    let skipped = snapshot
        .analysis_jobs
        .iter()
        .find(|job| job.pass_name == "binary.cfg")
        .unwrap();
    assert!(skipped
        .parameter_items
        .iter()
        .any(|item| item.key == "profile" && item.value == "quick"));
    assert!(skipped
        .log_snippets
        .iter()
        .any(|snippet| snippet.contains("skipped")));

    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();
    let backend = TestBackend::new(150, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Analysis Jobs"));
    assert!(text.contains("triage"));
    assert!(text.contains("skipped"));
    assert!(text.contains("quick"));
}

#[test]
fn session_commands_persist_to_project_and_export_report() {
    let temp = tempfile::tempdir().unwrap();
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("binaries")
        .join("sensitive_imports_elf");
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::import_binary(
        project.connection(),
        revdeck_index::ImportOptions::new(temp.path().to_path_buf(), binary),
    )
    .unwrap();
    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let graph = graph(&snapshot);
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(
        TuiAction::SwitchLens(NavigationLens::FunctionRadar),
        &snapshot,
    )
    .unwrap();
    let function = app.selected.clone().unwrap();

    app.submit_command("tag current suspicious", &graph)
        .unwrap();
    app.submit_command("note current reviewed dangerous import", &graph)
        .unwrap();
    app.submit_command("finding new high command execution path", &graph)
        .unwrap();
    let finding = app.command_state.findings.keys().next().cloned().unwrap();
    app.submit_command(&format!("finding link {finding} current primary"), &graph)
        .unwrap();
    app.submit_command("export md reports/session.md", &graph)
        .unwrap();

    let summary = app
        .persist_session_to_connection(
            project.connection(),
            temp.path(),
            datetime!(2026-05-13 12:00 UTC),
        )
        .unwrap();

    assert_eq!(summary.annotations, 2);
    assert_eq!(summary.findings, 1);
    assert_eq!(summary.exports, 1);

    let annotations = MemoryRepository::new(project.connection())
        .list_annotations_for_subject(&function)
        .unwrap();
    assert_eq!(annotations.len(), 2);
    assert!(annotations.iter().any(|item| item.body == "suspicious"));
    assert!(annotations
        .iter()
        .any(|item| item.body == "reviewed dangerous import"));

    let findings = FindingRepository::new(project.connection())
        .list_findings()
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence[0].evidence, function);

    let report = std::fs::read_to_string(temp.path().join("reports/session.md")).unwrap();
    assert!(report.contains("command execution path"));
    assert!(report.contains("primary"));
}
