use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use revdeck_core::{
    AnalysisJobRow, AnalysisJobsSummary, EdgeKind, InMemoryObjectGraph, NavigationLens,
    ObjectGraphQuery, ObjectKind, ObjectRef, ObjectRelation, ObjectSummary, StableObjectKey,
    StableObjectKeyBuilder,
};
use revdeck_db::{
    FindingRepository, IndexRepository, MemoryRepository, ObjectQueryRepository, ObjectRepository,
    ProjectDatabase, SectionRecord, StoredObject, StringRecord,
};
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

fn normalized_text(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ('\u{2500}'..='\u{257f}').contains(&ch) {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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
    let backend = TestBackend::new(120, 46);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Command Deck"));
    assert!(text.contains("Navigation"));
    assert!(text.contains("D diff"));
    assert!(text.contains(":find string password"));
    assert!(text.contains(":hex-search window"));
    assert!(text.contains("file + window offsets"));
    assert!(text.contains(":hex-find full file"));
    assert!(text.contains("text escapes"));
    assert!(text.contains(r#"\\ \" \' \n \r \t \0 \xNN"#));
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

    let backend = TestBackend::new(120, 48);
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
    let edge_cursor = snapshot
        .local_graph_model(&root, revdeck_core::RelationFilter::All, 2, 64)
        .unwrap()
        .path_rows
        .len();
    app.main_cursor = edge_cursor;

    assert_eq!(app.selected.as_ref(), Some(&root));

    let backend = TestBackend::new(120, 48);
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
    assert!(text.contains(":hex current/selected or :hex-current"));
    assert!(text.contains(":hex-search / :bytes-search"));
    assert!(text.contains(":hex-find / :bytes-find"));
    assert!(text.contains("current Hex window"));
    assert!(text.contains("window +0x offset"));
    assert!(text.contains("scan full file bytes"));
    assert!(text.contains("0xde 0xad"));
    assert!(text.contains(r#"\\ \" \' \n \r \t \0 \xNN"#));

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
    assert!(failed_text.contains("Recovery: rerun --no-tui"));
    assert!(failed_text.contains("Cancel: no destructive action"));

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
    assert!(running_text.contains("Cancel: read-only until safe"));
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
    let backend = TestBackend::new(150, 36);
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
fn project_snapshot_loads_hex_view_before_full_indexing() {
    let temp = tempfile::tempdir().unwrap();
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("binaries")
        .join("minimal_elf");
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();

    assert_eq!(snapshot.overview.import_status, "pending");
    assert_eq!(snapshot.analysis_jobs_summary.running, 1);
    assert!(!snapshot.hex.rows.is_empty());
    assert_eq!(snapshot.hex.rows[0].offset, 0);
    assert!(snapshot.hex.rows[0].hex.starts_with("7f 45 4c 46"));

    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Hex), &snapshot)
        .unwrap();
    let backend = TestBackend::new(150, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Hex Viewer"));
    assert!(text.contains("7f 45 4c 46"));
    assert!(text.contains("read-only"));
}

#[test]
fn hex_viewer_supports_goto_and_window_search_commands() {
    let temp = tempfile::tempdir().unwrap();
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("binaries")
        .join("minimal_elf");
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":goto 0X20", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, 0x20);
    assert!(app.status_line.contains("hex file offset=0x00000020"));

    app.submit_project_command(":hex-search 01 00", &mut snapshot, &project)
        .unwrap();

    assert!(app.status_line.contains("hex search: match at file offset"));

    app.submit_project_command(":bytes-search 0X01 0X00", &mut snapshot, &project)
        .unwrap();

    assert!(app.status_line.contains("hex search: match at file offset"));
}

#[test]
fn hex_goto_reports_offset_argument_errors() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("goto-errors.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":goto", &mut snapshot, &project)
        .unwrap_err();
    assert_eq!(
        err.kind,
        revdeck_core::CommandDiagnosticKind::MissingArgument
    );
    assert!(err.message.contains("missing required argument `offset`"));

    let err = app
        .submit_project_command(":goto nope", &mut snapshot, &project)
        .unwrap_err();
    assert_eq!(err.kind, revdeck_core::CommandDiagnosticKind::InvalidSyntax);
    assert!(err.message.contains("invalid byte offset `nope`"));
}

#[test]
fn hex_viewer_file_find_scans_beyond_loaded_window() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("wide-search.bin");
    let mut bytes = vec![0_u8; 640];
    bytes[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    bytes[0x180..0x184].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-search ca fe ba be", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0);
    assert!(app
        .status_line
        .contains("hex search: no match for ca fe ba be"));
    assert!(app
        .status_line
        .contains("scanned 256/640 bytes in current window 0x00000000-0x000000ff"));
    assert!(app.status_line.contains("try :hex-find ca fe ba be"));

    app.submit_project_command(":hex-find ca fe ba be", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, 0x180);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000180"));
    assert!(app.status_line.contains("scanned 640/640 bytes in 1 chunk"));
    assert_eq!(app.main_cursor, 0);

    app.submit_project_command(":bytes-find ff ee dd cc", &mut snapshot, &project)
        .unwrap();

    assert!(app
        .status_line
        .contains("hex find: no match for ff ee dd cc"));
    assert!(app.status_line.contains("scanned 640/640 bytes in 1 chunk"));

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let hex_jobs = snapshot
        .analysis_jobs
        .iter()
        .filter(|job| job.pass_name == "hex.find")
        .collect::<Vec<_>>();
    assert_eq!(hex_jobs.len(), 2);
    assert!(hex_jobs.iter().any(|job| job.status == "succeeded"));
    assert!(hex_jobs.iter().any(|job| job.status == "skipped"));
    let success = hex_jobs
        .iter()
        .find(|job| job.status == "succeeded")
        .expect("successful hex.find job");
    assert!(success.metadata_summary.contains("needle=ca fe ba be"));
    assert!(success.metadata_summary.contains("mode=auto"));
    assert!(success.metadata_summary.contains("len=4"));
    assert!(success.metadata_summary.contains("result=match"));
    assert!(success.metadata_summary.contains("offset=0x00000180"));
    assert!(success.metadata_summary.contains("scanned=640/640"));
    assert!(success.metadata_summary.contains("chunks=1 chunk"));
    assert!(success
        .metadata_items
        .iter()
        .any(|item| item.key == "result" && item.value == "match"));
    assert!(success
        .parameter_items
        .iter()
        .any(|item| item.key == "offset_space" && item.value == "file"));
    assert!(success
        .parameter_items
        .iter()
        .any(|item| item.key == "bytes_scanned" && item.value == "640"));
    assert!(success
        .parameter_items
        .iter()
        .any(|item| item.key == "chunk_count" && item.value == "1"));
    let skipped = hex_jobs
        .iter()
        .find(|job| job.status == "skipped")
        .expect("skipped hex.find job");
    assert_eq!(skipped.progress, "640/640");
    assert!(skipped.metadata_summary.contains("needle=ff ee dd cc"));
    assert!(skipped.metadata_summary.contains("mode=auto"));
    assert!(skipped.metadata_summary.contains("len=4"));
    assert!(skipped.metadata_summary.contains("result=no_match"));
    assert!(skipped.metadata_summary.contains("scanned=640/640"));
    assert!(skipped.metadata_summary.contains("chunks=1 chunk"));
    assert!(skipped
        .metadata_items
        .iter()
        .any(|item| item.key == "result" && item.value == "no_match"));
    assert!(skipped
        .parameter_items
        .iter()
        .any(|item| item.key == "bytes_scanned" && item.value == "640"));
}

#[test]
fn hex_search_window_summary_uses_short_file_bounds() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("short-window.bin");
    std::fs::write(&binary, b"short-window-data").unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-search ff ee", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0);
    assert!(app.status_line.contains("hex search: no match for ff ee"));
    assert!(app
        .status_line
        .contains("scanned 17/17 bytes in current window 0x00000000-0x00000010"));
}

#[test]
fn hex_search_window_summary_handles_empty_file() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("empty-window.bin");
    std::fs::write(&binary, []).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-search ff", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.file_size, Some(0));
    assert!(snapshot.hex.rows.is_empty());
    assert!(app.status_line.contains("hex search: no match for ff"));
    assert!(app
        .status_line
        .contains("scanned 0/0 bytes in current window 0x00000000-0x00000000"));
}

#[test]
fn hex_viewer_file_find_reports_multi_chunk_scans() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("multi-chunk-search.bin");
    let match_offset = 0x10020;
    let mut bytes = vec![0_u8; 0x10080];
    bytes[match_offset..match_offset + 4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find hex:ca fe ba be", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, match_offset as u64);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00010020"));
    assert!(app
        .status_line
        .contains("scanned 65664/65664 bytes in 2 chunks"));

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let job_index = snapshot
        .analysis_jobs
        .iter()
        .position(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be present");
    let job = &snapshot.analysis_jobs[job_index];
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.progress, "65664/65664");
    assert!(job.metadata_summary.contains("needle=hex:ca fe ba be"));
    assert!(job.metadata_summary.contains("mode=hex"));
    assert!(job.metadata_summary.contains("len=4"));
    assert!(job.metadata_summary.contains("result=match"));
    assert!(job.metadata_summary.contains("offset=0x00010020"));
    assert!(job.metadata_summary.contains("scanned=65664/65664"));
    assert!(job.metadata_summary.contains("chunks=2 chunks"));
    assert!(job
        .parameter_items
        .iter()
        .any(|item| item.key == "bytes_scanned" && item.value == "65664"));
    assert!(job
        .parameter_items
        .iter()
        .any(|item| item.key == "chunk_count" && item.value == "2"));

    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();
    app.main_cursor = job_index;
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();
    let backend = TestBackend::new(150, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    let normalized = normalized_text(&text);

    assert!(text.contains("Needle: hex:ca fe ba be"));
    assert!(normalized.contains("Scanned: 65664/65664 bytes in 2 chunks"));
    assert!(text.contains("Result: match"));
    assert!(text.contains("Result offset: 0x00010020"));
}

#[test]
fn hex_viewer_file_find_matches_needle_across_chunk_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("chunk-boundary-search.bin");
    let match_offset = 0xfffe;
    let mut bytes = vec![0_u8; 0x10040];
    bytes[match_offset..match_offset + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find de ad be ef", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, match_offset as u64);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x0000fffe"));
    assert!(app
        .status_line
        .contains("scanned 65600/65600 bytes in 2 chunks"));

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let job = snapshot
        .analysis_jobs
        .iter()
        .find(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be present");
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.progress, "65600/65600");
    assert!(job.metadata_summary.contains("needle=de ad be ef"));
    assert!(job.metadata_summary.contains("mode=auto"));
    assert!(job.metadata_summary.contains("len=4"));
    assert!(job.metadata_summary.contains("result=match"));
    assert!(job.metadata_summary.contains("offset=0x0000fffe"));
    assert!(job.metadata_summary.contains("scanned=65600/65600"));
    assert!(job.metadata_summary.contains("chunks=2 chunks"));
    assert!(job
        .parameter_items
        .iter()
        .any(|item| item.key == "chunk_count" && item.value == "2"));
}

#[test]
fn hex_search_status_preserves_explicit_text_needle_label() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("text-label.bin");
    std::fs::write(&binary, vec![0_u8; 256]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-search text:\"not present\"", &mut snapshot, &project)
        .unwrap();

    assert!(app
        .status_line
        .contains("hex search: no match for text:\"not present\""));
    assert!(app
        .status_line
        .contains("try :hex-find text:\"not present\""));

    app.submit_project_command(":hex-find text:\"not present\"", &mut snapshot, &project)
        .unwrap();

    assert!(app
        .status_line
        .contains("hex find: no match for text:\"not present\""));
    assert!(app.status_line.contains("scanned 256/256 bytes in 1 chunk"));
    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let job = snapshot
        .analysis_jobs
        .iter()
        .find(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be recorded");
    assert!(job
        .metadata_items
        .iter()
        .any(|item| item.key == "needle" && item.value == "text:\"not present\""));
    assert!(job
        .metadata_items
        .iter()
        .any(|item| item.key == "needle_mode" && item.value == "text"));
    assert!(job.metadata_summary.contains("mode=text"));
    assert!(job.metadata_summary.contains("len=11"));
}

#[test]
fn hex_search_supports_explicit_text_and_hex_needles() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("needle-modes.bin");
    let mut bytes = vec![0_u8; 512];
    bytes[0x80..0x84].copy_from_slice(b"dead");
    bytes[0xc0..0xce].copy_from_slice(b"admin password");
    bytes[0x120..0x122].copy_from_slice(&[0xde, 0xad]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find text:dead", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x80);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000080"));

    app.submit_project_command(":hex-find hex:0XDE 0XAD", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x120);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000120"));

    app.submit_project_command(":hex-find raw:de ad", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x120);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000120"));

    app.submit_project_command(":hex-find text:\"admin password\"", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0xc0);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x000000c0"));

    app.submit_project_command(
        ":hex-find string:\"admin password\"",
        &mut snapshot,
        &project,
    )
    .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0xc0);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x000000c0"));

    app.submit_project_command(":hex-find admin password", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0xc0);
    assert!(app.status_line.contains(
        "hex find: match at file offset 0x000000c0 for 61 64 6d 69 6e 20 70 61 73 73 77 6f 72 64"
    ));

    app.submit_project_command(":hex-find str:dead", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x80);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000080"));
}

#[test]
fn hex_search_decodes_quoted_text_escape_sequences() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("escaped-text-needles.bin");
    let mut bytes = vec![0_u8; 768];
    bytes[0x100..0x10c].copy_from_slice(br#"admin "root""#);
    bytes[0x180..0x18c].copy_from_slice(br#"path\to\file"#);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(
        ":hex-find text:\"admin \\\"root\\\"\"",
        &mut snapshot,
        &project,
    )
    .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x100);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000100"));

    app.submit_project_command(
        ":hex-find string:\"path\\\\to\\\\file\"",
        &mut snapshot,
        &project,
    )
    .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x180);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000180"));

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    assert!(snapshot.analysis_jobs.iter().any(|job| {
        job.pass_name == "hex.find"
            && job
                .metadata_summary
                .contains("needle=text:\"admin \\\"root\\\"\"")
            && job.metadata_summary.contains("mode=text")
            && job.metadata_summary.contains("len=12")
            && job.metadata_summary.contains("offset=0x00000100")
    }));
    assert!(snapshot.analysis_jobs.iter().any(|job| {
        job.pass_name == "hex.find"
            && job
                .metadata_summary
                .contains("needle=text:\"path\\\\to\\\\file\"")
            && job.metadata_summary.contains("mode=text")
            && job.metadata_summary.contains("len=12")
            && job.metadata_summary.contains("offset=0x00000180")
    }));
}

#[test]
fn hex_search_decodes_quoted_text_control_escapes() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("escaped-control-text.bin");
    let mut bytes = vec![0_u8; 768];
    bytes[0x220..0x230].copy_from_slice(b"line1\nline2\tend\r");
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(
        ":hex-find text:\"line1\\nline2\\tend\\r\"",
        &mut snapshot,
        &project,
    )
    .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x220);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000220"));
    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let job = snapshot
        .analysis_jobs
        .iter()
        .find(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be recorded");
    assert!(job
        .metadata_summary
        .contains("needle=text:\"line1\\nline2\\tend\\r\""));
    assert!(job.metadata_summary.contains("mode=text"));
    assert!(job.metadata_summary.contains("len=16"));
    assert!(job.metadata_summary.contains("offset=0x00000220"));
}

#[test]
fn hex_search_decodes_quoted_text_hex_byte_escapes() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("escaped-hex-byte-text.bin");
    let mut bytes = vec![0_u8; 768];
    bytes[0x40..0x45].copy_from_slice(b"MZ\0PE");
    bytes[0x120..0x125].copy_from_slice(&[b'A', b'P', b'I', 0xff, b'!']);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex 0x40", &mut snapshot, &project)
        .unwrap();
    app.submit_project_command(":hex-search text:\"MZ\\0PE\"", &mut snapshot, &project)
        .unwrap();

    assert!(app.status_line.contains(
        "hex search: match at file offset 0x00000040 (window +0x0) for text:\"MZ\\x00PE\""
    ));
    assert!(app
        .status_line
        .contains("scanned 256/768 bytes in current window 0x00000040-0x0000013f"));

    app.submit_project_command(":hex-search text:\"MZ\\x00PE\"", &mut snapshot, &project)
        .unwrap();

    assert!(app.status_line.contains(
        "hex search: match at file offset 0x00000040 (window +0x0) for text:\"MZ\\x00PE\""
    ));
    assert!(app
        .status_line
        .contains("scanned 256/768 bytes in current window 0x00000040-0x0000013f"));

    app.submit_project_command(":hex-search text:\"API\\xff!\"", &mut snapshot, &project)
        .unwrap();

    assert!(app.status_line.contains(
        "hex search: match at file offset 0x00000120 (window +0xe0) for text:\"API\\xff!\""
    ));
    assert!(app
        .status_line
        .contains("scanned 256/768 bytes in current window 0x00000040-0x0000013f"));

    app.submit_project_command(":hex-find text:\"API\\xff!\"", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x120);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000120 for text:\"API\\xff!\""));
    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let job = snapshot
        .analysis_jobs
        .iter()
        .find(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be recorded");
    assert!(job.metadata_summary.contains("needle=text:\"API\\xff!\""));
    assert!(job.metadata_summary.contains("mode=text"));
    assert!(job.metadata_summary.contains("len=5"));
    assert!(job.metadata_summary.contains("offset=0x00000120"));
}

#[test]
fn hex_search_keeps_malformed_hex_byte_escapes_literal() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("literal-malformed-hex-byte-text.bin");
    let mut bytes = vec![0_u8; 512];
    bytes[0x160..0x167].copy_from_slice(br"bad\xZZ");
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find text:\"bad\\xZZ\"", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x160);
    assert!(app
        .status_line
        .contains("hex find: match at file offset 0x00000160"));
    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let job = snapshot
        .analysis_jobs
        .iter()
        .find(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be recorded");
    assert!(job.metadata_summary.contains("needle=text:\"bad\\\\xZZ\""));
    assert!(job.metadata_summary.contains("mode=text"));
    assert!(job.metadata_summary.contains("len=7"));
    assert!(job.metadata_summary.contains("offset=0x00000160"));
}

#[test]
fn hex_search_rejects_invalid_explicit_hex_needle() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("invalid-needle.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":hex-find hex:zz", &mut snapshot, &project)
        .unwrap_err();

    assert_eq!(err.kind, revdeck_core::CommandDiagnosticKind::InvalidSyntax);
    assert!(err.message.contains("invalid hex search needle"));
}

#[test]
fn hex_search_rejects_empty_explicit_text_needle() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("empty-text-needle.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":hex-find text:\"\"", &mut snapshot, &project)
        .unwrap_err();

    assert_eq!(
        err.kind,
        revdeck_core::CommandDiagnosticKind::MissingArgument
    );
    assert!(err.message.contains("missing required argument `needle`"));
}

#[test]
fn hex_search_rejects_empty_explicit_hex_needle_as_missing_argument() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("empty-hex-needle.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":hex-find hex:", &mut snapshot, &project)
        .unwrap_err();

    assert_eq!(
        err.kind,
        revdeck_core::CommandDiagnosticKind::MissingArgument
    );
    assert!(err.message.contains("missing required argument `needle`"));
}

#[test]
fn hex_search_rejects_empty_explicit_raw_needle_as_missing_argument() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("empty-raw-needle.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":hex-find raw:", &mut snapshot, &project)
        .unwrap_err();

    assert_eq!(
        err.kind,
        revdeck_core::CommandDiagnosticKind::MissingArgument
    );
    assert!(err.message.contains("missing required argument `needle`"));
}

#[test]
fn hex_search_supports_case_insensitive_explicit_needle_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("case-prefix-needle.bin");
    let mut bytes = vec![0_u8; 512];
    bytes[0x90..0x95].copy_from_slice(b"Admin");
    bytes[0x150..0x152].copy_from_slice(&[0xde, 0xad]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find TEXT:Admin", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x90);

    app.submit_project_command(":hex-find ascii:Admin", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x90);

    app.submit_project_command(":hex-find HEX:de ad", &mut snapshot, &project)
        .unwrap();

    assert_eq!(snapshot.hex.base_offset, 0x150);
}

#[test]
fn hex_search_rejects_empty_explicit_ascii_needle_as_missing_argument() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("empty-ascii-needle.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":hex-find ascii:", &mut snapshot, &project)
        .unwrap_err();

    assert_eq!(
        err.kind,
        revdeck_core::CommandDiagnosticKind::MissingArgument
    );
    assert!(err.message.contains("missing required argument `needle`"));
}

#[test]
fn hex_search_rejects_empty_explicit_string_needle_as_missing_argument() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("empty-string-needle.bin");
    std::fs::write(&binary, vec![0_u8; 128]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    let err = app
        .submit_project_command(":hex-find string:", &mut snapshot, &project)
        .unwrap_err();

    assert_eq!(
        err.kind,
        revdeck_core::CommandDiagnosticKind::MissingArgument
    );
    assert!(err.message.contains("missing required argument `needle`"));
}

#[test]
fn hex_search_job_is_visible_in_jobs_inspector() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("hex-job.bin");
    let mut bytes = vec![0_u8; 640];
    bytes[0x180..0x184].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find ca fe ba be", &mut snapshot, &project)
        .unwrap();

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();
    app.main_cursor = snapshot
        .analysis_jobs
        .iter()
        .position(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be present");
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();
    let backend = TestBackend::new(150, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    let normalized = normalized_text(&text);

    assert!(text.contains("hex.find"));
    assert!(text.contains("Hex search job"));
    assert!(text.contains("Needle: ca fe ba be"));
    assert!(text.contains("Needle mode: auto"));
    assert!(text.contains("Needle length: 4 bytes"));
    assert!(text.contains("Offset space: file"));
    assert!(normalized.contains("Scanned: 640/640 bytes in 1 chunk"));
    assert!(text.contains("Result: match"));
    assert!(text.contains("Result navigation: :hex 0x180"));
    assert!(text.contains("Result offset: 0x00000180"));
    assert!(text.contains("Cancel state: not_requested"));
}

#[test]
fn hex_search_skipped_job_shows_no_match_in_jobs_inspector() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("hex-no-match-job.bin");
    std::fs::write(&binary, vec![0_u8; 320]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex-find hex:ff ee", &mut snapshot, &project)
        .unwrap();

    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Jobs), &snapshot)
        .unwrap();
    app.main_cursor = snapshot
        .analysis_jobs
        .iter()
        .position(|job| job.pass_name == "hex.find")
        .expect("hex.find job should be present");
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();
    let backend = TestBackend::new(150, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);
    let normalized = normalized_text(&text);

    assert!(text.contains("hex.find"));
    assert!(text.contains("Needle: hex:ff ee"));
    assert!(text.contains("Needle mode: hex"));
    assert!(normalized.contains("Scanned: 320/320 bytes in 1 chunk"));
    assert!(text.contains("Result: no match"));
    assert!(text.contains("Result navigation: no match"));
}

#[test]
fn hex_viewer_can_jump_from_selected_object_file_offset() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("offset-sync.bin");
    std::fs::write(&binary, vec![0_u8; 512]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("registered artifact");
    let offset_object = ObjectRef::new(
        ObjectKind::String,
        StableObjectKey::string(&artifact.key, 0x120, None, "offset marker").unwrap(),
    );
    snapshot.strings = vec![ObjectSummary {
        object_ref: offset_object.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("offset marker".to_string()),
        address: None,
        size: Some(12),
        metadata_json: r#"{"file_offset":288,"encoding":"ascii"}"#.to_string(),
    }];
    snapshot
        .objects
        .insert(offset_object.clone(), snapshot.strings[0].clone());
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Strings), &snapshot)
        .unwrap();

    app.submit_project_command(":hex-current", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, 0x120);
    assert!(app
        .status_line
        .contains("hex current: match at file offset 0x00000120"));
}

#[test]
fn hex_viewer_can_jump_from_real_indexed_string_offset() {
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
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let indexed_string = snapshot
        .strings
        .iter()
        .find(|summary| {
            serde_json::from_str::<serde_json::Value>(&summary.metadata_json)
                .ok()
                .and_then(|metadata| metadata.get("file_offset").and_then(|value| value.as_u64()))
                .is_some()
        })
        .cloned()
        .expect("indexed fixture should expose at least one string file offset");
    let metadata: serde_json::Value = serde_json::from_str(&indexed_string.metadata_json).unwrap();
    let offset = metadata["file_offset"].as_u64().unwrap();
    assert_eq!(metadata["offset_space"], "file");

    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Strings), &snapshot)
        .unwrap();
    app.main_cursor = snapshot
        .strings
        .iter()
        .position(|summary| summary.object_ref == indexed_string.object_ref)
        .unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::PreviousRow, &snapshot).unwrap();

    app.submit_project_command(":hex selected", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, offset);
    assert!(app
        .status_line
        .contains(&format!("hex current: match at file offset 0x{offset:08x}")));
}

#[test]
fn real_indexed_section_summaries_expose_file_offset_metadata() {
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
    let query = ObjectQueryRepository::new(project.connection());
    let sections = query
        .search_objects(
            &revdeck_core::ObjectSearch::new(Some(ObjectKind::Section), "").with_limit(64),
        )
        .unwrap();
    let section = sections
        .iter()
        .find(|summary| {
            serde_json::from_str::<serde_json::Value>(&summary.metadata_json)
                .ok()
                .and_then(|metadata| metadata.get("file_offset").and_then(|value| value.as_u64()))
                .is_some()
        })
        .expect("indexed fixture should expose at least one section file offset");
    let metadata: serde_json::Value = serde_json::from_str(&section.metadata_json).unwrap();

    assert_eq!(metadata["offset_space"], "file");
    assert!(metadata["file_offset"].as_u64().is_some());
}

#[test]
fn hex_viewer_maps_selected_va_to_file_offset_with_section_evidence() {
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
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let function = snapshot
        .functions
        .iter()
        .find(|summary| summary.address.is_some())
        .cloned()
        .expect("indexed fixture should expose at least one function VA");
    let ranges = IndexRepository::new(project.connection())
        .section_offset_mappings(snapshot.overview.artifact.as_ref().unwrap())
        .unwrap();
    let expected = revdeck_core::map_va_to_file_offset(function.address.unwrap(), &ranges)
        .file_offset
        .expect("function VA should map through indexed section ranges");

    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Functions), &snapshot)
        .unwrap();
    app.main_cursor = snapshot
        .functions
        .iter()
        .position(|summary| summary.object_ref == function.object_ref)
        .unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::PreviousRow, &snapshot).unwrap();

    app.submit_project_command(":hex current", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.base_offset, expected);
    assert!(app.status_line.contains("mapped VA"));
    assert!(app
        .status_line
        .contains(&format!("file offset 0x{expected:08x}")));
}

#[test]
fn hex_viewer_current_does_not_treat_virtual_address_as_file_offset() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("va-only.bin");
    std::fs::write(&binary, vec![0_u8; 512]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("registered artifact");
    let va_object = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, 0x401000, Some(16), Some("va_only")).unwrap(),
    );
    snapshot.functions = vec![ObjectSummary {
        object_ref: va_object.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("va_only".to_string()),
        address: Some(0x401000),
        size: Some(16),
        metadata_json: r#"{"virtual_address":4198400,"boundary_confidence":"symbol"}"#.to_string(),
    }];
    snapshot
        .objects
        .insert(va_object.clone(), snapshot.functions[0].clone());
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Functions), &snapshot)
        .unwrap();

    app.submit_project_command(":open-hex current", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Functions);
    assert_eq!(snapshot.hex.base_offset, 0);
    assert!(app
        .status_line
        .contains("no indexed section ranges can prove"));
}

#[test]
fn hex_viewer_refuses_ambiguous_va_to_file_offset_mapping() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("ambiguous-va.bin");
    std::fs::write(&binary, vec![0_u8; 1024]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("registered artifact");
    let function = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, 0x401040, Some(16), Some("ambiguous")).unwrap(),
    );
    snapshot.functions = vec![ObjectSummary {
        object_ref: function.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("ambiguous".to_string()),
        address: Some(0x401040),
        size: Some(16),
        metadata_json: r#"{"boundary_confidence":"synthetic"}"#.to_string(),
    }];
    snapshot
        .objects
        .insert(function.clone(), snapshot.functions[0].clone());
    let index_repo = IndexRepository::new(project.connection());
    let object_repo = ObjectRepository::new(project.connection());
    for (name, va, offset) in [(".text", 0x401000, 0x200), (".overlap", 0x401020, 0x300)] {
        let section = ObjectRef::new(
            ObjectKind::Section,
            StableObjectKey::section(&artifact.key, name, va, 0x80).unwrap(),
        );
        object_repo
            .upsert_object(&StoredObject {
                object_ref: section.clone(),
                artifact_key: Some(artifact.key.to_string()),
                display_name: Some(name.to_string()),
                address: Some(va),
                size: Some(0x80),
                source_run_id: None,
                metadata_json: "{}".to_string(),
            })
            .unwrap();
        index_repo
            .upsert_section(&SectionRecord {
                object_ref: section,
                name: name.to_string(),
                virtual_address: Some(va),
                file_offset: Some(offset),
                size: 0x80,
                flags: "AX".to_string(),
                entropy: None,
            })
            .unwrap();
    }
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Functions), &snapshot)
        .unwrap();

    app.submit_project_command(":hex current", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Functions);
    assert_eq!(snapshot.hex.base_offset, 0);
    assert!(app.status_line.contains("multiple indexed sections"));
}

#[test]
fn hex_viewer_persists_bookmarks_and_byte_notes() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("byte-notes.bin");
    std::fs::write(&binary, vec![0_u8; 512]).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let artifact = snapshot
        .hex
        .artifact
        .clone()
        .expect("registered artifact should be loaded in hex view");
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.submit_project_command(":hex 0x20", &mut snapshot, &project)
        .unwrap();

    app.submit_project_command(
        ":hex-bookmark current packet-header",
        &mut snapshot,
        &project,
    )
    .unwrap();
    app.submit_project_command(
        ":hex-note current review alignment",
        &mut snapshot,
        &project,
    )
    .unwrap();

    let subject = ObjectRef::new(
        ObjectKind::Annotation,
        StableObjectKeyBuilder::new(ObjectKind::Annotation)
            .component("artifact", artifact.key.as_str())
            .unwrap()
            .component("hex_offset", "0000000000000020")
            .unwrap()
            .finish()
            .unwrap(),
    );
    let annotations = MemoryRepository::new(project.connection())
        .list_annotations_for_subject(&subject)
        .unwrap();

    assert_eq!(annotations.len(), 2);
    assert!(annotations.iter().any(|item| item.body == "packet-header"));
    assert!(annotations
        .iter()
        .any(|item| item.body == "review alignment"));
    assert!(app.status_line.contains("hex note: 0x00000020 noted"));
}

#[test]
fn hex_viewer_renders_persisted_byte_markers_without_shifting_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("byte-markers.bin");
    let mut bytes = vec![0_u8; 512];
    bytes[0x20..0x24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.submit_project_command(":hex 0x20", &mut snapshot, &project)
        .unwrap();

    app.submit_project_command(
        ":hex-bookmark current packet-header",
        &mut snapshot,
        &project,
    )
    .unwrap();
    app.submit_project_command(
        ":hex-note current review alignment",
        &mut snapshot,
        &project,
    )
    .unwrap();

    let marked_row = snapshot
        .hex
        .rows
        .iter()
        .find(|row| row.offset == 0x20)
        .expect("selected row should remain visible");
    assert_eq!(marked_row.marker, "1/1");
    assert!(marked_row.hex.starts_with("de ad be ef"));

    let reloaded = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let reloaded_row = reloaded
        .hex
        .rows
        .iter()
        .find(|row| row.offset == 0x20)
        .expect("reloaded window should include the marked row");
    assert_eq!(reloaded_row.marker, "1/1");
    assert!(reloaded_row.hex.starts_with("de ad be ef"));

    let mut app = TuiShellState::from_snapshot(&reloaded);
    app.apply_action(TuiAction::SwitchLens(NavigationLens::Hex), &reloaded)
        .unwrap();
    app.main_cursor = reloaded
        .hex
        .rows
        .iter()
        .position(|row| row.offset == 0x20)
        .unwrap();
    let backend = TestBackend::new(150, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &reloaded))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("mk"));
    assert!(text.contains("offset"));
    assert!(text.contains("1/1"));
    assert!(text.contains("0x00000020"));
    assert!(text.contains("de ad be ef"));
}

#[test]
fn hex_inspector_shows_selected_offset_notes_source_and_nearby_objects() {
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
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let string = snapshot
        .strings
        .iter()
        .find_map(|summary| {
            let metadata: serde_json::Value = serde_json::from_str(&summary.metadata_json).ok()?;
            let offset = metadata.get("file_offset")?.as_u64()?;
            Some((summary.clone(), offset))
        })
        .expect("fixture should expose a string file offset");
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.submit_project_command(&format!(":hex 0x{:x}", string.1), &mut snapshot, &project)
        .unwrap();
    app.submit_project_command(":hex-note current inspect marker", &mut snapshot, &project)
        .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);
    app.submit_project_command(&format!(":hex 0x{:x}", string.1), &mut snapshot, &project)
        .unwrap();
    app.main_cursor = snapshot
        .hex
        .rows
        .iter()
        .position(|row| row.offset == string.1)
        .unwrap_or(0);
    app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
        .unwrap();
    let backend = TestBackend::new(150, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workspace(frame, &app, &snapshot))
        .unwrap();
    let text = buffer_text(&terminal);

    assert!(text.contains("Hex Inspector"));
    assert!(text.contains(&format!("File offset: 0x{:08x}", string.1)));
    assert!(text.contains("Source path:"));
    assert!(text.contains("Byte notes"));
    assert!(text.contains("note: inspect marker"));
    assert!(text.contains("Nearby objects"));
    assert!(text.contains(string.0.label()));
}

#[test]
fn cross_lab_offsets_round_trip_through_hex_workflows() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("cross-offsets.bin");
    let mut bytes = vec![0_u8; 768];
    bytes[0x40..0x44].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[0x120..0x124].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    bytes[0x200..0x20e].copy_from_slice(b"admin password");
    std::fs::write(&binary, bytes).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let artifact = snapshot
        .overview
        .artifact
        .clone()
        .expect("registered artifact");
    let section = ObjectRef::new(
        ObjectKind::Section,
        StableObjectKey::section(&artifact.key, ".data", 0x402000, 0x80).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: section.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(".data".to_string()),
            address: Some(0x402000),
            size: Some(0x80),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_section(&SectionRecord {
            object_ref: section.clone(),
            name: ".data".to_string(),
            virtual_address: Some(0x402000),
            file_offset: Some(0x200),
            size: 0x80,
            flags: "WA".to_string(),
            entropy: None,
        })
        .unwrap();
    let string = ObjectRef::new(
        ObjectKind::String,
        StableObjectKey::string(&artifact.key, 0x200, Some(0x402000), "admin password").unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: string.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("admin password".to_string()),
            address: Some(0x402000),
            size: Some(14),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_string(&StringRecord {
            object_ref: string.clone(),
            value: "admin password".to_string(),
            virtual_address: Some(0x402000),
            file_offset: 0x200,
            length: 14,
            encoding: "ascii".to_string(),
        })
        .unwrap();
    let protocol = ObjectRef::lab_object(
        ObjectKind::ProtocolField,
        Some(&artifact.key),
        "protocol",
        "sample-1/message-1/credential",
    )
    .unwrap();
    let protocol_summary = ObjectSummary {
        object_ref: protocol.clone(),
        artifact_key: Some(artifact.key.to_string()),
        display_name: Some("credential".to_string()),
        address: None,
        size: Some(4),
        metadata_json:
            r#"{"lab_id":"protocol","name":"credential","byte_offset":288,"byte_length":4}"#
                .to_string(),
    };
    snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    snapshot.protocol_items.push(protocol_summary.clone());
    snapshot
        .objects
        .insert(protocol.clone(), protocol_summary.clone());
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.apply_action(TuiAction::SwitchLens(NavigationLens::Strings), &snapshot)
        .unwrap();
    app.main_cursor = snapshot
        .strings
        .iter()
        .position(|summary| summary.object_ref == string)
        .unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::PreviousRow, &snapshot).unwrap();
    app.submit_project_command(":hex current", &mut snapshot, &project)
        .unwrap();
    assert_eq!(snapshot.hex.base_offset, 0x200);
    assert!(app.status_line.contains("file offset 0x00000200"));

    app.apply_action(TuiAction::SwitchLens(NavigationLens::Protocol), &snapshot)
        .unwrap();
    app.main_cursor = snapshot
        .protocol_items
        .iter()
        .position(|summary| summary.object_ref == protocol)
        .unwrap();
    app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
    app.apply_action(TuiAction::PreviousRow, &snapshot).unwrap();
    app.submit_project_command(":hex current", &mut snapshot, &project)
        .unwrap();
    assert_eq!(snapshot.hex.base_offset, 0x120);
    assert!(app.status_line.contains("file offset 0x00000120"));

    app.submit_project_command(
        ":hex-note current protocol credential",
        &mut snapshot,
        &project,
    )
    .unwrap();
    assert_eq!(
        snapshot
            .hex
            .rows
            .iter()
            .find(|row| row.offset == 0x120)
            .unwrap()
            .marker,
        "N1"
    );

    app.submit_project_command(":hex-find de ad be ef", &mut snapshot, &project)
        .unwrap();
    assert_eq!(snapshot.hex.base_offset, 0x120);
    let snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    assert!(snapshot
        .analysis_jobs
        .iter()
        .any(|job| job.pass_name == "hex.find"
            && job.metadata_summary.contains("needle=de ad be ef")
            && job.metadata_summary.contains("result=match")
            && job.metadata_summary.contains("offset=0x00000120")));

    let sections = ObjectQueryRepository::new(project.connection())
        .search_objects(&revdeck_core::ObjectSearch::new(
            Some(ObjectKind::Section),
            ".data",
        ))
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&sections[0].metadata_json).unwrap();
    assert_eq!(metadata["file_offset"], 0x200);
    assert_eq!(metadata["offset_space"], "file");
}

#[test]
fn hex_viewer_clamps_large_file_goto_to_bounded_eof_window() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("large.bin");
    let file = std::fs::File::create(&binary).unwrap();
    file.set_len(2 * 1024 * 1024 + 123).unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    revdeck_index::register_binary_for_analysis(
        project.connection(),
        revdeck_index::ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary,
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let mut snapshot = WorkspaceSnapshot::load_from_project(&project).unwrap();
    let mut app = TuiShellState::from_snapshot(&snapshot);

    app.submit_project_command(":hex 0xffffffff", &mut snapshot, &project)
        .unwrap();

    assert_eq!(app.active_lens, NavigationLens::Hex);
    assert_eq!(snapshot.hex.file_size, Some(2 * 1024 * 1024 + 123));
    assert_eq!(snapshot.hex.base_offset, (2 * 1024 * 1024 + 123) - 256);
    assert_eq!(snapshot.hex.rows.len(), 16);
    assert!(snapshot.hex.rows[0].offset < 2 * 1024 * 1024 + 123);
    assert!(app.status_line.contains("rows=16"));
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
