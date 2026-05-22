use assert_cmd::Command;
use revdeck_core::{
    EdgeKind, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectSearch, RelationDirection,
    StableObjectKey,
};
use revdeck_db::{
    AnalysisJobRepository, ArtifactRecord, ArtifactRepository, FunctionRecord, IndexRepository,
    ObjectQueryRepository, ObjectRepository, ProjectDatabase, StoredObject, TraceRepository,
};
use std::{path::PathBuf, sync::Once};
use tempfile::tempdir;
use time::macros::datetime;

static BUILD_REVDECK: Once = Once::new();

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture(path: &str) -> String {
    workspace_root().join(path).display().to_string()
}

fn revdeck_bin() -> PathBuf {
    BUILD_REVDECK.call_once(|| {
        Command::new("cargo")
            .current_dir(workspace_root())
            .args(["build", "-p", "revdeck-cli", "--bin", "revdeck"])
            .assert()
            .success();
    });
    let exe = if cfg!(windows) {
        "revdeck.exe"
    } else {
        "revdeck"
    };
    workspace_root().join("target").join("debug").join(exe)
}

fn seed_artifact(project: &ProjectDatabase) -> ObjectRef {
    let artifact = ObjectRef::artifact("trace123", "fixtures/traces/firmware.elf").unwrap();
    ArtifactRepository::new(project.connection())
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact.clone(),
            display_name: "trace-firmware".to_string(),
            source_path: "fixtures/traces/firmware.elf".to_string(),
            stored_path: None,
            sha256: "trace123".to_string(),
            size: 4096,
            kind: "binary".to_string(),
            format: "elf".to_string(),
            architecture: "x86_64".to_string(),
            import_status: "indexed".to_string(),
            created_at: datetime!(2026-05-23 00:00 UTC),
        })
        .unwrap();
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: artifact.clone(),
            artifact_key: None,
            display_name: Some("trace-firmware".to_string()),
            address: None,
            size: Some(4096),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    artifact
}

fn seed_function(project: &ProjectDatabase, artifact: &ObjectRef) -> ObjectRef {
    let object_ref = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, 0x401000, Some(0x80), Some("main")).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("main".to_string()),
            address: Some(0x401000),
            size: Some(0x80),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_function(&FunctionRecord {
            object_ref: object_ref.clone(),
            name: "main".to_string(),
            virtual_address: Some(0x401000),
            size: Some(0x80),
            boundary_source: "symbol".to_string(),
            boundary_confidence: "symbol".to_string(),
            call_count: 0,
            string_count: 0,
        })
        .unwrap();
    object_ref
}

#[test]
fn trace_lab_import_persists_timeline_correlation_and_job_metadata() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    let function = seed_function(&project, &artifact);
    let trace_path = fixture("fixtures/traces/minimal.jsonl");
    let jsonl = std::fs::read_to_string(&trace_path).unwrap();

    let outcome = TraceRepository::new(project.connection())
        .import_jsonl(
            &artifact,
            &trace_path,
            &jsonl,
            datetime!(2026-05-23 00:01 UTC),
        )
        .unwrap();

    assert_eq!(outcome.events_imported, 2);
    assert_eq!(outcome.correlated_events, 2);
    assert_eq!(outcome.malformed_lines, 0);
    assert_eq!(
        outcome.threads,
        vec!["main".to_string(), "worker".to_string()]
    );

    let trace_repo = TraceRepository::new(project.connection());
    let sessions = trace_repo
        .list_sessions_for_artifact(&artifact, 10)
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, "minimal");
    assert_eq!(sessions[0].event_count, 2);
    assert_eq!(sessions[0].thread_count, 2);

    let events = trace_repo
        .list_events_for_session(&outcome.session, 10)
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].thread_id, "main");
    assert_eq!(events[0].event_kind, "call");
    assert_eq!(events[0].timestamp_ns, Some(100));
    assert_eq!(events[0].address, Some(0x401000));
    assert_eq!(events[0].correlated.as_ref(), Some(&function));
    assert_eq!(events[1].thread_id, "worker");
    assert_eq!(events[1].function_name.as_deref(), Some("main"));

    let query = ObjectQueryRepository::new(project.connection());
    let trace_events = query
        .search_objects(&ObjectSearch::new(Some(ObjectKind::TraceEvent), "main"))
        .unwrap();
    assert_eq!(trace_events.len(), 2);

    let timeline = query
        .relations(
            &outcome.session,
            RelationDirection::Outgoing,
            Some(EdgeKind::Timeline),
        )
        .unwrap();
    assert_eq!(timeline.len(), 2);
    let correlation = query
        .relations(
            &trace_events[0].object_ref,
            RelationDirection::Outgoing,
            Some(EdgeKind::Correlates),
        )
        .unwrap();
    assert_eq!(correlation.len(), 1);
    assert_eq!(correlation[0].target, function);

    let jobs = AnalysisJobRepository::new(project.connection())
        .list_recent_for_artifact(&artifact, 10)
        .unwrap();
    let job = jobs
        .iter()
        .find(|job| job.pass_name == "trace.import")
        .expect("trace import job");
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.objects_produced, 3);
    assert_eq!(job.diagnostics_count, 0);
    let metadata: serde_json::Value = serde_json::from_str(&job.metadata_json).unwrap();
    assert_eq!(metadata["lab_id"], "trace");
    assert_eq!(metadata["events_imported"], 2);
    assert_eq!(metadata["correlated_events"], 2);
}

#[test]
fn trace_lab_malformed_jsonl_preserves_diagnostics_without_dropping_good_events() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    seed_function(&project, &artifact);
    let trace_path = fixture("fixtures/traces/malformed.jsonl");
    let jsonl = std::fs::read_to_string(&trace_path).unwrap();

    let outcome = TraceRepository::new(project.connection())
        .import_jsonl(
            &artifact,
            &trace_path,
            &jsonl,
            datetime!(2026-05-23 00:02 UTC),
        )
        .unwrap();

    assert_eq!(outcome.events_imported, 2);
    assert_eq!(outcome.correlated_events, 1);
    assert_eq!(outcome.malformed_lines, 1);
    assert_eq!(outcome.diagnostics.len(), 2);
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.contains("invalid JSONL")));
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.contains("address could not be parsed")));

    let events = TraceRepository::new(project.connection())
        .list_events_for_session(&outcome.session, 10)
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_id, "bad-address");
    assert_eq!(events[1].address, None);
    assert_eq!(events[1].correlated, None);
}

#[test]
fn trace_cli_import_and_status_emit_lab_json() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    seed_function(&project, &artifact);
    drop(project);

    let trace_path = fixture("fixtures/traces/minimal.jsonl");
    let output = Command::new(revdeck_bin())
        .args([
            "trace",
            "import",
            temp.path().to_str().unwrap(),
            &trace_path,
            "--artifact",
            &artifact.to_string(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["lab"], "trace");
    assert_eq!(json["label"], "Trace Lab");
    assert_eq!(json["events_imported"], 2);
    assert_eq!(json["correlated_events"], 2);
    assert_eq!(json["malformed_lines"], 0);
    assert_eq!(json["threads"].as_array().unwrap().len(), 2);

    let output = Command::new(revdeck_bin())
        .args([
            "trace",
            "status",
            temp.path().to_str().unwrap(),
            "--artifact",
            &artifact.to_string(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["lab"], "trace");
    assert_eq!(json["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(json["sessions"][0]["event_count"], 2);

    Command::new(revdeck_bin())
        .args(["trace", "--help"])
        .assert()
        .success();
}
