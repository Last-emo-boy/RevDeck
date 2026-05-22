use assert_cmd::Command;
use revdeck_core::{
    EdgeKind, FindingSeverity, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectSearch,
    RelationDirection, StableObjectKey,
};
use revdeck_db::{
    AnalysisJobRepository, ArtifactRecord, ArtifactRepository, CrashRepository, FindingRepository,
    FunctionRecord, IndexRepository, ObjectQueryRepository, ObjectRepository, ProjectDatabase,
    StoredObject,
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
    let artifact = ObjectRef::artifact("crash123", "fixtures/crashes/firmware.elf").unwrap();
    ArtifactRepository::new(project.connection())
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact.clone(),
            display_name: "crash-firmware".to_string(),
            source_path: "fixtures/crashes/firmware.elf".to_string(),
            stored_path: None,
            sha256: "crash123".to_string(),
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
            display_name: Some("crash-firmware".to_string()),
            address: None,
            size: Some(4096),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    artifact
}

fn seed_function(
    project: &ProjectDatabase,
    artifact: &ObjectRef,
    name: &str,
    address: u64,
    size: u64,
) -> ObjectRef {
    let object_ref = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, address, Some(size), Some(name)).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(name.to_string()),
            address: Some(address),
            size: Some(size),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_function(&FunctionRecord {
            object_ref: object_ref.clone(),
            name: name.to_string(),
            virtual_address: Some(address),
            size: Some(size),
            boundary_source: "symbol".to_string(),
            boundary_confidence: "symbol".to_string(),
            call_count: 0,
            string_count: 0,
        })
        .unwrap();
    object_ref
}

#[test]
fn crash_lab_import_persists_frames_correlation_clusters_and_findings() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    let main = seed_function(&project, &artifact, "main", 0x401000, 0x20);
    seed_function(&project, &artifact, "parse_request", 0x401040, 0x40);
    let crash_path = fixture("fixtures/crashes/asan_uaf.json");
    let crash_log = std::fs::read_to_string(&crash_path).unwrap();

    let outcome = CrashRepository::new(project.connection())
        .import_log(
            &artifact,
            &crash_path,
            &crash_log,
            datetime!(2026-05-23 00:04 UTC),
        )
        .unwrap();

    assert_eq!(outcome.frames_imported, 2);
    assert_eq!(outcome.correlated_frames, 2);
    assert_eq!(outcome.clustered_reports, 0);
    assert_eq!(outcome.findings_created, 1);
    assert!(outcome.signature.contains("heap-use-after-free"));

    let crash_repo = CrashRepository::new(project.connection());
    let reports = crash_repo.list_reports_for_artifact(&artifact, 10).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].crash_id, "asan-uaf-001");
    assert_eq!(reports[0].sanitizer, "asan");
    assert_eq!(reports[0].crash_class, "heap-use-after-free");
    assert_eq!(reports[0].signal.as_deref(), Some("SIGABRT"));
    assert_eq!(reports[0].frame_count, 2);
    assert_eq!(reports[0].correlated_frame_count, 2);

    let frames = crash_repo
        .list_frames_for_report(&outcome.report, 10)
        .unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].function_name.as_deref(), Some("main"));
    assert_eq!(frames[0].address, Some(0x401010));
    assert_eq!(frames[0].correlated.as_ref(), Some(&main));

    let query = ObjectQueryRepository::new(project.connection());
    let report_objects = query
        .search_objects(&ObjectSearch::new(
            Some(ObjectKind::CrashReport),
            "asan-uaf",
        ))
        .unwrap();
    assert_eq!(report_objects.len(), 1);
    let frame_objects = query
        .search_objects(&ObjectSearch::new(Some(ObjectKind::CrashFrame), "main"))
        .unwrap();
    assert_eq!(frame_objects.len(), 1);
    let contains = query
        .relations(
            &outcome.report,
            RelationDirection::Outgoing,
            Some(EdgeKind::Contains),
        )
        .unwrap();
    assert_eq!(contains.len(), 2);
    let correlation = query
        .relations(
            &frames[0].object_ref,
            RelationDirection::Outgoing,
            Some(EdgeKind::Correlates),
        )
        .unwrap();
    assert_eq!(correlation.len(), 1);
    assert_eq!(correlation[0].target, main);

    let findings = FindingRepository::new(project.connection())
        .list_findings()
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::High);
    assert_eq!(findings[0].evidence.len(), 2);
    assert!(findings[0]
        .evidence
        .iter()
        .any(|evidence| evidence.evidence.kind == ObjectKind::CrashFrame));

    let repeat_path = fixture("fixtures/crashes/asan_uaf_repeat.json");
    let repeat_log = std::fs::read_to_string(&repeat_path).unwrap();
    let repeat = CrashRepository::new(project.connection())
        .import_log(
            &artifact,
            &repeat_path,
            &repeat_log,
            datetime!(2026-05-23 00:05 UTC),
        )
        .unwrap();
    assert_eq!(repeat.frames_imported, 2);
    assert_eq!(repeat.correlated_frames, 2);
    assert_eq!(repeat.clustered_reports, 1);
    assert_eq!(repeat.signature, outcome.signature);
    let cluster = query
        .relations(
            &repeat.report,
            RelationDirection::Outgoing,
            Some(EdgeKind::ClustersWith),
        )
        .unwrap();
    assert_eq!(cluster.len(), 1);
    assert_eq!(cluster[0].target, outcome.report);

    let jobs = AnalysisJobRepository::new(project.connection())
        .list_recent_for_artifact(&artifact, 10)
        .unwrap();
    let job = jobs
        .iter()
        .find(|job| job.pass_name == "crash.import")
        .expect("crash import job");
    let metadata: serde_json::Value = serde_json::from_str(&job.metadata_json).unwrap();
    assert_eq!(metadata["lab_id"], "crash");
    assert!(metadata["frames_imported"].as_u64().unwrap() >= 2);
}

#[test]
fn crash_lab_text_fallback_imports_panic_stack_without_high_risk_finding() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    let main = seed_function(&project, &artifact, "main", 0x401000, 0x20);
    let crash_path = fixture("fixtures/crashes/panic.txt");
    let crash_log = std::fs::read_to_string(&crash_path).unwrap();

    let outcome = CrashRepository::new(project.connection())
        .import_log(
            &artifact,
            &crash_path,
            &crash_log,
            datetime!(2026-05-23 00:06 UTC),
        )
        .unwrap();

    assert_eq!(outcome.frames_imported, 2);
    assert_eq!(outcome.correlated_frames, 1);
    assert_eq!(outcome.findings_created, 0);
    let reports = CrashRepository::new(project.connection())
        .list_reports_for_artifact(&artifact, 10)
        .unwrap();
    assert_eq!(reports[0].sanitizer, "panic");
    assert_eq!(reports[0].crash_class, "panic");
    let frames = CrashRepository::new(project.connection())
        .list_frames_for_report(&outcome.report, 10)
        .unwrap();
    assert_eq!(frames[0].correlated.as_ref(), Some(&main));
}

#[test]
fn crash_cli_import_and_status_emit_lab_json() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    seed_function(&project, &artifact, "main", 0x401000, 0x80);
    drop(project);

    let crash_path = fixture("fixtures/crashes/asan_uaf.json");
    let output = Command::new(revdeck_bin())
        .args([
            "crash",
            "import",
            temp.path().to_str().unwrap(),
            &crash_path,
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
    assert_eq!(json["lab"], "crash");
    assert_eq!(json["label"], "Crash Lab");
    assert_eq!(json["frames_imported"], 2);
    assert_eq!(json["correlated_frames"], 2);
    assert_eq!(json["findings_created"], 1);
    assert!(json["signature"]
        .as_str()
        .unwrap()
        .contains("heap-use-after-free"));

    let output = Command::new(revdeck_bin())
        .args([
            "crash",
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
    assert_eq!(json["lab"], "crash");
    assert_eq!(json["reports"].as_array().unwrap().len(), 1);
    assert_eq!(json["reports"][0]["crash_class"], "heap-use-after-free");
    assert_eq!(json["reports"][0]["frames"].as_array().unwrap().len(), 2);

    Command::new(revdeck_bin())
        .args(["crash", "--help"])
        .assert()
        .success();
}
