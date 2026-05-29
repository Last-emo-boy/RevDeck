use assert_cmd::prelude::*;
use revdeck_core::{
    export_gate_summary, pre_export_validation, render_json, render_json_bundle, render_markdown,
    render_template_json, ExportBundle, Finding, FindingEvidence, FindingSeverity, FindingStatus,
    ObjectKind, ObjectRef, ReportTemplate, StableObjectKey,
};
use revdeck_db::{
    migrations::migrate, AnalysisJobRepository, ArtifactRecord, ArtifactRepository,
    FindingRepository, FunctionRecord, IndexRepository, MemoryRepository, NewAnalysisJob,
    NewPluginRun, ObjectRepository, PluginRunRepository, StoredObject,
};
use rusqlite::Connection;
use std::process::Command;
use std::{path::PathBuf, sync::Once};
use time::macros::datetime;

static BUILD_REVDECK: Once = Once::new();

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
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

fn migrated_connection() -> Connection {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate(&mut connection).unwrap();
    connection
}

fn seed_project(connection: &Connection) -> (ObjectRef, ObjectRef, ObjectRef) {
    let artifact = ObjectRef::artifact("abc123", "fixtures/export").unwrap();
    ArtifactRepository::new(connection)
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact.clone(),
            display_name: "export".to_string(),
            source_path: "fixtures/export".to_string(),
            stored_path: None,
            sha256: "abc123".to_string(),
            size: 128,
            kind: "binary".to_string(),
            format: "elf".to_string(),
            architecture: "x86_64".to_string(),
            import_status: "indexed".to_string(),
            created_at: datetime!(2026-05-13 00:00 UTC),
        })
        .unwrap();
    ObjectRepository::new(connection)
        .upsert_object(&StoredObject {
            object_ref: artifact.clone(),
            artifact_key: None,
            display_name: Some("export".to_string()),
            address: None,
            size: Some(128),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    let function = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
    );
    ObjectRepository::new(connection)
        .upsert_object(&StoredObject {
            object_ref: function.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("main".to_string()),
            address: Some(0x401000),
            size: Some(32),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(connection)
        .upsert_function(&FunctionRecord {
            object_ref: function.clone(),
            name: "main".to_string(),
            virtual_address: Some(0x401000),
            size: Some(32),
            boundary_source: "symbol".to_string(),
            boundary_confidence: "symbol".to_string(),
            call_count: 0,
            string_count: 0,
        })
        .unwrap();
    MemoryRepository::new(connection)
        .upsert_rename(
            &function,
            "auth_gate",
            datetime!(2026-05-13 00:01 UTC),
            datetime!(2026-05-13 00:01 UTC),
        )
        .unwrap();
    let finding = ObjectRef::new(
        ObjectKind::Finding,
        StableObjectKey::finding("auth-gate", "2026-05-13T00:02:00Z").unwrap(),
    );
    (artifact, function, finding)
}

fn seed_finding(connection: &Connection, function: &ObjectRef, finding_ref: &ObjectRef) {
    FindingRepository::new(connection)
        .upsert_finding(&Finding {
            object_ref: finding_ref.clone(),
            title: "Auth gate accepts weak credential path".to_string(),
            severity: FindingSeverity::High,
            status: FindingStatus::Confirmed,
            summary: "Suspicious credential check reaches auth_gate.".to_string(),
            body: "Evidence is linked by stable ObjectRef and analyst rename context.".to_string(),
            tags: vec!["suspicious".to_string(), "auth".to_string()],
            evidence: vec![FindingEvidence::new(
                function.clone(),
                "primary",
                0,
                "renamed function remains evidence",
                None,
            )],
            created_at: datetime!(2026-05-13 00:02 UTC),
            updated_at: datetime!(2026-05-13 00:03 UTC),
        })
        .unwrap();
}

fn seed_trace_finding(
    connection: &Connection,
    artifact: &ObjectRef,
    trace_event: &ObjectRef,
    finding_ref: &ObjectRef,
) {
    ObjectRepository::new(connection)
        .upsert_object(&StoredObject {
            object_ref: trace_event.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("trace event #4".to_string()),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: r#"{"lab_id":"trace","session":"session-1"}"#.to_string(),
        })
        .unwrap();
    FindingRepository::new(connection)
        .upsert_finding(&Finding {
            object_ref: finding_ref.clone(),
            title: "Runtime trace reaches auth gate".to_string(),
            severity: FindingSeverity::Medium,
            status: FindingStatus::Confirmed,
            summary: "Trace event correlates runtime behavior with auth_gate.".to_string(),
            body: String::new(),
            tags: vec!["trace".to_string()],
            evidence: vec![FindingEvidence::new(
                trace_event.clone(),
                "runtime",
                0,
                "runtime event is preserved as cross-lab evidence",
                None,
            )],
            created_at: datetime!(2026-05-13 00:05 UTC),
            updated_at: datetime!(2026-05-13 00:06 UTC),
        })
        .unwrap();
}

fn seed_plugin_finding(
    connection: &Connection,
    artifact: &ObjectRef,
    plugin_evidence: &ObjectRef,
    finding_ref: &ObjectRef,
    plugin_run_id: i64,
) {
    ObjectRepository::new(connection)
        .upsert_object(&StoredObject {
            object_ref: plugin_evidence.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("plugin contribution".to_string()),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: format!(
                r#"{{"lab_id":"plugin","plugin_run_id":{plugin_run_id},"namespace":"demo"}}"#
            ),
        })
        .unwrap();
    FindingRepository::new(connection)
        .upsert_finding(&Finding {
            object_ref: finding_ref.clone(),
            title: "Plugin contribution flags auth gate".to_string(),
            severity: FindingSeverity::Low,
            status: FindingStatus::Confirmed,
            summary: "Plugin output is retained with run provenance.".to_string(),
            body: String::new(),
            tags: vec!["plugin".to_string()],
            evidence: vec![FindingEvidence::new(
                plugin_evidence.clone(),
                "plugin",
                0,
                "plugin evidence keeps manifest and diagnostics lineage",
                None,
            )],
            created_at: datetime!(2026-05-13 00:09 UTC),
            updated_at: datetime!(2026-05-13 00:10 UTC),
        })
        .unwrap();
}

fn seed_analysis_job(connection: &Connection, artifact: &ObjectRef, status: &str) {
    AnalysisJobRepository::new(connection)
        .insert(&NewAnalysisJob {
            analysis_run_id: None,
            artifact_key: Some(artifact.key.to_string()),
            pass_name: format!("binary.{status}"),
            profile: "balanced".to_string(),
            status: status.to_string(),
            progress_current: 1,
            progress_total: Some(1),
            objects_produced: 1,
            diagnostics_count: u64::from(status != "succeeded"),
            byte_limit: Some(1024),
            function_limit: Some(16),
            time_limit_ms: Some(500),
            metadata_json: format!(r#"{{"status":"{status}","diagnostics":["fixture"]}}"#),
            started_at: datetime!(2026-05-13 00:08 UTC),
        })
        .unwrap();
}

fn seed_plugin_run(connection: &Connection, status: &str) -> i64 {
    PluginRunRepository::new(connection)
        .insert(&NewPluginRun {
            analysis_run_id: None,
            plugin_id: "com.example.auth".to_string(),
            plugin_version: "0.1.0".to_string(),
            manifest_digest: "manifest-digest".to_string(),
            input_digest: "input-digest".to_string(),
            config_digest: Some("config-digest".to_string()),
            status: status.to_string(),
            permissions_json: r#"{"lab_read":["binary-triage"],"lab_write":["plugin"]}"#
                .to_string(),
            diagnostics_json: r#"[{"severity":"info","message":"fixture"}]"#.to_string(),
            started_at: datetime!(2026-05-13 00:08 UTC),
        })
        .unwrap()
        .id
}

#[test]
fn findings_evidence() {
    let connection = migrated_connection();
    let (_, function, finding) = seed_project(&connection);
    seed_finding(&connection, &function, &finding);

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:04 UTC))
        .unwrap();
    let validation = pre_export_validation(&context).unwrap();
    assert!(validation.is_valid());
    assert_eq!(context.report.findings[0].evidence_count(), 1);
    assert_eq!(
        context.evidence_objects[0].display_name.as_deref(),
        Some("auth_gate")
    );
}

#[test]
fn export_json_round_trip() {
    let connection = migrated_connection();
    let (_, function, finding) = seed_project(&connection);
    seed_finding(&connection, &function, &finding);
    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:04 UTC))
        .unwrap();

    let json = render_json(&context).unwrap();
    let report: revdeck_core::Report = serde_json::from_str(&json).unwrap();

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].severity, FindingSeverity::High);
    assert_eq!(report.findings[0].status, FindingStatus::Confirmed);
    assert_eq!(report.findings[0].tags, vec!["auth", "suspicious"]);
    assert_eq!(report.findings[0].evidence[0].evidence, function);
}

#[test]
fn export_markdown_golden() {
    let connection = migrated_connection();
    let (_, function, finding) = seed_project(&connection);
    seed_finding(&connection, &function, &finding);
    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:04 UTC))
        .unwrap();

    let markdown = render_markdown(&context);
    let expected = format!(
        "# RevDeck Findings Report\n\n\
Generated: 2026-05-13 0:04:00.0 +00:00:00\n\n\
## Lab Coverage\n\n\
- `binary-triage`: findings=1 evidence=1\n\n\
## Auth gate accepts weak credential path\n\n\
- Severity: high\n\
- Status: confirmed\n\
- Object: `{finding}`\n\
- Tags: auth, suspicious\n\n\
Suspicious credential check reaches auth_gate.\n\n\
Evidence is linked by stable ObjectRef and analyst rename context.\n\n\
### Evidence\n\n\
- `{function}` (primary) - auth_gate: renamed function remains evidence\n\n"
    );
    assert_eq!(markdown, expected);
}

#[test]
fn export_json_bundle_preserves_cross_lab_evidence_context() {
    let connection = migrated_connection();
    let (artifact, _, _) = seed_project(&connection);
    let trace_event = ObjectRef::lab_object(
        ObjectKind::TraceEvent,
        Some(&artifact.key),
        "trace",
        "session-1/event-4",
    )
    .unwrap();
    let finding = ObjectRef::new(
        ObjectKind::Finding,
        StableObjectKey::finding("runtime-auth-gate", "2026-05-13T00:05:00Z").unwrap(),
    );
    seed_trace_finding(&connection, &artifact, &trace_event, &finding);
    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:07 UTC))
        .unwrap();

    let validation = pre_export_validation(&context).unwrap();
    assert!(validation.is_valid());

    let json = render_json_bundle(&context).unwrap();
    let bundle: ExportBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.report.findings.len(), 1);
    assert_eq!(bundle.report.findings[0].evidence[0].evidence, trace_event);
    assert_eq!(bundle.evidence_objects.len(), 1);
    assert_eq!(bundle.evidence_objects[0].lab_id.as_deref(), Some("trace"));
    assert_eq!(
        bundle.evidence_objects[0].artifact_key.as_deref(),
        Some(artifact.key.as_str())
    );
    assert_eq!(bundle.lab_summaries.len(), 1);
    assert_eq!(bundle.lab_summaries[0].lab_id, "trace");
    assert_eq!(bundle.lab_summaries[0].findings, 1);
    assert_eq!(bundle.lab_summaries[0].evidence_objects, 1);

    let markdown = render_markdown(&context);
    assert!(markdown.contains("[trace]: runtime event is preserved"));
}

#[test]
fn export_bundle_includes_analysis_jobs_and_warns_on_skipped_jobs() {
    let connection = migrated_connection();
    let (artifact, function, finding) = seed_project(&connection);
    seed_finding(&connection, &function, &finding);
    seed_analysis_job(&connection, &artifact, "skipped");

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:11 UTC))
        .unwrap();
    let validation = pre_export_validation(&context).unwrap();

    assert_eq!(context.analysis_jobs.len(), 1);
    assert_eq!(context.analysis_jobs[0].status, "skipped");
    assert!(validation
        .warnings
        .iter()
        .any(|issue| issue.code == "skipped_analysis_job"));

    let bundle: ExportBundle =
        serde_json::from_str(&render_json_bundle(&context).unwrap()).unwrap();
    assert_eq!(bundle.analysis_jobs.len(), 1);
    assert_eq!(bundle.validation.warnings[0].code, "skipped_analysis_job");
}

#[test]
fn export_templates_emit_summary_and_ci_gate_payloads() {
    let connection = migrated_connection();
    let (artifact, function, finding) = seed_project(&connection);
    seed_finding(&connection, &function, &finding);
    seed_analysis_job(&connection, &artifact, "skipped");

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:11 UTC))
        .unwrap();
    let summary: serde_json::Value = serde_json::from_str(
        &render_template_json(&context, ReportTemplate::Summary, Some(1)).unwrap(),
    )
    .unwrap();
    assert_eq!(summary["template"], "summary");
    assert_eq!(summary["gate"]["passed"], true);
    assert_eq!(summary["gate"]["lab_coverage"], 1);
    assert!(summary["validation"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["code"] == "skipped_analysis_job"));

    let ci: serde_json::Value =
        serde_json::from_str(&render_template_json(&context, ReportTemplate::Ci, Some(2)).unwrap())
            .unwrap();
    assert_eq!(ci["template"], "ci");
    assert_eq!(ci["gate"]["passed"], false);
    assert_eq!(ci["gate"]["min_lab_coverage"], 2);
    let gate = export_gate_summary(&context, ReportTemplate::Ci, Some(2));
    assert!(!gate.passed);
}

#[test]
fn export_release_gate_fails_on_failed_analysis_job() {
    let connection = migrated_connection();
    let (artifact, function, finding) = seed_project(&connection);
    seed_finding(&connection, &function, &finding);
    seed_analysis_job(&connection, &artifact, "failed");

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:11 UTC))
        .unwrap();
    let error = pre_export_validation(&context).unwrap_err();

    assert!(error
        .report
        .errors
        .iter()
        .any(|issue| issue.code == "failed_analysis_job"));
}

#[test]
fn export_bundle_includes_plugin_run_provenance() {
    let connection = migrated_connection();
    let (artifact, _, _) = seed_project(&connection);
    let plugin_run_id = seed_plugin_run(&connection, "succeeded");
    let plugin_evidence = ObjectRef::lab_object(
        ObjectKind::PluginContribution,
        Some(&artifact.key),
        "plugin",
        "auth-score",
    )
    .unwrap();
    let finding = ObjectRef::new(
        ObjectKind::Finding,
        StableObjectKey::finding("plugin-auth-score", "2026-05-13T00:09:00Z").unwrap(),
    );
    seed_plugin_finding(
        &connection,
        &artifact,
        &plugin_evidence,
        &finding,
        plugin_run_id,
    );

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:12 UTC))
        .unwrap();
    let validation = pre_export_validation(&context).unwrap();
    assert!(validation.is_valid());

    let bundle: ExportBundle =
        serde_json::from_str(&render_json_bundle(&context).unwrap()).unwrap();
    assert_eq!(bundle.plugin_runs.len(), 1);
    assert_eq!(bundle.plugin_runs[0].id, plugin_run_id);
    assert_eq!(bundle.plugin_runs[0].plugin_id, "com.example.auth");
    assert_eq!(bundle.evidence_objects[0].lab_id.as_deref(), Some("plugin"));
    assert!(bundle.validation.errors.is_empty());
}

#[test]
fn cli_bundle_export_writes_manifest_database_and_report() {
    let temp = tempfile::tempdir().unwrap();
    let project = revdeck_db::ProjectDatabase::create_or_open(temp.path()).unwrap();
    let (artifact, function, finding) = seed_project(project.connection());
    seed_finding(project.connection(), &function, &finding);
    seed_analysis_job(project.connection(), &artifact, "succeeded");
    drop(project);

    let out = temp.path().join("bundle");
    let output = Command::new(revdeck_bin())
        .args([
            "bundle",
            "export",
            temp.path().to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let manifest: serde_json::Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(manifest["schema"], "revdeck.bundle.v1");
    assert_eq!(
        manifest["schema_version"].as_i64().unwrap(),
        revdeck_db::migrations::SCHEMA_VERSION
    );
    assert!(manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["sha256"].as_str().is_some()
            && artifact["import_status"] == "indexed"));
    assert!(out.join("revdeck-bundle-manifest.json").exists());
    assert!(out.join("project.sqlite").exists());
    assert!(out.join("report.json").exists());
    assert!(manifest["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap_or_default()
            .contains("target build outputs")));
}

#[test]
fn export_release_gate_fails_on_orphan_plugin_output() {
    let connection = migrated_connection();
    let (artifact, _, _) = seed_project(&connection);
    let plugin_evidence = ObjectRef::lab_object(
        ObjectKind::PluginContribution,
        Some(&artifact.key),
        "plugin",
        "orphan-output",
    )
    .unwrap();
    let finding = ObjectRef::new(
        ObjectKind::Finding,
        StableObjectKey::finding("orphan-plugin-output", "2026-05-13T00:09:00Z").unwrap(),
    );
    ObjectRepository::new(&connection)
        .upsert_object(&StoredObject {
            object_ref: plugin_evidence.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("orphan plugin output".to_string()),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: r#"{"lab_id":"plugin"}"#.to_string(),
        })
        .unwrap();
    FindingRepository::new(&connection)
        .upsert_finding(&Finding {
            object_ref: finding,
            title: "Orphan plugin output".to_string(),
            severity: FindingSeverity::Low,
            status: FindingStatus::Confirmed,
            summary: "Plugin output without provenance must not ship.".to_string(),
            body: String::new(),
            tags: vec!["plugin".to_string()],
            evidence: vec![FindingEvidence::new(
                plugin_evidence,
                "plugin",
                0,
                "missing plugin_run_id",
                None,
            )],
            created_at: datetime!(2026-05-13 00:09 UTC),
            updated_at: datetime!(2026-05-13 00:10 UTC),
        })
        .unwrap();

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:12 UTC))
        .unwrap();
    let error = pre_export_validation(&context).unwrap_err();

    assert!(error
        .report
        .errors
        .iter()
        .any(|issue| issue.code == "orphan_plugin_output"));
}
