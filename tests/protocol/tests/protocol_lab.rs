use assert_cmd::Command;
use revdeck_core::{
    EdgeKind, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectSearch, RelationDirection,
    StableObjectKey,
};
use revdeck_db::{
    AnalysisJobRepository, ArtifactRecord, ArtifactRepository, IndexRepository,
    ObjectQueryRepository, ObjectRepository, ProjectDatabase, ProtocolRepository, StoredObject,
    StringRecord,
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
    let artifact = ObjectRef::artifact("protocol123", "fixtures/protocol/firmware.elf").unwrap();
    ArtifactRepository::new(project.connection())
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact.clone(),
            display_name: "protocol-firmware".to_string(),
            source_path: "fixtures/protocol/firmware.elf".to_string(),
            stored_path: None,
            sha256: "protocol123".to_string(),
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
            display_name: Some("protocol-firmware".to_string()),
            address: None,
            size: Some(4096),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    artifact
}

fn seed_string(project: &ProjectDatabase, artifact: &ObjectRef) -> ObjectRef {
    let object_ref = ObjectRef::new(
        ObjectKind::String,
        StableObjectKey::string(&artifact.key, 0x200, Some(0x402000), "admin password").unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
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
            object_ref: object_ref.clone(),
            value: "admin password".to_string(),
            virtual_address: Some(0x402000),
            file_offset: 0x200,
            length: 14,
            encoding: "ascii".to_string(),
        })
        .unwrap();
    object_ref
}

#[test]
fn protocol_lab_import_persists_fields_signals_jobs_and_string_links() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    let string = seed_string(&project, &artifact);
    let sample_path = fixture("fixtures/protocol/login_handshake.json");
    let sample_json = std::fs::read_to_string(&sample_path).unwrap();

    let outcome = ProtocolRepository::new(project.connection())
        .import_sample(
            &artifact,
            &sample_path,
            &sample_json,
            datetime!(2026-05-23 00:07 UTC),
        )
        .unwrap();

    assert_eq!(outcome.messages_imported, 1);
    assert_eq!(outcome.fields_imported, 3);
    assert_eq!(outcome.correlated_fields, 1);
    assert_eq!(
        outcome.schema_hypothesis.as_deref(),
        Some("login request: opcode, length, ascii credential")
    );

    let repo = ProtocolRepository::new(project.connection());
    let samples = repo.list_samples_for_artifact(&artifact, 10).unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].sample_id, "login-handshake");
    assert_eq!(samples[0].message_count, 1);
    assert_eq!(samples[0].field_count, 3);

    let messages = repo.list_messages_for_sample(&outcome.sample, 10).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id, "client-hello");
    assert_eq!(messages[0].direction, "client-to-server");
    assert_eq!(messages[0].payload_len, 16);

    let fields = repo
        .list_fields_for_message(&messages[0].object_ref, 10)
        .unwrap();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].name, "opcode");
    assert_eq!(fields[0].integer_value, Some(1));
    assert_eq!(fields[1].name, "credential_len");
    assert_eq!(fields[1].integer_value, Some(14));
    assert_eq!(fields[2].name, "credential");
    assert_eq!(fields[2].field_type, "string");
    assert_eq!(fields[2].string_hint.as_deref(), Some("admin password"));
    assert_eq!(fields[2].correlated.as_ref(), Some(&string));
    assert!(fields[2].entropy > 2.0);
    assert_eq!(fields[2].printable_ratio, 1.0);

    let query = ObjectQueryRepository::new(project.connection());
    let field_objects = query
        .search_objects(&ObjectSearch::new(
            Some(ObjectKind::ProtocolField),
            "credential",
        ))
        .unwrap();
    assert!(field_objects.iter().any(|object| object
        .display_name
        .as_deref()
        .unwrap_or("")
        .contains("credential")));

    let contains = query
        .relations(
            &messages[0].object_ref,
            RelationDirection::Outgoing,
            Some(EdgeKind::Contains),
        )
        .unwrap();
    assert_eq!(contains.len(), 3);
    let references = query
        .relations(
            &fields[2].object_ref,
            RelationDirection::Outgoing,
            Some(EdgeKind::References),
        )
        .unwrap();
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].target, string);

    let jobs = AnalysisJobRepository::new(project.connection())
        .list_recent_for_artifact(&artifact, 10)
        .unwrap();
    let job = jobs
        .iter()
        .find(|job| job.pass_name == "protocol.import")
        .expect("protocol import job");
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.objects_produced, 5);
    let metadata: serde_json::Value = serde_json::from_str(&job.metadata_json).unwrap();
    assert_eq!(metadata["lab_id"], "protocol");
    assert_eq!(metadata["fields_imported"], 3);
    assert_eq!(metadata["correlated_fields"], 1);
}

#[test]
fn protocol_cli_import_and_status_emit_lab_json() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let artifact = seed_artifact(&project);
    seed_string(&project, &artifact);
    drop(project);

    let sample_path = fixture("fixtures/protocol/login_handshake.json");
    let output = Command::new(revdeck_bin())
        .args([
            "protocol",
            "import",
            temp.path().to_str().unwrap(),
            &sample_path,
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
    assert_eq!(json["lab"], "protocol");
    assert_eq!(json["label"], "Protocol Lab");
    assert_eq!(json["messages_imported"], 1);
    assert_eq!(json["fields_imported"], 3);
    assert_eq!(json["correlated_fields"], 1);

    let output = Command::new(revdeck_bin())
        .args([
            "protocol",
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
    assert_eq!(json["lab"], "protocol");
    let samples = json["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0]["sample_id"], "login-handshake");
    assert_eq!(samples[0]["messages"].as_array().unwrap().len(), 1);
    let fields = samples[0]["messages"][0]["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 3);
    assert!(fields.iter().any(|field| field["name"] == "credential"
        && field["string_hint"] == "admin password"
        && field["correlated"].as_str().is_some()));

    Command::new(revdeck_bin())
        .args(["protocol", "--help"])
        .assert()
        .success();
}
