use revdeck_core::{NewAnalysisRun, ObjectKind, ObjectRef, StableObjectKey};
use revdeck_db::{
    migrations::current_version, AnalysisJobRepository, AnalysisRunRepository, ArtifactRecord,
    ArtifactRepository, IndexRepository, ObjectRepository, ProjectDatabase, StoredObject,
};
use revdeck_index::{register_binary_for_analysis, AnalysisProfile, ImportOptions};
use std::path::PathBuf;
use tempfile::tempdir;
use time::macros::datetime;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn project_creation_reopen_and_foundation_records_are_deterministic() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    assert_eq!(
        current_version(project.connection()).unwrap(),
        revdeck_db::migrations::SCHEMA_VERSION
    );

    let artifact_ref = ObjectRef::artifact(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "fixtures/foundation-empty-project",
    )
    .unwrap();
    let artifact_repo = ArtifactRepository::new(project.connection());
    artifact_repo
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact_ref.clone(),
            display_name: "foundation-empty-project".to_string(),
            source_path: "fixtures/foundation-empty-project".to_string(),
            stored_path: None,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            size: 0,
            kind: "project".to_string(),
            format: "unknown".to_string(),
            architecture: "unknown".to_string(),
            import_status: "pending".to_string(),
            created_at: datetime!(2026-05-13 00:00 UTC),
        })
        .unwrap();
    let object_repo = ObjectRepository::new(project.connection());
    object_repo
        .upsert_object(&StoredObject {
            object_ref: artifact_ref.clone(),
            artifact_key: None,
            display_name: Some("foundation-empty-project".to_string()),
            address: None,
            size: Some(0),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();

    let run_repo = AnalysisRunRepository::new(project.connection());
    let run = run_repo
        .start(
            &NewAnalysisRun::new(
                Some(artifact_ref.key.to_string()),
                "foundation.fixture",
                "0.1.0",
                artifact_ref.key.to_string(),
                datetime!(2026-05-13 00:00 UTC),
            )
            .unwrap(),
        )
        .unwrap();

    let function_ref = ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact_ref.key, 0x401000, Some(32), Some("main")).unwrap(),
    );
    object_repo
        .upsert_object(&StoredObject {
            object_ref: function_ref.clone(),
            artifact_key: Some(artifact_ref.key.to_string()),
            display_name: Some("main".to_string()),
            address: Some(0x401000),
            size: Some(32),
            source_run_id: Some(run.id),
            metadata_json: r#"{"boundary_source":"symbol"}"#.to_string(),
        })
        .unwrap();

    assert_eq!(
        object_repo
            .get_object(&function_ref)
            .unwrap()
            .unwrap()
            .object_ref,
        function_ref
    );
    drop(project);

    let reopened = ProjectDatabase::open_existing(temp.path()).unwrap();
    let reopened_object_repo = ObjectRepository::new(reopened.connection());
    assert_eq!(
        reopened_object_repo
            .get_object(&function_ref)
            .unwrap()
            .unwrap()
            .object_ref,
        function_ref
    );
}

#[test]
fn binary_registration_records_pending_artifact_before_indexing() {
    let workspace = workspace_root();
    let binary = workspace
        .join("fixtures")
        .join("binaries")
        .join("minimal_elf");
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();

    let registration = register_binary_for_analysis(
        project.connection(),
        ImportOptions::with_profile(
            temp.path().to_path_buf(),
            binary.clone(),
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();

    assert_eq!(registration.profile, AnalysisProfile::Quick);
    assert_eq!(registration.source_path, binary);
    assert_eq!(registration.display_name, "minimal_elf");
    assert!(registration.size > 0);

    let artifact = ArtifactRepository::new(project.connection())
        .get_artifact(&registration.artifact_ref)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.import_status, "pending");
    assert_eq!(artifact.format, "unknown");
    assert_eq!(artifact.architecture, "unknown");
    assert_eq!(artifact.size, registration.size);

    let object = ObjectRepository::new(project.connection())
        .get_object(&registration.artifact_ref)
        .unwrap()
        .unwrap();
    assert_eq!(object.object_ref, registration.artifact_ref);
    assert_eq!(object.display_name.as_deref(), Some("minimal_elf"));
    assert_eq!(object.size, Some(registration.size));

    let run = AnalysisRunRepository::new(project.connection())
        .get(registration.run_id)
        .unwrap()
        .unwrap();
    assert_eq!(run.status.as_str(), "running");
    assert_eq!(
        run.artifact_key.as_deref(),
        Some(registration.artifact_ref.key.as_str())
    );

    let parse_job = AnalysisJobRepository::new(project.connection())
        .get(registration.parse_job_id)
        .unwrap()
        .unwrap();
    assert_eq!(parse_job.pass_name, "binary.parse");
    assert_eq!(parse_job.status, "running");
    assert_eq!(
        parse_job.artifact_key.as_deref(),
        Some(registration.artifact_ref.key.as_str())
    );

    assert_eq!(
        IndexRepository::new(project.connection())
            .count_kind(&registration.artifact_ref, ObjectKind::Function)
            .unwrap(),
        0
    );
}
