use revdeck_core::{NewAnalysisRun, ObjectKind, ObjectRef, StableObjectKey};
use revdeck_db::{
    migrations::current_version, AnalysisRunRepository, ArtifactRecord, ArtifactRepository,
    ObjectRepository, ProjectDatabase, StoredObject,
};
use tempfile::tempdir;
use time::macros::datetime;

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
