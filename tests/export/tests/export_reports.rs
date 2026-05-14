use revdeck_core::{
    pre_export_validation, render_json, render_markdown, Finding, FindingEvidence, FindingSeverity,
    FindingStatus, ObjectKind, ObjectRef, StableObjectKey,
};
use revdeck_db::{
    migrations::migrate, ArtifactRecord, ArtifactRepository, FindingRepository, FunctionRecord,
    IndexRepository, MemoryRepository, ObjectRepository, StoredObject,
};
use rusqlite::Connection;
use time::macros::datetime;

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
