use revdeck_core::{
    AnnotationEvidence, Finding, FindingEvidence, FindingSeverity, FindingStatus, ObjectKind,
    ObjectRef, StableObjectKey,
};
use revdeck_db::{
    migrations::migrate, ArtifactRecord, ArtifactRepository, FindingRepository, FunctionRecord,
    IndexRepository, MemoryRepository, ObjectRepository, StoredObject, StringRecord,
};
use rusqlite::Connection;
use time::macros::datetime;

fn migrated_connection() -> Connection {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate(&mut connection).unwrap();
    connection
}

fn seed_artifact(connection: &Connection) -> ObjectRef {
    let artifact = ObjectRef::artifact("abc123", "fixtures/memory").unwrap();
    ArtifactRepository::new(connection)
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact.clone(),
            display_name: "memory".to_string(),
            source_path: "fixtures/memory".to_string(),
            stored_path: None,
            sha256: "abc123".to_string(),
            size: 64,
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
            display_name: Some("memory".to_string()),
            address: None,
            size: Some(64),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    artifact
}

fn function(artifact: &ObjectRef) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
    )
}

fn string_ref(artifact: &ObjectRef) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::String,
        StableObjectKey::string(&artifact.key, 0x20, Some(0x402020), "admin password").unwrap(),
    )
}

fn upsert_function(connection: &Connection, artifact: &ObjectRef, function_ref: &ObjectRef) {
    ObjectRepository::new(connection)
        .upsert_object(&StoredObject {
            object_ref: function_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("main".to_string()),
            address: Some(0x401000),
            size: Some(32),
            source_run_id: None,
            metadata_json: r#"{"boundary_confidence":"symbol"}"#.to_string(),
        })
        .unwrap();
    IndexRepository::new(connection)
        .upsert_function(&FunctionRecord {
            object_ref: function_ref.clone(),
            name: "main".to_string(),
            virtual_address: Some(0x401000),
            size: Some(32),
            boundary_source: "symbol".to_string(),
            boundary_confidence: "symbol".to_string(),
            call_count: 0,
            string_count: 1,
        })
        .unwrap();
}

fn upsert_string(connection: &Connection, artifact: &ObjectRef, string: &ObjectRef) {
    ObjectRepository::new(connection)
        .upsert_object(&StoredObject {
            object_ref: string.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("admin password".to_string()),
            address: Some(0x402020),
            size: Some(14),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(connection)
        .upsert_string(&StringRecord {
            object_ref: string.clone(),
            value: "admin password".to_string(),
            virtual_address: Some(0x402020),
            file_offset: 0x20,
            length: 14,
            encoding: "ascii".to_string(),
        })
        .unwrap();
}

#[test]
fn memory_annotations_cover_all_first_class_kinds() {
    let connection = migrated_connection();
    let artifact = seed_artifact(&connection);
    let function_ref = function(&artifact);
    let string = string_ref(&artifact);
    upsert_function(&connection, &artifact, &function_ref);
    upsert_string(&connection, &artifact, &string);

    let memory = MemoryRepository::new(&connection);
    memory
        .upsert_note(
            &function_ref,
            "review command execution path",
            datetime!(2026-05-13 00:00 UTC),
            datetime!(2026-05-13 00:01 UTC),
            vec![AnnotationEvidence::new(
                string.clone(),
                0,
                "password string",
            )],
        )
        .unwrap();
    memory
        .upsert_tag(
            &function_ref,
            "suspicious",
            datetime!(2026-05-13 00:02 UTC),
            datetime!(2026-05-13 00:02 UTC),
        )
        .unwrap();
    memory
        .upsert_rename(
            &function_ref,
            "auth_gate",
            datetime!(2026-05-13 00:03 UTC),
            datetime!(2026-05-13 00:03 UTC),
        )
        .unwrap();
    memory
        .upsert_status(
            &function_ref,
            "interesting",
            datetime!(2026-05-13 00:04 UTC),
            datetime!(2026-05-13 00:04 UTC),
        )
        .unwrap();
    memory
        .upsert_todo(
            &function_ref,
            "trace caller",
            datetime!(2026-05-13 00:05 UTC),
            datetime!(2026-05-13 00:05 UTC),
            Vec::new(),
        )
        .unwrap();
    memory
        .upsert_hypothesis(
            &function_ref,
            "credential gate",
            datetime!(2026-05-13 00:06 UTC),
            datetime!(2026-05-13 00:06 UTC),
            vec![AnnotationEvidence::new(string.clone(), 0, "auth string")],
        )
        .unwrap();

    let annotations = memory.list_annotations_for_subject(&function_ref).unwrap();
    assert_eq!(annotations.len(), 6);
    assert!(annotations
        .iter()
        .any(|annotation| annotation.body == "auth_gate"));
    assert!(annotations
        .iter()
        .any(|annotation| !annotation.evidence.is_empty()));
}

#[test]
fn reindex_preserves_analysis_memory() {
    let connection = migrated_connection();
    let artifact = seed_artifact(&connection);
    let function_ref = function(&artifact);
    let string = string_ref(&artifact);
    upsert_function(&connection, &artifact, &function_ref);
    upsert_string(&connection, &artifact, &string);

    let memory = MemoryRepository::new(&connection);
    memory
        .upsert_tag(
            &function_ref,
            "suspicious",
            datetime!(2026-05-13 00:00 UTC),
            datetime!(2026-05-13 00:00 UTC),
        )
        .unwrap();
    memory
        .upsert_rename(
            &function_ref,
            "auth_gate",
            datetime!(2026-05-13 00:01 UTC),
            datetime!(2026-05-13 00:01 UTC),
        )
        .unwrap();
    memory
        .upsert_note(
            &function_ref,
            "string proves auth path",
            datetime!(2026-05-13 00:02 UTC),
            datetime!(2026-05-13 00:02 UTC),
            vec![AnnotationEvidence::new(string.clone(), 0, "evidence")],
        )
        .unwrap();

    let finding_ref = ObjectRef::new(
        ObjectKind::Finding,
        StableObjectKey::finding("auth-gate", "2026-05-13T00:03:00Z").unwrap(),
    );
    FindingRepository::new(&connection)
        .upsert_finding(&Finding {
            object_ref: finding_ref.clone(),
            title: "Auth gate accepts weak credential path".to_string(),
            severity: FindingSeverity::High,
            status: FindingStatus::Confirmed,
            summary: "Suspicious credential check evidence survives re-index.".to_string(),
            body: "The analyst-owned evidence links stable ObjectRef values.".to_string(),
            tags: vec!["auth".to_string(), "suspicious".to_string()],
            evidence: vec![FindingEvidence::new(
                function_ref.clone(),
                "primary",
                0,
                "renamed function remains evidence",
                None,
            )],
            created_at: datetime!(2026-05-13 00:03 UTC),
            updated_at: datetime!(2026-05-13 00:04 UTC),
        })
        .unwrap();

    IndexRepository::new(&connection)
        .remove_indexed_facts_for_artifact(&artifact)
        .unwrap();
    upsert_function(&connection, &artifact, &function_ref);
    upsert_string(&connection, &artifact, &string);

    let annotations = MemoryRepository::new(&connection)
        .list_annotations_for_subject(&function_ref)
        .unwrap();
    assert_eq!(annotations.len(), 3);
    assert!(annotations
        .iter()
        .any(|annotation| annotation.body == "auth_gate"));

    let findings = FindingRepository::new(&connection).list_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].object_ref, finding_ref);
    assert_eq!(findings[0].evidence[0].evidence, function_ref);

    let context = FindingRepository::new(&connection)
        .export_context(datetime!(2026-05-13 00:10 UTC))
        .unwrap();
    assert_eq!(
        context.evidence_objects[0].display_name.as_deref(),
        Some("auth_gate")
    );
}
