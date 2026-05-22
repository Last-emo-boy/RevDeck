use assert_cmd::Command;
use revdeck_core::{
    DiffChangeKind, DiffEntityKind, DiffSummaryViewModel, EdgeKind, ObjectGraphQuery, ObjectKind,
    ObjectRef, ObjectSearch, StableObjectKey,
};
use revdeck_db::{
    ArtifactRecord, ArtifactRepository, FunctionRecord, ImportRecord, IndexRepository,
    ObjectQueryRepository, ObjectRepository, ProjectDatabase, SectionRecord, StoredEdge,
    StoredObject, StringRecord,
};
use rusqlite::params;
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

fn seed_artifact(project: &ProjectDatabase, sha: &str, label: &str) -> ObjectRef {
    let artifact = ObjectRef::artifact(sha, &format!("fixtures/diff/{label}")).unwrap();
    ArtifactRepository::new(project.connection())
        .upsert_artifact(&ArtifactRecord {
            object_ref: artifact.clone(),
            display_name: label.to_string(),
            source_path: format!("fixtures/diff/{label}"),
            stored_path: None,
            sha256: sha.to_string(),
            size: 1024,
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
            display_name: Some(label.to_string()),
            address: None,
            size: Some(1024),
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
    metadata_json: &str,
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
            metadata_json: metadata_json.to_string(),
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
            call_count: 1,
            string_count: 1,
        })
        .unwrap();
    object_ref
}

fn seed_import(project: &ProjectDatabase, artifact: &ObjectRef, symbol: &str) -> ObjectRef {
    let object_ref = ObjectRef::new(
        ObjectKind::Import,
        StableObjectKey::import(&artifact.key, Some("libc.so.6"), symbol, None).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(symbol.to_string()),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_import(&ImportRecord {
            object_ref: object_ref.clone(),
            module: Some("libc.so.6".to_string()),
            symbol: symbol.to_string(),
            ordinal: None,
            virtual_address: None,
        })
        .unwrap();
    object_ref
}

fn seed_string(
    project: &ProjectDatabase,
    artifact: &ObjectRef,
    value: &str,
    offset: u64,
    address: u64,
) -> ObjectRef {
    let object_ref = ObjectRef::new(
        ObjectKind::String,
        StableObjectKey::string(&artifact.key, offset, Some(address), value).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(value.to_string()),
            address: Some(address),
            size: Some(value.len() as u64),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_string(&StringRecord {
            object_ref: object_ref.clone(),
            value: value.to_string(),
            virtual_address: Some(address),
            file_offset: offset,
            length: value.len() as u64,
            encoding: "ascii".to_string(),
        })
        .unwrap();
    object_ref
}

fn seed_section(project: &ProjectDatabase, artifact: &ObjectRef) -> ObjectRef {
    let object_ref = ObjectRef::new(
        ObjectKind::Section,
        StableObjectKey::section(&artifact.key, ".text", 0x401000, 0x200).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some(".text".to_string()),
            address: Some(0x401000),
            size: Some(0x200),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    IndexRepository::new(project.connection())
        .upsert_section(&SectionRecord {
            object_ref: object_ref.clone(),
            name: ".text".to_string(),
            virtual_address: Some(0x401000),
            file_offset: Some(0x100),
            size: 0x200,
            flags: "rx".to_string(),
            entropy: Some(5.5),
        })
        .unwrap();
    object_ref
}

fn seed_score(project: &ProjectDatabase, artifact: &ObjectRef, subject: &ObjectRef, score: u64) {
    let score_ref = ObjectRef::new(
        ObjectKind::Score,
        StableObjectKey::score(subject, "function_radar", None).unwrap(),
    );
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: score_ref,
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("Function Radar score".to_string()),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: serde_json::json!({ "score": score }).to_string(),
        })
        .unwrap();
}

fn seed_finding(project: &ProjectDatabase, artifact: &ObjectRef) {
    let finding_ref = ObjectRef::lab_object(
        ObjectKind::Finding,
        Some(&artifact.key),
        "diff-fixture",
        "finding/auth-gate",
    )
    .unwrap();
    ObjectRepository::new(project.connection())
        .upsert_object(&StoredObject {
            object_ref: finding_ref,
            artifact_key: Some(artifact.key.to_string()),
            display_name: Some("Auth gate finding".to_string()),
            address: None,
            size: None,
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
}

fn seed_edge(
    project: &ProjectDatabase,
    source: &ObjectRef,
    target: &ObjectRef,
    kind: EdgeKind,
    confidence: f64,
) {
    ObjectRepository::new(project.connection())
        .upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(kind, source, target).unwrap(),
            ),
            source: source.clone(),
            target: target.clone(),
            kind,
            confidence,
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
}

fn seed_diff_fixture(project: &ProjectDatabase) -> (ObjectRef, ObjectRef) {
    let before = seed_artifact(project, "before123", "before");
    let after = seed_artifact(project, "after123", "after");

    let before_function = seed_function(
        project,
        &before,
        "auth_gate",
        0x401000,
        32,
        r#"{"stack":16}"#,
    );
    let after_function = seed_function(
        project,
        &after,
        "auth_gate",
        0x401000,
        48,
        r#"{"stack":32}"#,
    );
    let before_import = seed_import(project, &before, "system");
    let after_import = seed_import(project, &after, "system");
    let before_string = seed_string(project, &before, "legacy-token", 0x40, 0x402000);
    let after_string = seed_string(project, &after, "admin-token", 0x80, 0x402080);
    seed_section(project, &before);
    seed_section(project, &after);
    seed_score(project, &before, &before_function, 10);
    seed_score(project, &after, &after_function, 25);
    seed_finding(project, &before);
    seed_finding(project, &after);

    seed_edge(
        project,
        &before_function,
        &before_import,
        EdgeKind::CallsImport,
        1.0,
    );
    seed_edge(
        project,
        &after_function,
        &after_import,
        EdgeKind::CallsImport,
        0.5,
    );
    seed_edge(
        project,
        &before_function,
        &before_string,
        EdgeKind::References,
        1.0,
    );
    seed_edge(
        project,
        &after_function,
        &after_string,
        EdgeKind::References,
        1.0,
    );

    (before, after)
}

#[test]
fn diff_lab_persists_exact_object_and_relation_deltas() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let (before, after) = seed_diff_fixture(&project);

    let query = ObjectQueryRepository::new(project.connection());
    let before_snapshot = query.diff_artifact_snapshot(&before).unwrap();
    let after_snapshot = query.diff_artifact_snapshot(&after).unwrap();
    assert!(before_snapshot
        .objects
        .iter()
        .any(|object| object.kind == ObjectKind::Function));
    assert!(before_snapshot
        .objects
        .iter()
        .any(|object| object.kind == ObjectKind::Section));
    assert!(before_snapshot
        .objects
        .iter()
        .any(|object| object.kind == ObjectKind::Score));
    assert!(before_snapshot
        .objects
        .iter()
        .any(|object| object.kind == ObjectKind::Finding));

    let summary = DiffSummaryViewModel::compare(&before_snapshot, &after_snapshot);
    assert!(summary.rows.iter().any(|row| {
        row.entity_kind == DiffEntityKind::Object
            && row.change == DiffChangeKind::Changed
            && row.match_key.starts_with("function:address:")
    }));
    assert!(summary.rows.iter().any(|row| {
        row.entity_kind == DiffEntityKind::Object
            && row.change == DiffChangeKind::Added
            && row.after_label.as_deref() == Some("admin-token")
    }));
    assert!(summary.rows.iter().any(|row| {
        row.entity_kind == DiffEntityKind::Object
            && row.change == DiffChangeKind::Removed
            && row.before_label.as_deref() == Some("legacy-token")
    }));
    assert!(summary.rows.iter().any(|row| {
        row.entity_kind == DiffEntityKind::Relation
            && row.change == DiffChangeKind::Changed
            && row.match_key.contains("calls_import")
    }));

    ObjectRepository::new(project.connection())
        .upsert_diff_rows(&after, &summary)
        .unwrap();
    let delta_objects: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM objects WHERE kind = 'diff_delta'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(delta_objects, summary.total_deltas() as i64);
    let diff_edges: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE kind = 'differs_from'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(diff_edges >= summary.total_deltas() as i64);

    let delta_search = ObjectQueryRepository::new(project.connection())
        .search_objects(&ObjectSearch::new(Some(ObjectKind::DiffDelta), "changed"))
        .unwrap();
    assert!(!delta_search.is_empty());

    let output = Command::new(revdeck_bin())
        .args([
            "diff",
            temp.path().to_str().unwrap(),
            &before.to_string(),
            &after.to_string(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["lab"], "diff");
    assert_eq!(json["label"], "Diff Lab");
    assert!(json["summary"]["added"].as_u64().unwrap() > 0);
    assert!(json["summary"]["removed"].as_u64().unwrap() > 0);
    assert!(json["summary"]["changed"].as_u64().unwrap() > 0);
    assert!(json["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| { row["entity_kind"] == "relation" && row["change"] == "changed" }));

    let persisted_after_cli: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*)
            FROM objects
            WHERE kind = 'diff_delta'
              AND metadata_json LIKE '%\"lab_id\":\"diff\"%'",
            params![],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted_after_cli, summary.total_deltas() as i64);
}
