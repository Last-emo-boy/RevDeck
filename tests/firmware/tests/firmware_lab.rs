use assert_cmd::Command;
use revdeck_core::{EdgeKind, ObjectGraphQuery, ObjectKind, ObjectSearch, RelationDirection};
use revdeck_db::{
    AnalysisJobRepository, FirmwareRepository, ObjectQueryRepository, ProjectDatabase,
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

fn fixture(path: &str) -> PathBuf {
    workspace_root().join(path)
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

#[test]
fn firmware_lab_import_persists_file_inventory_nested_artifact_and_edges() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let firmware_dir = fixture("fixtures/firmware/router-root");

    let outcome = FirmwareRepository::new(project.connection())
        .import_directory(&firmware_dir, datetime!(2026-05-23 00:03 UTC))
        .unwrap();

    assert_eq!(outcome.files_imported, 4);
    assert_eq!(outcome.binaries_detected, 1);
    assert_eq!(outcome.unsupported_files, 3);
    assert!(outcome.total_bytes > 0);

    let files = FirmwareRepository::new(project.connection())
        .list_files_for_artifact(&outcome.firmware, 20)
        .unwrap();
    assert_eq!(files.len(), 4);
    assert!(files.iter().any(|file| file.path == "etc/passwd"));
    assert!(files.iter().any(|file| file.path == "etc/init.d/rcS"
        && file.file_type == "script"
        && file.executable));
    let elf = files
        .iter()
        .find(|file| file.path == "bin/httpd.elf")
        .expect("nested ELF firmware file");
    assert_eq!(elf.file_type, "elf");
    assert!(elf.executable);
    assert!(elf.nested_artifact.is_some());

    let query = ObjectQueryRepository::new(project.connection());
    let passwd = query
        .search_objects(&ObjectSearch::new(Some(ObjectKind::FirmwareFile), "passwd"))
        .unwrap();
    assert_eq!(passwd.len(), 1);
    assert_eq!(passwd[0].display_name.as_deref(), Some("etc/passwd"));

    let contains = query
        .relations(
            &outcome.firmware,
            RelationDirection::Outgoing,
            Some(EdgeKind::Contains),
        )
        .unwrap();
    assert_eq!(contains.len(), 4);
    assert!(contains
        .iter()
        .any(|relation| relation.target == passwd[0].object_ref));

    let nested = elf.nested_artifact.as_ref().unwrap();
    let derived = query
        .relations(
            nested,
            RelationDirection::Outgoing,
            Some(EdgeKind::DerivedFrom),
        )
        .unwrap();
    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0].target, elf.object_ref);

    let jobs = AnalysisJobRepository::new(project.connection())
        .list_recent_for_artifact(&outcome.firmware, 10)
        .unwrap();
    let job = jobs
        .iter()
        .find(|job| job.pass_name == "firmware.import")
        .expect("firmware import job");
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.objects_produced, 6);
    let metadata: serde_json::Value = serde_json::from_str(&job.metadata_json).unwrap();
    assert_eq!(metadata["lab_id"], "firmware");
    assert_eq!(metadata["files_imported"], 4);
    assert_eq!(metadata["binaries_detected"], 1);
}

#[test]
fn firmware_cli_import_and_status_emit_lab_json() {
    let temp = tempdir().unwrap();
    let firmware_dir = fixture("fixtures/firmware/router-root");

    let output = Command::new(revdeck_bin())
        .args([
            "firmware",
            "import",
            temp.path().to_str().unwrap(),
            firmware_dir.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["lab"], "firmware");
    assert_eq!(json["label"], "Firmware Lab");
    assert_eq!(json["files_imported"], 4);
    assert_eq!(json["binaries_detected"], 1);
    let firmware = json["firmware"].as_str().unwrap().to_string();

    let output = Command::new(revdeck_bin())
        .args([
            "firmware",
            "status",
            temp.path().to_str().unwrap(),
            &firmware,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["lab"], "firmware");
    assert_eq!(json["files"].as_array().unwrap().len(), 4);
    assert!(json["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| file["path"] == "bin/httpd.elf"
            && file["file_type"] == "elf"
            && file["nested_artifact"].as_str().is_some()));

    Command::new(revdeck_bin())
        .args(["firmware", "--help"])
        .assert()
        .success();
}
