use assert_cmd::Command;
use predicates::prelude::*;
use revdeck_db::ProjectDatabase;
use revdeck_plugin_host::{
    commit_plugin_directory, run_plugin_directory, test_plugin_directory, validate_manifest_file,
};
use std::{path::PathBuf, sync::Once};

static BUILD_REVDECK: Once = Once::new();

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture(path: &str) -> PathBuf {
    workspace_root().join("fixtures").join("plugins").join(path)
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
fn valid_manifest_passes_host_validation() {
    let output = validate_manifest_file(&fixture("valid-minimal/revdeck-plugin.toml")).unwrap();

    assert_eq!(output.status, "validated");
    assert!(output.validation.is_valid());
    assert_eq!(
        output.plugin.unwrap().id,
        "com.revdeck.examples.valid-minimal"
    );
}

#[test]
fn invalid_manifest_reports_structured_error() {
    let output =
        validate_manifest_file(&fixture("invalid-missing-capability/revdeck-plugin.toml")).unwrap();

    assert_eq!(output.status, "failed");
    assert!(output
        .validation
        .errors
        .iter()
        .any(|issue| issue.code == "missing_capabilities"));
}

#[test]
fn plugin_directory_test_validates_object_batch() {
    let output = test_plugin_directory(&fixture("valid-minimal")).unwrap();

    assert_eq!(output.status, "succeeded");
    assert!(output.validation.is_valid());
    assert_eq!(output.object_batch.unwrap().objects, 2);
}

#[test]
fn plugin_commit_persists_object_batch_and_audit() {
    let temp = tempfile::tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let output = commit_plugin_directory(&project, &fixture("valid-minimal")).unwrap();

    assert_eq!(output.status, "succeeded");
    assert_eq!(output.committed.as_ref().unwrap().objects, 2);
    assert_eq!(output.committed.as_ref().unwrap().edges, 1);
    assert_eq!(output.committed.as_ref().unwrap().attributes, 1);
    assert!(output.plugin_run_id.is_some());

    let object_count: i64 = project
        .connection()
        .query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))
        .unwrap();
    let edge_count: i64 = project
        .connection()
        .query_row("SELECT COUNT(*) FROM edges", [], |row| row.get(0))
        .unwrap();
    let attribute_count: i64 = project
        .connection()
        .query_row("SELECT COUNT(*) FROM plugin_attributes", [], |row| {
            row.get(0)
        })
        .unwrap();
    let run_status: String = project
        .connection()
        .query_row("SELECT status FROM plugin_runs", [], |row| row.get(0))
        .unwrap();

    assert_eq!(object_count, 2);
    assert_eq!(edge_count, 1);
    assert_eq!(attribute_count, 1);
    assert_eq!(run_status, "succeeded");
}

#[test]
fn plugin_run_commit_uses_fixture_replay_mode() {
    let temp = tempfile::tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let output = run_plugin_directory(&project, &fixture("valid-minimal"), true).unwrap();

    assert_eq!(output.status, "succeeded");
    assert_eq!(output.mode, "fixture_replay");
    assert_eq!(output.committed.as_ref().unwrap().objects, 2);
}

#[test]
fn cli_plugin_validate_inspect_and_test() {
    Command::new(revdeck_bin())
        .args([
            "plugin",
            "validate",
            fixture("valid-minimal/revdeck-plugin.toml")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "com.revdeck.examples.valid-minimal",
        ));

    Command::new(revdeck_bin())
        .args([
            "plugin",
            "inspect",
            fixture("valid-minimal/revdeck-plugin.toml")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact_read"));

    Command::new(revdeck_bin())
        .args(["plugin", "test", fixture("valid-minimal").to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"objects\": 2"));
}

#[test]
fn cli_plugin_commit_and_run_commit() {
    let commit_project = tempfile::tempdir().unwrap();
    Command::new(revdeck_bin())
        .args([
            "plugin",
            "commit",
            commit_project.path().to_str().unwrap(),
            fixture("valid-minimal").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"objects\": 2"))
        .stdout(predicate::str::contains("\"plugin_run_id\""));

    let run_project = tempfile::tempdir().unwrap();
    Command::new(revdeck_bin())
        .args([
            "plugin",
            "run",
            run_project.path().to_str().unwrap(),
            fixture("valid-minimal").to_str().unwrap(),
            "--commit",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"mode\": \"fixture_replay\""))
        .stdout(predicate::str::contains("\"edges\": 1"));
}

#[test]
fn cli_plugin_validate_fails_invalid_manifest() {
    Command::new(revdeck_bin())
        .args([
            "plugin",
            "validate",
            fixture("invalid-missing-capability/revdeck-plugin.toml")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("missing_capabilities"));
}
