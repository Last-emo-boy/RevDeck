use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;
use tempfile::tempdir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn analyze_quick_profile_reports_skipped_native_cfg_diagnostic() {
    let workspace = workspace_root();
    let temp = tempdir().unwrap();
    let binary = workspace
        .join("fixtures")
        .join("binaries")
        .join("minimal_elf");
    let project = temp.path().join("quick-project");

    let output = Command::cargo_bin("revdeck")
        .unwrap()
        .args([
            "analyze",
            binary.to_str().unwrap(),
            "--project",
            project.to_str().unwrap(),
            "--profile",
            "quick",
            "--no-tui",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(json["status"], "succeeded");
    assert_eq!(json["profile"], "quick");
    assert!(json["sections"].as_u64().unwrap() > 0);
    assert!(json["functions"].as_u64().unwrap() > 0);
    assert!(json["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| { item["code"] == "pass_skipped_by_profile" && item["recoverable"] == true }));

    let output = Command::cargo_bin("revdeck")
        .unwrap()
        .args(["jobs", project.to_str().unwrap(), "--limit", "20"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let jobs = json["jobs"].as_array().unwrap();
    let parse = jobs
        .iter()
        .find(|job| job["pass_name"] == "binary.parse")
        .unwrap();
    assert_eq!(parse["status"], "succeeded");
    assert_eq!(parse["metadata"]["lab_id"], "binary");
    assert_eq!(parse["metadata"]["pass_phase"], "parse");

    let cfg = jobs
        .iter()
        .find(|job| job["pass_name"] == "binary.cfg")
        .unwrap();
    assert_eq!(cfg["status"], "skipped");
    assert_eq!(cfg["metadata"]["lab_id"], "binary");
    assert_eq!(cfg["metadata"]["pass_phase"], "cfg");

    assert!(jobs
        .iter()
        .any(|job| job["pass_name"] == "binary.triage" && job["status"] == "succeeded"));
}
