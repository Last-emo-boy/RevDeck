use assert_cmd::Command;
use revdeck_core::{
    CommandDiagnosticKind, CommandExecutor, CommandParser, CommandResolver, CommandState,
    InMemoryObjectGraph, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectSearch, ObjectSummary,
    StableObjectKey, StableObjectKeyBuilder,
};
use revdeck_db::{ObjectQueryRepository, ProjectDatabase};
use revdeck_index::{import_binary, AnalysisProfile, ImportOptions};
use std::{path::PathBuf, sync::Once};
use tempfile::tempdir;

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

fn synthetic_pe_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    put_u16(&mut bytes, 0x00, 0x5a4d);
    put_u32(&mut bytes, 0x3c, 0x80);
    put_u32(&mut bytes, 0x80, 0x0000_4550);
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 2);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x96, 0x0022);

    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x20b);
    bytes[optional + 2] = 14;
    put_u32(&mut bytes, optional + 4, 0x200);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x140000000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x3000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u64(&mut bytes, optional + 72, 0x100000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x100000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);

    put_section(
        &mut bytes,
        0x188,
        b".text",
        0x40,
        0x1000,
        0x200,
        0x200,
        0x6000_0020,
    );
    put_section(
        &mut bytes,
        0x1b0,
        b".rdata",
        0x80,
        0x2000,
        0x200,
        0x400,
        0x4000_0040,
    );
    put_u32(&mut bytes, 0x1b0 + 8, 0x100);

    bytes[0x200..0x205].copy_from_slice(&[0x74, 0x02, 0x90, 0xc3, 0xc3]);
    bytes[0x400..0x500].fill(0);
    put_u32(&mut bytes, 0x400, 0x2040);
    put_u32(&mut bytes, 0x404, 0);
    put_u32(&mut bytes, 0x408, 0);
    put_u32(&mut bytes, 0x40c, 0x2030);
    put_u32(&mut bytes, 0x410, 0x2080);
    bytes[0x430..0x43c].copy_from_slice(b"kernel32.dll");
    put_u64(&mut bytes, 0x440, 0x2060);
    put_u64(&mut bytes, 0x448, 0);
    put_u16(&mut bytes, 0x460, 0);
    bytes[0x462..0x46d].copy_from_slice(b"ExitProcess");
    put_u64(&mut bytes, 0x480, 0x2060);
    put_u64(&mut bytes, 0x488, 0);
    put_u32(&mut bytes, 0x98 + 112 + 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 12, 0x100);
    bytes[0x4a0..0x4b3].copy_from_slice(b"admin-token notepad");
    bytes
}

fn put_section(
    bytes: &mut [u8],
    offset: usize,
    name: &[u8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) {
    bytes[offset..offset + name.len()].copy_from_slice(name);
    put_u32(bytes, offset + 8, virtual_size);
    put_u32(bytes, offset + 12, virtual_address);
    put_u32(bytes, offset + 16, raw_size);
    put_u32(bytes, offset + 20, raw_pointer);
    put_u32(bytes, offset + 36, characteristics);
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn artifact_key() -> StableObjectKey {
    StableObjectKeyBuilder::new(ObjectKind::Artifact)
        .component("sha256", "abc123")
        .unwrap()
        .component("path", "fixture")
        .unwrap()
        .finish()
        .unwrap()
}

fn function(name: &str, address: u64) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::Function,
        StableObjectKey::function(&artifact_key(), address, Some(16), Some(name)).unwrap(),
    )
}

fn string(value: &str, offset: u64) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::String,
        StableObjectKey::string(&artifact_key(), offset, Some(0x402000 + offset), value).unwrap(),
    )
}

#[test]
fn command_resolver_blocks_ambiguous_mutation_before_executor_runs() {
    let mut graph = InMemoryObjectGraph::new();
    graph.insert_object(ObjectSummary::new(function("system", 0x401000), "system"));
    graph.insert_object(ObjectSummary::new(string("system", 0x20), "system"));
    let resolver = CommandResolver::new(&graph);
    let mut state = CommandState::default();
    let before = state.clone();

    let ast = CommandParser::parse("tag system suspicious").unwrap();
    let err = resolver.resolve(ast, &state).unwrap_err();

    assert_eq!(err.kind, CommandDiagnosticKind::Ambiguous);
    assert_eq!(state, before);
    assert_eq!(state.tags.len(), 0);

    let err =
        CommandExecutor::execute(&mut state, revdeck_core::ResolvedCommand::Back).unwrap_err();
    assert_eq!(err.kind, CommandDiagnosticKind::Unresolved);
    assert_eq!(state, before);
}

#[test]
fn command_parser_handles_finding_and_export_commands() {
    assert!(CommandParser::parse("finding new high command execution").is_ok());
    assert!(CommandParser::parse("finding link current current evidence").is_ok());
    assert!(CommandParser::parse("export json report.json").is_ok());
    assert!(CommandParser::parse("export markdown report.md").is_ok());
}

#[test]
fn search_cli_lists_objects_in_text_and_json_modes() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    import_binary(
        project.connection(),
        ImportOptions::new(
            temp.path().to_path_buf(),
            workspace_root()
                .join("fixtures")
                .join("binaries")
                .join("sensitive_imports_elf"),
        ),
    )
    .unwrap();
    drop(project);

    let output = Command::new(revdeck_bin())
        .args([
            "search",
            temp.path().to_str().unwrap(),
            "system",
            "--kind",
            "import",
            "--limit",
            "5",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("Search query=`system` kind=import matches="));
    assert!(text.contains("import"));
    assert!(text.contains("system"));
    assert!(text.contains("ref=import:"));

    let output = Command::new(revdeck_bin())
        .args([
            "search",
            temp.path().to_str().unwrap(),
            "password",
            "--kind",
            "string",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["query"], "password");
    assert_eq!(json["kind"], "string");
    let matches = json["matches"].as_array().unwrap();
    assert!(!matches.is_empty());
    assert!(matches.iter().any(|item| item["label"]
        .as_str()
        .unwrap_or_default()
        .contains("password")));
    let object_ref = matches[0]["ref"].as_str().unwrap();

    let output = Command::new(revdeck_bin())
        .args(["inspect", temp.path().to_str().unwrap(), object_ref])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("Object string:"));
    assert!(text.contains("label="));
    assert!(text.contains("relations="));

    let output = Command::new(revdeck_bin())
        .args([
            "inspect",
            temp.path().to_str().unwrap(),
            object_ref,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["object"]["ref"], object_ref);
    assert_eq!(json["object"]["kind"], "string");
    assert!(json["relations"].is_array());

    Command::new(revdeck_bin())
        .args([
            "search",
            temp.path().to_str().unwrap(),
            "system",
            "--kind",
            "bad-kind",
        ])
        .assert()
        .failure();
}

#[test]
fn triage_cli_lists_xrefs_sections_imports_and_strings() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    import_binary(
        project.connection(),
        ImportOptions::new(
            temp.path().to_path_buf(),
            workspace_root()
                .join("fixtures")
                .join("binaries")
                .join("sensitive_imports_elf"),
        ),
    )
    .unwrap();
    drop(project);

    let output = Command::new(revdeck_bin())
        .args([
            "search",
            temp.path().to_str().unwrap(),
            "system",
            "--kind",
            "import",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let import_ref = json["matches"][0]["ref"].as_str().unwrap();

    let output = Command::new(revdeck_bin())
        .args([
            "xrefs",
            temp.path().to_str().unwrap(),
            import_ref,
            "--direction",
            "incoming",
            "--edge-kind",
            "calls-import",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["root"], import_ref);
    assert!(json["relations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|relation| {
            relation["kind"] == "calls_import" && relation["target"] == import_ref
        }));
    let function_ref = json["relations"][0]["source"].as_str().unwrap();

    let output = Command::new(revdeck_bin())
        .args([
            "inspect",
            temp.path().to_str().unwrap(),
            function_ref,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let packet = &json["function_packet"];
    assert!(packet.is_object());
    assert!(packet["score"].as_i64().unwrap_or_default() > 0);
    assert!(packet["reasons"].as_array().unwrap().iter().any(|reason| {
        reason["signal_key"] == "import_family"
            || reason["signal_key"] == "dangerous_import"
            || reason["signal_key"] == "string_signal"
    }));
    assert!(packet["imports"]
        .as_array()
        .unwrap()
        .iter()
        .any(|import| { import["family"] == "process" || import["family"] == "libc" }));

    let output = Command::new(revdeck_bin())
        .args([
            "xrefs",
            temp.path().to_str().unwrap(),
            import_ref,
            "--depth",
            "2",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["root"], import_ref);
    assert!(!json["nodes"].as_array().unwrap().is_empty());
    assert!(json["evidence_path"].is_array());

    let output = Command::new(revdeck_bin())
        .args(["sections", temp.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let sections = json["sections"].as_array().unwrap();
    assert!(!sections.is_empty());
    assert!(sections.iter().any(|section| section["name"] == ".text"));
    assert!(sections.iter().all(|section| section["ref"]
        .as_str()
        .unwrap_or_default()
        .starts_with("section:")));

    let output = Command::new(revdeck_bin())
        .args(["imports", temp.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["imports"].as_array().unwrap().iter().any(|import| {
        import["symbol"] == "system"
            && import["family"] == "process"
            && import["ref"]
                .as_str()
                .unwrap_or_default()
                .starts_with("import:")
    }));
    let module = json["imports"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|import| import["module"].as_str())
        .unwrap_or_default()
        .to_string();
    if !module.is_empty() {
        Command::new(revdeck_bin())
            .args([
                "imports",
                temp.path().to_str().unwrap(),
                "--module",
                &module,
                "--json",
            ])
            .assert()
            .success();
    }

    let output = Command::new(revdeck_bin())
        .args([
            "strings",
            temp.path().to_str().unwrap(),
            "--contains",
            "password",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["strings"].as_array().unwrap().iter().any(|string| {
        string["value"]
            .as_str()
            .unwrap_or_default()
            .contains("password")
            && string["signal"] == "credential"
            && string["file_offset"].is_number()
            && string["ref"]
                .as_str()
                .unwrap_or_default()
                .starts_with("string:")
    }));

    Command::new(revdeck_bin())
        .args(["sections", temp.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Sections count="));
    Command::new(revdeck_bin())
        .args(["imports", temp.path().to_str().unwrap(), "--limit", "5"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Imports count="));
    Command::new(revdeck_bin())
        .args(["strings", temp.path().to_str().unwrap(), "--limit", "5"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Strings count="));
}

#[test]
fn cli_pe_workflow_uses_synthetic_fixture_not_system_notepad() {
    let temp = tempdir().unwrap();
    let fixture_path = temp.path().join("synthetic-notepad-like.exe");
    std::fs::write(&fixture_path, synthetic_pe_fixture()).unwrap();

    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let outcome = import_binary(
        project.connection(),
        ImportOptions::new(temp.path().to_path_buf(), fixture_path.clone()),
    )
    .unwrap();
    assert_eq!(outcome.status.as_str(), "succeeded");
    assert_eq!(outcome.summary.imports, 1);
    assert!(outcome.summary.strings >= 2);
    drop(project);

    let output = Command::new(revdeck_bin())
        .args(["sections", temp.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == ".text"));
    assert!(json["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == ".rdata"));

    let output = Command::new(revdeck_bin())
        .args(["imports", temp.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["imports"].as_array().unwrap().iter().any(|import| {
        import["module"] == "kernel32.dll"
            && import["symbol"] == "ExitProcess"
            && import["virtual_address"].is_number()
    }));

    let output = Command::new(revdeck_bin())
        .args([
            "strings",
            temp.path().to_str().unwrap(),
            "--contains",
            "admin",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["strings"].as_array().unwrap().iter().any(|string| {
        string["value"]
            .as_str()
            .unwrap_or_default()
            .contains("admin-token")
    }));

    let output = Command::new(revdeck_bin())
        .args([
            "search",
            temp.path().to_str().unwrap(),
            "ExitProcess",
            "--kind",
            "import",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let import_ref = json["matches"][0]["ref"].as_str().unwrap();
    assert!(import_ref.starts_with("import:"));

    Command::new(revdeck_bin())
        .args([
            "inspect",
            temp.path().to_str().unwrap(),
            import_ref,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("ExitProcess"));

    assert!(!fixture_path
        .to_string_lossy()
        .contains(r"C:\Windows\System32\notepad.exe"));
}

#[test]
fn disasm_cli_lists_cfg_when_available_and_skipped_when_unavailable() {
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    import_binary(
        project.connection(),
        ImportOptions::new(
            temp.path().to_path_buf(),
            workspace_root()
                .join("fixtures")
                .join("binaries")
                .join("sensitive_imports_elf"),
        ),
    )
    .unwrap();
    let query = ObjectQueryRepository::new(project.connection());
    let function_ref = query
        .search_objects(&ObjectSearch::new(Some(ObjectKind::Function), "main").with_limit(20))
        .unwrap()
        .into_iter()
        .find_map(|function| {
            let preview = query
                .disassembly_preview(&function.object_ref, 4)
                .ok()
                .flatten()?;
            (!preview.instructions.is_empty()).then_some(function.object_ref)
        })
        .expect("balanced profile should index at least one function with instructions");
    drop(project);

    let output = Command::new(revdeck_bin())
        .args([
            "disasm",
            temp.path().to_str().unwrap(),
            &function_ref.to_string(),
            "--limit",
            "3",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["function"]["ref"], function_ref.to_string());
    assert_eq!(json["available"], true);
    assert!(json["total_basic_blocks"].as_u64().unwrap_or_default() > 0);
    assert!(json["total_instructions"].as_u64().unwrap_or_default() > 0);
    assert!(json["basic_blocks"].as_array().unwrap().len() <= 3);
    assert!(json["instructions"].as_array().unwrap().len() <= 3);
    assert!(json["instructions"].as_array().unwrap().iter().all(|item| {
        item["ref"]
            .as_str()
            .unwrap_or_default()
            .starts_with("instruction:")
            && item["block_ref"]
                .as_str()
                .unwrap_or_default()
                .starts_with("basic_block:")
            && item["mnemonic"].is_string()
            && item["text"].is_string()
            && item["address"].is_number()
    }));

    Command::new(revdeck_bin())
        .args([
            "disasm",
            temp.path().to_str().unwrap(),
            &function_ref.to_string(),
            "--limit",
            "2",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Disasm function="))
        .stdout(predicates::str::contains("Instructions:"));

    let quick_temp = tempdir().unwrap();
    let quick_project = ProjectDatabase::create_or_open(quick_temp.path()).unwrap();
    import_binary(
        quick_project.connection(),
        ImportOptions::with_profile(
            quick_temp.path().to_path_buf(),
            workspace_root()
                .join("fixtures")
                .join("binaries")
                .join("sensitive_imports_elf"),
            AnalysisProfile::Quick,
        ),
    )
    .unwrap();
    let quick_query = ObjectQueryRepository::new(quick_project.connection());
    let quick_function = quick_query
        .search_objects(&ObjectSearch::new(Some(ObjectKind::Function), "main").with_limit(1))
        .unwrap()
        .into_iter()
        .next()
        .expect("quick profile should still index function seeds")
        .object_ref;
    drop(quick_project);

    let output = Command::new(revdeck_bin())
        .args([
            "disasm",
            quick_temp.path().to_str().unwrap(),
            &quick_function.to_string(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["available"], false);
    assert!(json["unavailable_reason"]
        .as_str()
        .unwrap_or_default()
        .contains("quick profile"));

    Command::new(revdeck_bin())
        .args([
            "disasm",
            quick_temp.path().to_str().unwrap(),
            &quick_function.to_string(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("CFG unavailable"));
}
