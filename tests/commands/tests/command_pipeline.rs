use revdeck_core::{
    CommandDiagnosticKind, CommandExecutor, CommandParser, CommandResolver, CommandState,
    InMemoryObjectGraph, ObjectKind, ObjectRef, ObjectSummary, StableObjectKey,
    StableObjectKeyBuilder,
};

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
