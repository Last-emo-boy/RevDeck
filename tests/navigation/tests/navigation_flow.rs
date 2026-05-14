use revdeck_core::{
    CommandExecutor, CommandOutcome, CommandParser, CommandResolver, CommandState, EdgeKind,
    InMemoryObjectGraph, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectSummary, StableObjectKey,
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

fn import(symbol: &str) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::Import,
        StableObjectKey::import(&artifact_key(), Some("libc.so.6"), symbol, None).unwrap(),
    )
}

fn xref(source: &ObjectRef, target: &ObjectRef) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::Xref,
        StableObjectKey::xref(
            &artifact_key(),
            source,
            target,
            EdgeKind::CallsImport.as_str(),
            Some(0x401004),
        )
        .unwrap(),
    )
}

fn open(
    graph: &dyn ObjectGraphQuery,
    state: &mut CommandState,
    object_ref: &ObjectRef,
) -> CommandOutcome {
    let ast = CommandParser::parse(&format!("open {object_ref}")).unwrap();
    let resolved = CommandResolver::new(graph).resolve(ast, state).unwrap();
    CommandExecutor::execute(state, resolved).unwrap()
}

#[test]
fn string_to_xref_to_function_to_import_to_back_flow() {
    let password = string("password", 0x20);
    let main = function("main", 0x401000);
    let system = import("system");
    let call_xref = xref(&main, &system);
    let mut graph = InMemoryObjectGraph::new()
        .add_object(ObjectSummary::new(password.clone(), "password"))
        .add_object(ObjectSummary::new(call_xref.clone(), "CALLS_IMPORT"))
        .add_object(ObjectSummary::new(main.clone(), "main"))
        .add_object(ObjectSummary::new(system.clone(), "system"));
    graph
        .insert_relation(password.clone(), call_xref.clone(), EdgeKind::HasXref)
        .unwrap();
    graph
        .insert_relation(call_xref.clone(), main.clone(), EdgeKind::DerivedFrom)
        .unwrap();
    graph
        .insert_relation(main.clone(), system.clone(), EdgeKind::CallsImport)
        .unwrap();

    let mut state = CommandState::default();
    open(&graph, &mut state, &password);
    open(&graph, &mut state, &call_xref);
    open(&graph, &mut state, &main);
    open(&graph, &mut state, &system);

    assert_eq!(state.current_object.as_ref(), Some(&system));
    assert_eq!(state.navigation.len(), 4);

    let back = CommandParser::parse("back").unwrap();
    let resolved = CommandResolver::new(&graph).resolve(back, &state).unwrap();
    assert!(matches!(
        CommandExecutor::execute(&mut state, resolved).unwrap(),
        CommandOutcome::Navigated(_)
    ));
    assert_eq!(state.current_object.as_ref(), Some(&main));

    let forward = CommandParser::parse("forward").unwrap();
    let resolved = CommandResolver::new(&graph)
        .resolve(forward, &state)
        .unwrap();
    CommandExecutor::execute(&mut state, resolved).unwrap();
    assert_eq!(state.current_object.as_ref(), Some(&system));
}
