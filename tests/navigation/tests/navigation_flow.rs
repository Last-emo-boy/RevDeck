use revdeck_core::{
    CommandExecutor, CommandOutcome, CommandParser, CommandResolver, CommandState, EdgeKind,
    InMemoryObjectGraph, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectSummary, RelationDirection,
    RelationFilter, StableObjectKey, StableObjectKeyBuilder, TraversalOptions,
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

#[test]
fn traversal_filters_mixed_evidence_paths_without_losing_navigation_targets() {
    let main = function("main", 0x401000);
    let system = import("system");
    let password = string("password", 0x20);
    let trace_event = ObjectRef::lab_object(
        ObjectKind::TraceEvent,
        Some(&artifact_key()),
        "trace",
        "session-1/event-7",
    )
    .unwrap();
    let mut graph = InMemoryObjectGraph::new()
        .add_object(ObjectSummary::new(main.clone(), "main"))
        .add_object(ObjectSummary::new(system.clone(), "system"))
        .add_object(ObjectSummary::new(password.clone(), "password"))
        .add_object(ObjectSummary::new(trace_event.clone(), "trace event #7"));
    graph
        .insert_relation(main.clone(), system.clone(), EdgeKind::CallsImport)
        .unwrap();
    graph
        .insert_relation(main.clone(), password.clone(), EdgeKind::References)
        .unwrap();
    graph
        .insert_relation(trace_event.clone(), main.clone(), EdgeKind::Correlates)
        .unwrap();

    let calls = graph
        .local_traversal(
            &TraversalOptions::new(main.clone())
                .with_direction(RelationDirection::Both)
                .with_relation_filter(RelationFilter::Calls)
                .with_max_depth(1)
                .with_max_nodes(8),
        )
        .unwrap();
    assert!(calls.nodes.iter().any(|node| node.object_ref == system));
    assert!(!calls.nodes.iter().any(|node| node.object_ref == password));
    assert!(!calls
        .nodes
        .iter()
        .any(|node| node.object_ref == trace_event));

    let evidence = graph
        .local_traversal(
            &TraversalOptions::new(main.clone())
                .with_direction(RelationDirection::Both)
                .with_relation_filter(RelationFilter::Evidence)
                .with_max_depth(1)
                .with_max_nodes(8),
        )
        .unwrap();
    assert!(evidence
        .evidence_path_items()
        .iter()
        .any(|item| item.object_ref == trace_event
            && item.depth == 1
            && item.via == Some(EdgeKind::Correlates)));
    assert!(!evidence.nodes.iter().any(|node| node.object_ref == system));
}
