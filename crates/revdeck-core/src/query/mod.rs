use crate::{EdgeKind, ObjectKind, ObjectRef, StableObjectKey};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSummary {
    pub object_ref: ObjectRef,
    pub artifact_key: Option<String>,
    pub display_name: Option<String>,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub metadata_json: String,
}

impl ObjectSummary {
    pub fn new(object_ref: ObjectRef, display_name: impl Into<String>) -> Self {
        Self {
            object_ref,
            artifact_key: None,
            display_name: Some(display_name.into()),
            address: None,
            size: None,
            metadata_json: "{}".to_string(),
        }
    }

    pub fn label(&self) -> &str {
        self.display_name
            .as_deref()
            .unwrap_or_else(|| self.object_ref.key.as_str())
    }

    pub fn lab_id(&self) -> Option<String> {
        metadata_lab_id(&self.metadata_json).or_else(|| kind_lab_id(self.object_ref.kind))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObjectRelation {
    pub edge_ref: ObjectRef,
    pub source: ObjectRef,
    pub target: ObjectRef,
    pub kind: EdgeKind,
    pub confidence: f64,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationDirection {
    Outgoing,
    Incoming,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationFilter {
    All,
    Calls,
    Xrefs,
    Contains,
    Evidence,
    DerivedFrom,
    Timeline,
    Diff,
    Plugin,
}

impl RelationFilter {
    pub const fn id(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Calls => "calls",
            Self::Xrefs => "xrefs",
            Self::Contains => "contains",
            Self::Evidence => "evidence",
            Self::DerivedFrom => "derived_from",
            Self::Timeline => "timeline",
            Self::Diff => "diff",
            Self::Plugin => "plugin",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "all relations",
            Self::Calls => "calls",
            Self::Xrefs => "xrefs",
            Self::Contains => "containment",
            Self::Evidence => "evidence",
            Self::DerivedFrom => "derived",
            Self::Timeline => "timeline",
            Self::Diff => "diff",
            Self::Plugin => "plugin",
        }
    }

    pub const fn all() -> &'static [Self] {
        &[
            Self::All,
            Self::Calls,
            Self::Xrefs,
            Self::Contains,
            Self::Evidence,
            Self::DerivedFrom,
            Self::Timeline,
            Self::Diff,
            Self::Plugin,
        ]
    }

    pub const fn matches(self, edge_kind: EdgeKind) -> bool {
        match self {
            Self::All => true,
            Self::Calls => matches!(edge_kind, EdgeKind::Calls | EdgeKind::CallsImport),
            Self::Xrefs => matches!(
                edge_kind,
                EdgeKind::References | EdgeKind::HasXref | EdgeKind::XrefFrom
            ),
            Self::Contains => matches!(edge_kind, EdgeKind::Contains),
            Self::Evidence => matches!(
                edge_kind,
                EdgeKind::Annotates
                    | EdgeKind::EvidenceFor
                    | EdgeKind::Correlates
                    | EdgeKind::ClustersWith
            ),
            Self::DerivedFrom => matches!(edge_kind, EdgeKind::DerivedFrom),
            Self::Timeline => matches!(edge_kind, EdgeKind::Timeline),
            Self::Diff => matches!(edge_kind, EdgeKind::DiffersFrom),
            Self::Plugin => matches!(edge_kind, EdgeKind::Contributes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSearch {
    pub kind: Option<ObjectKind>,
    pub term: String,
    pub limit: usize,
}

impl ObjectSearch {
    pub fn new(kind: Option<ObjectKind>, term: impl Into<String>) -> Self {
        Self {
            kind,
            term: term.into(),
            limit: 25,
        }
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalOptions {
    pub root: ObjectRef,
    pub direction: RelationDirection,
    pub edge_kind: Option<EdgeKind>,
    pub relation_filter: RelationFilter,
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl TraversalOptions {
    pub fn new(root: ObjectRef) -> Self {
        Self {
            root,
            direction: RelationDirection::Both,
            edge_kind: None,
            relation_filter: RelationFilter::All,
            max_depth: 2,
            max_nodes: 64,
        }
    }

    pub fn with_direction(mut self, direction: RelationDirection) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_edge_kind(mut self, edge_kind: EdgeKind) -> Self {
        self.edge_kind = Some(edge_kind);
        self
    }

    pub fn with_relation_filter(mut self, relation_filter: RelationFilter) -> Self {
        self.relation_filter = relation_filter;
        self
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    pub fn with_max_nodes(mut self, max_nodes: usize) -> Self {
        self.max_nodes = max_nodes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalNode {
    pub object_ref: ObjectRef,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalTraversal {
    pub root: ObjectRef,
    pub nodes: Vec<TraversalNode>,
    pub relations: Vec<ObjectRelation>,
}

impl LocalTraversal {
    pub fn evidence_path_items(&self) -> Vec<EvidencePathItem> {
        let depth_by_ref = self
            .nodes
            .iter()
            .map(|node| (node.object_ref.clone(), node.depth))
            .collect::<BTreeMap<_, _>>();

        self.nodes
            .iter()
            .map(|node| {
                let (via, predecessor) = if node.depth == 0 {
                    (None, None)
                } else {
                    self.predecessor_for(&node.object_ref, node.depth, &depth_by_ref)
                        .map(|(predecessor, via)| (Some(via), Some(predecessor)))
                        .unwrap_or((None, None))
                };
                EvidencePathItem {
                    object_ref: node.object_ref.clone(),
                    depth: node.depth,
                    via,
                    predecessor,
                }
            })
            .collect()
    }

    fn predecessor_for(
        &self,
        object_ref: &ObjectRef,
        depth: usize,
        depth_by_ref: &BTreeMap<ObjectRef, usize>,
    ) -> Option<(ObjectRef, EdgeKind)> {
        let parent_depth = depth.saturating_sub(1);
        self.relations
            .iter()
            .filter_map(|relation| {
                let predecessor = if relation.target == *object_ref {
                    relation.source.clone()
                } else if relation.source == *object_ref {
                    relation.target.clone()
                } else {
                    return None;
                };
                if depth_by_ref.get(&predecessor) == Some(&parent_depth) {
                    Some((predecessor, relation.kind))
                } else {
                    None
                }
            })
            .min_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePathItem {
    pub object_ref: ObjectRef,
    pub depth: usize,
    pub via: Option<EdgeKind>,
    pub predecessor: Option<ObjectRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    #[error("object query backend failed: {0}")]
    Backend(String),
}

fn metadata_lab_id(metadata_json: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(metadata_json).ok()?;
    value
        .get("lab_id")
        .or_else(|| value.get("lab"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn kind_lab_id(kind: ObjectKind) -> Option<String> {
    match kind {
        ObjectKind::TraceSession | ObjectKind::TraceEvent => Some("trace".to_string()),
        ObjectKind::FirmwareFile => Some("firmware".to_string()),
        ObjectKind::CrashReport | ObjectKind::CrashFrame => Some("crash".to_string()),
        ObjectKind::ProtocolSample | ObjectKind::ProtocolMessage | ObjectKind::ProtocolField => {
            Some("protocol".to_string())
        }
        ObjectKind::DiffDelta => Some("diff".to_string()),
        ObjectKind::PluginContribution => Some("plugin".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ObjectRef {
        ObjectRef::artifact("abc123", "fixture").unwrap()
    }

    fn lab_object(kind: ObjectKind, lab_id: &str, local_id: &str) -> ObjectRef {
        let artifact = artifact();
        ObjectRef::lab_object(kind, Some(&artifact.key), lab_id, local_id).unwrap()
    }

    fn function() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
        )
    }

    fn string() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::String,
            StableObjectKey::string(&artifact.key, 0x220, Some(0x402220), "password").unwrap(),
        )
    }

    fn import() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::Import,
            StableObjectKey::import(&artifact.key, Some("libc.so.6"), "system", None).unwrap(),
        )
    }

    #[test]
    fn object_summary_exposes_lab_identity_from_metadata_or_kind() {
        let plugin = ObjectSummary {
            object_ref: lab_object(
                ObjectKind::PluginContribution,
                "plugin",
                "detector/finding-1",
            ),
            artifact_key: None,
            display_name: Some("plugin contribution".to_string()),
            address: None,
            size: None,
            metadata_json: r#"{"lab_id":"custom-plugin"}"#.to_string(),
        };
        let trace = ObjectSummary::new(
            lab_object(ObjectKind::TraceEvent, "trace", "session-1/event-1"),
            "trace event",
        );

        assert_eq!(plugin.lab_id().as_deref(), Some("custom-plugin"));
        assert_eq!(trace.lab_id().as_deref(), Some("trace"));
    }

    #[test]
    fn local_traversal_builds_mixed_lab_evidence_path_items() {
        let function = function();
        let import = import();
        let trace_event = lab_object(ObjectKind::TraceEvent, "trace", "session-1/event-4");
        let crash_frame = lab_object(ObjectKind::CrashFrame, "crash", "asan/frame-0");
        let protocol_field = lab_object(ObjectKind::ProtocolField, "protocol", "sample-1/opcode");
        let string = string();

        let mut graph = InMemoryObjectGraph::new()
            .add_object(ObjectSummary::new(function.clone(), "main"))
            .add_object(ObjectSummary::new(import.clone(), "system"))
            .add_object(ObjectSummary::new(trace_event.clone(), "trace event #4"))
            .add_object(ObjectSummary::new(crash_frame.clone(), "frame #0"))
            .add_object(ObjectSummary::new(protocol_field.clone(), "opcode"))
            .add_object(ObjectSummary::new(string.clone(), "password"));
        graph
            .insert_relation(function.clone(), import.clone(), EdgeKind::CallsImport)
            .unwrap();
        graph
            .insert_relation(trace_event.clone(), function.clone(), EdgeKind::Correlates)
            .unwrap();
        graph
            .insert_relation(crash_frame.clone(), function.clone(), EdgeKind::Correlates)
            .unwrap();
        graph
            .insert_relation(
                function.clone(),
                protocol_field.clone(),
                EdgeKind::Correlates,
            )
            .unwrap();
        graph
            .insert_relation(protocol_field.clone(), string.clone(), EdgeKind::References)
            .unwrap();

        let traversal = graph
            .local_traversal(
                &TraversalOptions::new(function.clone())
                    .with_direction(RelationDirection::Both)
                    .with_max_depth(2)
                    .with_max_nodes(8),
            )
            .unwrap();
        let path = traversal.evidence_path_items();

        assert!(path
            .iter()
            .any(|item| item.object_ref == function && item.depth == 0 && item.via.is_none()));
        assert!(path.iter().any(|item| item.object_ref == trace_event
            && item.depth == 1
            && item.via == Some(EdgeKind::Correlates)));
        assert!(path.iter().any(|item| item.object_ref == crash_frame
            && item.depth == 1
            && item.via == Some(EdgeKind::Correlates)));
        assert!(path.iter().any(|item| item.object_ref == import
            && item.depth == 1
            && item.via == Some(EdgeKind::CallsImport)));
        assert!(path.iter().any(|item| item.object_ref == string
            && item.depth == 2
            && item.via == Some(EdgeKind::References)
            && item.predecessor == Some(protocol_field.clone())));
    }

    #[test]
    fn local_traversal_keeps_relation_filters_bounded() {
        let function = function();
        let import = import();
        let trace_event = lab_object(ObjectKind::TraceEvent, "trace", "session-1/event-4");
        let mut graph = InMemoryObjectGraph::new()
            .add_object(ObjectSummary::new(function.clone(), "main"))
            .add_object(ObjectSummary::new(import, "system"))
            .add_object(ObjectSummary::new(trace_event.clone(), "trace event #4"));
        graph
            .insert_relation(trace_event.clone(), function.clone(), EdgeKind::Correlates)
            .unwrap();
        graph
            .insert_relation(function.clone(), trace_event.clone(), EdgeKind::EvidenceFor)
            .unwrap();

        let traversal = graph
            .local_traversal(
                &TraversalOptions::new(function)
                    .with_edge_kind(EdgeKind::Correlates)
                    .with_max_depth(1)
                    .with_max_nodes(2),
            )
            .unwrap();

        assert_eq!(traversal.nodes.len(), 2);
        assert!(traversal
            .relations
            .iter()
            .all(|relation| relation.kind == EdgeKind::Correlates));
    }

    #[test]
    fn relation_filter_groups_match_expected_edge_kinds() {
        assert!(RelationFilter::Calls.matches(EdgeKind::Calls));
        assert!(RelationFilter::Calls.matches(EdgeKind::CallsImport));
        assert!(!RelationFilter::Calls.matches(EdgeKind::References));

        assert!(RelationFilter::Xrefs.matches(EdgeKind::References));
        assert!(RelationFilter::Xrefs.matches(EdgeKind::HasXref));
        assert!(RelationFilter::Xrefs.matches(EdgeKind::XrefFrom));
        assert!(!RelationFilter::Xrefs.matches(EdgeKind::CallsImport));

        assert!(RelationFilter::Evidence.matches(EdgeKind::Annotates));
        assert!(RelationFilter::Evidence.matches(EdgeKind::EvidenceFor));
        assert!(RelationFilter::Evidence.matches(EdgeKind::Correlates));
        assert!(RelationFilter::Evidence.matches(EdgeKind::ClustersWith));
        assert!(!RelationFilter::Evidence.matches(EdgeKind::DiffersFrom));

        assert!(RelationFilter::Diff.matches(EdgeKind::DiffersFrom));
        assert!(RelationFilter::Plugin.matches(EdgeKind::Contributes));
        assert!(RelationFilter::Timeline.matches(EdgeKind::Timeline));
        assert!(RelationFilter::All.matches(EdgeKind::ControlFlow));
    }
}

pub trait ObjectGraphQuery {
    fn get_object(&self, object_ref: &ObjectRef) -> Result<Option<ObjectSummary>, QueryError>;

    fn search_objects(&self, search: &ObjectSearch) -> Result<Vec<ObjectSummary>, QueryError>;

    fn relations(
        &self,
        object_ref: &ObjectRef,
        direction: RelationDirection,
        edge_kind: Option<EdgeKind>,
    ) -> Result<Vec<ObjectRelation>, QueryError>;

    fn outgoing(
        &self,
        object_ref: &ObjectRef,
        edge_kind: Option<EdgeKind>,
    ) -> Result<Vec<ObjectRelation>, QueryError> {
        self.relations(object_ref, RelationDirection::Outgoing, edge_kind)
    }

    fn incoming(
        &self,
        object_ref: &ObjectRef,
        edge_kind: Option<EdgeKind>,
    ) -> Result<Vec<ObjectRelation>, QueryError> {
        self.relations(object_ref, RelationDirection::Incoming, edge_kind)
    }

    fn backlinks(&self, object_ref: &ObjectRef) -> Result<Vec<ObjectRelation>, QueryError> {
        self.incoming(object_ref, None)
    }

    fn local_traversal(&self, options: &TraversalOptions) -> Result<LocalTraversal, QueryError> {
        let mut queue = VecDeque::from([(options.root.clone(), 0usize)]);
        let mut visited = BTreeSet::from([options.root.clone()]);
        let mut nodes = vec![TraversalNode {
            object_ref: options.root.clone(),
            depth: 0,
        }];
        let mut relations = Vec::new();
        let mut seen_edges = BTreeSet::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= options.max_depth || nodes.len() >= options.max_nodes {
                continue;
            }

            for relation in self.relations(&current, options.direction, options.edge_kind)? {
                if !options.relation_filter.matches(relation.kind) {
                    continue;
                }
                if seen_edges.insert(relation.edge_ref.clone()) {
                    relations.push(relation.clone());
                }

                let next = match options.direction {
                    RelationDirection::Outgoing => relation.target.clone(),
                    RelationDirection::Incoming => relation.source.clone(),
                    RelationDirection::Both => {
                        if relation.source == current {
                            relation.target.clone()
                        } else {
                            relation.source.clone()
                        }
                    }
                };

                if visited.insert(next.clone()) {
                    let next_depth = depth + 1;
                    nodes.push(TraversalNode {
                        object_ref: next.clone(),
                        depth: next_depth,
                    });
                    if nodes.len() >= options.max_nodes {
                        break;
                    }
                    queue.push_back((next, next_depth));
                }
            }
        }

        Ok(LocalTraversal {
            root: options.root.clone(),
            nodes,
            relations,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryObjectGraph {
    objects: BTreeMap<ObjectRef, ObjectSummary>,
    relations: Vec<ObjectRelation>,
}

impl InMemoryObjectGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_object(&mut self, object: ObjectSummary) {
        self.objects.insert(object.object_ref.clone(), object);
    }

    pub fn add_object(mut self, object: ObjectSummary) -> Self {
        self.insert_object(object);
        self
    }

    pub fn insert_relation(
        &mut self,
        source: ObjectRef,
        target: ObjectRef,
        kind: EdgeKind,
    ) -> Result<(), QueryError> {
        let key = StableObjectKey::edge(kind, &source, &target)
            .map_err(|err| QueryError::Backend(err.to_string()))?;
        self.relations.push(ObjectRelation {
            edge_ref: ObjectRef::new(ObjectKind::Edge, key),
            source,
            target,
            kind,
            confidence: 1.0,
            metadata_json: "{}".to_string(),
        });
        Ok(())
    }
}

impl ObjectGraphQuery for InMemoryObjectGraph {
    fn get_object(&self, object_ref: &ObjectRef) -> Result<Option<ObjectSummary>, QueryError> {
        Ok(self.objects.get(object_ref).cloned())
    }

    fn search_objects(&self, search: &ObjectSearch) -> Result<Vec<ObjectSummary>, QueryError> {
        let term = search.term.to_ascii_lowercase();
        let mut matches = self
            .objects
            .values()
            .filter(|object| {
                search
                    .kind
                    .map_or(true, |kind| object.object_ref.kind == kind)
            })
            .filter(|object| {
                object
                    .display_name
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&term)
                    || object
                        .object_ref
                        .key
                        .as_str()
                        .to_ascii_lowercase()
                        .contains(&term)
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.object_ref
                .kind
                .cmp(&right.object_ref.kind)
                .then_with(|| left.label().cmp(right.label()))
                .then_with(|| left.object_ref.key.cmp(&right.object_ref.key))
        });
        matches.truncate(search.limit);
        Ok(matches)
    }

    fn relations(
        &self,
        object_ref: &ObjectRef,
        direction: RelationDirection,
        edge_kind: Option<EdgeKind>,
    ) -> Result<Vec<ObjectRelation>, QueryError> {
        let mut matches = self
            .relations
            .iter()
            .filter(|relation| edge_kind.map_or(true, |kind| relation.kind == kind))
            .filter(|relation| match direction {
                RelationDirection::Outgoing => relation.source == *object_ref,
                RelationDirection::Incoming => relation.target == *object_ref,
                RelationDirection::Both => {
                    relation.source == *object_ref || relation.target == *object_ref
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.target.cmp(&right.target))
        });
        Ok(matches)
    }
}
