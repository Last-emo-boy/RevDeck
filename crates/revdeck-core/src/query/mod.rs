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
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl TraversalOptions {
    pub fn new(root: ObjectRef) -> Self {
        Self {
            root,
            direction: RelationDirection::Both,
            edge_kind: None,
            max_depth: 2,
            max_nodes: 64,
        }
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    #[error("object query backend failed: {0}")]
    Backend(String),
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
