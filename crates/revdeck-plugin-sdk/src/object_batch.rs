use revdeck_core::{EdgeKind, ObjectKind, ObjectRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectBatch {
    pub provenance: BatchProvenance,
    #[serde(default)]
    pub objects: Vec<ObjectFact>,
    #[serde(default)]
    pub edges: Vec<EdgeFact>,
    #[serde(default)]
    pub attributes: Vec<TypedAttribute>,
    #[serde(default)]
    pub diagnostics: Vec<DiagnosticFact>,
}

impl ObjectBatch {
    pub fn summary(&self) -> ObjectBatchSummary {
        ObjectBatchSummary {
            plugin_id: self.provenance.plugin_id.clone(),
            plugin_version: self.provenance.plugin_version.clone(),
            objects: self.objects.len(),
            edges: self.edges.len(),
            attributes: self.attributes.len(),
            diagnostics: self.diagnostics.len(),
        }
    }

    pub fn audit(&self) -> ObjectBatchAudit {
        let mut object_kinds = BTreeMap::new();
        let mut edge_kinds = BTreeMap::new();
        let mut attribute_namespaces = BTreeSet::new();
        let mut diagnostic_severities = BTreeMap::new();
        let mut touched_labs = BTreeSet::new();

        if let Some(source_artifact) = &self.provenance.source_artifact {
            collect_lab(source_artifact.kind, &mut touched_labs);
        }
        for object in &self.objects {
            increment(&mut object_kinds, object.object_ref.kind.as_str());
            collect_lab(object.object_ref.kind, &mut touched_labs);
        }
        for edge in &self.edges {
            increment(&mut edge_kinds, edge.kind.as_str());
            collect_lab(edge.source.kind, &mut touched_labs);
            collect_lab(edge.target.kind, &mut touched_labs);
        }
        for attribute in &self.attributes {
            attribute_namespaces.insert(attribute.namespace.clone());
            collect_lab(attribute.subject.kind, &mut touched_labs);
        }
        for diagnostic in &self.diagnostics {
            increment(&mut diagnostic_severities, diagnostic.severity.as_str());
        }

        ObjectBatchAudit {
            object_kinds,
            edge_kinds,
            attribute_namespaces: attribute_namespaces.into_iter().collect(),
            diagnostic_severities,
            touched_labs: touched_labs.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchProvenance {
    pub plugin_id: String,
    pub plugin_version: String,
    pub input_digest: String,
    #[serde(default)]
    pub config_digest: Option<String>,
    #[serde(default)]
    pub source_artifact: Option<ObjectRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectFact {
    pub object_ref: ObjectRef,
    #[serde(default)]
    pub artifact_key: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub address: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default = "empty_json_object")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeFact {
    #[serde(default)]
    pub edge_ref: Option<ObjectRef>,
    pub source: ObjectRef,
    pub target: ObjectRef,
    pub kind: EdgeKind,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default = "empty_json_object")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedAttribute {
    pub subject: ObjectRef,
    pub namespace: String,
    pub schema_id: String,
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl DiagnosticSeverity {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticFact {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectBatchSummary {
    pub plugin_id: String,
    pub plugin_version: String,
    pub objects: usize,
    pub edges: usize,
    pub attributes: usize,
    pub diagnostics: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectBatchAudit {
    pub object_kinds: BTreeMap<String, usize>,
    pub edge_kinds: BTreeMap<String, usize>,
    pub attribute_namespaces: Vec<String>,
    pub diagnostic_severities: BTreeMap<String, usize>,
    pub touched_labs: Vec<String>,
}

fn increment(counts: &mut BTreeMap<String, usize>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

fn collect_lab(kind: ObjectKind, labs: &mut BTreeSet<String>) {
    if let Some(lab) = lab_id_for_object_kind(kind) {
        labs.insert(lab.to_string());
    }
}

pub const fn lab_id_for_object_kind(kind: ObjectKind) -> Option<&'static str> {
    match kind {
        ObjectKind::TraceSession | ObjectKind::TraceEvent => Some("trace"),
        ObjectKind::FirmwareFile => Some("firmware"),
        ObjectKind::CrashReport | ObjectKind::CrashFrame => Some("crash"),
        ObjectKind::ProtocolSample | ObjectKind::ProtocolMessage | ObjectKind::ProtocolField => {
            Some("protocol")
        }
        ObjectKind::DiffDelta => Some("diff"),
        ObjectKind::PluginContribution => Some("plugin"),
        _ => None,
    }
}

fn default_confidence() -> f64 {
    1.0
}

fn empty_json_object() -> Value {
    Value::Object(Default::default())
}
