use revdeck_core::{EdgeKind, ObjectRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

fn default_confidence() -> f64 {
    1.0
}

fn empty_json_object() -> Value {
    Value::Object(Default::default())
}
