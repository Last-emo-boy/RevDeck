use crate::{manifest::PluginManifest, object_batch::ObjectBatch};
use revdeck_core::ObjectRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidationReport {
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn error(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationIssue {
            code: code.into(),
            message: message.into(),
        });
    }

    pub fn warning(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(ValidationIssue {
            code: code.into(),
            message: message.into(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub code: String,
    pub message: String,
}

pub fn validate_manifest_toml(input: &str) -> Result<(PluginManifest, ValidationReport), String> {
    let manifest = PluginManifest::from_toml(input).map_err(|err| err.to_string())?;
    let report = manifest.validate();
    Ok((manifest, report))
}

pub fn validate_object_batch(batch: &ObjectBatch) -> ValidationReport {
    let mut report = ValidationReport::default();
    if batch.provenance.plugin_id.trim().is_empty() {
        report.error(
            "missing_plugin_id",
            "batch provenance plugin_id is required",
        );
    }
    if batch.provenance.plugin_version.trim().is_empty() {
        report.error(
            "missing_plugin_version",
            "batch provenance plugin_version is required",
        );
    }
    if batch.provenance.input_digest.trim().is_empty() {
        report.error(
            "missing_input_digest",
            "batch provenance input_digest is required",
        );
    }
    let mut object_refs = BTreeSet::new();
    for object in &batch.objects {
        if !object_refs.insert(object.object_ref.clone()) {
            report.error(
                "duplicate_object",
                format!("duplicate object {}", object.object_ref),
            );
        }
    }
    let known_refs = object_refs
        .iter()
        .cloned()
        .chain(batch.provenance.source_artifact.iter().cloned())
        .collect::<BTreeSet<ObjectRef>>();
    for edge in &batch.edges {
        if !known_refs.contains(&edge.source) {
            report.error("dangling_edge_source", format!("missing {}", edge.source));
        }
        if !known_refs.contains(&edge.target) {
            report.error("dangling_edge_target", format!("missing {}", edge.target));
        }
        if !(0.0..=1.0).contains(&edge.confidence) {
            report.error(
                "invalid_edge_confidence",
                "edge confidence must be between 0.0 and 1.0",
            );
        }
    }
    for attribute in &batch.attributes {
        if !known_refs.contains(&attribute.subject) {
            report.error(
                "dangling_attribute_subject",
                format!("missing {}", attribute.subject),
            );
        }
        if attribute.namespace.trim().is_empty() {
            report.error(
                "missing_attribute_namespace",
                "attribute namespace is required",
            );
        }
        if attribute.schema_id.trim().is_empty() {
            report.error(
                "missing_attribute_schema",
                "attribute schema_id is required",
            );
        }
        if attribute.key.trim().is_empty() {
            report.error("missing_attribute_key", "attribute key is required");
        }
    }
    report
}

pub fn digest_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_vec(value)?;
    let digest = Sha256::digest(&encoded);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        manifest::CapabilityKind,
        object_batch::{BatchProvenance, EdgeFact, ObjectBatch, ObjectFact},
    };
    use revdeck_core::{EdgeKind, ObjectRef, StableObjectKey};

    #[test]
    fn manifest_validation_accepts_minimal_plugin() {
        let input = r#"
            [plugin]
            id = "com.example.plugin"
            version = "0.1.0"
            sdk_version = "0.1.0"
            revdeck_compat = ">=0.1,<0.3"

            [[capabilities]]
            id = "import-object-batch"
            kind = "importer"
        "#;
        let (manifest, report) = validate_manifest_toml(input).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(manifest.capabilities[0].kind, CapabilityKind::Importer);
    }

    #[test]
    fn object_batch_rejects_dangling_edges() {
        let artifact = ObjectRef::artifact("abc", "sample.exe").unwrap();
        let function = ObjectRef::new(
            revdeck_core::ObjectKind::Function,
            StableObjectKey::new("function/artifact=abc/va=0x401000").unwrap(),
        );
        let missing = ObjectRef::new(
            revdeck_core::ObjectKind::Import,
            StableObjectKey::new("import/artifact=abc/symbol=system").unwrap(),
        );
        let batch = ObjectBatch {
            provenance: BatchProvenance {
                plugin_id: "com.example.plugin".to_string(),
                plugin_version: "0.1.0".to_string(),
                input_digest: "sha256:abc".to_string(),
                config_digest: None,
                source_artifact: Some(artifact),
            },
            objects: vec![ObjectFact {
                object_ref: function.clone(),
                artifact_key: None,
                display_name: Some("main".to_string()),
                address: Some(0x401000),
                size: None,
                metadata: serde_json::json!({}),
            }],
            edges: vec![EdgeFact {
                edge_ref: None,
                source: function,
                target: missing,
                kind: EdgeKind::CallsImport,
                confidence: 1.0,
                metadata: serde_json::json!({}),
            }],
            attributes: Vec::new(),
            diagnostics: Vec::new(),
        };
        let report = validate_object_batch(&batch);
        assert!(!report.is_valid());
        assert!(report
            .errors
            .iter()
            .any(|issue| issue.code == "dangling_edge_target"));
    }
}
