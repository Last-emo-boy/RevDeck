use anyhow::{Context, Result};

use revdeck_core::{ObjectKind, ObjectRef, StableObjectKey};
use revdeck_db::{
    ArtifactRecord, ArtifactRepository, NewPluginRun, ObjectRepository, PluginRunRecord,
    PluginRunRepository, ProjectDatabase, StoredEdge, StoredObject,
};
use revdeck_plugin_sdk::{
    digest_json, validate_manifest_toml, validate_object_batch, DiagnosticFact, EdgeFact,
    ManifestSummary, ObjectBatch, ObjectBatchSummary, ObjectFact, PluginManifest, TypedAttribute,
    ValidationReport,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestValidationOutput {
    pub status: &'static str,
    pub manifest_digest: String,
    pub plugin: Option<ManifestSummary>,
    pub validation: ValidationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTestOutput {
    pub status: &'static str,
    pub manifest_digest: String,
    pub object_batch: Option<ObjectBatchSummary>,
    pub validation: ValidationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCommitSummary {
    pub objects: usize,
    pub edges: usize,
    pub attributes: usize,
    pub diagnostics: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCommitOutput {
    pub status: &'static str,
    pub manifest_digest: String,
    pub plugin_run_id: Option<i64>,
    pub object_batch: Option<ObjectBatchSummary>,
    pub committed: Option<PluginCommitSummary>,
    pub validation: ValidationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRunOutput {
    pub status: &'static str,
    pub mode: &'static str,
    pub manifest_digest: String,
    pub plugin_run_id: Option<i64>,
    pub object_batch: Option<ObjectBatchSummary>,
    pub committed: Option<PluginCommitSummary>,
    pub validation: ValidationReport,
}

struct LoadedPluginDirectory {
    manifest: PluginManifest,
    manifest_digest: String,
    batch: Option<ObjectBatch>,
    batch_digest: String,
    validation: ValidationReport,
}

pub fn validate_manifest_file(path: &Path) -> Result<ManifestValidationOutput> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest {}", path.display()))?;
    validate_manifest_str(&input)
}

pub fn inspect_manifest_file(path: &Path) -> Result<ManifestValidationOutput> {
    validate_manifest_file(path)
}

pub fn validate_manifest_str(input: &str) -> Result<ManifestValidationOutput> {
    let manifest_digest = digest_bytes(input.as_bytes());
    let (manifest, validation) = validate_manifest_toml(input)
        .map_err(|err| anyhow::anyhow!("failed to parse plugin manifest: {err}"))?;
    let status = if validation.is_valid() {
        "validated"
    } else {
        "failed"
    };
    Ok(ManifestValidationOutput {
        status,
        manifest_digest,
        plugin: Some(manifest.summary()),
        validation,
    })
}

pub fn test_plugin_directory(path: &Path) -> Result<PluginTestOutput> {
    let loaded = load_plugin_directory(path)?;
    Ok(PluginTestOutput {
        status: if loaded.validation.is_valid() {
            "succeeded"
        } else {
            "failed"
        },
        manifest_digest: loaded.manifest_digest,
        object_batch: loaded.batch.as_ref().map(ObjectBatch::summary),
        validation: loaded.validation,
    })
}

pub fn commit_plugin_directory(
    project: &ProjectDatabase,
    path: &Path,
) -> Result<PluginCommitOutput> {
    commit_loaded_plugin(project, load_plugin_directory(path)?)
}

pub fn run_plugin_directory(
    project: &ProjectDatabase,
    path: &Path,
    commit: bool,
) -> Result<PluginRunOutput> {
    if commit {
        let output = commit_plugin_directory(project, path)?;
        return Ok(PluginRunOutput {
            status: output.status,
            mode: "fixture_replay",
            manifest_digest: output.manifest_digest,
            plugin_run_id: output.plugin_run_id,
            object_batch: output.object_batch,
            committed: output.committed,
            validation: output.validation,
        });
    }

    let loaded = load_plugin_directory(path)?;
    let status = if loaded.validation.is_valid() {
        "succeeded"
    } else {
        "failed"
    };
    let run = insert_and_finish_run(project, &loaded, status, None)?;
    Ok(PluginRunOutput {
        status,
        mode: "fixture_replay",
        manifest_digest: loaded.manifest_digest,
        plugin_run_id: Some(run.id),
        object_batch: loaded.batch.as_ref().map(ObjectBatch::summary),
        committed: None,
        validation: loaded.validation,
    })
}

fn load_plugin_directory(path: &Path) -> Result<LoadedPluginDirectory> {
    let manifest_path = path.join("revdeck-plugin.toml");
    let manifest_input = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read manifest {}", manifest_path.display()))?;
    let manifest_digest = digest_bytes(manifest_input.as_bytes());
    let (manifest, mut validation) = validate_manifest_toml(&manifest_input)
        .map_err(|err| anyhow::anyhow!("failed to parse plugin manifest: {err}"))?;
    let batch_path = path.join("object-batch.json");
    let mut batch_digest = "none".to_string();
    let batch = if batch_path.exists() {
        let batch_input = fs::read_to_string(&batch_path)
            .with_context(|| format!("failed to read object batch {}", batch_path.display()))?;
        batch_digest = digest_bytes(batch_input.as_bytes());
        let batch: ObjectBatch = serde_json::from_str(&batch_input)
            .with_context(|| format!("failed to parse object batch {}", batch_path.display()))?;
        let batch_report = validate_object_batch(&batch);
        validation.errors.extend(batch_report.errors);
        validation.warnings.extend(batch_report.warnings);
        Some(batch)
    } else {
        validation.warning(
            "missing_object_batch_fixture",
            "object-batch.json was not found; only manifest validation ran",
        );
        None
    };
    for grant in manifest.permissions.risky_grants() {
        validation.warning(
            "risky_permission",
            format!("plugin requests risky permission `{grant}`"),
        );
    }
    Ok(LoadedPluginDirectory {
        manifest,
        manifest_digest,
        batch,
        batch_digest,
        validation,
    })
}

fn commit_loaded_plugin(
    project: &ProjectDatabase,
    loaded: LoadedPluginDirectory,
) -> Result<PluginCommitOutput> {
    let mut validation = loaded.validation.clone();
    let batch = loaded.batch.as_ref();
    if batch.is_none() {
        validation.error(
            "missing_object_batch",
            "object-batch.json is required for plugin commit",
        );
    }
    if let Some(batch) = batch {
        validate_commit_permissions(&loaded.manifest, batch, &mut validation);
    }

    let run_status = if validation.is_valid() {
        "running"
    } else {
        "failed"
    };
    let run = insert_plugin_run(project, &loaded, run_status, &validation)?;

    if !validation.is_valid() {
        let finished = finish_plugin_run(project, run.id, "failed", &validation, None)?;
        return Ok(PluginCommitOutput {
            status: "failed",
            manifest_digest: loaded.manifest_digest,
            plugin_run_id: Some(finished.id),
            object_batch: batch.map(ObjectBatch::summary),
            committed: None,
            validation,
        });
    }

    let batch = batch.expect("validated batch exists");
    match commit_object_batch(project, batch, run.id) {
        Ok(summary) => {
            let finished =
                finish_plugin_run(project, run.id, "succeeded", &validation, Some(&summary))?;
            Ok(PluginCommitOutput {
                status: "succeeded",
                manifest_digest: loaded.manifest_digest,
                plugin_run_id: Some(finished.id),
                object_batch: Some(batch.summary()),
                committed: Some(summary),
                validation,
            })
        }
        Err(err) => {
            validation.error("object_batch_commit_failed", err.to_string());
            let finished = finish_plugin_run(project, run.id, "failed", &validation, None)?;
            Ok(PluginCommitOutput {
                status: "failed",
                manifest_digest: loaded.manifest_digest,
                plugin_run_id: Some(finished.id),
                object_batch: Some(batch.summary()),
                committed: None,
                validation,
            })
        }
    }
}

fn validate_commit_permissions(
    manifest: &PluginManifest,
    batch: &ObjectBatch,
    validation: &mut ValidationReport,
) {
    require_project_write(manifest, validation, "objects", !batch.objects.is_empty());
    require_project_write(manifest, validation, "edges", !batch.edges.is_empty());
    require_project_write(
        manifest,
        validation,
        "attributes",
        !batch.attributes.is_empty(),
    );
    require_project_write(
        manifest,
        validation,
        "diagnostics",
        !batch.diagnostics.is_empty(),
    );
    if batch.provenance.plugin_id != manifest.plugin.id {
        validation.error(
            "plugin_id_mismatch",
            "object batch provenance plugin_id must match manifest plugin.id",
        );
    }
    if batch.provenance.plugin_version != manifest.plugin.version {
        validation.error(
            "plugin_version_mismatch",
            "object batch provenance plugin_version must match manifest plugin.version",
        );
    }
}

fn require_project_write(
    manifest: &PluginManifest,
    validation: &mut ValidationReport,
    grant: &str,
    needed: bool,
) {
    if needed
        && !manifest
            .permissions
            .project_write
            .iter()
            .any(|candidate| candidate == grant)
    {
        validation.error(
            "missing_project_write_permission",
            format!("plugin must request project_write `{grant}` to commit this object batch"),
        );
    }
}

fn commit_object_batch(
    project: &ProjectDatabase,
    batch: &ObjectBatch,
    plugin_run_id: i64,
) -> Result<PluginCommitSummary> {
    let connection = project.connection();
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let result = apply_object_batch(connection, batch, plugin_run_id);
    match result {
        Ok(summary) => {
            connection.execute_batch("COMMIT")?;
            Ok(summary)
        }
        Err(err) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

fn apply_object_batch(
    connection: &rusqlite::Connection,
    batch: &ObjectBatch,
    plugin_run_id: i64,
) -> Result<PluginCommitSummary> {
    let object_repo = ObjectRepository::new(connection);
    for object in &batch.objects {
        if object.object_ref.kind == ObjectKind::Artifact {
            upsert_plugin_artifact(connection, object, batch)?;
        }
    }
    for object in &batch.objects {
        object_repo.upsert_object(&stored_object(connection, object, batch, plugin_run_id)?)?;
    }
    for edge in &batch.edges {
        object_repo.upsert_edge(&stored_edge(edge, batch, plugin_run_id)?)?;
    }
    for attribute in &batch.attributes {
        insert_plugin_attribute(connection, attribute, plugin_run_id)?;
    }
    for diagnostic in &batch.diagnostics {
        insert_plugin_diagnostic(connection, diagnostic, plugin_run_id)?;
    }
    Ok(PluginCommitSummary {
        objects: batch.objects.len(),
        edges: batch.edges.len(),
        attributes: batch.attributes.len(),
        diagnostics: batch.diagnostics.len(),
    })
}

fn stored_object(
    connection: &rusqlite::Connection,
    object: &ObjectFact,
    batch: &ObjectBatch,
    plugin_run_id: i64,
) -> Result<StoredObject> {
    let artifact_key = match &object.artifact_key {
        Some(key) if artifact_exists(connection, key)? => Some(key.clone()),
        _ => None,
    };
    Ok(StoredObject {
        object_ref: object.object_ref.clone(),
        artifact_key,
        display_name: object.display_name.clone(),
        address: object.address,
        size: object.size,
        source_run_id: None,
        metadata_json: serde_json::to_string(&serde_json::json!({
            "plugin_run_id": plugin_run_id,
            "plugin_id": batch.provenance.plugin_id,
            "plugin_version": batch.provenance.plugin_version,
            "fact": object.metadata,
        }))?,
    })
}

fn upsert_plugin_artifact(
    connection: &rusqlite::Connection,
    object: &ObjectFact,
    batch: &ObjectBatch,
) -> Result<()> {
    let display_name = object
        .display_name
        .clone()
        .unwrap_or_else(|| object.object_ref.key.as_str().to_string());
    let source_path =
        artifact_metadata_string(&object.metadata, "source_path").unwrap_or(display_name.clone());
    let sha256 = artifact_metadata_string(&object.metadata, "sha256")
        .unwrap_or_else(|| batch.provenance.input_digest.clone());
    let size = artifact_metadata_u64(&object.metadata, "size")
        .or(object.size)
        .unwrap_or_default();
    let kind =
        artifact_metadata_string(&object.metadata, "kind").unwrap_or_else(|| "binary".to_string());
    let format = artifact_metadata_string(&object.metadata, "format")
        .unwrap_or_else(|| "external".to_string());
    let architecture = artifact_metadata_string(&object.metadata, "architecture")
        .unwrap_or_else(|| "unknown".to_string());
    let import_status = artifact_metadata_string(&object.metadata, "import_status")
        .unwrap_or_else(|| "plugin_imported".to_string());

    ArtifactRepository::new(connection).upsert_artifact(&ArtifactRecord {
        object_ref: object.object_ref.clone(),
        display_name,
        source_path,
        stored_path: None,
        sha256,
        size,
        kind,
        format,
        architecture,
        import_status,
        created_at: OffsetDateTime::now_utc(),
    })?;
    Ok(())
}

fn artifact_metadata_string(metadata: &serde_json::Value, key: &str) -> Option<String> {
    artifact_metadata_value(metadata, key).and_then(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .or_else(|| value.as_u64().map(|number| number.to_string()))
    })
}

fn artifact_metadata_u64(metadata: &serde_json::Value, key: &str) -> Option<u64> {
    artifact_metadata_value(metadata, key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
    })
}

fn artifact_metadata_value<'value>(
    metadata: &'value serde_json::Value,
    key: &str,
) -> Option<&'value serde_json::Value> {
    metadata
        .get("artifact")
        .and_then(|artifact| artifact.get(key))
        .or_else(|| metadata.get(key))
}

fn artifact_exists(connection: &rusqlite::Connection, key: &str) -> Result<bool> {
    let found = connection
        .query_row(
            "SELECT 1 FROM artifacts WHERE object_key = ?1",
            [key],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn stored_edge(edge: &EdgeFact, batch: &ObjectBatch, plugin_run_id: i64) -> Result<StoredEdge> {
    Ok(StoredEdge {
        edge_ref: edge_object_ref(edge)?,
        source: edge.source.clone(),
        target: edge.target.clone(),
        kind: edge.kind,
        confidence: edge.confidence,
        source_run_id: None,
        metadata_json: serde_json::to_string(&serde_json::json!({
            "plugin_run_id": plugin_run_id,
            "plugin_id": batch.provenance.plugin_id,
            "plugin_version": batch.provenance.plugin_version,
            "fact": edge.metadata,
        }))?,
    })
}

fn edge_object_ref(edge: &EdgeFact) -> Result<ObjectRef> {
    if let Some(edge_ref) = &edge.edge_ref {
        if edge_ref.kind != ObjectKind::Edge {
            anyhow::bail!("edge_ref must have kind edge");
        }
        return Ok(edge_ref.clone());
    }
    Ok(ObjectRef::new(
        ObjectKind::Edge,
        StableObjectKey::edge(edge.kind, &edge.source, &edge.target)?,
    ))
}

fn insert_plugin_attribute(
    connection: &rusqlite::Connection,
    attribute: &TypedAttribute,
    plugin_run_id: i64,
) -> Result<()> {
    let value_json = serde_json::to_string(&attribute.value)?;
    connection.execute(
        "INSERT INTO plugin_attributes (
            plugin_run_id, subject_object_key, namespace, schema_id, attr_key, value_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(plugin_run_id, subject_object_key, namespace, schema_id, attr_key)
        DO UPDATE SET value_json = excluded.value_json",
        params![
            plugin_run_id,
            attribute.subject.key.as_str(),
            attribute.namespace,
            attribute.schema_id,
            attribute.key,
            value_json,
        ],
    )?;
    Ok(())
}

fn insert_plugin_diagnostic(
    connection: &rusqlite::Connection,
    diagnostic: &DiagnosticFact,
    plugin_run_id: i64,
) -> Result<()> {
    connection.execute(
        "INSERT INTO plugin_diagnostics (plugin_run_id, severity, code, message)
        VALUES (?1, ?2, ?3, ?4)",
        params![
            plugin_run_id,
            format!("{:?}", diagnostic.severity).to_ascii_lowercase(),
            diagnostic.code,
            diagnostic.message,
        ],
    )?;
    Ok(())
}

fn insert_and_finish_run(
    project: &ProjectDatabase,
    loaded: &LoadedPluginDirectory,
    status: &str,
    summary: Option<&PluginCommitSummary>,
) -> Result<PluginRunRecord> {
    let validation = loaded.validation.clone();
    let run = insert_plugin_run(project, loaded, "running", &validation)?;
    finish_plugin_run(project, run.id, status, &validation, summary)
}

fn insert_plugin_run(
    project: &ProjectDatabase,
    loaded: &LoadedPluginDirectory,
    status: &str,
    validation: &ValidationReport,
) -> Result<PluginRunRecord> {
    let repo = PluginRunRepository::new(project.connection());
    let permissions_json = serde_json::to_string(&loaded.manifest.permissions)
        .context("failed to serialize plugin permissions")?;
    let diagnostics_json =
        serde_json::to_string(validation).context("failed to serialize plugin diagnostics")?;
    repo.insert(&NewPluginRun {
        analysis_run_id: None,
        plugin_id: loaded.manifest.plugin.id.clone(),
        plugin_version: loaded.manifest.plugin.version.clone(),
        manifest_digest: loaded.manifest_digest.clone(),
        input_digest: loaded.batch_digest.clone(),
        config_digest: loaded
            .batch
            .as_ref()
            .and_then(|batch| batch.provenance.config_digest.clone()),
        status: status.to_string(),
        permissions_json,
        diagnostics_json,
        started_at: OffsetDateTime::now_utc(),
    })
    .map_err(Into::into)
}

fn finish_plugin_run(
    project: &ProjectDatabase,
    run_id: i64,
    status: &str,
    validation: &ValidationReport,
    summary: Option<&PluginCommitSummary>,
) -> Result<PluginRunRecord> {
    let repo = PluginRunRepository::new(project.connection());
    let diagnostics_json = serde_json::to_string(&serde_json::json!({
        "validation": validation,
        "committed": summary,
    }))
    .context("failed to serialize plugin run diagnostics")?;
    repo.finish(run_id, status, &diagnostics_json, OffsetDateTime::now_utc())
        .map_err(Into::into)
}

pub fn record_plugin_test_run(
    project: &ProjectDatabase,
    manifest: &PluginManifest,
    manifest_digest: String,
    output: &PluginTestOutput,
) -> Result<PluginRunRecord> {
    let repo = PluginRunRepository::new(project.connection());
    let diagnostics_json = serde_json::to_string(&output.validation)
        .context("failed to serialize plugin diagnostics")?;
    let permissions_json = serde_json::to_string(&manifest.permissions)
        .context("failed to serialize plugin permissions")?;
    let now = OffsetDateTime::now_utc();
    let run = repo.insert(&NewPluginRun {
        analysis_run_id: None,
        plugin_id: manifest.plugin.id.clone(),
        plugin_version: manifest.plugin.version.clone(),
        manifest_digest,
        input_digest: output
            .object_batch
            .as_ref()
            .map(digest_json)
            .transpose()
            .context("failed to digest object batch summary")?
            .unwrap_or_else(|| "none".to_string()),
        config_digest: None,
        status: output.status.to_string(),
        permissions_json,
        diagnostics_json,
        started_at: now,
    })?;
    let finished = repo.finish(
        run.id,
        output.status,
        &run.diagnostics_json,
        OffsetDateTime::now_utc(),
    )?;
    Ok(finished)
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_directory_validates_batch_fixture() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("revdeck-plugin.toml"),
            r#"
            [plugin]
            id = "com.example.test"
            version = "0.1.0"
            sdk_version = "0.1.0"

            [[capabilities]]
            id = "adapter"
            kind = "adapter"
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("object-batch.json"),
            r#"{
              "provenance": {
                "plugin_id": "com.example.test",
                "plugin_version": "0.1.0",
                "input_digest": "fixture"
              },
              "objects": [],
              "edges": [],
              "attributes": [],
              "diagnostics": []
            }"#,
        )
        .unwrap();
        let output = test_plugin_directory(temp.path()).unwrap();
        assert_eq!(output.status, "succeeded");
        assert!(output.validation.is_valid());
    }
}
