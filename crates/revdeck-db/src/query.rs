use revdeck_core::{
    DiffArtifactSnapshot, DiffComparableObject, DiffComparableRelation, EdgeKind, ObjectGraphQuery,
    ObjectKind, ObjectRef, ObjectRelation, ObjectSearch, ObjectSummary, QueryError,
    RelationDirection,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;

pub struct ObjectQueryRepository<'conn> {
    connection: &'conn Connection,
}

impl<'conn> ObjectQueryRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }

    pub fn diff_artifact_snapshot(
        &self,
        artifact: &ObjectRef,
    ) -> Result<DiffArtifactSnapshot, QueryError> {
        let artifact_label = self.diff_artifact_label(artifact)?;
        let objects = self.diff_comparable_objects(artifact)?;
        let identity_by_object_key = objects
            .iter()
            .map(|object| {
                (
                    object.object_ref.key.as_str().to_string(),
                    object.identity_key.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let relations = self.diff_comparable_relations(artifact, &identity_by_object_key)?;

        Ok(DiffArtifactSnapshot {
            artifact: artifact.clone(),
            artifact_label,
            objects,
            relations,
        })
    }

    fn diff_artifact_label(&self, artifact: &ObjectRef) -> Result<String, QueryError> {
        self.connection
            .query_row(
                "SELECT coalesce(a.display_name, o.display_name, ?1)
                FROM objects o
                LEFT JOIN artifacts a ON a.object_key = o.object_key
                WHERE o.object_key = ?1 AND o.kind = 'artifact'
                LIMIT 1",
                [artifact.key.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map(|label| label.unwrap_or_else(|| artifact.key.as_str().to_string()))
            .map_err(db_error)
    }

    fn diff_comparable_objects(
        &self,
        artifact: &ObjectRef,
    ) -> Result<Vec<DiffComparableObject>, QueryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    o.object_key,
                    o.kind,
                    coalesce(rn.body, o.display_name, o.object_key),
                    o.address,
                    o.size,
                    o.metadata_json,
                    fn.name,
                    fn.virtual_address,
                    fn.size,
                    im.module,
                    im.symbol,
                    im.ordinal,
                    im.virtual_address,
                    st.value,
                    st.virtual_address,
                    st.file_offset,
                    st.length,
                    sec.name,
                    sec.virtual_address,
                    sec.size,
                    fd.title
                FROM objects o
                LEFT JOIN annotations rn
                  ON rn.subject_object_key = o.object_key
                 AND rn.subject_object_kind = o.kind
                 AND rn.annotation_kind = 'rename'
                LEFT JOIN functions fn ON fn.object_key = o.object_key
                LEFT JOIN imports im ON im.object_key = o.object_key
                LEFT JOIN strings st ON st.object_key = o.object_key
                LEFT JOIN sections sec ON sec.object_key = o.object_key
                LEFT JOIN findings fd ON fd.object_key = o.object_key
                WHERE o.artifact_key = ?1
                  AND o.kind IN ('function', 'import', 'string', 'section', 'score', 'finding')
                ORDER BY o.kind, o.address, o.object_key",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([artifact.key.as_str()], |row| {
                let object_key: String = row.get(0)?;
                let kind_text: String = row.get(1)?;
                let kind: ObjectKind = kind_text.parse().map_err(from_core_error)?;
                let display_label: String = row.get(2)?;
                let address = row.get::<_, Option<i64>>(3)?.map(from_i64);
                let size = row.get::<_, Option<i64>>(4)?.map(from_i64);
                let metadata_json: String = row.get(5)?;
                let function_name: Option<String> = row.get(6)?;
                let function_address = row.get::<_, Option<i64>>(7)?.map(from_i64);
                let function_size = row.get::<_, Option<i64>>(8)?.map(from_i64);
                let import_module: Option<String> = row.get(9)?;
                let import_symbol: Option<String> = row.get(10)?;
                let import_ordinal = row.get::<_, Option<i64>>(11)?.map(from_i64);
                let import_address = row.get::<_, Option<i64>>(12)?.map(from_i64);
                let string_value: Option<String> = row.get(13)?;
                let string_address = row.get::<_, Option<i64>>(14)?.map(from_i64);
                let string_offset = row.get::<_, Option<i64>>(15)?.map(from_i64);
                let string_length = row.get::<_, Option<i64>>(16)?.map(from_i64);
                let section_name: Option<String> = row.get(17)?;
                let section_address = row.get::<_, Option<i64>>(18)?.map(from_i64);
                let section_size = row.get::<_, Option<i64>>(19)?.map(from_i64);
                let finding_title: Option<String> = row.get(20)?;
                let object_ref = ObjectRef::new(kind, object_key.parse().map_err(from_core_error)?);
                let identity_key = diff_object_identity_key(&DiffObjectIdentityInput {
                    kind,
                    object_key: object_ref.key.as_str(),
                    display_label: &display_label,
                    address,
                    function_name: function_name.as_deref(),
                    function_address,
                    import_module: import_module.as_deref(),
                    import_symbol: import_symbol.as_deref(),
                    import_ordinal,
                    import_address,
                    string_value: string_value.as_deref(),
                    string_address,
                    string_offset,
                    section_name: section_name.as_deref(),
                    section_address,
                    finding_title: finding_title.as_deref(),
                });
                let fingerprint = serde_json::json!({
                    "kind": kind.as_str(),
                    "display_label": display_label,
                    "address": address,
                    "size": size,
                    "metadata": parsed_json_or_raw(&metadata_json),
                    "function": {
                        "name": function_name,
                        "address": function_address,
                        "size": function_size
                    },
                    "import": {
                        "module": import_module,
                        "symbol": import_symbol,
                        "ordinal": import_ordinal,
                        "address": import_address
                    },
                    "string": {
                        "value": string_value,
                        "address": string_address,
                        "offset": string_offset,
                        "length": string_length
                    },
                    "section": {
                        "name": section_name,
                        "address": section_address,
                        "size": section_size
                    },
                    "finding": {
                        "title": finding_title
                    }
                })
                .to_string();

                Ok(DiffComparableObject {
                    object_ref,
                    kind,
                    identity_key,
                    display_label,
                    address,
                    size,
                    fingerprint,
                })
            })
            .map_err(db_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }

    fn diff_comparable_relations(
        &self,
        artifact: &ObjectRef,
        identity_by_object_key: &BTreeMap<String, String>,
    ) -> Result<Vec<DiffComparableRelation>, QueryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    e.edge_key,
                    e.kind,
                    e.confidence,
                    e.metadata_json,
                    e.src_object_key,
                    e.dst_object_key
                FROM edges e
                JOIN objects src ON src.object_key = e.src_object_key
                JOIN objects dst ON dst.object_key = e.dst_object_key
                WHERE e.kind <> 'differs_from'
                  AND (src.artifact_key = ?1 OR dst.artifact_key = ?1)
                ORDER BY e.kind, e.src_object_key, e.dst_object_key, e.edge_key",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([artifact.key.as_str()], |row| {
                let edge_key: String = row.get(0)?;
                let kind_text: String = row.get(1)?;
                let kind: EdgeKind = kind_text.parse().map_err(from_core_error)?;
                let confidence: f64 = row.get(2)?;
                let metadata_json: String = row.get(3)?;
                let source_key: String = row.get(4)?;
                let target_key: String = row.get(5)?;
                Ok((
                    edge_key,
                    kind,
                    confidence,
                    metadata_json,
                    source_key,
                    target_key,
                ))
            })
            .map_err(db_error)?;

        let mut relations = Vec::new();
        for row in rows {
            let (edge_key, kind, confidence, metadata_json, source_key, target_key) =
                row.map_err(db_error)?;
            let (Some(source_identity), Some(target_identity)) = (
                identity_by_object_key.get(&source_key),
                identity_by_object_key.get(&target_key),
            ) else {
                continue;
            };
            let fingerprint = serde_json::json!({
                "kind": kind.as_str(),
                "source": source_identity,
                "target": target_identity,
                "confidence": confidence,
                "metadata": parsed_json_or_raw(&metadata_json)
            })
            .to_string();
            relations.push(DiffComparableRelation {
                relation_ref: ObjectRef::new(
                    ObjectKind::Edge,
                    edge_key
                        .parse::<revdeck_core::StableObjectKey>()
                        .map_err(|err| QueryError::Backend(err.to_string()))?,
                ),
                kind,
                source_identity: source_identity.clone(),
                target_identity: target_identity.clone(),
                confidence,
                fingerprint,
            });
        }
        Ok(relations)
    }
}

struct DiffObjectIdentityInput<'a> {
    kind: ObjectKind,
    object_key: &'a str,
    display_label: &'a str,
    address: Option<u64>,
    function_name: Option<&'a str>,
    function_address: Option<u64>,
    import_module: Option<&'a str>,
    import_symbol: Option<&'a str>,
    import_ordinal: Option<u64>,
    import_address: Option<u64>,
    string_value: Option<&'a str>,
    string_address: Option<u64>,
    string_offset: Option<u64>,
    section_name: Option<&'a str>,
    section_address: Option<u64>,
    finding_title: Option<&'a str>,
}

fn diff_object_identity_key(input: &DiffObjectIdentityInput<'_>) -> String {
    match input.kind {
        ObjectKind::Function => input
            .function_address
            .or(input.address)
            .map(|address| format!("function:address:{address:016x}"))
            .or_else(|| {
                input
                    .function_name
                    .map(|name| format!("function:name:{}", normalize_diff_component(name)))
            })
            .unwrap_or_else(|| {
                format!(
                    "function:key:{}",
                    normalize_diff_component(input.object_key)
                )
            }),
        ObjectKind::Import => input
            .import_symbol
            .map(|symbol| {
                format!(
                    "import:{}:{}",
                    input
                        .import_module
                        .map(normalize_diff_component)
                        .unwrap_or_else(|| "unknown-module".to_string()),
                    normalize_diff_component(symbol)
                )
            })
            .or_else(|| {
                input
                    .import_ordinal
                    .map(|ordinal| format!("import:ordinal:{ordinal}"))
            })
            .or_else(|| {
                input
                    .import_address
                    .map(|address| format!("import:address:{address:016x}"))
            })
            .unwrap_or_else(|| {
                format!(
                    "import:label:{}",
                    normalize_diff_component(input.display_label)
                )
            }),
        ObjectKind::String => input
            .string_address
            .or(input.address)
            .map(|address| format!("string:address:{address:016x}"))
            .or_else(|| {
                input
                    .string_offset
                    .map(|offset| format!("string:offset:{offset:016x}"))
            })
            .or_else(|| {
                input
                    .string_value
                    .map(|value| format!("string:value:{}", normalize_diff_component(value)))
            })
            .unwrap_or_else(|| {
                format!("string:key:{}", normalize_diff_component(input.object_key))
            }),
        ObjectKind::Section => input
            .section_name
            .map(|name| format!("section:name:{}", normalize_diff_component(name)))
            .or_else(|| {
                input
                    .section_address
                    .or(input.address)
                    .map(|address| format!("section:address:{address:016x}"))
            })
            .unwrap_or_else(|| {
                format!("section:key:{}", normalize_diff_component(input.object_key))
            }),
        ObjectKind::Finding => input
            .finding_title
            .map(|title| format!("finding:title:{}", normalize_diff_component(title)))
            .unwrap_or_else(|| {
                format!(
                    "finding:label:{}",
                    normalize_diff_component(input.display_label)
                )
            }),
        ObjectKind::Score => format!(
            "score:label:{}",
            normalize_diff_component(input.display_label)
        ),
        _ => format!(
            "{}:key:{}",
            input.kind.as_str(),
            normalize_diff_component(input.object_key)
        ),
    }
}

fn normalize_diff_component(value: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            output.push('-');
            last_was_dash = true;
        }
    }
    output.trim_matches('-').to_string()
}

fn parsed_json_or_raw(value: &str) -> serde_json::Value {
    serde_json::from_str(value).unwrap_or_else(|_| serde_json::json!({ "raw": value }))
}

impl ObjectGraphQuery for ObjectQueryRepository<'_> {
    fn get_object(&self, object_ref: &ObjectRef) -> Result<Option<ObjectSummary>, QueryError> {
        self.connection
            .query_row(
                "SELECT o.object_key, o.kind, o.artifact_key, coalesce(rn.body, o.display_name),
                    o.address, o.size, o.metadata_json
                FROM objects o
                LEFT JOIN annotations rn
                  ON rn.subject_object_key = o.object_key
                 AND rn.subject_object_kind = o.kind
                 AND rn.annotation_kind = 'rename'
                WHERE o.object_key = ?1 AND o.kind = ?2
                ORDER BY rn.updated_at DESC
                LIMIT 1",
                params![object_ref.key.as_str(), object_ref.kind.as_str()],
                map_object_summary,
            )
            .optional()
            .map_err(db_error)
    }

    fn search_objects(&self, search: &ObjectSearch) -> Result<Vec<ObjectSummary>, QueryError> {
        let kind = search.kind.map(|kind| kind.as_str().to_string());
        let like = format!("%{}%", search.term.to_ascii_lowercase());
        let exact = search.term.to_ascii_lowercase();
        let mut statement = self
            .connection
            .prepare(
                "SELECT DISTINCT
                    o.object_key, o.kind, o.artifact_key, coalesce(rn.body, o.display_name),
                    o.address, o.size,
                    o.metadata_json
                FROM objects o
                LEFT JOIN annotations rn
                  ON rn.subject_object_key = o.object_key
                 AND rn.subject_object_kind = o.kind
                 AND rn.annotation_kind = 'rename'
                LEFT JOIN strings st ON st.object_key = o.object_key
                LEFT JOIN imports im ON im.object_key = o.object_key
                LEFT JOIN functions fn ON fn.object_key = o.object_key
                LEFT JOIN xrefs xr ON xr.object_key = o.object_key
                WHERE (?1 IS NULL OR o.kind = ?1)
                  AND (
                    lower(o.object_key) LIKE ?2
                    OR lower(coalesce(o.display_name, '')) LIKE ?2
                    OR lower(coalesce(rn.body, '')) LIKE ?2
                    OR lower(coalesce(st.value, '')) LIKE ?2
                    OR lower(coalesce(im.symbol, '')) LIKE ?2
                    OR lower(coalesce(im.module, '')) LIKE ?2
                    OR lower(coalesce(fn.name, '')) LIKE ?2
                    OR lower(coalesce(xr.relation, '')) LIKE ?2
                    OR (o.address IS NOT NULL AND printf('0x%016x', o.address) LIKE ?2)
                  )
                ORDER BY
                    CASE
                        WHEN lower(coalesce(rn.body, '')) = ?3 THEN 0
                        WHEN lower(coalesce(o.display_name, '')) = ?3 THEN 0
                        WHEN lower(coalesce(st.value, '')) = ?3 THEN 0
                        WHEN lower(coalesce(im.symbol, '')) = ?3 THEN 0
                        WHEN lower(coalesce(fn.name, '')) = ?3 THEN 0
                        ELSE 1
                    END,
                    o.kind,
                    o.address,
                    o.object_key
                LIMIT ?4",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map(
                params![kind.as_deref(), like, exact, search.limit as i64],
                map_object_summary,
            )
            .map_err(db_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }

    fn relations(
        &self,
        object_ref: &ObjectRef,
        direction: RelationDirection,
        edge_kind: Option<EdgeKind>,
    ) -> Result<Vec<ObjectRelation>, QueryError> {
        let edge_kind = edge_kind.map(|kind| kind.as_str().to_string());
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    e.edge_key,
                    e.kind,
                    e.confidence,
                    e.metadata_json,
                    src.object_key,
                    src.kind,
                    dst.object_key,
                    dst.kind
                FROM edges e
                JOIN objects src ON src.object_key = e.src_object_key
                JOIN objects dst ON dst.object_key = e.dst_object_key
                WHERE (?2 IS NULL OR e.kind = ?2)
                  AND (
                    (?3 = 'outgoing' AND e.src_object_key = ?1)
                    OR (?3 = 'incoming' AND e.dst_object_key = ?1)
                    OR (?3 = 'both' AND (e.src_object_key = ?1 OR e.dst_object_key = ?1))
                  )
                ORDER BY e.kind, src.kind, src.object_key, dst.kind, dst.object_key",
            )
            .map_err(db_error)?;
        let direction = match direction {
            RelationDirection::Outgoing => "outgoing",
            RelationDirection::Incoming => "incoming",
            RelationDirection::Both => "both",
        };
        let rows = statement
            .query_map(
                params![object_ref.key.as_str(), edge_kind.as_deref(), direction],
                |row| {
                    let edge_key: String = row.get(0)?;
                    let edge_kind: String = row.get(1)?;
                    let source_key: String = row.get(4)?;
                    let source_kind: String = row.get(5)?;
                    let target_key: String = row.get(6)?;
                    let target_kind: String = row.get(7)?;
                    Ok(ObjectRelation {
                        edge_ref: ObjectRef::new(
                            ObjectKind::Edge,
                            edge_key.parse().map_err(from_core_error)?,
                        ),
                        source: ObjectRef::new(
                            source_kind.parse().map_err(from_core_error)?,
                            source_key.parse().map_err(from_core_error)?,
                        ),
                        target: ObjectRef::new(
                            target_kind.parse().map_err(from_core_error)?,
                            target_key.parse().map_err(from_core_error)?,
                        ),
                        kind: edge_kind.parse().map_err(from_core_error)?,
                        confidence: row.get(2)?,
                        metadata_json: row.get(3)?,
                    })
                },
            )
            .map_err(db_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }
}

fn map_object_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObjectSummary> {
    let key: String = row.get(0)?;
    let kind: String = row.get(1)?;
    Ok(ObjectSummary {
        object_ref: ObjectRef::new(
            kind.parse().map_err(from_core_error)?,
            key.parse().map_err(from_core_error)?,
        ),
        artifact_key: row.get(2)?,
        display_name: row.get(3)?,
        address: row.get::<_, Option<i64>>(4)?.map(from_i64),
        size: row.get::<_, Option<i64>>(5)?.map(from_i64),
        metadata_json: row.get(6)?,
    })
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).expect("stored unsigned value must be non-negative")
}

fn db_error(err: rusqlite::Error) -> QueryError {
    QueryError::Backend(err.to_string())
}

fn from_core_error(err: revdeck_core::RevDeckError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        migrations::migrate, ArtifactRecord, ArtifactRepository, ObjectRepository, StoredEdge,
        StoredObject,
    };
    use revdeck_core::{EdgeKind, StableObjectKey};
    use rusqlite::Connection;
    use time::macros::datetime;

    fn migrated_connection() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        connection
    }

    fn seed_object(
        repo: &ObjectRepository<'_>,
        object_ref: ObjectRef,
        artifact_key: Option<&str>,
        display_name: &str,
        address: Option<u64>,
    ) -> ObjectRef {
        repo.upsert_object(&StoredObject {
            object_ref: object_ref.clone(),
            artifact_key: artifact_key.map(str::to_string),
            display_name: Some(display_name.to_string()),
            address,
            size: Some(16),
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
        object_ref
    }

    fn edge(repo: &ObjectRepository<'_>, source: &ObjectRef, target: &ObjectRef, kind: EdgeKind) {
        repo.upsert_edge(&StoredEdge {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(kind, source, target).unwrap(),
            ),
            source: source.clone(),
            target: target.clone(),
            kind,
            confidence: 1.0,
            source_run_id: None,
            metadata_json: "{}".to_string(),
        })
        .unwrap();
    }

    #[test]
    fn object_relation_queries() {
        let connection = migrated_connection();
        let repo = ObjectRepository::new(&connection);
        let artifact = ObjectRef::artifact("abc123", "fixture").unwrap();
        ArtifactRepository::new(&connection)
            .upsert_artifact(&ArtifactRecord {
                object_ref: artifact.clone(),
                display_name: "fixture".to_string(),
                source_path: "fixture".to_string(),
                stored_path: None,
                sha256: "abc123".to_string(),
                size: 64,
                kind: "binary".to_string(),
                format: "elf".to_string(),
                architecture: "x86_64".to_string(),
                import_status: "indexed".to_string(),
                created_at: datetime!(2026-05-13 00:00 UTC),
            })
            .unwrap();
        seed_object(&repo, artifact.clone(), None, "fixture", None);
        let function = seed_object(
            &repo,
            ObjectRef::new(
                ObjectKind::Function,
                StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
            ),
            Some(artifact.key.as_str()),
            "main",
            Some(0x401000),
        );
        let string = seed_object(
            &repo,
            ObjectRef::new(
                ObjectKind::String,
                StableObjectKey::string(&artifact.key, 0x200, Some(0x402000), "password").unwrap(),
            ),
            Some(artifact.key.as_str()),
            "password",
            Some(0x402000),
        );
        let import = seed_object(
            &repo,
            ObjectRef::new(
                ObjectKind::Import,
                StableObjectKey::import(&artifact.key, Some("libc.so.6"), "system", None).unwrap(),
            ),
            Some(artifact.key.as_str()),
            "system",
            None,
        );
        edge(&repo, &artifact, &function, EdgeKind::Contains);
        edge(&repo, &function, &string, EdgeKind::References);
        edge(&repo, &string, &function, EdgeKind::XrefFrom);
        edge(&repo, &function, &import, EdgeKind::CallsImport);

        let query = ObjectQueryRepository::new(&connection);
        let strings = query
            .search_objects(&ObjectSearch::new(Some(ObjectKind::String), "password"))
            .unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].object_ref, string);

        let outgoing = query
            .relations(&function, RelationDirection::Outgoing, None)
            .unwrap();
        assert!(outgoing
            .iter()
            .any(|edge| edge.kind == EdgeKind::References));
        assert!(outgoing
            .iter()
            .any(|edge| edge.kind == EdgeKind::CallsImport));

        let traversal = query
            .local_traversal(&revdeck_core::TraversalOptions {
                root: string.clone(),
                direction: RelationDirection::Outgoing,
                edge_kind: None,
                relation_filter: revdeck_core::RelationFilter::All,
                max_depth: 2,
                max_nodes: 8,
            })
            .unwrap();
        assert!(traversal
            .nodes
            .iter()
            .any(|node| node.object_ref == function && node.depth == 1));
        assert!(traversal
            .nodes
            .iter()
            .any(|node| node.object_ref == import && node.depth == 2));
    }

    #[test]
    fn mixed_lab_evidence_queries_round_trip_through_db() {
        let connection = migrated_connection();
        let repo = ObjectRepository::new(&connection);
        let artifact = ObjectRef::artifact("abc123", "fixture").unwrap();
        ArtifactRepository::new(&connection)
            .upsert_artifact(&ArtifactRecord {
                object_ref: artifact.clone(),
                display_name: "fixture".to_string(),
                source_path: "fixture".to_string(),
                stored_path: None,
                sha256: "abc123".to_string(),
                size: 64,
                kind: "binary".to_string(),
                format: "elf".to_string(),
                architecture: "x86_64".to_string(),
                import_status: "indexed".to_string(),
                created_at: datetime!(2026-05-13 00:00 UTC),
            })
            .unwrap();
        seed_object(&repo, artifact.clone(), None, "fixture", None);
        let function = seed_object(
            &repo,
            ObjectRef::new(
                ObjectKind::Function,
                StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
            ),
            Some(artifact.key.as_str()),
            "main",
            Some(0x401000),
        );
        let trace_event = seed_object(
            &repo,
            ObjectRef::lab_object(
                ObjectKind::TraceEvent,
                Some(&artifact.key),
                "trace",
                "session-1/event-4",
            )
            .unwrap(),
            Some(artifact.key.as_str()),
            "trace event #4",
            None,
        );
        let crash_frame = seed_object(
            &repo,
            ObjectRef::lab_object(
                ObjectKind::CrashFrame,
                Some(&artifact.key),
                "crash",
                "asan/frame-0",
            )
            .unwrap(),
            Some(artifact.key.as_str()),
            "frame #0",
            Some(0x401000),
        );
        let protocol_field = seed_object(
            &repo,
            ObjectRef::lab_object(
                ObjectKind::ProtocolField,
                Some(&artifact.key),
                "protocol",
                "sample-1/message-2/opcode",
            )
            .unwrap(),
            Some(artifact.key.as_str()),
            "opcode",
            None,
        );
        edge(&repo, &trace_event, &function, EdgeKind::Correlates);
        edge(&repo, &crash_frame, &function, EdgeKind::Correlates);
        edge(&repo, &function, &protocol_field, EdgeKind::Correlates);

        let query = ObjectQueryRepository::new(&connection);
        let protocol_objects = query
            .search_objects(&ObjectSearch::new(
                Some(ObjectKind::ProtocolField),
                "opcode",
            ))
            .unwrap();
        assert_eq!(protocol_objects.len(), 1);
        assert_eq!(protocol_objects[0].object_ref, protocol_field);

        let traversal = query
            .local_traversal(
                &revdeck_core::TraversalOptions::new(function.clone())
                    .with_edge_kind(EdgeKind::Correlates)
                    .with_max_depth(1)
                    .with_max_nodes(8),
            )
            .unwrap();
        let path = traversal.evidence_path_items();
        assert!(path
            .iter()
            .any(|item| item.object_ref == trace_event && item.via == Some(EdgeKind::Correlates)));
        assert!(path
            .iter()
            .any(|item| item.object_ref == crash_frame && item.via == Some(EdgeKind::Correlates)));
        assert!(path.iter().any(
            |item| item.object_ref == protocol_field && item.via == Some(EdgeKind::Correlates)
        ));
    }
}
