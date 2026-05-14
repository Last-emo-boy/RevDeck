use revdeck_core::{
    EdgeKind, ObjectGraphQuery, ObjectKind, ObjectRef, ObjectRelation, ObjectSearch, ObjectSummary,
    QueryError, RelationDirection,
};
use rusqlite::{params, Connection, OptionalExtension};

pub struct ObjectQueryRepository<'conn> {
    connection: &'conn Connection,
}

impl<'conn> ObjectQueryRepository<'conn> {
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }
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
}
