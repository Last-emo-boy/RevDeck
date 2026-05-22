use revdeck_core::{
    FunctionRadarFilter, FunctionRadarViewModel, InspectorViewModel, ObjectKind,
    SIGNAL_DANGEROUS_IMPORT, SIGNAL_SENSITIVE_STRING,
};
use revdeck_db::{ProjectDatabase, RadarRepository};
use revdeck_index::{import_binary, ImportOptions};
use rusqlite::params;
use std::path::PathBuf;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn fixture_radar_rows_have_ordered_scores_and_evidence_reasons() {
    let root = repo_root();
    let temp = tempdir().unwrap();
    let project = ProjectDatabase::create_or_open(temp.path()).unwrap();
    let outcome = import_binary(
        project.connection(),
        ImportOptions::new(
            root.clone(),
            root.join("fixtures")
                .join("binaries")
                .join("sensitive_imports_elf"),
        ),
    )
    .unwrap();

    let basic_block_count: i64 = project
        .connection()
        .query_row("SELECT COUNT(*) FROM basic_blocks", [], |row| row.get(0))
        .unwrap();
    assert!(
        basic_block_count > 0,
        "balanced fixture should persist native basic blocks"
    );
    let typed_operand_count: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*)
            FROM objects o
            JOIN instructions i ON i.object_key = o.object_key
            WHERE o.metadata_json LIKE '%\"typed_operands\"%'
              AND o.metadata_json NOT LIKE '%\"typed_operands\":[]%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        typed_operand_count > 0,
        "fixture instructions should preserve typed operands in object metadata"
    );
    let calls_import_xrefs: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM xrefs WHERE relation = 'calls_import'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        calls_import_xrefs > 0,
        "fixture should include native import-call xrefs"
    );
    let string_xrefs: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM xrefs WHERE relation = 'references'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        string_xrefs > 0,
        "fixture should include data/string reference xrefs"
    );
    let block_contains_instructions: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*)
            FROM edges e
            JOIN objects src ON src.object_key = e.src_object_key
            JOIN objects dst ON dst.object_key = e.dst_object_key
            WHERE e.kind = 'contains'
              AND src.kind = 'basic_block'
              AND dst.kind = 'instruction'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        block_contains_instructions > 0,
        "fixture should link basic blocks to contained instructions"
    );

    let scores = RadarRepository::new(project.connection())
        .load_function_scores(&outcome.artifact_ref)
        .unwrap();
    assert!(!scores.is_empty());

    let scored = scores
        .iter()
        .filter(|score| score.score > 0)
        .collect::<Vec<_>>();
    assert!(!scored.is_empty());
    for pair in scores.windows(2) {
        assert!(
            pair[0].score > pair[1].score
                || pair[0].virtual_address.unwrap_or(u64::MAX)
                    <= pair[1].virtual_address.unwrap_or(u64::MAX)
        );
    }
    for score in scored {
        assert!(
            !score.reasons.is_empty(),
            "non-zero score for {} has no reasons",
            score.function_ref
        );
        assert!(score
            .reasons
            .iter()
            .filter(|reason| reason.contribution > 0)
            .all(|reason| !reason.evidence_refs.is_empty()));
    }

    let top = &scores[0];
    assert!(top
        .reasons
        .iter()
        .any(|reason| reason.signal_key == SIGNAL_DANGEROUS_IMPORT
            && reason
                .evidence_refs
                .iter()
                .any(|item| item.kind == ObjectKind::Import)));
    assert!(top
        .reasons
        .iter()
        .any(|reason| reason.signal_key == SIGNAL_SENSITIVE_STRING
            && reason
                .evidence_refs
                .iter()
                .any(|item| item.kind == ObjectKind::String)));
    for reason in top.reasons.iter().filter(|reason| reason.contribution > 0) {
        for evidence_ref in &reason.evidence_refs {
            let exists: i64 = project
                .connection()
                .query_row(
                    "SELECT COUNT(*)
                    FROM objects
                    WHERE object_key = ?1 AND kind = ?2",
                    params![evidence_ref.key.as_str(), evidence_ref.kind.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                exists, 1,
                "radar evidence ref {} should resolve to a persisted object",
                evidence_ref
            );
        }
    }
    let persisted_score_reasons_with_evidence: i64 = project
        .connection()
        .query_row(
            "SELECT COUNT(*)
            FROM score_reasons
            WHERE contribution > 0 AND evidence_refs_json <> '[]'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        persisted_score_reasons_with_evidence > 0,
        "score reasons should persist evidence refs for later Labs"
    );

    let radar = FunctionRadarViewModel::from_scores(
        Some(outcome.artifact_ref),
        &scores,
        &FunctionRadarFilter {
            include_zero_score: true,
            ..FunctionRadarFilter::default()
        },
    );
    assert_eq!(radar.total_functions, scores.len());
    assert!(!radar.rows[0].reasons.is_empty());

    let inspector = InspectorViewModel::for_function(top);
    assert!(inspector.boundary_confidence.is_some());
    assert!(inspector
        .evidence_navigation
        .iter()
        .any(|item| item.target.kind == ObjectKind::Import));
}
