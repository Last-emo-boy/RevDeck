use revdeck_core::{
    FunctionRadarFilter, FunctionRadarViewModel, InspectorViewModel, ObjectKind,
    SIGNAL_DANGEROUS_IMPORT, SIGNAL_SENSITIVE_STRING,
};
use revdeck_db::{ProjectDatabase, RadarRepository};
use revdeck_index::{import_binary, ImportOptions};
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
