use crate::radar::{
    evidence_kind_label, filter_function_scores, format_address, FunctionRadarFilter,
    FunctionScore, ScoreReason, SIGNAL_DANGEROUS_IMPORT, SIGNAL_SENSITIVE_STRING,
};
use crate::{AnalysisRunStatus, ObjectRef};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverviewViewModel {
    pub artifact: Option<ObjectRef>,
    pub artifact_label: String,
    pub import_status: String,
    pub analysis_status: Option<AnalysisRunStatus>,
    pub section_count: usize,
    pub function_count: usize,
    pub string_count: usize,
    pub import_count: usize,
    pub finding_count: usize,
    pub top_functions: Vec<FunctionRadarRow>,
    pub degraded_indexing_warnings: Vec<String>,
}

impl OverviewViewModel {
    pub fn new(
        artifact: Option<ObjectRef>,
        artifact_label: impl Into<String>,
        import_status: impl Into<String>,
    ) -> Self {
        Self {
            artifact,
            artifact_label: artifact_label.into(),
            import_status: import_status.into(),
            analysis_status: None,
            section_count: 0,
            function_count: 0,
            string_count: 0,
            import_count: 0,
            finding_count: 0,
            top_functions: Vec::new(),
            degraded_indexing_warnings: Vec::new(),
        }
    }

    pub fn with_counts(
        mut self,
        section_count: usize,
        function_count: usize,
        string_count: usize,
        import_count: usize,
        finding_count: usize,
    ) -> Self {
        self.section_count = section_count;
        self.function_count = function_count;
        self.string_count = string_count;
        self.import_count = import_count;
        self.finding_count = finding_count;
        self
    }

    pub fn with_top_functions(mut self, scores: &[FunctionScore], limit: usize) -> Self {
        self.top_functions = scores
            .iter()
            .take(limit)
            .map(FunctionRadarRow::from_score)
            .collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageBoardViewModel {
    pub rows: Vec<TriageActionRow>,
    pub high_score_count: usize,
    pub finding_gap: bool,
}

impl TriageBoardViewModel {
    pub fn from_overview_and_scores(
        overview: &OverviewViewModel,
        scores: &[FunctionScore],
    ) -> Self {
        let high_score_count = scores.iter().filter(|score| score.score >= 40).count();
        let mut rows = Vec::new();

        for warning in &overview.degraded_indexing_warnings {
            if let Some(target) = overview.artifact.clone() {
                rows.push(TriageActionRow {
                    target,
                    priority: "P1".to_string(),
                    title: "Review indexing warning".to_string(),
                    rationale: warning.clone(),
                    command_hints: vec![":open".to_string(), ":note warning reviewed".to_string()],
                });
            }
        }

        for score in scores.iter().filter(|score| score.score > 0).take(10) {
            rows.push(TriageActionRow::from_score(score));
        }

        let finding_gap = overview.finding_count == 0 && high_score_count > 0;
        if finding_gap {
            if let Some(target) = overview.artifact.clone() {
                rows.push(TriageActionRow {
                    target,
                    priority: "P2".to_string(),
                    title: "Promote reviewed evidence into a finding".to_string(),
                    rationale: format!(
                        "{high_score_count} high-score functions exist, but no findings are recorded"
                    ),
                    command_hints: vec![
                        ":finding new high".to_string(),
                        ":finding link".to_string(),
                    ],
                });
            }
        }

        if rows.is_empty() {
            if let Some(target) = overview.artifact.clone() {
                rows.push(TriageActionRow {
                    target,
                    priority: "P3".to_string(),
                    title: "Build first analysis lead".to_string(),
                    rationale: "No scored leads yet; start from Binary Map, imports, or strings"
                        .to_string(),
                    command_hints: vec![
                        ":find string password".to_string(),
                        ":find import system".to_string(),
                    ],
                });
            }
        }

        rows.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.title.cmp(&right.title))
        });
        Self {
            rows,
            high_score_count,
            finding_gap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageActionRow {
    pub target: ObjectRef,
    pub priority: String,
    pub title: String,
    pub rationale: String,
    pub command_hints: Vec<String>,
}

impl TriageActionRow {
    pub fn from_score(score: &FunctionScore) -> Self {
        let has_dangerous_import = score
            .reasons
            .iter()
            .any(|reason| reason.signal_key == SIGNAL_DANGEROUS_IMPORT);
        let has_sensitive_string = score
            .reasons
            .iter()
            .any(|reason| reason.signal_key == SIGNAL_SENSITIVE_STRING);
        let weak_boundary = matches!(
            score.boundary_confidence.as_str(),
            "heuristic" | "unknown" | "import_thunk"
        );
        let priority = if has_dangerous_import {
            "P0"
        } else if has_sensitive_string || score.score >= 40 {
            "P1"
        } else if weak_boundary {
            "P2"
        } else {
            "P3"
        };
        let title = if has_dangerous_import {
            format!("Dangerous import path: {}", score.name)
        } else if has_sensitive_string {
            format!("Sensitive string evidence: {}", score.name)
        } else if weak_boundary {
            format!("Validate weak boundary: {}", score.name)
        } else {
            format!("Review radar lead: {}", score.name)
        };
        let reasons = score
            .reasons
            .iter()
            .take(3)
            .map(|reason| reason.display_label.clone())
            .collect::<Vec<_>>();
        let rationale = if reasons.is_empty() {
            format!(
                "score={} calls={} strings={} xrefs={} boundary={}",
                score.score,
                score.call_count,
                score.string_count,
                score.xref_count,
                score.boundary_confidence
            )
        } else {
            format!("score={} because {}", score.score, reasons.join(", "))
        };
        Self {
            target: score.function_ref.clone(),
            priority: priority.to_string(),
            title,
            rationale,
            command_hints: vec![
                ":xrefs current".to_string(),
                ":open current".to_string(),
                ":note reviewed".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRadarViewModel {
    pub artifact: Option<ObjectRef>,
    pub rows: Vec<FunctionRadarRow>,
    pub total_functions: usize,
    pub visible_functions: usize,
    pub warnings: Vec<String>,
}

impl FunctionRadarViewModel {
    pub fn from_scores(
        artifact: Option<ObjectRef>,
        scores: &[FunctionScore],
        filter: &FunctionRadarFilter,
    ) -> Self {
        let filtered = filter_function_scores(scores, filter);
        let mut warnings = Vec::new();
        if filtered
            .iter()
            .any(|score| score.score > 0 && score.reasons.is_empty())
        {
            warnings.push("non-zero radar score without structured reasons".to_string());
        }
        if filtered
            .iter()
            .any(|score| matches!(score.boundary_confidence.as_str(), "heuristic" | "unknown"))
        {
            warnings
                .push("some functions have heuristic or unknown boundary_confidence".to_string());
        }
        Self {
            artifact,
            rows: filtered.iter().map(FunctionRadarRow::from_score).collect(),
            total_functions: scores.len(),
            visible_functions: filtered.len(),
            warnings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRadarRow {
    pub function_ref: ObjectRef,
    pub score: i32,
    pub name: String,
    pub address: String,
    pub size: Option<u64>,
    pub call_count: u64,
    pub string_count: u64,
    pub xref_count: u64,
    pub boundary_source: String,
    pub boundary_confidence: String,
    pub reason_labels: Vec<String>,
    pub reasons: Vec<ScoreReasonView>,
    pub tags: Vec<String>,
    pub status: Option<String>,
}

impl FunctionRadarRow {
    pub fn from_score(score: &FunctionScore) -> Self {
        Self {
            function_ref: score.function_ref.clone(),
            score: score.score,
            name: score.name.clone(),
            address: format_address(score.virtual_address),
            size: score.size,
            call_count: score.call_count,
            string_count: score.string_count,
            xref_count: score.xref_count,
            boundary_source: score.boundary_source.clone(),
            boundary_confidence: score.boundary_confidence.clone(),
            reason_labels: score
                .reasons
                .iter()
                .map(|reason| reason.display_label.clone())
                .collect(),
            reasons: score
                .reasons
                .iter()
                .map(ScoreReasonView::from_reason)
                .collect(),
            tags: score.tags.clone(),
            status: score.status.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreReasonView {
    pub reason_code: String,
    pub signal_key: String,
    pub label: String,
    pub contribution: i32,
    pub evidence_refs: Vec<ObjectRef>,
    pub evidence_labels: Vec<String>,
}

impl ScoreReasonView {
    pub fn from_reason(reason: &ScoreReason) -> Self {
        Self {
            reason_code: reason.reason_code.clone(),
            signal_key: reason.signal_key.clone(),
            label: reason.display_label.clone(),
            contribution: reason.contribution,
            evidence_refs: reason.evidence_refs.clone(),
            evidence_labels: reason
                .evidence_refs
                .iter()
                .map(|object_ref| {
                    format!(
                        "{} {}",
                        evidence_kind_label(object_ref),
                        object_ref.key.as_str()
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectorViewModel {
    pub selected: ObjectRef,
    pub title: String,
    pub address: Option<String>,
    pub size: Option<u64>,
    pub boundary_source: Option<String>,
    pub boundary_confidence: Option<String>,
    pub radar_score: Option<i32>,
    pub score_reasons: Vec<ScoreReasonView>,
    pub evidence_navigation: Vec<EvidenceNavigationItem>,
    pub tags: Vec<String>,
    pub status: Option<String>,
    pub warnings: Vec<String>,
}

impl InspectorViewModel {
    pub fn for_function(score: &FunctionScore) -> Self {
        let score_reasons = score
            .reasons
            .iter()
            .map(ScoreReasonView::from_reason)
            .collect::<Vec<_>>();
        let evidence_navigation = score_reasons
            .iter()
            .flat_map(|reason| {
                reason
                    .evidence_refs
                    .iter()
                    .cloned()
                    .map(|target| EvidenceNavigationItem {
                        source_reason_code: reason.reason_code.clone(),
                        target,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut warnings = Vec::new();
        if score.score > 0 && score.reasons.is_empty() {
            warnings.push("non-zero radar score has no structured reasons".to_string());
        }
        if matches!(score.boundary_confidence.as_str(), "heuristic" | "unknown") {
            warnings.push(format!(
                "boundary_confidence is {} from {}",
                score.boundary_confidence, score.boundary_source
            ));
        }
        Self {
            selected: score.function_ref.clone(),
            title: score.name.clone(),
            address: score
                .virtual_address
                .map(|_| format_address(score.virtual_address)),
            size: score.size,
            boundary_source: Some(score.boundary_source.clone()),
            boundary_confidence: Some(score.boundary_confidence.clone()),
            radar_score: Some(score.score),
            score_reasons,
            evidence_navigation,
            tags: score.tags.clone(),
            status: score.status.clone(),
            warnings,
        }
    }

    pub fn for_object(selected: ObjectRef, title: impl Into<String>) -> Self {
        Self {
            selected,
            title: title.into(),
            address: None,
            size: None,
            boundary_source: None,
            boundary_confidence: None,
            radar_score: None,
            score_reasons: Vec::new(),
            evidence_navigation: Vec::new(),
            tags: Vec::new(),
            status: None,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceNavigationItem {
    pub source_reason_code: String,
    pub target: ObjectRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radar::{score_function, FunctionScoreInput, RadarEvidence};
    use crate::{ObjectKind, StableObjectKey};

    fn artifact() -> ObjectRef {
        ObjectRef::artifact("abc123", "fixture").unwrap()
    }

    fn function() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, 0x401000, Some(64), Some("main")).unwrap(),
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
    fn radar_view_model_keeps_reasons_visible() {
        let artifact = artifact();
        let mut input = FunctionScoreInput::new(artifact.clone(), function(), "main");
        input.boundary_source = "symbol".to_string();
        input.boundary_confidence = "symbol".to_string();
        input
            .called_imports
            .push(RadarEvidence::new(import(), "system", "system"));
        let score = score_function(input);

        let model = FunctionRadarViewModel::from_scores(
            Some(artifact),
            &[score],
            &FunctionRadarFilter {
                include_zero_score: true,
                ..FunctionRadarFilter::default()
            },
        );

        assert_eq!(model.rows.len(), 1);
        assert!(!model.rows[0].reasons.is_empty());
        assert!(!model.rows[0].reasons[0].evidence_refs.is_empty());
    }

    #[test]
    fn inspector_exposes_boundary_confidence_and_reason_navigation() {
        let mut input = FunctionScoreInput::new(artifact(), function(), "main");
        input.boundary_source = "symbol".to_string();
        input.boundary_confidence = "symbol".to_string();
        input
            .called_imports
            .push(RadarEvidence::new(import(), "system", "system"));
        let score = score_function(input);

        let inspector = InspectorViewModel::for_function(&score);

        assert_eq!(inspector.boundary_confidence.as_deref(), Some("symbol"));
        assert!(inspector
            .evidence_navigation
            .iter()
            .any(|item| item.target.kind == ObjectKind::Import));
    }

    #[test]
    fn triage_board_prioritizes_dangerous_import_leads() {
        let artifact = artifact();
        let mut dangerous = FunctionScoreInput::new(artifact.clone(), function(), "main");
        dangerous.boundary_source = "symbol".to_string();
        dangerous.boundary_confidence = "symbol".to_string();
        dangerous
            .called_imports
            .push(RadarEvidence::new(import(), "system", "system"));
        let score = score_function(dangerous);
        let overview =
            OverviewViewModel::new(Some(artifact), "fixture", "indexed").with_counts(3, 1, 1, 1, 0);

        let board = TriageBoardViewModel::from_overview_and_scores(&overview, &[score]);

        assert_eq!(board.rows[0].priority, "P0");
        assert!(board.rows[0].title.contains("Dangerous import"));
        assert!(board.finding_gap);
        assert_eq!(board.high_score_count, 1);
    }
}
