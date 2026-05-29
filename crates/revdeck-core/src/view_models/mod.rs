use crate::radar::{
    dangerous_import_match, evidence_kind_label, filter_function_scores, format_address,
    sensitive_string_match, FunctionRadarFilter, FunctionScore, ScoreReason,
    SIGNAL_DANGEROUS_IMPORT, SIGNAL_SENSITIVE_STRING,
};
use crate::{
    AnalysisRunStatus, EdgeKind, EvidencePathItem, LabDescriptor, LabMaturity, LocalTraversal,
    NavigationLens, ObjectKind, ObjectRef, ObjectRelation, RelationFilter, StableObjectKey,
    ALL_LABS,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const JOB_DETAIL_ITEM_LIMIT: usize = 8;
const JOB_DETAIL_SNIPPET_LIMIT: usize = 4;
const JOB_DETAIL_VALUE_LIMIT: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisJobRow {
    pub id: i64,
    pub analysis_run_id: Option<i64>,
    pub artifact_key: Option<String>,
    pub pass_name: String,
    pub profile: String,
    pub status: String,
    pub progress: String,
    pub objects_produced: u64,
    pub diagnostics_count: u64,
    pub byte_limit: Option<u64>,
    pub function_limit: Option<u64>,
    pub time_limit_ms: Option<u64>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub updated_at: String,
    pub metadata_summary: String,
    pub metadata_items: Vec<AnalysisJobDetailItem>,
    pub parameter_items: Vec<AnalysisJobDetailItem>,
    pub diagnostic_snippets: Vec<String>,
    pub log_snippets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisJobDetail {
    pub metadata_items: Vec<AnalysisJobDetailItem>,
    pub parameter_items: Vec<AnalysisJobDetailItem>,
    pub diagnostic_snippets: Vec<String>,
    pub log_snippets: Vec<String>,
}

impl AnalysisJobDetail {
    pub fn from_metadata_json(metadata_json: &str) -> Self {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(metadata_json) else {
            return Self {
                metadata_items: vec![AnalysisJobDetailItem::new(
                    "raw",
                    truncate_detail_value(metadata_json),
                )],
                parameter_items: Vec::new(),
                diagnostic_snippets: vec!["metadata_json parse failed".to_string()],
                log_snippets: Vec::new(),
            };
        };

        let Some(map) = value.as_object() else {
            return Self {
                metadata_items: vec![AnalysisJobDetailItem::new(
                    "value",
                    compact_json_value(&value),
                )],
                parameter_items: Vec::new(),
                diagnostic_snippets: Vec::new(),
                log_snippets: Vec::new(),
            };
        };

        let mut metadata_items = Vec::new();
        let mut parameter_items = Vec::new();
        let mut diagnostic_snippets = Vec::new();
        let mut log_snippets = Vec::new();

        for (key, value) in map {
            match key.as_str() {
                "parameters" | "parameter_snapshot" | "params" => {
                    append_detail_items(&mut parameter_items, value);
                }
                "diagnostic" | "diagnostics" | "diagnostic_snippets" => {
                    append_diagnostic_snippets(&mut diagnostic_snippets, value);
                }
                "log" | "logs" | "log_snippets" => {
                    append_string_snippets(&mut log_snippets, value);
                }
                _ => {
                    if metadata_items.len() < JOB_DETAIL_ITEM_LIMIT {
                        metadata_items
                            .push(AnalysisJobDetailItem::new(key, compact_json_value(value)));
                    }
                }
            }
        }

        metadata_items.truncate(JOB_DETAIL_ITEM_LIMIT);
        parameter_items.truncate(JOB_DETAIL_ITEM_LIMIT);
        diagnostic_snippets.truncate(JOB_DETAIL_SNIPPET_LIMIT);
        log_snippets.truncate(JOB_DETAIL_SNIPPET_LIMIT);

        Self {
            metadata_items,
            parameter_items,
            diagnostic_snippets,
            log_snippets,
        }
    }

    pub fn summary(&self) -> String {
        self.metadata_items
            .iter()
            .chain(self.parameter_items.iter())
            .take(2)
            .map(|item| format!("{}={}", item.key, item.value))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisJobDetailItem {
    pub key: String,
    pub value: String,
}

impl AnalysisJobDetailItem {
    fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestAnalysisJob {
    pub pass_name: String,
    pub profile: String,
    pub status: String,
    pub progress: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisJobsSummary {
    pub total: usize,
    pub queued: usize,
    pub running: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub canceled: usize,
    pub skipped: usize,
    pub latest: Option<LatestAnalysisJob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexByteRow {
    pub offset: u64,
    pub marker: String,
    pub marker_details: Vec<String>,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexViewModel {
    pub artifact: Option<ObjectRef>,
    pub source_path: Option<String>,
    pub file_size: Option<u64>,
    pub base_offset: u64,
    pub selected_offset: u64,
    pub bytes_per_row: usize,
    pub rows: Vec<HexByteRow>,
    pub status: String,
}

impl HexViewModel {
    pub fn empty(status: impl Into<String>) -> Self {
        Self {
            artifact: None,
            source_path: None,
            file_size: None,
            base_offset: 0,
            selected_offset: 0,
            bytes_per_row: 16,
            rows: Vec::new(),
            status: status.into(),
        }
    }

    pub fn from_bytes(
        artifact: ObjectRef,
        source_path: impl Into<String>,
        file_size: u64,
        base_offset: u64,
        bytes: &[u8],
    ) -> Self {
        let bytes_per_row = 16;
        let rows = bytes
            .chunks(bytes_per_row)
            .enumerate()
            .map(|(index, chunk)| {
                let offset = base_offset + (index * bytes_per_row) as u64;
                HexByteRow {
                    offset,
                    marker: String::new(),
                    marker_details: Vec::new(),
                    hex: format_hex_bytes(chunk, bytes_per_row),
                    ascii: format_ascii_bytes(chunk),
                }
            })
            .collect::<Vec<_>>();
        Self {
            artifact: Some(artifact),
            source_path: Some(source_path.into()),
            file_size: Some(file_size),
            base_offset,
            selected_offset: base_offset,
            bytes_per_row,
            rows,
            status: "ready".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexOffsetMappingRange {
    pub section_name: String,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexOffsetMappingStatus {
    Mapped,
    NoSections,
    OutOfRange,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexOffsetMapping {
    pub status: HexOffsetMappingStatus,
    pub source_offset: u64,
    pub file_offset: Option<u64>,
    pub section_name: Option<String>,
    pub message: String,
}

pub fn map_va_to_file_offset(
    virtual_address: u64,
    ranges: &[HexOffsetMappingRange],
) -> HexOffsetMapping {
    if ranges.is_empty() {
        return HexOffsetMapping {
            status: HexOffsetMappingStatus::NoSections,
            source_offset: virtual_address,
            file_offset: None,
            section_name: None,
            message: "no indexed section ranges can prove a VA to file offset mapping".to_string(),
        };
    }

    let matches = ranges
        .iter()
        .filter(|range| {
            let end = range.virtual_address.saturating_add(range.size);
            virtual_address >= range.virtual_address && virtual_address < end
        })
        .collect::<Vec<_>>();

    if matches.is_empty() {
        return HexOffsetMapping {
            status: HexOffsetMappingStatus::OutOfRange,
            source_offset: virtual_address,
            file_offset: None,
            section_name: None,
            message: format!("VA 0x{virtual_address:08x} is outside indexed section ranges"),
        };
    }

    if matches.len() > 1 {
        let sections = matches
            .iter()
            .map(|range| range.section_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return HexOffsetMapping {
            status: HexOffsetMappingStatus::Ambiguous,
            source_offset: virtual_address,
            file_offset: None,
            section_name: None,
            message: format!(
                "VA 0x{virtual_address:08x} maps to multiple indexed sections: {sections}"
            ),
        };
    }

    let range = matches[0];
    let delta = virtual_address - range.virtual_address;
    let file_offset = range.file_offset.saturating_add(delta);
    HexOffsetMapping {
        status: HexOffsetMappingStatus::Mapped,
        source_offset: virtual_address,
        file_offset: Some(file_offset),
        section_name: Some(range.section_name.clone()),
        message: format!(
            "mapped VA 0x{virtual_address:08x} through section {} to file offset 0x{file_offset:08x}",
            range.section_name
        ),
    }
}

fn format_hex_bytes(bytes: &[u8], width: usize) -> String {
    let mut rendered = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>();
    rendered.resize(width, "  ".to_string());
    rendered.join(" ")
}

fn format_ascii_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabSummary {
    pub id: &'static str,
    pub label: &'static str,
    pub badge: &'static str,
    pub purpose: &'static str,
    pub default_lens: NavigationLens,
    pub default_lens_label: &'static str,
    pub shortcut: Option<char>,
    pub maturity: LabMaturity,
}

impl LabSummary {
    pub fn all() -> Vec<Self> {
        ALL_LABS.iter().map(Self::from_descriptor).collect()
    }

    pub fn from_descriptor(descriptor: &LabDescriptor) -> Self {
        Self {
            id: descriptor.stable_id(),
            label: descriptor.label,
            badge: descriptor.badge,
            purpose: descriptor.purpose,
            default_lens: descriptor.default_lens,
            default_lens_label: descriptor.default_lens.label(),
            shortcut: descriptor.shortcut,
            maturity: descriptor.maturity,
        }
    }
}

impl AnalysisJobsSummary {
    pub fn from_rows(rows: &[AnalysisJobRow]) -> Self {
        let mut summary = Self {
            total: rows.len(),
            latest: rows.first().map(|row| LatestAnalysisJob {
                pass_name: row.pass_name.clone(),
                profile: row.profile.clone(),
                status: row.status.clone(),
                progress: row.progress.clone(),
            }),
            ..Self::default()
        };

        for row in rows {
            match row.status.to_ascii_lowercase().as_str() {
                "queued" => summary.queued += 1,
                "running" => summary.running += 1,
                "succeeded" => summary.succeeded += 1,
                "failed" => summary.failed += 1,
                "canceled" => summary.canceled += 1,
                "skipped" => summary.skipped += 1,
                _ => {}
            }
        }

        summary
    }

    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

fn append_detail_items(items: &mut Vec<AnalysisJobDetailItem>, value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if items.len() >= JOB_DETAIL_ITEM_LIMIT {
                    break;
                }
                items.push(AnalysisJobDetailItem::new(key, compact_json_value(value)));
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if items.len() >= JOB_DETAIL_ITEM_LIMIT {
                    break;
                }
                items.push(AnalysisJobDetailItem::new(
                    format!("#{index}"),
                    compact_json_value(value),
                ));
            }
        }
        other => {
            if items.len() < JOB_DETAIL_ITEM_LIMIT {
                items.push(AnalysisJobDetailItem::new(
                    "value",
                    compact_json_value(other),
                ));
            }
        }
    }
}

fn append_diagnostic_snippets(snippets: &mut Vec<String>, value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let code = map.get("code").and_then(serde_json::Value::as_str);
            let message = map.get("message").and_then(serde_json::Value::as_str);
            if let Some(snippet) = diagnostic_snippet(code, message) {
                snippets.push(snippet);
            } else {
                snippets.push(compact_json_value(value));
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                if snippets.len() >= JOB_DETAIL_SNIPPET_LIMIT {
                    break;
                }
                append_diagnostic_snippets(snippets, value);
            }
        }
        other => append_string_snippets(snippets, other),
    }
}

fn diagnostic_snippet(code: Option<&str>, message: Option<&str>) -> Option<String> {
    match (code, message) {
        (Some(code), Some(message)) => Some(format!("{code}: {}", truncate_detail_value(message))),
        (Some(code), None) => Some(code.to_string()),
        (None, Some(message)) => Some(truncate_detail_value(message)),
        (None, None) => None,
    }
}

fn append_string_snippets(snippets: &mut Vec<String>, value: &serde_json::Value) {
    match value {
        serde_json::Value::String(value) => snippets.push(truncate_detail_value(value)),
        serde_json::Value::Array(values) => {
            for value in values {
                if snippets.len() >= JOB_DETAIL_SNIPPET_LIMIT {
                    break;
                }
                append_string_snippets(snippets, value);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                if snippets.len() >= JOB_DETAIL_SNIPPET_LIMIT {
                    break;
                }
                append_string_snippets(snippets, value);
            }
        }
        other => snippets.push(compact_json_value(other)),
    }
}

fn compact_json_value(value: &serde_json::Value) -> String {
    let text = match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Array(items) => format!("{} items", items.len()),
        serde_json::Value::Object(items) => format!("{} fields", items.len()),
    };
    truncate_detail_value(&text)
}

fn truncate_detail_value(value: &str) -> String {
    if value.chars().count() <= JOB_DETAIL_VALUE_LIMIT {
        return value.to_string();
    }
    value
        .chars()
        .take(JOB_DETAIL_VALUE_LIMIT.saturating_sub(1))
        .collect::<String>()
        + "."
}

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

#[derive(Debug, Clone, PartialEq)]
pub struct GraphLabViewModel {
    pub root: ObjectRef,
    pub root_label: String,
    pub active_filter: RelationFilter,
    pub relation_filters: Vec<GraphRelationFilterRow>,
    pub path_rows: Vec<GraphPathRow>,
    pub edge_details: Vec<GraphEdgeDetail>,
    pub limit_notice: Option<String>,
}

impl GraphLabViewModel {
    pub fn from_traversal<F>(
        traversal: &LocalTraversal,
        active_filter: RelationFilter,
        max_nodes: usize,
        label_for: F,
    ) -> Self
    where
        F: Fn(&ObjectRef) -> String,
    {
        let relation_filters = RelationFilter::all()
            .iter()
            .copied()
            .map(|filter| GraphRelationFilterRow {
                id: filter.id().to_string(),
                label: filter.label().to_string(),
                active: filter == active_filter,
                relation_count: traversal
                    .relations
                    .iter()
                    .filter(|relation| filter.matches(relation.kind))
                    .count(),
            })
            .collect::<Vec<_>>();
        let path_rows = traversal
            .evidence_path_items()
            .into_iter()
            .map(|item| GraphPathRow::from_path_item(item, &label_for))
            .collect::<Vec<_>>();
        let edge_details = traversal
            .relations
            .iter()
            .map(|relation| GraphEdgeDetail::from_relation(relation, &label_for))
            .collect::<Vec<_>>();
        let limit_notice = if traversal.nodes.len() >= max_nodes {
            Some(format!(
                "path limited to {max_nodes} nodes; narrow the relation filter or start from a closer object"
            ))
        } else {
            None
        };

        Self {
            root: traversal.root.clone(),
            root_label: label_for(&traversal.root),
            active_filter,
            relation_filters,
            path_rows,
            edge_details,
            limit_notice,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphRelationFilterRow {
    pub id: String,
    pub label: String,
    pub active: bool,
    pub relation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPathRow {
    pub target: ObjectRef,
    pub target_label: String,
    pub depth: usize,
    pub via: Option<EdgeKind>,
    pub predecessor: Option<ObjectRef>,
    pub predecessor_label: Option<String>,
    pub summary: String,
    pub command_preview: String,
}

impl GraphPathRow {
    fn from_path_item<F>(item: EvidencePathItem, label_for: &F) -> Self
    where
        F: Fn(&ObjectRef) -> String,
    {
        let target_label = label_for(&item.object_ref);
        let predecessor_label = item.predecessor.as_ref().map(label_for);
        let summary = match (item.depth, item.via, predecessor_label.as_deref()) {
            (0, _, _) => format!("d0 root {target_label}"),
            (_, Some(kind), Some(predecessor)) => {
                format!(
                    "d{} {} from {predecessor} to {target_label}",
                    item.depth,
                    kind.label()
                )
            }
            (_, Some(kind), None) => {
                format!("d{} {} to {target_label}", item.depth, kind.label())
            }
            _ => format!("d{} linked {target_label}", item.depth),
        };
        Self {
            target: item.object_ref.clone(),
            target_label,
            depth: item.depth,
            via: item.via,
            predecessor: item.predecessor,
            predecessor_label,
            summary,
            command_preview: format!(":open {}", item.object_ref),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdgeDetail {
    pub edge_ref: ObjectRef,
    pub source: ObjectRef,
    pub target: ObjectRef,
    pub kind: EdgeKind,
    pub title: String,
    pub source_label: String,
    pub target_label: String,
    pub confidence: f64,
    pub metadata_items: Vec<AnalysisJobDetailItem>,
    pub command_previews: Vec<String>,
}

impl GraphEdgeDetail {
    pub fn from_relation<F>(relation: &ObjectRelation, label_for: &F) -> Self
    where
        F: Fn(&ObjectRef) -> String,
    {
        let source_label = label_for(&relation.source);
        let target_label = label_for(&relation.target);
        Self {
            edge_ref: relation.edge_ref.clone(),
            source: relation.source.clone(),
            target: relation.target.clone(),
            kind: relation.kind,
            title: format!(
                "{}: {} -> {}",
                relation.kind.label(),
                source_label,
                target_label
            ),
            source_label,
            target_label,
            confidence: relation.confidence,
            metadata_items: graph_metadata_items(&relation.metadata_json),
            command_previews: vec![
                format!(":open {}", relation.source),
                format!(":open {}", relation.target),
                format!(":finding link <finding> {} evidence", relation.target),
            ],
        }
    }
}

fn graph_metadata_items(metadata_json: &str) -> Vec<AnalysisJobDetailItem> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(metadata_json) else {
        return vec![AnalysisJobDetailItem {
            key: "raw".to_string(),
            value: truncate_detail_value(metadata_json),
        }];
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    map.iter()
        .take(6)
        .map(|(key, value)| AnalysisJobDetailItem {
            key: key.clone(),
            value: compact_json_value(value),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffArtifactSnapshot {
    pub artifact: ObjectRef,
    pub artifact_label: String,
    pub objects: Vec<DiffComparableObject>,
    pub relations: Vec<DiffComparableRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffComparableObject {
    pub object_ref: ObjectRef,
    pub kind: ObjectKind,
    pub identity_key: String,
    pub display_label: String,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffComparableRelation {
    pub relation_ref: ObjectRef,
    pub kind: EdgeKind,
    pub source_identity: String,
    pub target_identity: String,
    pub confidence: f64,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffEntityKind {
    Object,
    Relation,
}

impl DiffEntityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Relation => "relation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffChangeKind {
    Added,
    Removed,
    Changed,
}

impl DiffChangeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffRow {
    pub delta_ref: ObjectRef,
    pub entity_kind: DiffEntityKind,
    pub change: DiffChangeKind,
    pub match_key: String,
    pub title: String,
    pub before: Option<ObjectRef>,
    pub after: Option<ObjectRef>,
    pub before_label: Option<String>,
    pub after_label: Option<String>,
    pub command_previews: Vec<String>,
    pub risk_level: Option<String>,
    pub risk_reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRiskSummary {
    pub high_risk_rows: usize,
    pub dangerous_import_deltas: usize,
    pub sensitive_string_deltas: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffSummaryViewModel {
    pub before_artifact: ObjectRef,
    pub before_label: String,
    pub after_artifact: ObjectRef,
    pub after_label: String,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub unchanged: usize,
    pub object_deltas: usize,
    pub relation_deltas: usize,
    pub risk_summary: DiffRiskSummary,
    pub rows: Vec<DiffRow>,
}

impl DiffSummaryViewModel {
    pub fn compare(before: &DiffArtifactSnapshot, after: &DiffArtifactSnapshot) -> Self {
        let mut rows = Vec::new();
        let mut unchanged = 0usize;
        compare_objects(before, after, &mut rows, &mut unchanged);
        compare_relations(before, after, &mut rows, &mut unchanged);
        rows.sort_by(|left, right| {
            left.change
                .as_str()
                .cmp(right.change.as_str())
                .then_with(|| left.entity_kind.as_str().cmp(right.entity_kind.as_str()))
                .then_with(|| left.match_key.cmp(&right.match_key))
        });

        let added = rows
            .iter()
            .filter(|row| row.change == DiffChangeKind::Added)
            .count();
        let removed = rows
            .iter()
            .filter(|row| row.change == DiffChangeKind::Removed)
            .count();
        let changed = rows
            .iter()
            .filter(|row| row.change == DiffChangeKind::Changed)
            .count();
        let object_deltas = rows
            .iter()
            .filter(|row| row.entity_kind == DiffEntityKind::Object)
            .count();
        let relation_deltas = rows
            .iter()
            .filter(|row| row.entity_kind == DiffEntityKind::Relation)
            .count();
        let risk_summary = DiffRiskSummary::from_rows(&rows);

        Self {
            before_artifact: before.artifact.clone(),
            before_label: before.artifact_label.clone(),
            after_artifact: after.artifact.clone(),
            after_label: after.artifact_label.clone(),
            added,
            removed,
            changed,
            unchanged,
            object_deltas,
            relation_deltas,
            risk_summary,
            rows,
        }
    }

    pub fn total_deltas(&self) -> usize {
        self.rows.len()
    }
}

impl DiffRiskSummary {
    fn from_rows(rows: &[DiffRow]) -> Self {
        Self {
            high_risk_rows: rows.iter().filter(|row| row.risk_level.is_some()).count(),
            dangerous_import_deltas: rows
                .iter()
                .filter(|row| {
                    row.risk_reasons
                        .iter()
                        .any(|reason| reason.starts_with("dangerous_import:"))
                })
                .count(),
            sensitive_string_deltas: rows
                .iter()
                .filter(|row| {
                    row.risk_reasons
                        .iter()
                        .any(|reason| reason.starts_with("sensitive_string:"))
                })
                .count(),
        }
    }
}

fn compare_objects(
    before: &DiffArtifactSnapshot,
    after: &DiffArtifactSnapshot,
    rows: &mut Vec<DiffRow>,
    unchanged: &mut usize,
) {
    let before_by_key = before
        .objects
        .iter()
        .map(|object| (object.identity_key.clone(), object))
        .collect::<BTreeMap<_, _>>();
    let after_by_key = after
        .objects
        .iter()
        .map(|object| (object.identity_key.clone(), object))
        .collect::<BTreeMap<_, _>>();
    for match_key in before_by_key
        .keys()
        .chain(after_by_key.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        match (before_by_key.get(match_key), after_by_key.get(match_key)) {
            (Some(before_object), Some(after_object)) => {
                if before_object.fingerprint == after_object.fingerprint {
                    *unchanged += 1;
                } else {
                    rows.push(diff_object_row(
                        DiffChangeKind::Changed,
                        match_key,
                        Some(before_object),
                        Some(after_object),
                        &after.artifact,
                    ));
                }
            }
            (Some(before_object), None) => rows.push(diff_object_row(
                DiffChangeKind::Removed,
                match_key,
                Some(before_object),
                None,
                &before.artifact,
            )),
            (None, Some(after_object)) => rows.push(diff_object_row(
                DiffChangeKind::Added,
                match_key,
                None,
                Some(after_object),
                &after.artifact,
            )),
            (None, None) => {}
        }
    }
}

fn compare_relations(
    before: &DiffArtifactSnapshot,
    after: &DiffArtifactSnapshot,
    rows: &mut Vec<DiffRow>,
    unchanged: &mut usize,
) {
    let before_by_key = before
        .relations
        .iter()
        .map(|relation| (diff_relation_match_key(relation), relation))
        .collect::<BTreeMap<_, _>>();
    let after_by_key = after
        .relations
        .iter()
        .map(|relation| (diff_relation_match_key(relation), relation))
        .collect::<BTreeMap<_, _>>();
    for match_key in before_by_key
        .keys()
        .chain(after_by_key.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        match (before_by_key.get(match_key), after_by_key.get(match_key)) {
            (Some(before_relation), Some(after_relation)) => {
                if before_relation.fingerprint == after_relation.fingerprint {
                    *unchanged += 1;
                } else {
                    rows.push(diff_relation_row(
                        DiffChangeKind::Changed,
                        match_key,
                        Some(before_relation),
                        Some(after_relation),
                        &after.artifact,
                    ));
                }
            }
            (Some(before_relation), None) => rows.push(diff_relation_row(
                DiffChangeKind::Removed,
                match_key,
                Some(before_relation),
                None,
                &before.artifact,
            )),
            (None, Some(after_relation)) => rows.push(diff_relation_row(
                DiffChangeKind::Added,
                match_key,
                None,
                Some(after_relation),
                &after.artifact,
            )),
            (None, None) => {}
        }
    }
}

fn diff_object_row(
    change: DiffChangeKind,
    match_key: &str,
    before: Option<&DiffComparableObject>,
    after: Option<&DiffComparableObject>,
    artifact: &ObjectRef,
) -> DiffRow {
    let before_ref = before.map(|object| object.object_ref.clone());
    let after_ref = after.map(|object| object.object_ref.clone());
    let label = after
        .or(before)
        .map(|object| object.display_label.as_str())
        .unwrap_or(match_key);
    let title = format!("{} object {label}", change.as_str());
    let risk_reasons = diff_object_risk_reasons(before, after);
    let risk_level = diff_risk_level(&risk_reasons);
    DiffRow {
        delta_ref: diff_delta_ref(artifact, DiffEntityKind::Object, change, match_key),
        entity_kind: DiffEntityKind::Object,
        change,
        match_key: match_key.to_string(),
        title,
        before: before_ref.clone(),
        after: after_ref.clone(),
        before_label: before.map(|object| object.display_label.clone()),
        after_label: after.map(|object| object.display_label.clone()),
        command_previews: diff_command_previews(before_ref.as_ref(), after_ref.as_ref()),
        risk_level,
        risk_reasons,
    }
}

fn diff_relation_row(
    change: DiffChangeKind,
    match_key: &str,
    before: Option<&DiffComparableRelation>,
    after: Option<&DiffComparableRelation>,
    artifact: &ObjectRef,
) -> DiffRow {
    let before_ref = before.map(|relation| relation.relation_ref.clone());
    let after_ref = after.map(|relation| relation.relation_ref.clone());
    let relation = after.or(before);
    let label = relation
        .map(|relation| {
            format!(
                "{} {} -> {}",
                relation.kind.label(),
                relation.source_identity,
                relation.target_identity
            )
        })
        .unwrap_or_else(|| match_key.to_string());
    let title = format!("{} relation {label}", change.as_str());
    let risk_reasons = diff_relation_risk_reasons(match_key, before, after);
    let risk_level = diff_risk_level(&risk_reasons);
    DiffRow {
        delta_ref: diff_delta_ref(artifact, DiffEntityKind::Relation, change, match_key),
        entity_kind: DiffEntityKind::Relation,
        change,
        match_key: match_key.to_string(),
        title,
        before: before_ref.clone(),
        after: after_ref.clone(),
        before_label: before.map(|relation| diff_relation_label(relation)),
        after_label: after.map(|relation| diff_relation_label(relation)),
        command_previews: diff_command_previews(before_ref.as_ref(), after_ref.as_ref()),
        risk_level,
        risk_reasons,
    }
}

fn diff_object_risk_reasons(
    before: Option<&DiffComparableObject>,
    after: Option<&DiffComparableObject>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for object in before.into_iter().chain(after.into_iter()) {
        let haystack = format!("{} {}", object.display_label, object.fingerprint);
        match object.kind {
            ObjectKind::Import => {
                if let Some(matched) = dangerous_import_match(&haystack) {
                    reasons.push(format!("dangerous_import:{matched}"));
                }
            }
            ObjectKind::String => {
                if let Some(matched) = sensitive_string_match(&haystack) {
                    reasons.push(format!("sensitive_string:{matched}"));
                }
            }
            _ => {}
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn diff_relation_risk_reasons(
    match_key: &str,
    before: Option<&DiffComparableRelation>,
    after: Option<&DiffComparableRelation>,
) -> Vec<String> {
    let mut haystack = match_key.to_string();
    for relation in before.into_iter().chain(after.into_iter()) {
        haystack.push(' ');
        haystack.push_str(&relation.fingerprint);
    }
    let mut reasons = Vec::new();
    if let Some(matched) = dangerous_import_match(&haystack) {
        reasons.push(format!("dangerous_import:{matched}"));
    }
    if let Some(matched) = sensitive_string_match(&haystack) {
        reasons.push(format!("sensitive_string:{matched}"));
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn diff_risk_level(reasons: &[String]) -> Option<String> {
    if reasons.is_empty() {
        None
    } else {
        Some("high".to_string())
    }
}

fn diff_relation_match_key(relation: &DiffComparableRelation) -> String {
    format!(
        "relation:{}:{}:{}",
        relation.kind.as_str(),
        relation.source_identity,
        relation.target_identity
    )
}

fn diff_relation_label(relation: &DiffComparableRelation) -> String {
    format!(
        "{} {} -> {}",
        relation.kind.label(),
        relation.source_identity,
        relation.target_identity
    )
}

fn diff_command_previews(before: Option<&ObjectRef>, after: Option<&ObjectRef>) -> Vec<String> {
    let mut previews = Vec::new();
    if let Some(before) = before {
        previews.push(format!(":open {before}"));
    }
    if let Some(after) = after {
        previews.push(format!(":open {after}"));
        previews.push(format!(":finding link <finding> {after} evidence"));
    }
    previews
}

fn diff_delta_ref(
    artifact: &ObjectRef,
    entity_kind: DiffEntityKind,
    change: DiffChangeKind,
    match_key: &str,
) -> ObjectRef {
    ObjectRef::new(
        ObjectKind::DiffDelta,
        StableObjectKey::lab_object(
            ObjectKind::DiffDelta,
            Some(&artifact.key),
            "diff",
            &format!(
                "{}/{}/{}",
                entity_kind.as_str(),
                change.as_str(),
                stable_diff_hash(match_key)
            ),
        )
        .expect("diff delta stable key must be valid"),
    )
}

fn stable_diff_hash(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radar::{score_function, FunctionScoreInput, RadarEvidence};
    use crate::{ObjectKind, StableObjectKey, TraversalNode};

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

    fn job(pass_name: &str, status: &str) -> AnalysisJobRow {
        AnalysisJobRow {
            pass_name: pass_name.to_string(),
            profile: "quick".to_string(),
            status: status.to_string(),
            progress: "1/1".to_string(),
            objects_produced: 1,
            diagnostics_count: 0,
            started_at: "2026-05-13T00:00:00Z".to_string(),
            finished_at: Some("2026-05-13T00:00:01Z".to_string()),
            updated_at: "2026-05-13T00:00:01Z".to_string(),
            ..AnalysisJobRow::default()
        }
    }

    #[test]
    fn analysis_jobs_summary_treats_skipped_as_neutral() {
        let rows = vec![
            job("parse", "running"),
            job("cfg", "skipped"),
            job("triage", "failed"),
            job("surface", "succeeded"),
        ];

        let summary = AnalysisJobsSummary::from_rows(&rows);

        assert_eq!(summary.total, 4);
        assert_eq!(summary.running, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.succeeded, 1);
        assert!(summary.has_failures());
        assert_eq!(
            summary
                .latest
                .as_ref()
                .map(|latest| latest.pass_name.as_str()),
            Some("parse")
        );
    }

    #[test]
    fn lab_summary_exposes_stable_registry_for_ui_and_cli() {
        let labs = LabSummary::all();

        assert_eq!(labs.len(), 10);
        assert_eq!(labs[0].id, "binary-triage");
        assert_eq!(labs[0].label, "Binary Triage Lab");
        assert_eq!(labs[0].default_lens_label, "Overview");
        assert_eq!(labs[1].shortcut, Some('J'));
        assert!(labs.iter().any(|lab| lab.id == "diff"));
        assert!(labs.iter().any(|lab| lab.id == "protocol"));
    }

    #[test]
    fn graph_lab_view_model_exposes_filters_paths_edges_and_link_previews() {
        let function = function();
        let import = import();
        let relation = ObjectRelation {
            edge_ref: ObjectRef::new(
                ObjectKind::Edge,
                StableObjectKey::edge(EdgeKind::CallsImport, &function, &import).unwrap(),
            ),
            source: function.clone(),
            target: import.clone(),
            kind: EdgeKind::CallsImport,
            confidence: 0.82,
            metadata_json: r#"{"source":"radar","reason":"dangerous_import"}"#.to_string(),
        };
        let traversal = LocalTraversal {
            root: function.clone(),
            nodes: vec![
                TraversalNode {
                    object_ref: function.clone(),
                    depth: 0,
                },
                TraversalNode {
                    object_ref: import.clone(),
                    depth: 1,
                },
            ],
            relations: vec![relation],
        };

        let model =
            GraphLabViewModel::from_traversal(&traversal, RelationFilter::Calls, 8, |object_ref| {
                if *object_ref == function {
                    "main".to_string()
                } else if *object_ref == import {
                    "system".to_string()
                } else {
                    object_ref.key.to_string()
                }
            });

        assert_eq!(model.root_label, "main");
        assert!(model
            .relation_filters
            .iter()
            .any(|row| row.id == "calls" && row.active && row.relation_count == 1));
        assert!(model
            .relation_filters
            .iter()
            .any(|row| row.id == "xrefs" && !row.active && row.relation_count == 0));
        assert_eq!(model.path_rows.len(), 2);
        assert!(model.path_rows[1].summary.contains("CALLS_IMPORT"));
        assert!(model.path_rows[1].command_preview.contains(":open"));
        assert_eq!(model.edge_details.len(), 1);
        assert_eq!(model.edge_details[0].confidence, 0.82);
        assert!(model.edge_details[0]
            .metadata_items
            .iter()
            .any(|item| item.key == "source" && item.value == "radar"));
        assert!(model.edge_details[0]
            .command_previews
            .iter()
            .any(|preview| preview.contains(":finding link <finding>")));
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
    fn analysis_job_detail_extracts_metadata_parameters_and_snippets() {
        let detail = AnalysisJobDetail::from_metadata_json(
            r#"{
                "format": "elf",
                "parameters": {"profile":"quick","byte_limit":4096},
                "diagnostics": [{"code":"pass_skipped_by_profile","message":"quick skipped native CFG"}],
                "log_snippets": ["cfg skipped by quick profile"]
            }"#,
        );

        assert!(detail
            .metadata_items
            .iter()
            .any(|item| item.key == "format" && item.value == "elf"));
        assert!(detail
            .parameter_items
            .iter()
            .any(|item| item.key == "profile" && item.value == "quick"));
        assert_eq!(
            detail.diagnostic_snippets,
            vec!["pass_skipped_by_profile: quick skipped native CFG"]
        );
        assert_eq!(detail.log_snippets, vec!["cfg skipped by quick profile"]);
    }

    #[test]
    fn hex_offset_mapping_maps_va_with_single_section_evidence() {
        let mapping = map_va_to_file_offset(
            0x401020,
            &[HexOffsetMappingRange {
                section_name: ".text".to_string(),
                virtual_address: 0x401000,
                file_offset: 0x200,
                size: 0x80,
            }],
        );

        assert_eq!(mapping.status, HexOffsetMappingStatus::Mapped);
        assert_eq!(mapping.file_offset, Some(0x220));
        assert_eq!(mapping.section_name.as_deref(), Some(".text"));
    }

    #[test]
    fn hex_offset_mapping_refuses_missing_out_of_range_and_ambiguous_ranges() {
        let missing = map_va_to_file_offset(0x401000, &[]);
        assert_eq!(missing.status, HexOffsetMappingStatus::NoSections);
        assert_eq!(missing.file_offset, None);

        let out_of_range = map_va_to_file_offset(
            0x402000,
            &[HexOffsetMappingRange {
                section_name: ".text".to_string(),
                virtual_address: 0x401000,
                file_offset: 0x200,
                size: 0x80,
            }],
        );
        assert_eq!(out_of_range.status, HexOffsetMappingStatus::OutOfRange);
        assert_eq!(out_of_range.file_offset, None);

        let ambiguous = map_va_to_file_offset(
            0x401040,
            &[
                HexOffsetMappingRange {
                    section_name: ".text".to_string(),
                    virtual_address: 0x401000,
                    file_offset: 0x200,
                    size: 0x80,
                },
                HexOffsetMappingRange {
                    section_name: ".overlap".to_string(),
                    virtual_address: 0x401020,
                    file_offset: 0x300,
                    size: 0x80,
                },
            ],
        );
        assert_eq!(ambiguous.status, HexOffsetMappingStatus::Ambiguous);
        assert_eq!(ambiguous.file_offset, None);
    }

    #[test]
    fn analysis_job_detail_keeps_invalid_metadata_as_raw_fallback() {
        let detail = AnalysisJobDetail::from_metadata_json("{not-json");

        assert_eq!(detail.metadata_items[0].key, "raw");
        assert!(detail
            .diagnostic_snippets
            .iter()
            .any(|snippet| snippet.contains("parse failed")));
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
