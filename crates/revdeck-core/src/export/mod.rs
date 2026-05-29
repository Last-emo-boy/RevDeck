use crate::{lab_id_for_kind, Finding, FindingSeverity, FindingStatus, ObjectRef, ObjectSummary};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Markdown,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportTemplate {
    Summary,
    Full,
    Ci,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub generated_at: OffsetDateTime,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportContext {
    pub report: Report,
    pub evidence_objects: Vec<ObjectSummary>,
    pub lab_summaries: Vec<ExportLabSummary>,
    pub analysis_jobs: Vec<ExportAnalysisJob>,
    pub plugin_runs: Vec<ExportPluginRun>,
    pub case_metadata: Vec<ExportCaseMetadata>,
    pub case_notes: Vec<ExportCaseNote>,
}

impl ExportContext {
    pub fn new(report: Report, evidence_objects: Vec<ObjectSummary>) -> Self {
        let lab_summaries = summarize_labs(&report, &evidence_objects);
        Self {
            report,
            evidence_objects,
            lab_summaries,
            analysis_jobs: Vec::new(),
            plugin_runs: Vec::new(),
            case_metadata: Vec::new(),
            case_notes: Vec::new(),
        }
    }

    pub fn refresh_lab_summaries(&mut self) {
        self.lab_summaries = summarize_labs(&self.report, &self.evidence_objects);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundle {
    pub report: Report,
    pub evidence_objects: Vec<ExportEvidenceObject>,
    pub lab_summaries: Vec<ExportLabSummary>,
    pub analysis_jobs: Vec<ExportAnalysisJob>,
    pub plugin_runs: Vec<ExportPluginRun>,
    pub case_metadata: Vec<ExportCaseMetadata>,
    pub case_notes: Vec<ExportCaseNote>,
    pub validation: ExportValidationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportCaseMetadata {
    pub key: String,
    pub value: String,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportCaseNote {
    pub note_id: i64,
    pub category: String,
    pub title: String,
    pub body: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportLabSummary {
    pub lab_id: String,
    pub findings: usize,
    pub evidence_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAnalysisJob {
    pub id: i64,
    pub artifact_key: Option<String>,
    pub pass_name: String,
    pub profile: String,
    pub status: String,
    pub diagnostics_count: u64,
    pub metadata_json: String,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPluginRun {
    pub id: i64,
    pub plugin_id: String,
    pub plugin_version: String,
    pub manifest_digest: String,
    pub input_digest: String,
    pub config_digest: Option<String>,
    pub status: String,
    pub permissions_json: String,
    pub diagnostics_json: String,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEvidenceObject {
    pub object_ref: ObjectRef,
    pub artifact_key: Option<String>,
    pub lab_id: Option<String>,
    pub display_name: Option<String>,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub metadata_json: String,
}

impl ExportEvidenceObject {
    pub fn from_summary(summary: &ObjectSummary) -> Self {
        Self {
            object_ref: summary.object_ref.clone(),
            artifact_key: summary.artifact_key.clone(),
            lab_id: summary
                .lab_id()
                .or_else(|| lab_id_for_kind(summary.object_ref.kind).map(str::to_string)),
            display_name: summary.display_name.clone(),
            address: summary.address,
            size: summary.size,
            metadata_json: summary.metadata_json.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportValidationReport {
    pub errors: Vec<ExportValidationIssue>,
    pub warnings: Vec<ExportValidationIssue>,
}

impl ExportValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportValidationIssue {
    pub code: String,
    pub message: String,
    pub finding: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportGateSummary {
    pub template: ReportTemplate,
    pub min_lab_coverage: Option<usize>,
    pub lab_coverage: usize,
    pub validation_errors: usize,
    pub validation_warnings: usize,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("pre-export validation failed with {error_count} error(s)")]
pub struct ExportValidationError {
    pub error_count: usize,
    pub report: ExportValidationReport,
}

pub fn validation_report(context: &ExportContext) -> ExportValidationReport {
    let mut report = ExportValidationReport {
        errors: Vec::new(),
        warnings: Vec::new(),
    };
    let evidence_keys = context
        .evidence_objects
        .iter()
        .map(|object| object.object_ref.to_string())
        .collect::<std::collections::BTreeSet<_>>();

    if context.report.findings.is_empty() {
        report.warnings.push(ExportValidationIssue {
            code: "no_findings".to_string(),
            message: "report contains no findings".to_string(),
            finding: None,
            evidence: None,
        });
    }

    for finding in &context.report.findings {
        if finding.status == FindingStatus::Draft {
            report.warnings.push(ExportValidationIssue {
                code: "draft_finding".to_string(),
                message: "draft finding will be exported as draft".to_string(),
                finding: Some(finding.object_ref.to_string()),
                evidence: None,
            });
        }
        if finding.title.trim().is_empty() {
            report.errors.push(ExportValidationIssue {
                code: "missing_title".to_string(),
                message: "finding title is required".to_string(),
                finding: Some(finding.object_ref.to_string()),
                evidence: None,
            });
        }
        if finding.summary.trim().is_empty() && finding.body.trim().is_empty() {
            report.warnings.push(ExportValidationIssue {
                code: "missing_detail".to_string(),
                message: "finding has no summary or body".to_string(),
                finding: Some(finding.object_ref.to_string()),
                evidence: None,
            });
        }
        if finding.evidence.is_empty() {
            report.errors.push(ExportValidationIssue {
                code: "missing_evidence".to_string(),
                message: "finding must link at least one evidence object before export".to_string(),
                finding: Some(finding.object_ref.to_string()),
                evidence: None,
            });
        }
        for evidence in &finding.evidence {
            let evidence_ref = evidence.evidence.to_string();
            if !evidence_keys.contains(&evidence_ref) {
                report.errors.push(ExportValidationIssue {
                    code: "broken_evidence".to_string(),
                    message: "finding evidence object is missing from the project".to_string(),
                    finding: Some(finding.object_ref.to_string()),
                    evidence: Some(evidence_ref),
                });
            }
            if evidence.role.trim().is_empty() {
                report.errors.push(ExportValidationIssue {
                    code: "missing_evidence_role".to_string(),
                    message: "finding evidence role is required".to_string(),
                    finding: Some(finding.object_ref.to_string()),
                    evidence: Some(evidence.evidence.to_string()),
                });
            }
        }
    }

    for job in &context.analysis_jobs {
        if job.status == "failed" {
            report.errors.push(ExportValidationIssue {
                code: "failed_analysis_job".to_string(),
                message: format!(
                    "analysis job `{}` failed before export; inspect diagnostics before release",
                    job.pass_name
                ),
                finding: None,
                evidence: None,
            });
        } else if job.status == "skipped" {
            report.warnings.push(ExportValidationIssue {
                code: "skipped_analysis_job".to_string(),
                message: format!(
                    "analysis job `{}` was skipped; report may be profile-limited",
                    job.pass_name
                ),
                finding: None,
                evidence: None,
            });
        }
    }

    for run in &context.plugin_runs {
        if run.status == "failed" {
            report.warnings.push(ExportValidationIssue {
                code: "failed_plugin_run".to_string(),
                message: format!(
                    "plugin run `{}` {} failed before export",
                    run.plugin_id, run.id
                ),
                finding: None,
                evidence: None,
            });
        }
    }

    let plugin_run_ids = context
        .plugin_runs
        .iter()
        .map(|run| run.id)
        .collect::<BTreeSet<_>>();
    for object in &context.evidence_objects {
        if evidence_lab_id(object) != "plugin" {
            continue;
        }
        match metadata_plugin_run_id(&object.metadata_json) {
            Some(plugin_run_id) if !plugin_run_ids.contains(&plugin_run_id) => {
                report.errors.push(ExportValidationIssue {
                    code: "orphan_plugin_output".to_string(),
                    message: format!(
                        "plugin evidence `{}` references missing plugin_run_id {}",
                        object.object_ref, plugin_run_id
                    ),
                    finding: None,
                    evidence: Some(object.object_ref.to_string()),
                });
            }
            None if plugin_run_ids.is_empty() => {
                report.errors.push(ExportValidationIssue {
                    code: "orphan_plugin_output".to_string(),
                    message: format!(
                        "plugin evidence `{}` has no plugin run provenance",
                        object.object_ref
                    ),
                    finding: None,
                    evidence: Some(object.object_ref.to_string()),
                });
            }
            None => {
                report.warnings.push(ExportValidationIssue {
                    code: "missing_plugin_provenance".to_string(),
                    message: format!(
                        "plugin evidence `{}` does not record plugin_run_id",
                        object.object_ref
                    ),
                    finding: None,
                    evidence: Some(object.object_ref.to_string()),
                });
            }
            Some(_) => {}
        }
    }

    report
}

pub fn pre_export_validation(
    context: &ExportContext,
) -> Result<ExportValidationReport, ExportValidationError> {
    let report = validation_report(context);
    if report.errors.is_empty() {
        Ok(report)
    } else {
        Err(ExportValidationError {
            error_count: report.errors.len(),
            report,
        })
    }
}

pub fn validate_export(
    context: &ExportContext,
) -> Result<ExportValidationReport, ExportValidationError> {
    pre_export_validation(context)
}

pub fn render_json(context: &ExportContext) -> Result<String, serde_json::Error> {
    let mut report = context.report.clone();
    normalize_report(&mut report);
    serde_json::to_string_pretty(&report)
}

pub fn render_json_bundle(context: &ExportContext) -> Result<String, serde_json::Error> {
    let bundle = export_bundle(context);
    serde_json::to_string_pretty(&bundle)
}

pub fn export_gate_summary(
    context: &ExportContext,
    template: ReportTemplate,
    min_lab_coverage: Option<usize>,
) -> ExportGateSummary {
    let validation = validation_report(context);
    let lab_coverage = context.lab_summaries.len();
    let passed = validation.errors.is_empty()
        && min_lab_coverage
            .map(|minimum| lab_coverage >= minimum)
            .unwrap_or(true);
    ExportGateSummary {
        template,
        min_lab_coverage,
        lab_coverage,
        validation_errors: validation.errors.len(),
        validation_warnings: validation.warnings.len(),
        passed,
    }
}

pub fn render_template_json(
    context: &ExportContext,
    template: ReportTemplate,
    min_lab_coverage: Option<usize>,
) -> Result<String, serde_json::Error> {
    match template {
        ReportTemplate::Summary => serde_json::to_string_pretty(&serde_json::json!({
            "template": template,
            "generated_at": context.report.generated_at,
            "findings": context.report.findings.len(),
            "lab_summaries": context.lab_summaries,
            "gate": export_gate_summary(context, template, min_lab_coverage),
            "validation": validation_report(context)
        })),
        ReportTemplate::Full => render_json_bundle(context),
        ReportTemplate::Ci => serde_json::to_string_pretty(&serde_json::json!({
            "template": template,
            "gate": export_gate_summary(context, template, min_lab_coverage),
            "validation": validation_report(context),
            "lab_summaries": context.lab_summaries,
            "analysis_jobs": context.analysis_jobs,
            "plugin_runs": context.plugin_runs,
            "case_metadata": context.case_metadata,
            "case_notes": context.case_notes
        })),
    }
}

pub fn export_bundle(context: &ExportContext) -> ExportBundle {
    let mut report = context.report.clone();
    normalize_report(&mut report);
    let mut evidence_objects = context
        .evidence_objects
        .iter()
        .map(ExportEvidenceObject::from_summary)
        .collect::<Vec<_>>();
    evidence_objects.sort_by(|left, right| {
        left.object_ref
            .cmp(&right.object_ref)
            .then_with(|| left.artifact_key.cmp(&right.artifact_key))
    });
    let mut lab_summaries = context.lab_summaries.clone();
    lab_summaries.sort_by(|left, right| left.lab_id.cmp(&right.lab_id));
    let mut analysis_jobs = context.analysis_jobs.clone();
    analysis_jobs.sort_by(|left, right| {
        left.artifact_key
            .cmp(&right.artifact_key)
            .then_with(|| left.pass_name.cmp(&right.pass_name))
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut plugin_runs = context.plugin_runs.clone();
    plugin_runs.sort_by(|left, right| {
        left.plugin_id
            .cmp(&right.plugin_id)
            .then_with(|| left.id.cmp(&right.id))
    });
    ExportBundle {
        report,
        evidence_objects,
        lab_summaries,
        analysis_jobs,
        plugin_runs,
        case_metadata: context.case_metadata.clone(),
        case_notes: context.case_notes.clone(),
        validation: validation_report(context),
    }
}

pub fn render_markdown(context: &ExportContext) -> String {
    let mut report = context.report.clone();
    normalize_report(&mut report);
    let mut markdown = String::from("# RevDeck Findings Report\n\n");
    markdown.push_str(&format!("Generated: {}\n\n", report.generated_at));
    if !context.case_metadata.is_empty() || !context.case_notes.is_empty() {
        markdown.push_str("## Case Metadata\n\n");
        for item in &context.case_metadata {
            markdown.push_str(&format!("- `{}`: {}\n", item.key, item.value));
        }
        for note in &context.case_notes {
            markdown.push_str(&format!(
                "- Note #{} [{}] {}: {}\n",
                note.note_id, note.category, note.title, note.body
            ));
        }
        markdown.push('\n');
    }
    if !context.lab_summaries.is_empty() {
        markdown.push_str("## Lab Coverage\n\n");
        let mut lab_summaries = context.lab_summaries.clone();
        lab_summaries.sort_by(|left, right| left.lab_id.cmp(&right.lab_id));
        for lab in lab_summaries {
            markdown.push_str(&format!(
                "- `{}`: findings={} evidence={}\n",
                lab.lab_id, lab.findings, lab.evidence_objects
            ));
        }
        markdown.push('\n');
    }
    if report.findings.is_empty() {
        markdown.push_str("No findings.\n");
        return markdown;
    }

    for finding in &report.findings {
        markdown.push_str(&format!("## {}\n\n", finding.title));
        markdown.push_str(&format!("- Severity: {}\n", finding.severity));
        markdown.push_str(&format!("- Status: {}\n", finding.status));
        markdown.push_str(&format!("- Object: `{}`\n", finding.object_ref));
        if !finding.tags.is_empty() {
            markdown.push_str(&format!("- Tags: {}\n", finding.tags.join(", ")));
        }
        markdown.push('\n');
        if !finding.summary.is_empty() {
            markdown.push_str(&finding.summary);
            markdown.push_str("\n\n");
        }
        if !finding.body.is_empty() {
            markdown.push_str(&finding.body);
            markdown.push_str("\n\n");
        }
        markdown.push_str("### Evidence\n\n");
        for evidence in &finding.evidence {
            let label = evidence
                .label
                .as_deref()
                .unwrap_or_else(|| evidence.evidence.key.as_str());
            markdown.push_str(&format!(
                "- `{}` ({}) - {}",
                evidence.evidence, evidence.role, label
            ));
            if let Some(lab_id) = evidence.lab_id() {
                markdown.push_str(&format!(" [{}]", lab_id));
            }
            if !evidence.note.is_empty() {
                markdown.push_str(&format!(": {}", evidence.note));
            }
            markdown.push('\n');
        }
        markdown.push('\n');
    }
    markdown
}

fn normalize_report(report: &mut Report) {
    report.findings.sort_by(compare_findings);
    for finding in &mut report.findings {
        finding.tags.sort();
        finding.tags.dedup();
        finding.evidence.sort_by(compare_evidence);
        for evidence in &mut finding.evidence {
            if evidence.note.trim().is_empty() {
                evidence.note.clear();
            }
            if evidence
                .label
                .as_deref()
                .is_some_and(|label| label.trim().is_empty())
            {
                evidence.label = None;
            }
        }
    }
}

fn compare_findings(left: &Finding, right: &Finding) -> Ordering {
    severity_rank(left.severity)
        .cmp(&severity_rank(right.severity))
        .then_with(|| left.status.cmp(&right.status))
        .then_with(|| left.title.cmp(&right.title))
        .then_with(|| left.object_ref.cmp(&right.object_ref))
}

fn compare_evidence(left: &crate::FindingEvidence, right: &crate::FindingEvidence) -> Ordering {
    left.order
        .cmp(&right.order)
        .then_with(|| left.evidence.cmp(&right.evidence))
        .then_with(|| left.role.cmp(&right.role))
        .then_with(|| left.note.cmp(&right.note))
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

fn summarize_labs(report: &Report, evidence_objects: &[ObjectSummary]) -> Vec<ExportLabSummary> {
    let lab_by_object = evidence_objects
        .iter()
        .map(|object| (object.object_ref.clone(), evidence_lab_id(object)))
        .collect::<BTreeMap<_, _>>();
    let mut evidence_counts = BTreeMap::<String, usize>::new();
    for lab in lab_by_object.values() {
        *evidence_counts.entry(lab.clone()).or_default() += 1;
    }

    let mut finding_counts = BTreeMap::<String, usize>::new();
    for finding in &report.findings {
        let mut finding_labs = BTreeSet::new();
        for evidence in &finding.evidence {
            let lab = lab_by_object
                .get(&evidence.evidence)
                .cloned()
                .or_else(|| lab_id_for_kind(evidence.evidence.kind).map(str::to_string))
                .unwrap_or_else(|| "binary-triage".to_string());
            finding_labs.insert(lab);
        }
        if finding_labs.is_empty() {
            finding_labs.insert("unlinked".to_string());
        }
        for lab in finding_labs {
            *finding_counts.entry(lab).or_default() += 1;
        }
    }

    evidence_counts
        .keys()
        .chain(finding_counts.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|lab_id| ExportLabSummary {
            findings: finding_counts.get(&lab_id).copied().unwrap_or_default(),
            evidence_objects: evidence_counts.get(&lab_id).copied().unwrap_or_default(),
            lab_id,
        })
        .collect()
}

fn evidence_lab_id(object: &ObjectSummary) -> String {
    object
        .lab_id()
        .or_else(|| lab_id_for_kind(object.object_ref.kind).map(str::to_string))
        .unwrap_or_else(|| "binary-triage".to_string())
}

fn metadata_plugin_run_id(metadata_json: &str) -> Option<i64> {
    let value = serde_json::from_str::<serde_json::Value>(metadata_json).ok()?;
    value.get("plugin_run_id").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
            .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
    })
}
