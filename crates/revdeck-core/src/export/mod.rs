use crate::{Finding, FindingSeverity, FindingStatus, ObjectSummary};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Markdown,
    Json,
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("pre-export validation failed with {error_count} error(s)")]
pub struct ExportValidationError {
    pub error_count: usize,
    pub report: ExportValidationReport,
}

pub fn pre_export_validation(
    context: &ExportContext,
) -> Result<ExportValidationReport, ExportValidationError> {
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

pub fn render_markdown(context: &ExportContext) -> String {
    let mut report = context.report.clone();
    normalize_report(&mut report);
    let mut markdown = String::from("# RevDeck Findings Report\n\n");
    markdown.push_str(&format!("Generated: {}\n\n", report.generated_at));
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
