use crate::ObjectRef;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for FindingSeverity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown finding severity `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Draft,
    Confirmed,
    NeedsReview,
    FalsePositive,
    Fixed,
}

impl FindingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Confirmed => "confirmed",
            Self::NeedsReview => "needs_review",
            Self::FalsePositive => "false_positive",
            Self::Fixed => "fixed",
        }
    }
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for FindingStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "draft" => Ok(Self::Draft),
            "confirmed" => Ok(Self::Confirmed),
            "needs_review" => Ok(Self::NeedsReview),
            "false_positive" => Ok(Self::FalsePositive),
            "fixed" => Ok(Self::Fixed),
            other => Err(format!("unknown finding status `{other}`")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub object_ref: ObjectRef,
    pub title: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub summary: String,
    pub body: String,
    pub tags: Vec<String>,
    pub evidence: Vec<FindingEvidence>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Finding {
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    pub fn normalized(mut self) -> Self {
        self.tags.sort();
        self.tags.dedup();
        self.evidence.sort_by(|left, right| {
            left.order
                .cmp(&right.order)
                .then_with(|| left.evidence.cmp(&right.evidence))
                .then_with(|| left.role.cmp(&right.role))
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub evidence: ObjectRef,
    pub role: String,
    pub order: u64,
    pub note: String,
    pub label: Option<String>,
}

impl FindingEvidence {
    pub fn new(
        evidence: ObjectRef,
        role: impl Into<String>,
        order: u64,
        note: impl Into<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            evidence,
            role: role.into(),
            order,
            note: note.into(),
            label,
        }
    }

    pub fn normalized(mut self) -> Self {
        self.role = self.role.trim().to_string();
        self.note = self.note.trim().to_string();
        self.label = self
            .label
            .map(|label| label.trim().to_string())
            .filter(|label| !label.is_empty());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pre_export_validation, ExportContext, ObjectKind, ObjectRef, ObjectSummary, Report,
        StableObjectKey,
    };
    use time::macros::datetime;

    fn artifact() -> ObjectRef {
        ObjectRef::artifact("abc123", "fixtures/findings").unwrap()
    }

    fn function() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
        )
    }

    #[test]
    fn findings_evidence() {
        let function = function();
        let finding_ref = ObjectRef::new(
            ObjectKind::Finding,
            StableObjectKey::finding("auth-gate", "2026-05-13T00:00:00Z").unwrap(),
        );
        let finding = Finding {
            object_ref: finding_ref,
            title: "Auth gate accepts weak credential path".to_string(),
            severity: FindingSeverity::High,
            status: FindingStatus::Confirmed,
            summary: "Suspicious function has linked evidence.".to_string(),
            body: String::new(),
            tags: vec!["auth".to_string()],
            evidence: vec![FindingEvidence::new(
                function.clone(),
                "primary",
                0,
                "reviewed function",
                Some("auth_gate".to_string()),
            )],
            created_at: datetime!(2026-05-13 00:00 UTC),
            updated_at: datetime!(2026-05-13 00:00 UTC),
        }
        .normalized();
        let context = ExportContext {
            report: Report {
                generated_at: datetime!(2026-05-13 00:01 UTC),
                findings: vec![finding],
            },
            evidence_objects: vec![ObjectSummary::new(function, "auth_gate")],
        };

        let validation = pre_export_validation(&context).unwrap();
        assert!(validation.is_valid());
    }
}
