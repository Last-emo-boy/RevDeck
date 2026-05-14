use crate::error::{RevDeckError, RevDeckResult};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisRunStatus {
    Running,
    Succeeded,
    Failed,
    Canceled,
}

impl AnalysisRunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Canceled)
    }
}

impl fmt::Display for AnalysisRunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AnalysisRunStatus {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            other => Err(RevDeckError::InvalidAnalysisRunStatus(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewAnalysisRun {
    pub artifact_key: Option<String>,
    pub analyzer_id: String,
    pub analyzer_version: String,
    pub input_hash: String,
    pub started_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRun {
    pub id: i64,
    pub artifact_key: Option<String>,
    pub analyzer_id: String,
    pub analyzer_version: String,
    pub input_hash: String,
    pub status: AnalysisRunStatus,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    pub diagnostics_json: Option<String>,
    pub error_json: Option<String>,
    pub recoverable: bool,
}

pub const FUNCTION_BOUNDARY_CONFIDENCE_FIELD: &str = "boundary_confidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryConfidence {
    Symbol,
    Entrypoint,
    ImportThunk,
    Heuristic,
    ExternalAdapter,
    Unknown,
}

impl BoundaryConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Symbol => "symbol",
            Self::Entrypoint => "entrypoint",
            Self::ImportThunk => "import_thunk",
            Self::Heuristic => "heuristic",
            Self::ExternalAdapter => "external_adapter",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for BoundaryConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl DiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStage {
    RegisterArtifact,
    Parse,
    IndexSections,
    IndexSymbols,
    IndexImports,
    IndexStrings,
    IndexFunctions,
    IndexEdges,
    Persist,
}

impl DiagnosticStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegisterArtifact => "register_artifact",
            Self::Parse => "parse",
            Self::IndexSections => "index_sections",
            Self::IndexSymbols => "index_symbols",
            Self::IndexImports => "index_imports",
            Self::IndexStrings => "index_strings",
            Self::IndexFunctions => "index_functions",
            Self::IndexEdges => "index_edges",
            Self::Persist => "persist",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisDiagnostic {
    pub severity: DiagnosticSeverity,
    pub stage: DiagnosticStage,
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl AnalysisDiagnostic {
    pub fn new(
        severity: DiagnosticSeverity,
        stage: DiagnosticStage,
        code: impl Into<String>,
        message: impl Into<String>,
        recoverable: bool,
    ) -> RevDeckResult<Self> {
        let code = non_empty("diagnostic_code", code.into())?;
        let message = non_empty("diagnostic_message", message.into())?;
        Ok(Self {
            severity,
            stage,
            code,
            message,
            recoverable,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub sections: usize,
    pub symbols: usize,
    pub imports: usize,
    pub strings: usize,
    pub functions: usize,
    pub xrefs: usize,
    pub edges: usize,
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

impl NewAnalysisRun {
    pub fn new(
        artifact_key: Option<String>,
        analyzer_id: impl Into<String>,
        analyzer_version: impl Into<String>,
        input_hash: impl Into<String>,
        started_at: OffsetDateTime,
    ) -> RevDeckResult<Self> {
        let analyzer_id = non_empty("analyzer_id", analyzer_id.into())?;
        let analyzer_version = non_empty("analyzer_version", analyzer_version.into())?;
        let input_hash = non_empty("input_hash", input_hash.into())?;
        Ok(Self {
            artifact_key,
            analyzer_id,
            analyzer_version,
            input_hash,
            started_at,
        })
    }
}

fn non_empty(field: &str, value: String) -> RevDeckResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(RevDeckError::InvalidObjectKeyComponent {
            component: field.to_string(),
            reason: "value cannot be empty".to_string(),
        })
    } else {
        Ok(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn analysis_run_status_round_trips() {
        assert_eq!(
            AnalysisRunStatus::Succeeded
                .to_string()
                .parse::<AnalysisRunStatus>()
                .unwrap(),
            AnalysisRunStatus::Succeeded
        );
        assert!(AnalysisRunStatus::Failed.is_terminal());
        assert!(!AnalysisRunStatus::Running.is_terminal());
    }

    #[test]
    fn analysis_run_requires_identity_fields() {
        let err = NewAnalysisRun::new(
            None,
            "",
            "0.1.0",
            "fixture-hash",
            datetime!(2026-05-13 00:00 UTC),
        )
        .unwrap_err();
        assert!(err.to_string().contains("analyzer_id"));
    }

    #[test]
    fn boundary_confidence_values_are_stable() {
        assert_eq!(BoundaryConfidence::Symbol.as_str(), "symbol");
        assert_eq!(BoundaryConfidence::Entrypoint.as_str(), "entrypoint");
        assert_eq!(BoundaryConfidence::ImportThunk.as_str(), "import_thunk");
        assert_eq!(BoundaryConfidence::Heuristic.as_str(), "heuristic");
        assert_eq!(
            BoundaryConfidence::ExternalAdapter.as_str(),
            "external_adapter"
        );
        assert_eq!(BoundaryConfidence::Unknown.as_str(), "unknown");
    }
}
