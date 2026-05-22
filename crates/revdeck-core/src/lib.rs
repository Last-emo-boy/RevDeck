pub mod analysis;
pub mod artifact;
pub mod commands;
pub mod error;
pub mod export;
pub mod findings;
pub mod memory;
pub mod navigation;
pub mod object;
pub mod query;
pub mod radar;
pub mod view_models;

pub use analysis::{
    AnalysisDiagnostic, AnalysisRun, AnalysisRunStatus, AnalysisSummary, BoundaryConfidence,
    DiagnosticSeverity, DiagnosticStage, NewAnalysisRun, FUNCTION_BOUNDARY_CONFIDENCE_FIELD,
};
pub use artifact::{ArtifactFormat, ArtifactKind, ArtifactMetadata, ImportStatus};
pub use commands::{
    CommandAst, CommandDiagnostic, CommandDiagnosticKind, CommandExecutor, CommandOutcome,
    CommandParser, CommandResolver, CommandState, CommandTarget, ExportFormat, FindingDraft,
    FindingEvidenceDraft, ResolvedCommand,
};
pub use error::{RevDeckError, RevDeckResult};
pub use export::{
    export_bundle, pre_export_validation, render_json, render_json_bundle, render_markdown,
    validate_export, validation_report, ExportAnalysisJob, ExportBundle, ExportContext,
    ExportEvidenceObject, ExportLabSummary, ExportPluginRun, ExportValidationError,
    ExportValidationIssue, ExportValidationReport, Report, ReportFormat,
};
pub use findings::{lab_id_for_kind, Finding, FindingEvidence, FindingSeverity, FindingStatus};
pub use memory::{Annotation, AnnotationEvidence, AnnotationKind};
pub use navigation::{
    BrokenObject, LabDescriptor, LabId, LabMaturity, NavigationEntry, NavigationHistory,
    NavigationLens, SelectionContext, ALL_LABS, WORKSPACE_LENSES,
};
pub use object::{EdgeKind, ObjectKind, ObjectRef, StableObjectKey, StableObjectKeyBuilder};
pub use query::{
    EvidencePathItem, InMemoryObjectGraph, LocalTraversal, ObjectGraphQuery, ObjectRelation,
    ObjectSearch, ObjectSummary, QueryError, RelationDirection, RelationFilter, TraversalNode,
    TraversalOptions,
};
pub use radar::{
    filter_function_scores, score_function, score_functions, sort_function_scores,
    FunctionRadarFilter, FunctionScore, FunctionScoreInput, RadarEvidence, ScoreReason,
    FUNCTION_RADAR_SCORE_KIND, SIGNAL_ANALYST_TAG, SIGNAL_BOUNDARY_CONFIDENCE, SIGNAL_CALL_COUNT,
    SIGNAL_DANGEROUS_IMPORT, SIGNAL_ENTRYPOINT, SIGNAL_FUNCTION_SIZE, SIGNAL_SENSITIVE_STRING,
    SIGNAL_XREF_COUNT,
};
pub use view_models::{
    AnalysisJobDetail, AnalysisJobDetailItem, AnalysisJobRow, AnalysisJobsSummary,
    DiffArtifactSnapshot, DiffChangeKind, DiffComparableObject, DiffComparableRelation,
    DiffEntityKind, DiffRow, DiffSummaryViewModel, EvidenceNavigationItem, FunctionRadarRow,
    FunctionRadarViewModel, GraphEdgeDetail, GraphLabViewModel, GraphPathRow,
    GraphRelationFilterRow, InspectorViewModel, LabSummary, LatestAnalysisJob, OverviewViewModel,
    ScoreReasonView, TriageActionRow, TriageBoardViewModel,
};
