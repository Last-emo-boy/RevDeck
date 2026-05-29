use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use revdeck_core::{
    classify_import_family, classify_string_signal, export_gate_summary, pre_export_validation,
    render_markdown, render_template_json, AnalysisDiagnostic, DiagnosticSeverity, DiagnosticStage,
    DiffSummaryViewModel, DisassemblyPreview, EdgeKind, LabSummary, ObjectGraphQuery, ObjectKind,
    ObjectRef, ObjectSearch, ObjectSummary, RelationDirection, ReportTemplate, StableObjectKey,
    TraversalOptions,
};
use revdeck_db::{
    migrations, AnalysisJobRepository, CrashFrameRecord, CrashImportOutcome, CrashReportRecord,
    CrashRepository, FindingRepository, FirmwareFileRecord, FirmwareImportOutcome,
    FirmwareRepository, ObjectQueryRepository, ObjectRepository, ProjectDatabase,
    ProjectMetadataRepository, ProtocolFieldRecord, ProtocolImportOutcome, ProtocolMessageRecord,
    ProtocolRepository, ProtocolSampleRecord, RadarRepository, TraceEventRecord,
    TraceImportOutcome, TraceRepository, TraceSessionRecord,
};
use revdeck_index::{
    fail_registered_binary_analysis, finish_registered_binary_analysis, import_binary,
    register_binary_for_analysis, AnalysisProfile, BinaryRegistration, ImportOptions,
    ImportOutcome,
};
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
};
use time::OffsetDateTime;

#[derive(Debug, Parser)]
#[command(name = "revdeck")]
#[command(about = "Terminal-native reverse engineering workspace")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Analyze {
        /// Binary to register, analyze, and open in the TUI.
        binary_path: PathBuf,
        /// Project directory. Defaults to .revdeck/workspaces/<binary>-<hash>.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Analysis profile: quick opens fastest, balanced is default, deep is reserved for heavier analysis.
        #[arg(long, value_enum, default_value_t = CliAnalysisProfile::Balanced)]
        profile: CliAnalysisProfile,
        /// Run analysis in the foreground and print the final JSON outcome instead of opening the TUI.
        #[arg(long)]
        no_tui: bool,
    },
    Init {
        project_dir: PathBuf,
    },
    Open {
        project_dir: PathBuf,
    },
    Import {
        project_dir: PathBuf,
        binary_path: PathBuf,
        #[arg(long, value_enum, default_value_t = CliAnalysisProfile::Balanced)]
        profile: CliAnalysisProfile,
    },
    Jobs {
        project_dir: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Search {
        project_dir: PathBuf,
        query: String,
        /// Restrict results to one object kind, such as function, string, import, section, or finding.
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Inspect {
        project_dir: PathBuf,
        object_ref: String,
        #[arg(long, default_value_t = 20)]
        relations: usize,
        #[arg(long)]
        json: bool,
    },
    Xrefs {
        project_dir: PathBuf,
        object_ref: String,
        #[arg(long, value_enum, default_value_t = CliRelationDirection::Both)]
        direction: CliRelationDirection,
        #[arg(long)]
        edge_kind: Option<String>,
        #[arg(long, default_value_t = 1)]
        depth: usize,
        #[arg(long, default_value_t = 64)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Disasm {
        project_dir: PathBuf,
        function_ref: String,
        #[arg(long, default_value_t = 64)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Sections {
        project_dir: PathBuf,
        #[arg(long)]
        artifact: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Imports {
        project_dir: PathBuf,
        #[arg(long)]
        module: Option<String>,
        #[arg(long)]
        artifact: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Strings {
        project_dir: PathBuf,
        #[arg(long)]
        contains: Option<String>,
        #[arg(long, default_value_t = 4)]
        min_len: u64,
        #[arg(long)]
        artifact: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Labs {
        #[arg(long)]
        json: bool,
    },
    Index {
        project_dir: PathBuf,
        artifact_id: Option<String>,
    },
    Stats {
        project_dir: PathBuf,
    },
    Report {
        project_dir: PathBuf,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
        #[arg(long, value_enum, default_value_t = CliReportTemplate::Full)]
        template: CliReportTemplate,
        #[arg(long)]
        min_lab_coverage: Option<usize>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Diff {
        project_dir: PathBuf,
        before_artifact: String,
        after_artifact: String,
        #[arg(long)]
        json: bool,
    },
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    Firmware {
        #[command(subcommand)]
        command: FirmwareCommand,
    },
    Crash {
        #[command(subcommand)]
        command: CrashCommand,
    },
    Protocol {
        #[command(subcommand)]
        command: ProtocolCommand,
    },
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    Tui {
        project_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    Import {
        project_dir: PathBuf,
        trace_path: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        json: bool,
    },
    Status {
        project_dir: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum FirmwareCommand {
    Import {
        project_dir: PathBuf,
        firmware_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Status {
        project_dir: PathBuf,
        firmware_artifact: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CrashCommand {
    Import {
        project_dir: PathBuf,
        crash_path: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        json: bool,
    },
    Status {
        project_dir: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProtocolCommand {
    Import {
        project_dir: PathBuf,
        sample_path: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        json: bool,
    },
    Status {
        project_dir: PathBuf,
        #[arg(long)]
        artifact: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    Scaffold {
        plugin_dir: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        force: bool,
    },
    Validate {
        manifest_path: PathBuf,
    },
    Inspect {
        manifest_path: PathBuf,
    },
    Test {
        plugin_dir: PathBuf,
    },
    Commit {
        project_dir: PathBuf,
        plugin_dir: PathBuf,
    },
    Run {
        project_dir: PathBuf,
        plugin_dir: PathBuf,
        #[arg(long)]
        commit: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    Metadata {
        #[command(subcommand)]
        command: CaseMetadataCommand,
    },
    Note {
        #[command(subcommand)]
        command: CaseNoteCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CaseMetadataCommand {
    Set {
        project_dir: PathBuf,
        key: String,
        value: String,
    },
    Get {
        project_dir: PathBuf,
        key: String,
    },
    List {
        project_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CaseNoteCommand {
    Add {
        project_dir: PathBuf,
        title: String,
        body: String,
        #[arg(long, default_value = "note")]
        category: String,
    },
    List {
        project_dir: PathBuf,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    Export {
        project_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Md,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliReportTemplate {
    Summary,
    Full,
    Ci,
}

impl From<CliReportTemplate> for ReportTemplate {
    fn from(value: CliReportTemplate) -> Self {
        match value {
            CliReportTemplate::Summary => Self::Summary,
            CliReportTemplate::Full => Self::Full,
            CliReportTemplate::Ci => Self::Ci,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliAnalysisProfile {
    Quick,
    Balanced,
    Deep,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliRelationDirection {
    Incoming,
    Outgoing,
    Both,
}

impl From<CliRelationDirection> for RelationDirection {
    fn from(value: CliRelationDirection) -> Self {
        match value {
            CliRelationDirection::Incoming => Self::Incoming,
            CliRelationDirection::Outgoing => Self::Outgoing,
            CliRelationDirection::Both => Self::Both,
        }
    }
}

impl From<CliAnalysisProfile> for AnalysisProfile {
    fn from(value: CliAnalysisProfile) -> Self {
        match value {
            CliAnalysisProfile::Quick => Self::Quick,
            CliAnalysisProfile::Balanced => Self::Balanced,
            CliAnalysisProfile::Deep => Self::Deep,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            binary_path,
            project,
            profile,
            no_tui,
        } => {
            let project_dir = project.unwrap_or_else(|| default_analysis_project_dir(&binary_path));
            let project = ProjectDatabase::create_or_open(&project_dir).with_context(|| {
                format!("failed to initialize project at {}", project_dir.display())
            })?;
            let profile = AnalysisProfile::from(profile);
            if !no_tui {
                let registration = register_binary_for_analysis(
                    project.connection(),
                    ImportOptions::with_profile(project_dir.clone(), binary_path.clone(), profile),
                )
                .map_err(|err| anyhow::anyhow!(err.structured_message()))?;
                println!(
                    "{}",
                    registration_json(&registration, Some(&project), "background-running")
                );
                drop(project);
                spawn_registered_analysis_worker(project_dir.clone(), registration)
                    .context("failed to start background analysis worker")?;
                revdeck_tui::run_project_tui(project_dir)?;
                return Ok(());
            }
            let outcome = import_binary(
                project.connection(),
                ImportOptions::with_profile(project_dir.clone(), binary_path.clone(), profile),
            )
            .map_err(|err| anyhow::anyhow!(err.structured_message()))?;
            println!("{}", outcome_json(&outcome, Some(&project)));
            if outcome.status == revdeck_core::AnalysisRunStatus::Failed {
                anyhow::bail!(
                    "{}",
                    serde_json::json!({
                        "status": "failed",
                        "profile": outcome.profile.as_str(),
                        "artifact": outcome.artifact_ref.to_string(),
                        "analysis_run": outcome.run_id,
                        "diagnostics": outcome.summary.diagnostics,
                    })
                );
            }
            drop(project);
            if !no_tui {
                revdeck_tui::run_project_tui(project_dir)?;
            }
        }
        Command::Init { project_dir } => {
            let project = ProjectDatabase::create_or_open(&project_dir).with_context(|| {
                format!("failed to initialize project at {}", project_dir.display())
            })?;
            println!("initialized {}", project.info().db_path.display());
        }
        Command::Open { project_dir } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            println!("opened {}", project.info().db_path.display());
        }
        Command::Tui { project_dir } => {
            revdeck_tui::run_project_tui(project_dir)?;
        }
        Command::Import {
            project_dir,
            binary_path,
            profile,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let outcome = import_binary(
                project.connection(),
                ImportOptions::with_profile(project_dir, binary_path, profile.into()),
            )
            .map_err(|err| anyhow::anyhow!(err.structured_message()))?;
            if outcome.status == revdeck_core::AnalysisRunStatus::Failed {
                anyhow::bail!(
                    "{}",
                    serde_json::json!({
                        "status": "failed",
                        "profile": outcome.profile.as_str(),
                        "artifact": outcome.artifact_ref.to_string(),
                        "analysis_run": outcome.run_id,
                        "diagnostics": outcome.summary.diagnostics,
                    })
                );
            }
            println!("{}", outcome_json(&outcome, None));
        }
        Command::Jobs { project_dir, limit } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let jobs = AnalysisJobRepository::new(project.connection()).list_recent(limit)?;
            println!("{}", jobs_json(&jobs));
        }
        Command::Search {
            project_dir,
            query,
            kind,
            limit,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let kind = parse_object_kind_arg(kind.as_deref())?;
            let matches = ObjectQueryRepository::new(project.connection())
                .search_objects(&ObjectSearch::new(kind, query.clone()).with_limit(limit))
                .with_context(|| format!("failed to search project for `{query}`"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&search_results_json(&query, kind, &matches))?
                );
            } else {
                print_search_results(&query, kind, &matches);
            }
        }
        Command::Inspect {
            project_dir,
            object_ref,
            relations,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let object_ref = object_ref
                .parse::<ObjectRef>()
                .with_context(|| format!("invalid object ref `{object_ref}`"))?;
            let query = ObjectQueryRepository::new(project.connection());
            let object = query
                .get_object(&object_ref)
                .with_context(|| format!("failed to inspect `{object_ref}`"))?
                .ok_or_else(|| anyhow::anyhow!("object `{object_ref}` does not exist"))?;
            let object_relations = query
                .relations(&object_ref, revdeck_core::RelationDirection::Both, None)
                .with_context(|| format!("failed to load relations for `{object_ref}`"))?;
            let object_relations = object_relations
                .into_iter()
                .take(relations)
                .collect::<Vec<_>>();
            let function_packet = function_evidence_packet(&project, &object)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&inspect_result_json(
                        &object,
                        &object_relations,
                        function_packet.as_ref()
                    ))?
                );
            } else {
                print_inspect_result(&object, &object_relations);
                if let Some(packet) = &function_packet {
                    print_function_packet(packet);
                }
            }
        }
        Command::Xrefs {
            project_dir,
            object_ref,
            direction,
            edge_kind,
            depth,
            limit,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let object_ref = object_ref
                .parse::<ObjectRef>()
                .with_context(|| format!("invalid object ref `{object_ref}`"))?;
            let query = ObjectQueryRepository::new(project.connection());
            ensure_object_exists(&query, &object_ref)?;
            let edge_kind = parse_edge_kind_arg(edge_kind.as_deref())?;
            if depth > 1 {
                let mut options = TraversalOptions::new(object_ref.clone())
                    .with_direction(direction.into())
                    .with_max_depth(depth)
                    .with_max_nodes(limit);
                if let Some(edge_kind) = edge_kind {
                    options = options.with_edge_kind(edge_kind);
                }
                let traversal = query
                    .local_traversal(&options)
                    .with_context(|| format!("failed to traverse xrefs for `{object_ref}`"))?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&traversal_json(&traversal))?
                    );
                } else {
                    print_traversal(&traversal);
                }
            } else {
                let relations = query
                    .relations(&object_ref, direction.into(), edge_kind)
                    .with_context(|| format!("failed to load xrefs for `{object_ref}`"))?
                    .into_iter()
                    .take(limit)
                    .collect::<Vec<_>>();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&xrefs_json(&object_ref, &relations))?
                    );
                } else {
                    print_xrefs(&object_ref, &relations);
                }
            }
        }
        Command::Disasm {
            project_dir,
            function_ref,
            limit,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let function_ref = function_ref
                .parse::<ObjectRef>()
                .with_context(|| format!("invalid function ref `{function_ref}`"))?;
            if function_ref.kind != ObjectKind::Function {
                anyhow::bail!("expected function ref, got {function_ref}");
            }
            let query = ObjectQueryRepository::new(project.connection());
            let preview = query
                .disassembly_preview(&function_ref, limit)
                .with_context(|| format!("failed to load disassembly for `{function_ref}`"))?
                .ok_or_else(|| anyhow::anyhow!("function `{function_ref}` does not exist"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&disasm_json(&preview, limit))?
                );
            } else {
                print_disasm(&preview, limit);
            }
        }
        Command::Sections {
            project_dir,
            artifact,
            limit,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let artifact = parse_optional_artifact_ref(artifact.as_deref())?;
            let sections = list_sections(project.connection(), artifact.as_ref(), limit)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&sections_json(&sections))?
                );
            } else {
                print_sections(&sections);
            }
        }
        Command::Imports {
            project_dir,
            module,
            artifact,
            limit,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let artifact = parse_optional_artifact_ref(artifact.as_deref())?;
            let imports = list_imports(
                project.connection(),
                artifact.as_ref(),
                module.as_deref(),
                limit,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&imports_json(&imports))?);
            } else {
                print_imports(&imports);
            }
        }
        Command::Strings {
            project_dir,
            contains,
            min_len,
            artifact,
            limit,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let artifact = parse_optional_artifact_ref(artifact.as_deref())?;
            let strings = list_strings(
                project.connection(),
                artifact.as_ref(),
                contains.as_deref(),
                min_len,
                limit,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&strings_json(&strings))?);
            } else {
                print_strings(&strings);
            }
        }
        Command::Labs { json } => {
            let labs = LabSummary::all();
            if json {
                println!("{}", serde_json::to_string_pretty(&labs_json(&labs))?);
            } else {
                for lab in labs {
                    let shortcut = lab
                        .shortcut
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<16} {:<22} maturity={:<7} lens={:<15} shortcut={} {}",
                        lab.id,
                        lab.label,
                        lab.maturity.as_str(),
                        lab.default_lens_label,
                        shortcut,
                        lab.purpose
                    );
                }
            }
        }
        Command::Index {
            project_dir,
            artifact_id,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            println!(
                "index skeleton for {} in {}; binary indexing is implemented in a later task",
                artifact_id.as_deref().unwrap_or("all artifacts"),
                project.info().db_path.display()
            );
        }
        Command::Stats { project_dir } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let version = migrations::current_version(project.connection())?;
            let artifacts = count(project.connection(), "artifacts")?;
            let runs = count(project.connection(), "analysis_runs")?;
            let objects = count(project.connection(), "objects")?;
            let edges = count(project.connection(), "edges")?;
            let instructions = count(project.connection(), "instructions")?;
            let basic_blocks = count(project.connection(), "basic_blocks")?;
            let cfg_edges = count(project.connection(), "cfg_edges")?;
            println!(
                "schema_version={version} artifacts={artifacts} analysis_runs={runs} objects={objects} edges={edges} instructions={instructions} basic_blocks={basic_blocks} cfg_edges={cfg_edges}"
            );
        }
        Command::Report {
            project_dir,
            format,
            template,
            min_lab_coverage,
            out,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let context = FindingRepository::new(project.connection())
                .export_context(OffsetDateTime::now_utc())
                .context("failed to load findings for report")?;
            let template = ReportTemplate::from(template);
            let gate = export_gate_summary(&context, template, min_lab_coverage);
            let rendered = match format {
                ReportFormat::Md => {
                    pre_export_validation(&context).map_err(|err| {
                        anyhow::anyhow!(
                            "{}",
                            serde_json::to_string_pretty(&err.report)
                                .unwrap_or_else(|_| err.to_string())
                        )
                    })?;
                    render_markdown(&context)
                }
                ReportFormat::Json => render_template_json(&context, template, min_lab_coverage)
                    .context("failed to render JSON report")?,
            };
            if let Some(path) = out {
                fs::write(&path, rendered)
                    .with_context(|| format!("failed to write report to {}", path.display()))?;
                println!(
                    "wrote report {} gate={} labs={} validation_errors={} validation_warnings={}",
                    path.display(),
                    gate.passed,
                    gate.lab_coverage,
                    gate.validation_errors,
                    gate.validation_warnings
                );
            } else {
                println!("{rendered}");
            }
            if template == ReportTemplate::Ci && !gate.passed {
                anyhow::bail!(
                    "report gate failed: labs={} min_lab_coverage={:?} validation_errors={}",
                    gate.lab_coverage,
                    gate.min_lab_coverage,
                    gate.validation_errors
                );
            }
        }
        Command::Diff {
            project_dir,
            before_artifact,
            after_artifact,
            json,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let before_ref = parse_artifact_ref(&before_artifact)?;
            let after_ref = parse_artifact_ref(&after_artifact)?;
            let query = ObjectQueryRepository::new(project.connection());
            let before = query
                .diff_artifact_snapshot(&before_ref)
                .with_context(|| format!("failed to load before artifact {before_ref}"))?;
            let after = query
                .diff_artifact_snapshot(&after_ref)
                .with_context(|| format!("failed to load after artifact {after_ref}"))?;
            let summary = DiffSummaryViewModel::compare(&before, &after);
            ObjectRepository::new(project.connection())
                .upsert_diff_rows(&after_ref, &summary)
                .context("failed to persist diff deltas")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&diff_json(&summary))?);
            } else {
                println!(
                    "Diff Lab before={} after={} added={} removed={} changed={} unchanged={} deltas={}",
                    summary.before_label,
                    summary.after_label,
                    summary.added,
                    summary.removed,
                    summary.changed,
                    summary.unchanged,
                    summary.total_deltas()
                );
                for row in &summary.rows {
                    println!(
                        "{:<8} {:<8} {}",
                        row.change.as_str(),
                        row.entity_kind.as_str(),
                        row.title
                    );
                }
            }
        }
        Command::Trace { command } => match command {
            TraceCommand::Import {
                project_dir,
                trace_path,
                artifact,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let artifact_ref = parse_artifact_ref(&artifact)?;
                let jsonl = fs::read_to_string(&trace_path)
                    .with_context(|| format!("failed to read trace {}", trace_path.display()))?;
                let outcome = TraceRepository::new(project.connection())
                    .import_jsonl(
                        &artifact_ref,
                        &trace_path.display().to_string(),
                        &jsonl,
                        OffsetDateTime::now_utc(),
                    )
                    .context("failed to import JSONL trace")?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&trace_import_json(&outcome))?
                    );
                } else {
                    println!(
                        "Trace Lab session={} events={} correlated={} malformed={} job={}",
                        outcome.session,
                        outcome.events_imported,
                        outcome.correlated_events,
                        outcome.malformed_lines,
                        outcome.analysis_job_id
                    );
                    if !outcome.threads.is_empty() {
                        println!("threads={}", outcome.threads.join(","));
                    }
                    for diagnostic in &outcome.diagnostics {
                        println!("diagnostic: {diagnostic}");
                    }
                }
            }
            TraceCommand::Status {
                project_dir,
                artifact,
                limit,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let artifact_ref = parse_artifact_ref(&artifact)?;
                let trace_repo = TraceRepository::new(project.connection());
                let sessions = trace_repo
                    .list_sessions_for_artifact(&artifact_ref, limit)
                    .context("failed to list trace sessions")?;
                let sessions_with_events = sessions
                    .into_iter()
                    .map(|session| {
                        let events = trace_repo
                            .list_events_for_session(&session.object_ref, 50)
                            .context("failed to list trace events")?;
                        Ok((session, events))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&trace_status_json(&sessions_with_events))?
                    );
                } else if sessions_with_events.is_empty() {
                    println!("Trace Lab sessions=0");
                } else {
                    println!("Trace Lab sessions={}", sessions_with_events.len());
                    for (session, events) in &sessions_with_events {
                        let quality = trace_quality(events);
                        println!(
                            "{:<24} events={:<5} correlated={:<4} uncorrelated={:<4} threads={:<3} source={}",
                            session.session_id,
                            session.event_count,
                            quality.correlated,
                            quality.uncorrelated,
                            session.thread_count,
                            session.source_path
                        );
                    }
                }
            }
        },
        Command::Firmware { command } => match command {
            FirmwareCommand::Import {
                project_dir,
                firmware_dir,
                json,
            } => {
                let project = ProjectDatabase::create_or_open(&project_dir).with_context(|| {
                    format!("failed to initialize project at {}", project_dir.display())
                })?;
                let outcome = FirmwareRepository::new(project.connection())
                    .import_directory(&firmware_dir, OffsetDateTime::now_utc())
                    .with_context(|| {
                        format!(
                            "failed to import firmware directory {}",
                            firmware_dir.display()
                        )
                    })?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&firmware_import_json(&outcome))?
                    );
                } else {
                    println!(
                        "Firmware Lab firmware={} files={} binaries={} unsupported={} bytes={} job={}",
                        outcome.firmware,
                        outcome.files_imported,
                        outcome.binaries_detected,
                        outcome.unsupported_files,
                        outcome.total_bytes,
                        outcome.analysis_job_id
                    );
                }
            }
            FirmwareCommand::Status {
                project_dir,
                firmware_artifact,
                limit,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let firmware = parse_artifact_ref(&firmware_artifact)?;
                let files = FirmwareRepository::new(project.connection())
                    .list_files_for_artifact(&firmware, limit)
                    .context("failed to list firmware files")?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&firmware_status_json(&firmware, &files))?
                    );
                } else if files.is_empty() {
                    println!("Firmware Lab files=0");
                } else {
                    println!("Firmware Lab files={}", files.len());
                    for file in &files {
                        let nested = file
                            .nested_artifact
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "-".to_string());
                        println!(
                            "{:<32} type={:<8} size={:<8} exec={} nested={}",
                            file.path, file.file_type, file.size, file.executable, nested
                        );
                    }
                }
            }
        },
        Command::Crash { command } => match command {
            CrashCommand::Import {
                project_dir,
                crash_path,
                artifact,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let artifact_ref = parse_artifact_ref(&artifact)?;
                let log = fs::read_to_string(&crash_path).with_context(|| {
                    format!("failed to read crash log {}", crash_path.display())
                })?;
                let outcome = CrashRepository::new(project.connection())
                    .import_log(
                        &artifact_ref,
                        &crash_path.display().to_string(),
                        &log,
                        OffsetDateTime::now_utc(),
                    )
                    .context("failed to import crash log")?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&crash_import_json(&outcome))?
                    );
                } else {
                    println!(
                        "Crash Lab report={} frames={} correlated={} clustered={} findings={} job={}",
                        outcome.report,
                        outcome.frames_imported,
                        outcome.correlated_frames,
                        outcome.clustered_reports,
                        outcome.findings_created,
                        outcome.analysis_job_id
                    );
                    println!("signature={}", outcome.signature);
                    for diagnostic in &outcome.diagnostics {
                        println!("diagnostic: {diagnostic}");
                    }
                }
            }
            CrashCommand::Status {
                project_dir,
                artifact,
                limit,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let artifact_ref = parse_artifact_ref(&artifact)?;
                let crash_repo = CrashRepository::new(project.connection());
                let reports = crash_repo
                    .list_reports_for_artifact(&artifact_ref, limit)
                    .context("failed to list crash reports")?;
                let reports_with_frames = reports
                    .into_iter()
                    .map(|report| {
                        let frames = crash_repo
                            .list_frames_for_report(&report.object_ref, 5)
                            .context("failed to list crash frames")?;
                        Ok((report, frames))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&crash_status_json(&reports_with_frames))?
                    );
                } else if reports_with_frames.is_empty() {
                    println!("Crash Lab reports=0");
                } else {
                    println!("Crash Lab reports={}", reports_with_frames.len());
                    for (report, frames) in &reports_with_frames {
                        let signal = report.signal.as_deref().unwrap_or("-");
                        let top = frames
                            .first()
                            .and_then(|frame| frame.function_name.as_deref())
                            .unwrap_or("-");
                        println!(
                            "{:<24} class={:<24} signal={:<8} frames={:<4} correlated={:<4} top={} signature={}",
                            report.crash_id,
                            report.crash_class,
                            signal,
                            report.frame_count,
                            report.correlated_frame_count,
                            top,
                            report.signature
                        );
                    }
                }
            }
        },
        Command::Protocol { command } => match command {
            ProtocolCommand::Import {
                project_dir,
                sample_path,
                artifact,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let artifact_ref = parse_artifact_ref(&artifact)?;
                let sample_json = fs::read_to_string(&sample_path).with_context(|| {
                    format!("failed to read protocol sample {}", sample_path.display())
                })?;
                let outcome = ProtocolRepository::new(project.connection())
                    .import_sample(
                        &artifact_ref,
                        &sample_path.display().to_string(),
                        &sample_json,
                        OffsetDateTime::now_utc(),
                    )
                    .context("failed to import protocol sample")?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&protocol_import_json(&outcome))?
                    );
                } else {
                    println!(
                        "Protocol Lab sample={} messages={} fields={} correlated={} job={}",
                        outcome.sample,
                        outcome.messages_imported,
                        outcome.fields_imported,
                        outcome.correlated_fields,
                        outcome.analysis_job_id
                    );
                    if let Some(schema_hypothesis) = &outcome.schema_hypothesis {
                        println!("schema_hypothesis={schema_hypothesis}");
                    }
                    for diagnostic in &outcome.diagnostics {
                        println!("diagnostic: {diagnostic}");
                    }
                }
            }
            ProtocolCommand::Status {
                project_dir,
                artifact,
                limit,
                json,
            } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let artifact_ref = parse_artifact_ref(&artifact)?;
                let protocol_repo = ProtocolRepository::new(project.connection());
                let samples = protocol_repo
                    .list_samples_for_artifact(&artifact_ref, limit)
                    .context("failed to list protocol samples")?;
                let samples_with_messages = samples
                    .into_iter()
                    .map(|sample| {
                        let messages = protocol_repo
                            .list_messages_for_sample(&sample.object_ref, 20)
                            .context("failed to list protocol messages")?;
                        let messages_with_fields = messages
                            .into_iter()
                            .map(|message| {
                                let fields = protocol_repo
                                    .list_fields_for_message(&message.object_ref, 20)
                                    .context("failed to list protocol fields")?;
                                Ok((message, fields))
                            })
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        Ok((sample, messages_with_fields))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&protocol_status_json(
                            &samples_with_messages
                        ))?
                    );
                } else if samples_with_messages.is_empty() {
                    println!("Protocol Lab samples=0");
                } else {
                    println!("Protocol Lab samples={}", samples_with_messages.len());
                    for (sample, messages) in &samples_with_messages {
                        let schema = sample.schema_hypothesis.as_deref().unwrap_or("-");
                        println!(
                            "{:<24} messages={:<4} fields={:<4} schema={} source={}",
                            sample.sample_id,
                            sample.message_count,
                            sample.field_count,
                            schema,
                            sample.source_path
                        );
                        for (message, fields) in messages.iter().take(3) {
                            println!(
                                "  {:<18} dir={:<8} payload={} fields={}",
                                message.message_id,
                                message.direction,
                                message.payload_len,
                                fields.len()
                            );
                            for field in fields.iter().take(4) {
                                let hint = field.string_hint.as_deref().unwrap_or("-");
                                println!(
                                    "    {:<18} off={:<4} len={:<4} type={:<10} entropy={:.2} hint={}",
                                    field.name,
                                    field.byte_offset,
                                    field.byte_length,
                                    field.field_type,
                                    field.entropy,
                                    hint
                                );
                            }
                        }
                    }
                }
            }
        },
        Command::Plugin { command } => match command {
            PluginCommand::Scaffold {
                plugin_dir,
                id,
                force,
            } => {
                let output =
                    revdeck_plugin_host::scaffold_plugin_directory(&plugin_dir, &id, force)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if !output.validation.is_valid() {
                    anyhow::bail!("plugin scaffold validation failed");
                }
            }
            PluginCommand::Validate { manifest_path } => {
                let output = revdeck_plugin_host::validate_manifest_file(&manifest_path)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if !output.validation.is_valid() {
                    anyhow::bail!("plugin manifest validation failed");
                }
            }
            PluginCommand::Inspect { manifest_path } => {
                let output = revdeck_plugin_host::inspect_manifest_file(&manifest_path)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if !output.validation.is_valid() {
                    anyhow::bail!("plugin manifest validation failed");
                }
            }
            PluginCommand::Test { plugin_dir } => {
                let output = revdeck_plugin_host::test_plugin_directory(&plugin_dir)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if !output.validation.is_valid() {
                    anyhow::bail!("plugin test failed");
                }
            }
            PluginCommand::Commit {
                project_dir,
                plugin_dir,
            } => {
                let project = ProjectDatabase::create_or_open(&project_dir).with_context(|| {
                    format!("failed to initialize project at {}", project_dir.display())
                })?;
                let output = revdeck_plugin_host::commit_plugin_directory(&project, &plugin_dir)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if output.status != "succeeded" {
                    anyhow::bail!("plugin commit failed");
                }
            }
            PluginCommand::Run {
                project_dir,
                plugin_dir,
                commit,
            } => {
                let project = ProjectDatabase::create_or_open(&project_dir).with_context(|| {
                    format!("failed to initialize project at {}", project_dir.display())
                })?;
                let output =
                    revdeck_plugin_host::run_plugin_directory(&project, &plugin_dir, commit)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if output.status != "succeeded" {
                    anyhow::bail!("plugin run failed");
                }
            }
        },
        Command::Case { command } => {
            match command {
                CaseCommand::Metadata { command } => match command {
                    CaseMetadataCommand::Set {
                        project_dir,
                        key,
                        value,
                    } => {
                        let project =
                            ProjectDatabase::open_existing(&project_dir).with_context(|| {
                                format!("failed to open project at {}", project_dir.display())
                            })?;
                        ProjectMetadataRepository::new(project.connection()).set_metadata(
                            &key,
                            &value,
                            OffsetDateTime::now_utc(),
                        )?;
                        println!("metadata {key}={value}");
                    }
                    CaseMetadataCommand::Get { project_dir, key } => {
                        let project =
                            ProjectDatabase::open_existing(&project_dir).with_context(|| {
                                format!("failed to open project at {}", project_dir.display())
                            })?;
                        let Some(record) = ProjectMetadataRepository::new(project.connection())
                            .get_metadata(&key)?
                        else {
                            anyhow::bail!("metadata key `{key}` does not exist");
                        };
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&case_metadata_json(&[record]))?
                        );
                    }
                    CaseMetadataCommand::List { project_dir, json } => {
                        let project =
                            ProjectDatabase::open_existing(&project_dir).with_context(|| {
                                format!("failed to open project at {}", project_dir.display())
                            })?;
                        let records = ProjectMetadataRepository::new(project.connection())
                            .list_metadata()
                            .context("failed to list case metadata")?;
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&case_metadata_json(&records))?
                            );
                        } else if records.is_empty() {
                            println!("Case metadata entries=0");
                        } else {
                            println!("Case metadata entries={}", records.len());
                            for record in &records {
                                println!(
                                    "{}={} updated={}",
                                    record.key, record.value, record.updated_at
                                );
                            }
                        }
                    }
                },
                CaseCommand::Note { command } => {
                    match command {
                        CaseNoteCommand::Add {
                            project_dir,
                            title,
                            body,
                            category,
                        } => {
                            let project = ProjectDatabase::open_existing(&project_dir)
                                .with_context(|| {
                                    format!("failed to open project at {}", project_dir.display())
                                })?;
                            let note = ProjectMetadataRepository::new(project.connection())
                                .add_note(&category, &title, &body, OffsetDateTime::now_utc())?;
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&case_notes_json(&[note]))?
                            );
                        }
                        CaseNoteCommand::List {
                            project_dir,
                            limit,
                            json,
                        } => {
                            let project = ProjectDatabase::open_existing(&project_dir)
                                .with_context(|| {
                                    format!("failed to open project at {}", project_dir.display())
                                })?;
                            let notes = ProjectMetadataRepository::new(project.connection())
                                .list_notes(limit)
                                .context("failed to list case notes")?;
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&case_notes_json(&notes))?
                                );
                            } else if notes.is_empty() {
                                println!("Case notes=0");
                            } else {
                                println!("Case notes={}", notes.len());
                                for note in &notes {
                                    println!(
                                        "#{} [{}] {} updated={}",
                                        note.note_id, note.category, note.title, note.updated_at
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Command::Bundle { command } => match command {
            BundleCommand::Export { project_dir, out } => {
                let project = ProjectDatabase::open_existing(&project_dir).with_context(|| {
                    format!("failed to open project at {}", project_dir.display())
                })?;
                let manifest = export_project_bundle(&project, &out)?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            }
        },
    }
    Ok(())
}

fn count(connection: &rusqlite::Connection, table: &str) -> anyhow::Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    Ok(connection.query_row(&sql, [], |row| row.get(0))?)
}

fn export_project_bundle(
    project: &ProjectDatabase,
    out: &Path,
) -> anyhow::Result<serde_json::Value> {
    fs::create_dir_all(out)
        .with_context(|| format!("failed to create bundle directory {}", out.display()))?;
    let manifest_path = out.join("revdeck-bundle-manifest.json");
    let db_path = out.join("project.sqlite");
    let report_path = out.join("report.json");

    fs::copy(&project.info().db_path, &db_path).with_context(|| {
        format!(
            "failed to copy project database {} to {}",
            project.info().db_path.display(),
            db_path.display()
        )
    })?;
    let context = FindingRepository::new(project.connection())
        .export_context(OffsetDateTime::now_utc())
        .context("failed to load report context for bundle")?;
    fs::write(
        &report_path,
        render_template_json(&context, ReportTemplate::Full, None)
            .context("failed to render bundle report")?,
    )
    .with_context(|| format!("failed to write report {}", report_path.display()))?;

    let manifest = serde_json::json!({
        "schema": "revdeck.bundle.v1",
        "created_at": OffsetDateTime::now_utc().to_string(),
        "schema_version": migrations::current_version(project.connection())?,
        "source": {
            "project_dir": project.info().root_dir.display().to_string(),
            "database": project.info().db_path.display().to_string()
        },
        "artifacts": bundle_artifact_identity(project.connection())?,
        "analysis_profiles": bundle_analysis_profiles(project.connection())?,
        "plugin_runs": context.plugin_runs.iter().map(|run| {
            serde_json::json!({
                "id": run.id,
                "plugin_id": &run.plugin_id,
                "plugin_version": &run.plugin_version,
                "manifest_digest": &run.manifest_digest,
                "status": &run.status
            })
        }).collect::<Vec<_>>(),
        "files": [
            {
                "role": "project_database",
                "path": "project.sqlite"
            },
            {
                "role": "report",
                "path": "report.json"
            }
        ],
        "exclusions": [
            ".revdeck workspace caches other than project.sqlite",
            "target build outputs",
            "external source binaries not stored in the project database"
        ]
    });
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("failed to write manifest {}", manifest_path.display()))?;
    Ok(manifest)
}

fn bundle_artifact_identity(
    connection: &rusqlite::Connection,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut statement = connection.prepare(
        "SELECT object_key, display_name, source_path, sha256, size, kind, format,
            architecture, import_status
        FROM artifacts
        ORDER BY object_key",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(serde_json::json!({
            "artifact": row.get::<_, String>(0)?,
            "display_name": row.get::<_, String>(1)?,
            "source_path": row.get::<_, String>(2)?,
            "sha256": row.get::<_, String>(3)?,
            "size": row.get::<_, i64>(4)?,
            "kind": row.get::<_, String>(5)?,
            "format": row.get::<_, String>(6)?,
            "architecture": row.get::<_, String>(7)?,
            "import_status": row.get::<_, String>(8)?
        }))
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn bundle_analysis_profiles(
    connection: &rusqlite::Connection,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut statement = connection.prepare(
        "SELECT pass_name, profile, status, COUNT(*)
        FROM analysis_jobs
        GROUP BY pass_name, profile, status
        ORDER BY pass_name, profile, status",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(serde_json::json!({
            "pass_name": row.get::<_, String>(0)?,
            "profile": row.get::<_, String>(1)?,
            "status": row.get::<_, String>(2)?,
            "count": row.get::<_, i64>(3)?
        }))
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn case_metadata_json(records: &[revdeck_db::ProjectMetadataRecord]) -> serde_json::Value {
    serde_json::json!({
        "metadata": records.iter().map(|record| {
            serde_json::json!({
                "key": &record.key,
                "value": &record.value,
                "updated_at": record.updated_at.to_string()
            })
        }).collect::<Vec<_>>()
    })
}

fn case_notes_json(records: &[revdeck_db::ProjectNoteRecord]) -> serde_json::Value {
    serde_json::json!({
        "notes": records.iter().map(|record| {
            serde_json::json!({
                "note_id": record.note_id,
                "category": &record.category,
                "title": &record.title,
                "body": &record.body,
                "created_at": record.created_at.to_string(),
                "updated_at": record.updated_at.to_string()
            })
        }).collect::<Vec<_>>()
    })
}

fn parse_object_kind_arg(value: Option<&str>) -> anyhow::Result<Option<ObjectKind>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    normalized
        .parse::<ObjectKind>()
        .map(Some)
        .with_context(|| format!("unknown object kind `{value}`"))
}

fn parse_edge_kind_arg(value: Option<&str>) -> anyhow::Result<Option<EdgeKind>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    normalized
        .parse::<EdgeKind>()
        .map(Some)
        .with_context(|| format!("unknown edge kind `{value}`"))
}

fn parse_optional_artifact_ref(value: Option<&str>) -> anyhow::Result<Option<ObjectRef>> {
    value.map(parse_artifact_ref).transpose()
}

fn parse_artifact_ref(value: &str) -> anyhow::Result<ObjectRef> {
    let artifact_ref = if value.contains(':') {
        value
            .parse::<ObjectRef>()
            .with_context(|| format!("invalid artifact ref `{value}`"))?
    } else {
        ObjectRef::new(
            ObjectKind::Artifact,
            value
                .parse::<StableObjectKey>()
                .with_context(|| format!("invalid artifact key `{value}`"))?,
        )
    };
    if artifact_ref.kind != ObjectKind::Artifact {
        anyhow::bail!("expected artifact ref, got {artifact_ref}");
    }
    Ok(artifact_ref)
}

fn ensure_object_exists(
    query: &ObjectQueryRepository<'_>,
    object_ref: &ObjectRef,
) -> anyhow::Result<()> {
    if query
        .get_object(object_ref)
        .with_context(|| format!("failed to load `{object_ref}`"))?
        .is_some()
    {
        Ok(())
    } else {
        anyhow::bail!("object `{object_ref}` does not exist")
    }
}

#[derive(Debug, Clone)]
struct SectionListingRow {
    object_ref: ObjectRef,
    artifact_key: Option<String>,
    name: String,
    virtual_address: Option<u64>,
    file_offset: Option<u64>,
    size: u64,
    flags: String,
    entropy: Option<f64>,
}

#[derive(Debug, Clone)]
struct ImportListingRow {
    object_ref: ObjectRef,
    artifact_key: Option<String>,
    module: Option<String>,
    symbol: String,
    ordinal: Option<u64>,
    virtual_address: Option<u64>,
}

#[derive(Debug, Clone)]
struct StringListingRow {
    object_ref: ObjectRef,
    artifact_key: Option<String>,
    value: String,
    virtual_address: Option<u64>,
    file_offset: u64,
    length: u64,
    encoding: String,
}

#[derive(Debug, Clone)]
struct FunctionEvidencePacket {
    score: revdeck_core::FunctionScore,
    imports: Vec<ImportListingRow>,
    strings: Vec<StringListingRow>,
    relation_count: usize,
}

fn function_evidence_packet(
    project: &ProjectDatabase,
    object: &ObjectSummary,
) -> anyhow::Result<Option<FunctionEvidencePacket>> {
    if object.object_ref.kind != ObjectKind::Function {
        return Ok(None);
    }
    let Some(artifact_key) = &object.artifact_key else {
        return Ok(None);
    };
    let artifact = ObjectRef::new(ObjectKind::Artifact, artifact_key.parse()?);
    let score = RadarRepository::new(project.connection())
        .load_function_scores(&artifact)?
        .into_iter()
        .find(|score| score.function_ref == object.object_ref)
        .unwrap_or_else(|| {
            revdeck_core::score_function(revdeck_core::FunctionScoreInput::new(
                artifact.clone(),
                object.object_ref.clone(),
                object.label(),
            ))
        });
    let relations = ObjectQueryRepository::new(project.connection()).relations(
        &object.object_ref,
        RelationDirection::Outgoing,
        None,
    )?;
    let import_refs = relations
        .iter()
        .filter(|relation| relation.target.kind == ObjectKind::Import)
        .map(|relation| relation.target.clone())
        .collect::<Vec<_>>();
    let string_refs = relations
        .iter()
        .filter(|relation| relation.target.kind == ObjectKind::String)
        .map(|relation| relation.target.clone())
        .collect::<Vec<_>>();
    let imports = list_imports(project.connection(), Some(&artifact), None, 256)?
        .into_iter()
        .filter(|row| import_refs.contains(&row.object_ref))
        .collect();
    let strings = list_strings(project.connection(), Some(&artifact), None, 0, 256)?
        .into_iter()
        .filter(|row| string_refs.contains(&row.object_ref))
        .collect();
    Ok(Some(FunctionEvidencePacket {
        score,
        imports,
        strings,
        relation_count: relations.len(),
    }))
}

fn list_sections(
    connection: &rusqlite::Connection,
    artifact: Option<&ObjectRef>,
    limit: usize,
) -> anyhow::Result<Vec<SectionListingRow>> {
    let mut statement = connection.prepare(
        "SELECT o.object_key, o.artifact_key, sec.name, sec.virtual_address,
            sec.file_offset, sec.size, sec.flags, sec.entropy
        FROM sections sec
        JOIN objects o ON o.object_key = sec.object_key
        WHERE (?1 IS NULL OR o.artifact_key = ?1)
        ORDER BY coalesce(sec.file_offset, sec.virtual_address, 0), sec.name, o.object_key
        LIMIT ?2",
    )?;
    let rows = statement.query_map(
        rusqlite::params![artifact.map(|value| value.key.as_str()), limit as i64],
        |row| {
            let object_key: String = row.get(0)?;
            Ok(SectionListingRow {
                object_ref: ObjectRef::new(
                    ObjectKind::Section,
                    object_key.parse().map_err(from_core_error)?,
                ),
                artifact_key: row.get(1)?,
                name: row.get(2)?,
                virtual_address: row.get::<_, Option<i64>>(3)?.map(from_i64),
                file_offset: row.get::<_, Option<i64>>(4)?.map(from_i64),
                size: from_i64(row.get(5)?),
                flags: row.get(6)?,
                entropy: row.get(7)?,
            })
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list sections")
}

fn list_imports(
    connection: &rusqlite::Connection,
    artifact: Option<&ObjectRef>,
    module: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<ImportListingRow>> {
    let module_filter = module.map(|value| format!("%{}%", value.to_ascii_lowercase()));
    let mut statement = connection.prepare(
        "SELECT o.object_key, o.artifact_key, im.module, im.symbol, im.ordinal,
            im.virtual_address
        FROM imports im
        JOIN objects o ON o.object_key = im.object_key
        WHERE (?1 IS NULL OR o.artifact_key = ?1)
          AND (?2 IS NULL OR lower(coalesce(im.module, '')) LIKE ?2)
        ORDER BY coalesce(im.module, ''), im.symbol, im.ordinal, o.object_key
        LIMIT ?3",
    )?;
    let rows = statement.query_map(
        rusqlite::params![
            artifact.map(|value| value.key.as_str()),
            module_filter.as_deref(),
            limit as i64
        ],
        |row| {
            let object_key: String = row.get(0)?;
            Ok(ImportListingRow {
                object_ref: ObjectRef::new(
                    ObjectKind::Import,
                    object_key.parse().map_err(from_core_error)?,
                ),
                artifact_key: row.get(1)?,
                module: row.get(2)?,
                symbol: row.get(3)?,
                ordinal: row.get::<_, Option<i64>>(4)?.map(from_i64),
                virtual_address: row.get::<_, Option<i64>>(5)?.map(from_i64),
            })
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list imports")
}

fn list_strings(
    connection: &rusqlite::Connection,
    artifact: Option<&ObjectRef>,
    contains: Option<&str>,
    min_len: u64,
    limit: usize,
) -> anyhow::Result<Vec<StringListingRow>> {
    let contains_filter = contains.map(|value| format!("%{}%", value.to_ascii_lowercase()));
    let mut statement = connection.prepare(
        "SELECT o.object_key, o.artifact_key, st.value, st.virtual_address,
            st.file_offset, st.length, st.encoding
        FROM strings st
        JOIN objects o ON o.object_key = st.object_key
        WHERE (?1 IS NULL OR o.artifact_key = ?1)
          AND st.length >= ?2
          AND (?3 IS NULL OR lower(st.value) LIKE ?3)
        ORDER BY st.file_offset, st.value, o.object_key
        LIMIT ?4",
    )?;
    let rows = statement.query_map(
        rusqlite::params![
            artifact.map(|value| value.key.as_str()),
            to_i64(min_len),
            contains_filter.as_deref(),
            limit as i64
        ],
        |row| {
            let object_key: String = row.get(0)?;
            Ok(StringListingRow {
                object_ref: ObjectRef::new(
                    ObjectKind::String,
                    object_key.parse().map_err(from_core_error)?,
                ),
                artifact_key: row.get(1)?,
                value: row.get(2)?,
                virtual_address: row.get::<_, Option<i64>>(3)?.map(from_i64),
                file_offset: from_i64(row.get(4)?),
                length: from_i64(row.get(5)?),
                encoding: row.get(6)?,
            })
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to list strings")
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).expect("stored unsigned value must be non-negative")
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).expect("value must fit in SQLite INTEGER")
}

fn from_core_error(err: revdeck_core::RevDeckError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(err))
}

fn print_search_results(query: &str, kind: Option<ObjectKind>, matches: &[ObjectSummary]) {
    let scope = kind.map(|kind| kind.as_str()).unwrap_or("all");
    println!(
        "Search query=`{query}` kind={scope} matches={}",
        matches.len()
    );
    if matches.is_empty() {
        println!("No objects matched. Try --kind string, --kind import, or a shorter query.");
        return;
    }
    for item in matches {
        let address = item
            .address
            .map(|value| format!("0x{value:08x}"))
            .unwrap_or_else(|| "-".to_string());
        let size = item
            .size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let artifact = item.artifact_key.as_deref().unwrap_or("-");
        println!(
            "{:<16} {:<12} size={:<8} artifact={} label={} ref={}",
            item.object_ref.kind.as_str(),
            address,
            size,
            artifact,
            item.label(),
            item.object_ref
        );
    }
}

fn search_results_json(
    query: &str,
    kind: Option<ObjectKind>,
    matches: &[ObjectSummary],
) -> serde_json::Value {
    serde_json::json!({
        "query": query,
        "kind": kind.map(|kind| kind.as_str()),
        "matches": matches.iter().map(search_result_json).collect::<Vec<_>>(),
    })
}

fn search_result_json(item: &ObjectSummary) -> serde_json::Value {
    serde_json::json!({
        "ref": item.object_ref.to_string(),
        "kind": item.object_ref.kind.as_str(),
        "key": item.object_ref.key.as_str(),
        "label": item.label(),
        "artifact_key": item.artifact_key,
        "address": item.address,
        "size": item.size,
        "metadata": parsed_json_or_raw(&item.metadata_json),
    })
}

fn print_inspect_result(object: &ObjectSummary, relations: &[revdeck_core::ObjectRelation]) {
    println!("Object {}", object.object_ref);
    println!("kind={}", object.object_ref.kind.as_str());
    println!("label={}", object.label());
    println!("artifact={}", object.artifact_key.as_deref().unwrap_or("-"));
    println!(
        "address={}",
        object
            .address
            .map(|value| format!("0x{value:08x}"))
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "size={}",
        object
            .size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("metadata={}", object.metadata_json);
    println!("relations={}", relations.len());
    for relation in relations {
        println!(
            "{:<14} confidence={:<4.2} {} -> {}",
            relation.kind.as_str(),
            relation.confidence,
            relation.source,
            relation.target
        );
    }
}

fn inspect_result_json(
    object: &ObjectSummary,
    relations: &[revdeck_core::ObjectRelation],
    function_packet: Option<&FunctionEvidencePacket>,
) -> serde_json::Value {
    serde_json::json!({
        "object": search_result_json(object),
        "relations": relations.iter().map(relation_json).collect::<Vec<_>>(),
        "function_packet": function_packet.map(function_packet_json),
    })
}

fn print_function_packet(packet: &FunctionEvidencePacket) {
    println!(
        "Function packet score={} imports={} strings={} outgoing_relations={}",
        packet.score.score,
        packet.imports.len(),
        packet.strings.len(),
        packet.relation_count
    );
    for reason in packet.score.reasons.iter().take(8) {
        println!(
            "reason {:<24} contribution={:<4} {}",
            reason.reason_code, reason.contribution, reason.display_label
        );
    }
    for import in &packet.imports {
        let family =
            classify_import_family(import.module.as_deref().unwrap_or_default(), &import.symbol);
        println!(
            "import family={:<12} symbol={} ref={}",
            family.as_str(),
            import.symbol,
            import.object_ref
        );
    }
    for string in &packet.strings {
        let signal = classify_string_signal(&string.value);
        println!(
            "string signal={:<14} value={} ref={}",
            signal.as_str(),
            string.value,
            string.object_ref
        );
    }
}

fn function_packet_json(packet: &FunctionEvidencePacket) -> serde_json::Value {
    serde_json::json!({
        "score": packet.score.score,
        "reasons": packet.score.reasons.iter().map(|reason| {
            serde_json::json!({
                "signal_key": reason.signal_key,
                "reason_code": reason.reason_code,
                "display_label": reason.display_label,
                "contribution": reason.contribution,
                "weight": reason.weight,
                "evidence_refs": reason.evidence_refs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "metadata": reason.metadata,
            })
        }).collect::<Vec<_>>(),
        "imports": packet.imports.iter().map(|import| {
            let family = classify_import_family(import.module.as_deref().unwrap_or_default(), &import.symbol);
            serde_json::json!({
                "ref": import.object_ref.to_string(),
                "module": import.module,
                "symbol": import.symbol,
                "family": family.as_str(),
            })
        }).collect::<Vec<_>>(),
        "strings": packet.strings.iter().map(|string| {
            let signal = classify_string_signal(&string.value);
            serde_json::json!({
                "ref": string.object_ref.to_string(),
                "value": string.value,
                "signal": signal.as_str(),
                "file_offset": string.file_offset,
            })
        }).collect::<Vec<_>>(),
        "relation_count": packet.relation_count,
    })
}

fn relation_json(relation: &revdeck_core::ObjectRelation) -> serde_json::Value {
    serde_json::json!({
        "ref": relation.edge_ref.to_string(),
        "kind": relation.kind.as_str(),
        "source": relation.source.to_string(),
        "target": relation.target.to_string(),
        "confidence": relation.confidence,
        "metadata": parsed_json_or_raw(&relation.metadata_json),
    })
}

fn print_xrefs(root: &ObjectRef, relations: &[revdeck_core::ObjectRelation]) {
    println!("Xrefs root={root} relations={}", relations.len());
    for relation in relations {
        println!(
            "{:<14} confidence={:<4.2} {} -> {} ref={}",
            relation.kind.as_str(),
            relation.confidence,
            relation.source,
            relation.target,
            relation.edge_ref
        );
    }
}

fn xrefs_json(root: &ObjectRef, relations: &[revdeck_core::ObjectRelation]) -> serde_json::Value {
    serde_json::json!({
        "root": root.to_string(),
        "relations": relations.iter().map(relation_json).collect::<Vec<_>>(),
    })
}

fn print_traversal(traversal: &revdeck_core::LocalTraversal) {
    println!(
        "Traversal root={} nodes={} relations={}",
        traversal.root,
        traversal.nodes.len(),
        traversal.relations.len()
    );
    for item in traversal.evidence_path_items() {
        let via = item
            .via
            .map(|kind| kind.as_str().to_string())
            .unwrap_or_else(|| "-".to_string());
        let predecessor = item
            .predecessor
            .map(|object_ref| object_ref.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "depth={:<3} via={:<14} predecessor={} object={}",
            item.depth, via, predecessor, item.object_ref
        );
    }
}

fn traversal_json(traversal: &revdeck_core::LocalTraversal) -> serde_json::Value {
    serde_json::json!({
        "root": traversal.root.to_string(),
        "nodes": traversal.nodes.iter().map(|node| {
            serde_json::json!({
                "ref": node.object_ref.to_string(),
                "depth": node.depth,
            })
        }).collect::<Vec<_>>(),
        "relations": traversal.relations.iter().map(relation_json).collect::<Vec<_>>(),
        "evidence_path": traversal.evidence_path_items().iter().map(|item| {
            serde_json::json!({
                "ref": item.object_ref.to_string(),
                "depth": item.depth,
                "via": item.via.map(|kind| kind.as_str()),
                "predecessor": item.predecessor.as_ref().map(ToString::to_string),
            })
        }).collect::<Vec<_>>(),
    })
}

fn print_disasm(preview: &DisassemblyPreview, limit: usize) {
    println!(
        "Disasm function={} label={} basic_blocks={} instructions={} limit={}",
        preview.function.object_ref,
        preview.function.label(),
        preview.total_basic_blocks,
        preview.total_instructions,
        limit
    );
    if preview.total_basic_blocks == 0 && preview.total_instructions == 0 {
        println!(
            "CFG unavailable: no basic blocks or instructions were indexed for this function."
        );
        println!("If this project was imported with --profile quick, native CFG was intentionally skipped.");
        return;
    }
    println!("Basic blocks:");
    for block in &preview.basic_blocks {
        println!(
            "block ordinal={:<4} range={}-{} size={:<6} terminator={:<10} confidence={:<4.2} ref={}",
            block.ordinal,
            optional_hex(Some(block.start_address)),
            optional_hex(Some(block.end_address)),
            block.size,
            block.terminator,
            block.confidence,
            block.object_ref
        );
    }
    println!("Instructions:");
    for instruction in &preview.instructions {
        let text = instruction_text(
            instruction.mnemonic.as_str(),
            instruction.operands_text.as_str(),
        );
        println!(
            "{} {:<18} {:<8} size={:<3} block={} ref={}",
            optional_hex(Some(instruction.address)),
            instruction.bytes_hex,
            text,
            instruction.size,
            instruction.block_ref,
            instruction.object_ref
        );
    }
}

fn disasm_json(preview: &DisassemblyPreview, limit: usize) -> serde_json::Value {
    serde_json::json!({
        "function": search_result_json(&preview.function),
        "available": preview.total_basic_blocks > 0 || preview.total_instructions > 0,
        "limit": limit,
        "total_basic_blocks": preview.total_basic_blocks,
        "total_instructions": preview.total_instructions,
        "basic_blocks": preview.basic_blocks.iter().map(|block| {
            serde_json::json!({
                "ref": block.object_ref.to_string(),
                "start_address": block.start_address,
                "end_address": block.end_address,
                "size": block.size,
                "ordinal": block.ordinal,
                "terminator": block.terminator,
                "confidence": block.confidence,
            })
        }).collect::<Vec<_>>(),
        "instructions": preview.instructions.iter().map(|instruction| {
            serde_json::json!({
                "ref": instruction.object_ref.to_string(),
                "block_ref": instruction.block_ref.to_string(),
                "address": instruction.address,
                "size": instruction.size,
                "bytes_hex": instruction.bytes_hex,
                "mnemonic": instruction.mnemonic,
                "operands_text": instruction.operands_text,
                "text": instruction_text(instruction.mnemonic.as_str(), instruction.operands_text.as_str()),
                "ordinal": instruction.ordinal,
                "confidence": instruction.confidence,
            })
        }).collect::<Vec<_>>(),
        "unavailable_reason": if preview.total_basic_blocks == 0 && preview.total_instructions == 0 {
            Some("no indexed CFG rows; quick profile may have skipped native CFG")
        } else {
            None
        },
    })
}

fn instruction_text(mnemonic: &str, operands_text: &str) -> String {
    let operands_text = operands_text.trim();
    if operands_text.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {operands_text}")
    }
}

fn print_sections(sections: &[SectionListingRow]) {
    println!("Sections count={}", sections.len());
    for section in sections {
        println!(
            "{:<16} va={:<12} file={:<12} size={:<8} flags={:<8} entropy={:<6} artifact={} ref={}",
            section.name,
            optional_hex(section.virtual_address),
            optional_hex(section.file_offset),
            section.size,
            section.flags,
            optional_f64(section.entropy),
            section.artifact_key.as_deref().unwrap_or("-"),
            section.object_ref
        );
    }
}

fn sections_json(sections: &[SectionListingRow]) -> serde_json::Value {
    serde_json::json!({
        "sections": sections.iter().map(|section| {
            serde_json::json!({
                "ref": section.object_ref.to_string(),
                "artifact_key": section.artifact_key,
                "name": section.name,
                "virtual_address": section.virtual_address,
                "file_offset": section.file_offset,
                "size": section.size,
                "flags": section.flags,
                "entropy": section.entropy,
            })
        }).collect::<Vec<_>>(),
    })
}

fn print_imports(imports: &[ImportListingRow]) {
    println!("Imports count={}", imports.len());
    for import in imports {
        let family =
            classify_import_family(import.module.as_deref().unwrap_or_default(), &import.symbol);
        println!(
            "{:<24} family={:<12} symbol={:<32} ordinal={:<8} va={:<12} artifact={} ref={}",
            import.module.as_deref().unwrap_or("-"),
            family.as_str(),
            import.symbol,
            import
                .ordinal
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            optional_hex(import.virtual_address),
            import.artifact_key.as_deref().unwrap_or("-"),
            import.object_ref
        );
    }
}

fn imports_json(imports: &[ImportListingRow]) -> serde_json::Value {
    serde_json::json!({
        "imports": imports.iter().map(|import| {
            let family = classify_import_family(import.module.as_deref().unwrap_or_default(), &import.symbol);
            serde_json::json!({
                "ref": import.object_ref.to_string(),
                "artifact_key": import.artifact_key,
                "module": import.module,
                "symbol": import.symbol,
                "family": family.as_str(),
                "ordinal": import.ordinal,
                "virtual_address": import.virtual_address,
            })
        }).collect::<Vec<_>>(),
    })
}

fn print_strings(strings: &[StringListingRow]) {
    println!("Strings count={}", strings.len());
    for string in strings {
        let signal = classify_string_signal(&string.value);
        println!(
            "file={:<12} va={:<12} len={:<6} enc={:<8} signal={:<14} artifact={} value={} ref={}",
            optional_hex(Some(string.file_offset)),
            optional_hex(string.virtual_address),
            string.length,
            string.encoding,
            signal.as_str(),
            string.artifact_key.as_deref().unwrap_or("-"),
            string.value,
            string.object_ref
        );
    }
}

fn strings_json(strings: &[StringListingRow]) -> serde_json::Value {
    serde_json::json!({
        "strings": strings.iter().map(|string| {
            let signal = classify_string_signal(&string.value);
            serde_json::json!({
                "ref": string.object_ref.to_string(),
                "artifact_key": string.artifact_key,
                "value": string.value,
                "signal": signal.as_str(),
                "virtual_address": string.virtual_address,
                "file_offset": string.file_offset,
                "length": string.length,
                "encoding": string.encoding,
            })
        }).collect::<Vec<_>>(),
    })
}

fn optional_hex(value: Option<u64>) -> String {
    value
        .map(|value| format!("0x{value:08x}"))
        .unwrap_or_else(|| "-".to_string())
}

fn optional_f64(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|| "-".to_string())
}

fn parsed_json_or_raw(value: &str) -> serde_json::Value {
    serde_json::from_str(value).unwrap_or_else(|_| serde_json::json!({ "raw": value }))
}

fn diff_json(summary: &DiffSummaryViewModel) -> serde_json::Value {
    serde_json::json!({
        "lab": "diff",
        "label": "Diff Lab",
        "before": {
            "artifact": summary.before_artifact.to_string(),
            "label": summary.before_label
        },
        "after": {
            "artifact": summary.after_artifact.to_string(),
            "label": summary.after_label
        },
        "summary": {
            "added": summary.added,
            "removed": summary.removed,
            "changed": summary.changed,
            "unchanged": summary.unchanged,
            "object_deltas": summary.object_deltas,
            "relation_deltas": summary.relation_deltas,
            "total_deltas": summary.total_deltas(),
            "risk": {
                "high_risk_rows": summary.risk_summary.high_risk_rows,
                "dangerous_import_deltas": summary.risk_summary.dangerous_import_deltas,
                "sensitive_string_deltas": summary.risk_summary.sensitive_string_deltas
            }
        },
        "rows": summary.rows.iter().map(|row| {
            serde_json::json!({
                "delta_ref": row.delta_ref.to_string(),
                "entity_kind": row.entity_kind.as_str(),
                "change": row.change.as_str(),
                "match_key": row.match_key,
                "title": row.title,
                "before_ref": row.before.as_ref().map(ToString::to_string),
                "after_ref": row.after.as_ref().map(ToString::to_string),
                "before_label": row.before_label,
                "after_label": row.after_label,
                "command_previews": row.command_previews,
                "risk_level": row.risk_level,
                "risk_reasons": row.risk_reasons,
            })
        }).collect::<Vec<_>>()
    })
}

fn trace_import_json(outcome: &TraceImportOutcome) -> serde_json::Value {
    serde_json::json!({
        "lab": "trace",
        "label": "Trace Lab",
        "session": outcome.session.to_string(),
        "events_imported": outcome.events_imported,
        "correlated_events": outcome.correlated_events,
        "malformed_lines": outcome.malformed_lines,
        "diagnostics": &outcome.diagnostics,
        "threads": &outcome.threads,
        "analysis_job_id": outcome.analysis_job_id
    })
}

#[derive(Debug, Clone, Default)]
struct CorrelationQuality {
    correlated: usize,
    uncorrelated: usize,
    confidence: std::collections::BTreeMap<String, usize>,
}

fn trace_quality(events: &[TraceEventRecord]) -> CorrelationQuality {
    let mut quality = CorrelationQuality::default();
    for event in events {
        if event.correlated.is_some() {
            quality.correlated += 1;
        } else {
            quality.uncorrelated += 1;
        }
        *quality
            .confidence
            .entry(event.correlation_confidence.clone())
            .or_default() += 1;
    }
    quality
}

fn crash_quality(frames: &[CrashFrameRecord]) -> CorrelationQuality {
    let mut quality = CorrelationQuality::default();
    for frame in frames {
        if frame.correlated.is_some() {
            quality.correlated += 1;
        } else {
            quality.uncorrelated += 1;
        }
        *quality
            .confidence
            .entry(frame.correlation_confidence.clone())
            .or_default() += 1;
    }
    quality
}

fn trace_status_json(
    sessions: &[(TraceSessionRecord, Vec<TraceEventRecord>)],
) -> serde_json::Value {
    serde_json::json!({
        "lab": "trace",
        "label": "Trace Lab",
        "summary": {
            "sessions": sessions.len(),
            "events": sessions.iter().map(|(_, events)| events.len()).sum::<usize>(),
            "correlated_events": sessions.iter().map(|(_, events)| trace_quality(events).correlated).sum::<usize>(),
            "uncorrelated_events": sessions.iter().map(|(_, events)| trace_quality(events).uncorrelated).sum::<usize>()
        },
        "sessions": sessions
            .iter()
            .map(|(session, events)| {
                let quality = trace_quality(events);
                serde_json::json!({
                    "session": session.object_ref.to_string(),
                    "artifact": session.artifact.to_string(),
                    "session_id": &session.session_id,
                    "label": &session.label,
                    "source_path": &session.source_path,
                    "event_count": session.event_count,
                    "thread_count": session.thread_count,
                    "quality": {
                        "correlated": quality.correlated,
                        "uncorrelated": quality.uncorrelated,
                        "confidence": quality.confidence
                    },
                    "diagnostics": &session.diagnostics,
                    "imported_at": session.imported_at.to_string(),
                    "events": events.iter().map(|event| {
                        serde_json::json!({
                            "event": event.object_ref.to_string(),
                            "event_id": &event.event_id,
                            "thread_id": &event.thread_id,
                            "event_kind": &event.event_kind,
                            "timestamp_ns": event.timestamp_ns,
                            "function": &event.function_name,
                            "address": event.address,
                            "message": &event.message,
                            "correlated": event.correlated.as_ref().map(ToString::to_string),
                            "correlation_method": &event.correlation_method,
                            "correlation_confidence": &event.correlation_confidence
                        })
                    }).collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
    })
}

fn firmware_import_json(outcome: &FirmwareImportOutcome) -> serde_json::Value {
    serde_json::json!({
        "lab": "firmware",
        "label": "Firmware Lab",
        "firmware": outcome.firmware.to_string(),
        "files_imported": outcome.files_imported,
        "binaries_detected": outcome.binaries_detected,
        "unsupported_files": outcome.unsupported_files,
        "total_bytes": outcome.total_bytes,
        "analysis_job_id": outcome.analysis_job_id
    })
}

fn firmware_status_json(firmware: &ObjectRef, files: &[FirmwareFileRecord]) -> serde_json::Value {
    serde_json::json!({
        "lab": "firmware",
        "label": "Firmware Lab",
        "firmware": firmware.to_string(),
        "summary": {
            "files": files.len(),
            "nested_artifacts": files.iter().filter(|file| file.nested_artifact.is_some()).count(),
            "executables": files.iter().filter(|file| file.executable).count(),
            "total_bytes": files.iter().map(|file| file.size).sum::<u64>()
        },
        "files": files
            .iter()
            .map(|file| {
                serde_json::json!({
                    "object": file.object_ref.to_string(),
                    "firmware": file.firmware_artifact.to_string(),
                    "path": &file.path,
                    "parent_path": &file.parent_path,
                    "size": file.size,
                    "sha256": &file.sha256,
                    "file_type": &file.file_type,
                    "executable": file.executable,
                    "nested_artifact": file.nested_artifact.as_ref().map(ToString::to_string),
                    "nested_artifact_summary": file.nested_artifact.as_ref().map(|nested| serde_json::json!({
                        "artifact": nested.to_string(),
                        "source_file": file.object_ref.to_string(),
                        "path": &file.path,
                        "sha256": &file.sha256,
                        "size": file.size,
                        "file_type": &file.file_type
                    })),
                    "pivots": firmware_file_pivots(file),
                    "imported_at": file.imported_at.to_string()
                })
            })
            .collect::<Vec<_>>()
    })
}

fn firmware_file_pivots(file: &FirmwareFileRecord) -> Vec<serde_json::Value> {
    let mut pivots = vec![serde_json::json!({
        "kind": "file",
        "label": "Open firmware file",
        "target": file.object_ref.to_string(),
        "command": format!("revdeck inspect <project> {} --json", file.object_ref)
    })];
    if let Some(nested) = &file.nested_artifact {
        pivots.push(serde_json::json!({
            "kind": "nested_artifact",
            "label": "Inspect nested binary artifact",
            "target": nested.to_string(),
            "command": format!("revdeck inspect <project> {nested} --json")
        }));
        pivots.push(serde_json::json!({
            "kind": "nested_sections",
            "label": "List nested binary sections after import",
            "target": nested.to_string(),
            "command": format!("revdeck sections <project> --artifact {nested} --json")
        }));
    }
    pivots
}

fn crash_import_json(outcome: &CrashImportOutcome) -> serde_json::Value {
    serde_json::json!({
        "lab": "crash",
        "label": "Crash Lab",
        "report": outcome.report.to_string(),
        "frames_imported": outcome.frames_imported,
        "correlated_frames": outcome.correlated_frames,
        "clustered_reports": outcome.clustered_reports,
        "findings_created": outcome.findings_created,
        "signature": &outcome.signature,
        "diagnostics": &outcome.diagnostics,
        "analysis_job_id": outcome.analysis_job_id
    })
}

fn crash_status_json(reports: &[(CrashReportRecord, Vec<CrashFrameRecord>)]) -> serde_json::Value {
    serde_json::json!({
        "lab": "crash",
        "label": "Crash Lab",
        "summary": {
            "reports": reports.len(),
            "frames": reports.iter().map(|(_, frames)| frames.len()).sum::<usize>(),
            "correlated_frames": reports.iter().map(|(_, frames)| crash_quality(frames).correlated).sum::<usize>(),
            "uncorrelated_frames": reports.iter().map(|(_, frames)| crash_quality(frames).uncorrelated).sum::<usize>()
        },
        "reports": reports
            .iter()
            .map(|(report, frames)| {
                let quality = crash_quality(frames);
                serde_json::json!({
                    "report": report.object_ref.to_string(),
                    "artifact": report.artifact.to_string(),
                    "crash_id": &report.crash_id,
                    "label": &report.label,
                    "source_path": &report.source_path,
                    "sanitizer": &report.sanitizer,
                    "crash_class": &report.crash_class,
                    "signal": &report.signal,
                    "message": &report.message,
                    "signature": &report.signature,
                    "frame_count": report.frame_count,
                    "correlated_frame_count": report.correlated_frame_count,
                    "quality": {
                        "correlated": quality.correlated,
                        "uncorrelated": quality.uncorrelated,
                        "confidence": quality.confidence
                    },
                    "diagnostics": &report.diagnostics,
                    "imported_at": report.imported_at.to_string(),
                    "frames": frames
                        .iter()
                        .map(|frame| {
                            serde_json::json!({
                                "frame": frame.object_ref.to_string(),
                                "report": frame.report.to_string(),
                                "artifact": frame.artifact.to_string(),
                                "frame_index": frame.frame_index,
                                "module": &frame.module,
                                "function": &frame.function_name,
                                "address": frame.address,
                                "offset": frame.offset,
                                "source_location": &frame.source_location,
                                "confidence": &frame.confidence,
                                "correlated": frame.correlated.as_ref().map(ToString::to_string),
                                "correlation_method": &frame.correlation_method,
                                "correlation_confidence": &frame.correlation_confidence
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
    })
}

fn protocol_import_json(outcome: &ProtocolImportOutcome) -> serde_json::Value {
    serde_json::json!({
        "lab": "protocol",
        "label": "Protocol Lab",
        "sample": outcome.sample.to_string(),
        "messages_imported": outcome.messages_imported,
        "fields_imported": outcome.fields_imported,
        "correlated_fields": outcome.correlated_fields,
        "diagnostics": &outcome.diagnostics,
        "schema_hypothesis": &outcome.schema_hypothesis,
        "analysis_job_id": outcome.analysis_job_id
    })
}

fn protocol_status_json(
    samples: &[(
        ProtocolSampleRecord,
        Vec<(ProtocolMessageRecord, Vec<ProtocolFieldRecord>)>,
    )],
) -> serde_json::Value {
    serde_json::json!({
        "lab": "protocol",
        "label": "Protocol Lab",
        "summary": {
            "samples": samples.len(),
            "messages": samples.iter().map(|(_, messages)| messages.len()).sum::<usize>(),
            "fields": samples.iter().flat_map(|(_, messages)| messages.iter()).map(|(_, fields)| fields.len()).sum::<usize>(),
            "correlated_fields": samples.iter().flat_map(|(_, messages)| messages.iter()).flat_map(|(_, fields)| fields.iter()).filter(|field| field.correlated.is_some()).count(),
            "string_hint_fields": samples.iter().flat_map(|(_, messages)| messages.iter()).flat_map(|(_, fields)| fields.iter()).filter(|field| field.string_hint.is_some()).count()
        },
        "samples": samples
            .iter()
            .map(|(sample, messages)| protocol_sample_json(sample, messages))
            .collect::<Vec<_>>()
    })
}

fn protocol_sample_json(
    sample: &ProtocolSampleRecord,
    messages: &[(ProtocolMessageRecord, Vec<ProtocolFieldRecord>)],
) -> serde_json::Value {
    serde_json::json!({
        "sample": sample.object_ref.to_string(),
        "artifact": sample.artifact.to_string(),
        "sample_id": &sample.sample_id,
        "label": &sample.label,
        "source_path": &sample.source_path,
        "schema_hypothesis": &sample.schema_hypothesis,
        "message_count": sample.message_count,
        "field_count": sample.field_count,
        "diagnostics": &sample.diagnostics,
        "imported_at": sample.imported_at.to_string(),
        "messages": messages
            .iter()
            .map(|(message, fields)| protocol_message_json(message, fields))
            .collect::<Vec<_>>()
    })
}

fn protocol_message_json(
    message: &ProtocolMessageRecord,
    fields: &[ProtocolFieldRecord],
) -> serde_json::Value {
    serde_json::json!({
        "message": message.object_ref.to_string(),
        "sample": message.sample.to_string(),
        "artifact": message.artifact.to_string(),
        "message_index": message.message_index,
        "message_id": &message.message_id,
        "direction": &message.direction,
        "payload_len": message.payload_len,
        "field_count": message.field_count,
        "schema_hypothesis": &message.schema_hypothesis,
        "fields": fields.iter().map(protocol_field_json).collect::<Vec<_>>()
    })
}

fn protocol_field_json(field: &ProtocolFieldRecord) -> serde_json::Value {
    serde_json::json!({
        "field": field.object_ref.to_string(),
        "message": field.message.to_string(),
        "sample": field.sample.to_string(),
        "artifact": field.artifact.to_string(),
        "field_index": field.field_index,
        "name": &field.name,
        "byte_offset": field.byte_offset,
        "byte_length": field.byte_length,
        "field_type": &field.field_type,
        "confidence": &field.confidence,
        "entropy": field.entropy,
        "printable_ratio": field.printable_ratio,
        "integer_value": field.integer_value,
        "string_hint": &field.string_hint,
        "correlated": field.correlated.as_ref().map(ToString::to_string),
        "byte_range": {
            "start": field.byte_offset,
            "end": field.byte_offset + field.byte_length,
            "length": field.byte_length
        },
        "pivots": protocol_field_pivots_cli(field)
    })
}

fn protocol_field_pivots_cli(field: &ProtocolFieldRecord) -> Vec<serde_json::Value> {
    let mut pivots = vec![
        serde_json::json!({
            "kind": "field",
            "label": "Open protocol field",
            "target": field.object_ref.to_string(),
            "command": format!("revdeck inspect <project> {} --json", field.object_ref)
        }),
        serde_json::json!({
            "kind": "offset",
            "label": "Protocol payload byte range",
            "byte_offset": field.byte_offset,
            "byte_length": field.byte_length
        }),
    ];
    if let Some(hint) = field.string_hint.as_deref() {
        pivots.push(serde_json::json!({
            "kind": "string_hint",
            "label": "Search matching strings",
            "value": hint,
            "correlated": field.correlated.as_ref().map(ToString::to_string),
            "command": format!("revdeck strings <project> --contains \"{hint}\" --json")
        }));
    }
    pivots
}

fn outcome_json(outcome: &ImportOutcome, project: Option<&ProjectDatabase>) -> serde_json::Value {
    let mut value = serde_json::json!({
        "status": outcome.status.as_str(),
        "profile": outcome.profile.as_str(),
        "artifact": outcome.artifact_ref.to_string(),
        "analysis_run": outcome.run_id,
        "sections": outcome.summary.sections,
        "symbols": outcome.summary.symbols,
        "imports": outcome.summary.imports,
        "strings": outcome.summary.strings,
        "functions": outcome.summary.functions,
        "xrefs": outcome.summary.xrefs,
        "edges": outcome.summary.edges,
        "diagnostics": outcome.summary.diagnostics
    });
    if let Some(project) = project {
        value["project"] = serde_json::json!(project.info().root_dir.display().to_string());
        value["database"] = serde_json::json!(project.info().db_path.display().to_string());
    }
    value
}

fn registration_json(
    registration: &BinaryRegistration,
    project: Option<&ProjectDatabase>,
    status: &str,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "status": status,
        "profile": registration.profile.as_str(),
        "artifact": registration.artifact_ref.to_string(),
        "analysis_run": registration.run_id,
        "parse_job": registration.parse_job_id,
        "source_path": registration.source_path.display().to_string(),
        "display_name": registration.display_name,
        "sha256": registration.sha256,
        "size": registration.size,
        "background": true,
        "tui": true
    });
    if let Some(project) = project {
        value["project"] = serde_json::json!(project.info().root_dir.display().to_string());
        value["database"] = serde_json::json!(project.info().db_path.display().to_string());
    }
    value
}

fn spawn_registered_analysis_worker(
    project_dir: PathBuf,
    registration: BinaryRegistration,
) -> anyhow::Result<()> {
    thread::Builder::new()
        .name("revdeck-analysis-worker".to_string())
        .spawn(move || {
            if let Err(err) = run_registered_analysis_worker(&project_dir, registration) {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "status": "background-analysis-failed",
                        "project": project_dir.display().to_string(),
                        "error": err.to_string()
                    })
                );
            }
        })
        .context("failed to spawn revdeck-analysis-worker")?;
    Ok(())
}

fn run_registered_analysis_worker(
    project_dir: &Path,
    registration: BinaryRegistration,
) -> anyhow::Result<()> {
    let project = ProjectDatabase::open_existing(project_dir).with_context(|| {
        format!(
            "failed to open project at {} for background analysis",
            project_dir.display()
        )
    })?;
    match finish_registered_binary_analysis(project.connection(), registration.clone()) {
        Ok(_) => Ok(()),
        Err(err) => {
            let diagnostic = AnalysisDiagnostic::new(
                DiagnosticSeverity::Error,
                DiagnosticStage::Parse,
                "background_analysis_failed",
                err.to_string(),
                true,
            )
            .expect("static diagnostic fields are valid");
            let _ = fail_registered_binary_analysis(project.connection(), registration, diagnostic);
            Err(anyhow::anyhow!(err.structured_message()))
        }
    }
}

fn jobs_json(jobs: &[revdeck_db::AnalysisJobRecord]) -> serde_json::Value {
    serde_json::json!({
        "jobs": jobs
            .iter()
            .map(|job| {
                serde_json::json!({
                    "id": job.id,
                    "analysis_run_id": job.analysis_run_id,
                    "artifact_key": &job.artifact_key,
                    "pass_name": &job.pass_name,
                    "profile": &job.profile,
                    "status": &job.status,
                    "progress_current": job.progress_current,
                    "progress_total": job.progress_total,
                    "objects_produced": job.objects_produced,
                    "diagnostics_count": job.diagnostics_count,
                    "byte_limit": job.byte_limit,
                    "function_limit": job.function_limit,
                    "time_limit_ms": job.time_limit_ms,
                    "metadata": serde_json::from_str::<serde_json::Value>(&job.metadata_json)
                        .unwrap_or_else(|_| serde_json::json!({ "raw": &job.metadata_json })),
                    "started_at": job.started_at.to_string(),
                    "finished_at": job.finished_at.map(|value| value.to_string()),
                    "updated_at": job.updated_at.to_string()
                })
            })
            .collect::<Vec<_>>()
    })
}

fn labs_json(labs: &[LabSummary]) -> serde_json::Value {
    serde_json::json!({
        "labs": labs
            .iter()
            .map(|lab| {
                serde_json::json!({
                    "id": lab.id,
                    "label": lab.label,
                    "badge": lab.badge,
                    "purpose": lab.purpose,
                    "maturity": lab.maturity.as_str(),
                    "default_lens": lab.default_lens_label,
                    "shortcut": lab.shortcut.map(|value| value.to_string())
                })
            })
            .collect::<Vec<_>>()
    })
}

fn default_analysis_project_dir(binary_path: &Path) -> PathBuf {
    let stem = binary_path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(slug)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "binary".to_string());
    let path = binary_path
        .canonicalize()
        .unwrap_or_else(|_| binary_path.to_path_buf());
    let digest = stable_path_digest(&path);
    PathBuf::from(".revdeck")
        .join("workspaces")
        .join(format!("{stem}-{digest}"))
}

fn stable_path_digest(path: &Path) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut digest = format!("{hash:016x}");
    digest.truncate(8);
    digest
}

fn slug(value: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            output.push('-');
            last_was_dash = true;
        }
    }
    output.trim_matches('-').to_string()
}
