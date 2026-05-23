use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use revdeck_core::{
    pre_export_validation, render_json_bundle, render_markdown, AnalysisDiagnostic,
    DiagnosticSeverity, DiagnosticStage, DiffSummaryViewModel, LabSummary, ObjectKind, ObjectRef,
    StableObjectKey,
};
use revdeck_db::{
    migrations, AnalysisJobRepository, CrashFrameRecord, CrashImportOutcome, CrashReportRecord,
    CrashRepository, FindingRepository, FirmwareFileRecord, FirmwareImportOutcome,
    FirmwareRepository, ObjectQueryRepository, ObjectRepository, ProjectDatabase,
    ProtocolFieldRecord, ProtocolImportOutcome, ProtocolMessageRecord, ProtocolRepository,
    ProtocolSampleRecord, TraceImportOutcome, TraceRepository, TraceSessionRecord,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Md,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliAnalysisProfile {
    Quick,
    Balanced,
    Deep,
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
                spawn_registered_analysis_worker(project_dir.clone(), registration);
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
            out,
        } => {
            let project = ProjectDatabase::open_existing(&project_dir)
                .with_context(|| format!("failed to open project at {}", project_dir.display()))?;
            let context = FindingRepository::new(project.connection())
                .export_context(OffsetDateTime::now_utc())
                .context("failed to load findings for report")?;
            pre_export_validation(&context).map_err(|err| {
                anyhow::anyhow!(
                    "{}",
                    serde_json::to_string_pretty(&err.report).unwrap_or_else(|_| err.to_string())
                )
            })?;
            let rendered = match format {
                ReportFormat::Md => render_markdown(&context),
                ReportFormat::Json => {
                    render_json_bundle(&context).context("failed to render JSON report")?
                }
            };
            if let Some(path) = out {
                fs::write(&path, rendered)
                    .with_context(|| format!("failed to write report to {}", path.display()))?;
                println!("wrote report {}", path.display());
            } else {
                println!("{rendered}");
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
                let sessions = TraceRepository::new(project.connection())
                    .list_sessions_for_artifact(&artifact_ref, limit)
                    .context("failed to list trace sessions")?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&trace_status_json(&sessions))?
                    );
                } else if sessions.is_empty() {
                    println!("Trace Lab sessions=0");
                } else {
                    println!("Trace Lab sessions={}", sessions.len());
                    for session in &sessions {
                        println!(
                            "{:<24} events={:<5} threads={:<3} source={}",
                            session.session_id,
                            session.event_count,
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
    }
    Ok(())
}

fn count(connection: &rusqlite::Connection, table: &str) -> anyhow::Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    Ok(connection.query_row(&sql, [], |row| row.get(0))?)
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
            "total_deltas": summary.total_deltas()
        },
        "rows": &summary.rows
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

fn trace_status_json(sessions: &[TraceSessionRecord]) -> serde_json::Value {
    serde_json::json!({
        "lab": "trace",
        "label": "Trace Lab",
        "sessions": sessions
            .iter()
            .map(|session| {
                serde_json::json!({
                    "session": session.object_ref.to_string(),
                    "artifact": session.artifact.to_string(),
                    "session_id": &session.session_id,
                    "label": &session.label,
                    "source_path": &session.source_path,
                    "event_count": session.event_count,
                    "thread_count": session.thread_count,
                    "diagnostics": &session.diagnostics,
                    "imported_at": session.imported_at.to_string()
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
                    "imported_at": file.imported_at.to_string()
                })
            })
            .collect::<Vec<_>>()
    })
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
        "reports": reports
            .iter()
            .map(|(report, frames)| {
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
                                "correlated": frame.correlated.as_ref().map(ToString::to_string)
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
        "correlated": field.correlated.as_ref().map(ToString::to_string)
    })
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

fn spawn_registered_analysis_worker(project_dir: PathBuf, registration: BinaryRegistration) {
    thread::spawn(move || {
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
    });
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
