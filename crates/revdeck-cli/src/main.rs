use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use revdeck_core::{pre_export_validation, render_json, render_markdown};
use revdeck_db::{migrations, AnalysisJobRepository, FindingRepository, ProjectDatabase};
use revdeck_index::{import_binary, AnalysisProfile, ImportOptions, ImportOutcome};
use std::{
    fs,
    path::{Path, PathBuf},
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
        binary_path: PathBuf,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = CliAnalysisProfile::Balanced)]
        profile: CliAnalysisProfile,
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
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    Tui {
        project_dir: PathBuf,
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
            let outcome = import_binary(
                project.connection(),
                ImportOptions::with_profile(
                    project_dir.clone(),
                    binary_path.clone(),
                    profile.into(),
                ),
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
                    render_json(&context).context("failed to render JSON report")?
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
