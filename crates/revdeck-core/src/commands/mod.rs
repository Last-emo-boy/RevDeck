use crate::{
    navigation::{NavigationEntry, NavigationHistory, NavigationLens},
    query::{
        ObjectGraphQuery, ObjectRelation, ObjectSearch, ObjectSummary, QueryError,
        RelationDirection,
    },
    ObjectKind, ObjectRef, StableObjectKeyBuilder,
};
use std::{collections::BTreeMap, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandDiagnosticKind {
    InvalidSyntax,
    UnknownCommand,
    MissingArgument,
    Ambiguous,
    Unresolved,
    UnsupportedInV01,
    BrokenObject,
    QueryFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct CommandDiagnostic {
    pub kind: CommandDiagnosticKind,
    pub message: String,
    pub candidates: Vec<ObjectRef>,
}

impl CommandDiagnostic {
    pub fn new(kind: CommandDiagnosticKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            candidates: Vec::new(),
        }
    }

    pub fn with_candidates(mut self, candidates: Vec<ObjectRef>) -> Self {
        self.candidates = candidates;
        self
    }

    fn missing(argument: &str) -> Self {
        Self::new(
            CommandDiagnosticKind::MissingArgument,
            format!("missing required argument `{argument}`"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandTarget {
    Current,
    Ref(ObjectRef),
    Query {
        kind: Option<ObjectKind>,
        term: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFormat {
    Markdown,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAst {
    Find {
        kind: Option<ObjectKind>,
        query: String,
    },
    Xrefs {
        target: CommandTarget,
    },
    Open {
        target: CommandTarget,
    },
    Back,
    Forward,
    Tag {
        target: CommandTarget,
        tag: String,
    },
    Note {
        target: CommandTarget,
        body: String,
    },
    Rename {
        target: CommandTarget,
        name: String,
    },
    Status {
        target: CommandTarget,
        status: String,
    },
    FindingNew {
        severity: String,
        title: String,
    },
    FindingLink {
        finding: CommandTarget,
        evidence: CommandTarget,
        role: String,
    },
    Export {
        format: ExportFormat,
        path: String,
    },
    Help {
        topic: Option<String>,
    },
    Unsupported {
        name: String,
    },
}

pub struct CommandParser;

impl CommandParser {
    pub fn parse(input: &str) -> Result<CommandAst, CommandDiagnostic> {
        let command = input.trim().trim_start_matches(':').trim();
        if command.is_empty() {
            return Err(CommandDiagnostic::missing("command"));
        }
        let tokens = tokenize(command)?;
        let (name, args) = tokens
            .split_first()
            .ok_or_else(|| CommandDiagnostic::missing("command"))?;
        match name.to_ascii_lowercase().as_str() {
            "find" | "search" => parse_find(args),
            "xrefs" | "xref" => Ok(CommandAst::Xrefs {
                target: parse_target_or_current(args),
            }),
            "open" | "jump" => {
                require_args(args, "target")?;
                Ok(CommandAst::Open {
                    target: parse_target_or_current(args),
                })
            }
            "back" => Ok(CommandAst::Back),
            "forward" => Ok(CommandAst::Forward),
            "tag" => {
                parse_target_then_value(args, "tag", |target, tag| CommandAst::Tag { target, tag })
            }
            "note" => parse_targeted_value(args, "body", |target, body| CommandAst::Note {
                target,
                body,
            }),
            "rename" => parse_target_then_value(args, "name", |target, name| CommandAst::Rename {
                target,
                name,
            }),
            "status" => parse_target_then_value(args, "status", |target, status| {
                CommandAst::Status { target, status }
            }),
            "finding" => parse_finding(args),
            "export" | "report" => parse_export(args),
            "help" => Ok(CommandAst::Help {
                topic: args.first().cloned(),
            }),
            unsupported if is_known_later_command(unsupported) => Ok(CommandAst::Unsupported {
                name: unsupported.to_string(),
            }),
            unknown => Err(CommandDiagnostic::new(
                CommandDiagnosticKind::UnknownCommand,
                format!("unknown command `{unknown}`"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedCommand {
    Find {
        kind: Option<ObjectKind>,
        query: String,
        matches: Vec<ObjectSummary>,
    },
    Xrefs {
        target: ObjectRef,
        relations: Vec<ObjectRelation>,
    },
    Open {
        target: ObjectRef,
    },
    Back,
    Forward,
    Tag {
        target: ObjectRef,
        tag: String,
    },
    Note {
        target: ObjectRef,
        body: String,
    },
    Rename {
        target: ObjectRef,
        name: String,
    },
    Status {
        target: ObjectRef,
        status: String,
    },
    FindingNew {
        severity: String,
        title: String,
    },
    FindingLink {
        finding: ObjectRef,
        evidence: ObjectRef,
        role: String,
    },
    Export {
        format: ExportFormat,
        path: String,
    },
    Help {
        topic: Option<String>,
    },
}

pub struct CommandResolver<'query> {
    query: &'query dyn ObjectGraphQuery,
}

impl<'query> CommandResolver<'query> {
    pub fn new(query: &'query dyn ObjectGraphQuery) -> Self {
        Self { query }
    }

    pub fn resolve(
        &self,
        command: CommandAst,
        state: &CommandState,
    ) -> Result<ResolvedCommand, CommandDiagnostic> {
        match command {
            CommandAst::Find { kind, query } => {
                let matches = self
                    .query
                    .search_objects(&ObjectSearch::new(kind, query.clone()).with_limit(50))
                    .map_err(command_query_error)?;
                Ok(ResolvedCommand::Find {
                    kind,
                    query,
                    matches,
                })
            }
            CommandAst::Xrefs { target } => {
                let target = self.resolve_target(target, state)?;
                let relations = self
                    .query
                    .relations(&target, RelationDirection::Both, None)
                    .map_err(command_query_error)?;
                Ok(ResolvedCommand::Xrefs { target, relations })
            }
            CommandAst::Open { target } => Ok(ResolvedCommand::Open {
                target: self.resolve_target(target, state)?,
            }),
            CommandAst::Back => Ok(ResolvedCommand::Back),
            CommandAst::Forward => Ok(ResolvedCommand::Forward),
            CommandAst::Tag { target, tag } => Ok(ResolvedCommand::Tag {
                target: self.resolve_target(target, state)?,
                tag,
            }),
            CommandAst::Note { target, body } => Ok(ResolvedCommand::Note {
                target: self.resolve_target(target, state)?,
                body,
            }),
            CommandAst::Rename { target, name } => Ok(ResolvedCommand::Rename {
                target: self.resolve_target(target, state)?,
                name,
            }),
            CommandAst::Status { target, status } => Ok(ResolvedCommand::Status {
                target: self.resolve_target(target, state)?,
                status,
            }),
            CommandAst::FindingNew { severity, title } => {
                Ok(ResolvedCommand::FindingNew { severity, title })
            }
            CommandAst::FindingLink {
                finding,
                evidence,
                role,
            } => Ok(ResolvedCommand::FindingLink {
                finding: self.resolve_target(finding, state)?,
                evidence: self.resolve_target(evidence, state)?,
                role,
            }),
            CommandAst::Export { format, path } => Ok(ResolvedCommand::Export { format, path }),
            CommandAst::Help { topic } => Ok(ResolvedCommand::Help { topic }),
            CommandAst::Unsupported { name } => Err(CommandDiagnostic::new(
                CommandDiagnosticKind::UnsupportedInV01,
                format!("`{name}` is not supported in RevDeck v0.1"),
            )),
        }
    }

    fn resolve_target(
        &self,
        target: CommandTarget,
        state: &CommandState,
    ) -> Result<ObjectRef, CommandDiagnostic> {
        match target {
            CommandTarget::Current => state.current_object.clone().ok_or_else(|| {
                CommandDiagnostic::new(
                    CommandDiagnosticKind::Unresolved,
                    "no current object is selected",
                )
            }),
            CommandTarget::Ref(object_ref) => {
                if object_ref.kind == ObjectKind::Finding
                    && state.findings.contains_key(&object_ref)
                {
                    return Ok(object_ref);
                }
                if self
                    .query
                    .get_object(&object_ref)
                    .map_err(command_query_error)?
                    .is_some()
                {
                    Ok(object_ref)
                } else {
                    Err(CommandDiagnostic::new(
                        CommandDiagnosticKind::BrokenObject,
                        format!("object `{object_ref}` does not exist in this project"),
                    )
                    .with_candidates(vec![object_ref]))
                }
            }
            CommandTarget::Query { kind, term } => {
                let matches = self
                    .query
                    .search_objects(&ObjectSearch::new(kind, term.clone()).with_limit(10))
                    .map_err(command_query_error)?;
                match matches.len() {
                    0 => Err(CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        format!("no object matched `{term}`"),
                    )),
                    1 => Ok(matches[0].object_ref.clone()),
                    _ => Err(CommandDiagnostic::new(
                        CommandDiagnosticKind::Ambiguous,
                        format!("target `{term}` matched multiple objects"),
                    )
                    .with_candidates(matches.into_iter().map(|item| item.object_ref).collect())),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommandState {
    pub navigation: NavigationHistory,
    pub current_lens: NavigationLens,
    pub current_object: Option<ObjectRef>,
    pub last_search: Vec<ObjectSummary>,
    pub last_xrefs: Vec<ObjectRelation>,
    pub tags: BTreeMap<ObjectRef, Vec<String>>,
    pub notes: BTreeMap<ObjectRef, Vec<String>>,
    pub renames: BTreeMap<ObjectRef, String>,
    pub statuses: BTreeMap<ObjectRef, String>,
    pub findings: BTreeMap<ObjectRef, FindingDraft>,
    pub finding_links: Vec<FindingEvidenceDraft>,
    pub export_requests: Vec<ExportRequest>,
}

impl Default for CommandState {
    fn default() -> Self {
        Self {
            navigation: NavigationHistory::new(),
            current_lens: NavigationLens::Overview,
            current_object: None,
            last_search: Vec::new(),
            last_xrefs: Vec::new(),
            tags: BTreeMap::new(),
            notes: BTreeMap::new(),
            renames: BTreeMap::new(),
            statuses: BTreeMap::new(),
            findings: BTreeMap::new(),
            finding_links: Vec::new(),
            export_requests: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDraft {
    pub object_ref: ObjectRef,
    pub severity: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEvidenceDraft {
    pub finding: ObjectRef,
    pub evidence: ObjectRef,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRequest {
    pub format: ExportFormat,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandOutcome {
    SearchResults(Vec<ObjectSummary>),
    Xrefs(Vec<ObjectRelation>),
    Navigated(ObjectRef),
    Mutated(ObjectRef),
    FindingCreated(ObjectRef),
    FindingLinked(FindingEvidenceDraft),
    ExportRequested(ExportRequest),
    Help(Option<String>),
}

pub struct CommandExecutor;

impl CommandExecutor {
    pub fn execute(
        state: &mut CommandState,
        command: ResolvedCommand,
    ) -> Result<CommandOutcome, CommandDiagnostic> {
        match command {
            ResolvedCommand::Find { matches, .. } => {
                state.last_search = matches.clone();
                Ok(CommandOutcome::SearchResults(matches))
            }
            ResolvedCommand::Xrefs { relations, .. } => {
                state.last_xrefs = relations.clone();
                Ok(CommandOutcome::Xrefs(relations))
            }
            ResolvedCommand::Open { target } => {
                navigate_state_to(state, target.clone());
                Ok(CommandOutcome::Navigated(target))
            }
            ResolvedCommand::Back => {
                if !state.navigation.can_back() {
                    return Err(CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        "navigation history has no previous entry",
                    ));
                }
                let entry = state
                    .navigation
                    .back()
                    .expect("can_back checked previous navigation entry")
                    .clone();
                sync_state_to_entry(state, &entry);
                Ok(CommandOutcome::Navigated(entry.object_ref))
            }
            ResolvedCommand::Forward => {
                if !state.navigation.can_forward() {
                    return Err(CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        "navigation history has no next entry",
                    ));
                }
                let entry = state
                    .navigation
                    .forward()
                    .expect("can_forward checked next navigation entry")
                    .clone();
                sync_state_to_entry(state, &entry);
                Ok(CommandOutcome::Navigated(entry.object_ref))
            }
            ResolvedCommand::Tag { target, tag } => {
                state.tags.entry(target.clone()).or_default().push(tag);
                Ok(CommandOutcome::Mutated(target))
            }
            ResolvedCommand::Note { target, body } => {
                state.notes.entry(target.clone()).or_default().push(body);
                Ok(CommandOutcome::Mutated(target))
            }
            ResolvedCommand::Rename { target, name } => {
                state.renames.insert(target.clone(), name);
                Ok(CommandOutcome::Mutated(target))
            }
            ResolvedCommand::Status { target, status } => {
                state.statuses.insert(target.clone(), status);
                Ok(CommandOutcome::Mutated(target))
            }
            ResolvedCommand::FindingNew { severity, title } => {
                let key = StableObjectKeyBuilder::new(ObjectKind::Finding)
                    .component("title", &title)
                    .and_then(|builder| {
                        builder.component("index", (state.findings.len() + 1).to_string())
                    })
                    .and_then(|builder| builder.finish())
                    .map_err(|err| {
                        CommandDiagnostic::new(
                            CommandDiagnosticKind::InvalidSyntax,
                            err.to_string(),
                        )
                    })?;
                let object_ref = ObjectRef::new(ObjectKind::Finding, key);
                let draft = FindingDraft {
                    object_ref: object_ref.clone(),
                    severity,
                    title,
                };
                state.findings.insert(object_ref.clone(), draft);
                Ok(CommandOutcome::FindingCreated(object_ref))
            }
            ResolvedCommand::FindingLink {
                finding,
                evidence,
                role,
            } => {
                let link = FindingEvidenceDraft {
                    finding,
                    evidence,
                    role,
                };
                state.finding_links.push(link.clone());
                Ok(CommandOutcome::FindingLinked(link))
            }
            ResolvedCommand::Export { format, path } => {
                let request = ExportRequest { format, path };
                state.export_requests.push(request.clone());
                Ok(CommandOutcome::ExportRequested(request))
            }
            ResolvedCommand::Help { topic } => Ok(CommandOutcome::Help(topic)),
        }
    }
}

fn navigate_state_to(state: &mut CommandState, object_ref: ObjectRef) {
    let lens = NavigationLens::for_object_kind(object_ref.kind);
    state
        .navigation
        .navigate_to(NavigationEntry::new(lens, object_ref.clone()));
    state.current_lens = lens;
    state.current_object = Some(object_ref);
}

fn sync_state_to_entry(state: &mut CommandState, entry: &NavigationEntry) {
    state.current_lens = entry.lens;
    state.current_object = Some(entry.object_ref.clone());
}

fn parse_find(args: &[String]) -> Result<CommandAst, CommandDiagnostic> {
    require_args(args, "query")?;
    let (kind, query) = parse_kind_prefixed_query(args)?;
    if query.trim().is_empty() {
        return Err(CommandDiagnostic::missing("query"));
    }
    Ok(CommandAst::Find { kind, query })
}

fn parse_targeted_value<F>(
    args: &[String],
    value_name: &str,
    build: F,
) -> Result<CommandAst, CommandDiagnostic>
where
    F: FnOnce(CommandTarget, String) -> CommandAst,
{
    require_args(args, value_name)?;
    let (target, value_start) = if args.len() >= 2 && token_can_be_target(&args[0]) {
        (parse_target_or_current(&args[..1]), 1)
    } else {
        (CommandTarget::Current, 0)
    };
    let value = args[value_start..].join(" ");
    if value.trim().is_empty() {
        return Err(CommandDiagnostic::missing(value_name));
    }
    Ok(build(target, value))
}

fn parse_target_then_value<F>(
    args: &[String],
    value_name: &str,
    build: F,
) -> Result<CommandAst, CommandDiagnostic>
where
    F: FnOnce(CommandTarget, String) -> CommandAst,
{
    require_args(args, value_name)?;
    let (target, value_start) = if args.len() >= 2 {
        (parse_target_or_current(&args[..1]), 1)
    } else {
        (CommandTarget::Current, 0)
    };
    let value = args[value_start..].join(" ");
    if value.trim().is_empty() {
        return Err(CommandDiagnostic::missing(value_name));
    }
    Ok(build(target, value))
}

fn parse_finding(args: &[String]) -> Result<CommandAst, CommandDiagnostic> {
    require_args(args, "finding subcommand")?;
    match args[0].to_ascii_lowercase().as_str() {
        "new" => {
            if args.len() < 3 {
                return Err(CommandDiagnostic::missing("severity and title"));
            }
            Ok(CommandAst::FindingNew {
                severity: args[1].clone(),
                title: args[2..].join(" "),
            })
        }
        "link" => {
            if args.len() < 3 {
                return Err(CommandDiagnostic::missing("finding and evidence"));
            }
            Ok(CommandAst::FindingLink {
                finding: parse_target_or_current(&args[1..2]),
                evidence: parse_target_or_current(&args[2..3]),
                role: args
                    .get(3)
                    .cloned()
                    .unwrap_or_else(|| "evidence".to_string()),
            })
        }
        other => Err(CommandDiagnostic::new(
            CommandDiagnosticKind::UnknownCommand,
            format!("unknown finding subcommand `{other}`"),
        )),
    }
}

fn parse_export(args: &[String]) -> Result<CommandAst, CommandDiagnostic> {
    if args.len() < 2 {
        return Err(CommandDiagnostic::missing("format and path"));
    }
    let format = match args[0].to_ascii_lowercase().as_str() {
        "markdown" | "md" => ExportFormat::Markdown,
        "json" => ExportFormat::Json,
        other => {
            return Err(CommandDiagnostic::new(
                CommandDiagnosticKind::InvalidSyntax,
                format!("unsupported export format `{other}`"),
            ));
        }
    };
    Ok(CommandAst::Export {
        format,
        path: args[1..].join(" "),
    })
}

fn parse_target_or_current(args: &[String]) -> CommandTarget {
    if args.is_empty() {
        return CommandTarget::Current;
    }
    if args.len() == 1 {
        let token = &args[0];
        if matches!(token.as_str(), "current" | "selected") {
            return CommandTarget::Current;
        }
        if let Ok(object_ref) = ObjectRef::from_str(token) {
            return CommandTarget::Ref(object_ref);
        }
    }
    let (kind, term) = parse_kind_prefixed_query(args).unwrap_or_else(|_| (None, args.join(" ")));
    CommandTarget::Query { kind, term }
}

fn parse_kind_prefixed_query(
    args: &[String],
) -> Result<(Option<ObjectKind>, String), CommandDiagnostic> {
    let Some(first) = args.first() else {
        return Err(CommandDiagnostic::missing("query"));
    };
    if let Some(kind) = parse_kind(first) {
        if args.len() == 1 {
            return Err(CommandDiagnostic::missing("query"));
        }
        Ok((Some(kind), args[1..].join(" ")))
    } else {
        Ok((None, args.join(" ")))
    }
}

fn parse_kind(value: &str) -> Option<ObjectKind> {
    value.to_ascii_lowercase().parse().ok()
}

fn token_can_be_target(token: &str) -> bool {
    matches!(token, "current" | "selected") || ObjectRef::from_str(token).is_ok()
}

fn require_args(args: &[String], argument: &str) -> Result<(), CommandDiagnostic> {
    if args.is_empty() {
        Err(CommandDiagnostic::missing(argument))
    } else {
        Ok(())
    }
}

fn tokenize(input: &str) -> Result<Vec<String>, CommandDiagnostic> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(active), next) if next == active => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), next) => current.push(next),
            (None, '"' | '\'') => quote = Some(ch),
            (None, next) if next.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (None, next) => current.push(next),
        }
    }
    if quote.is_some() {
        return Err(CommandDiagnostic::new(
            CommandDiagnosticKind::InvalidSyntax,
            "unterminated quoted string",
        ));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn is_known_later_command(value: &str) -> bool {
    matches!(
        value,
        "trace" | "diff" | "firmware" | "crash" | "protocol" | "memory" | "graph"
    )
}

fn command_query_error(err: QueryError) -> CommandDiagnostic {
    CommandDiagnostic::new(CommandDiagnosticKind::QueryFailed, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::{InMemoryObjectGraph, ObjectSummary},
        EdgeKind, StableObjectKey,
    };

    fn artifact_key() -> StableObjectKey {
        StableObjectKeyBuilder::new(ObjectKind::Artifact)
            .component("sha256", "abc123")
            .unwrap()
            .component("path", "fixture")
            .unwrap()
            .finish()
            .unwrap()
    }

    fn object(kind: ObjectKind, name: &str, address: u64) -> ObjectRef {
        let artifact = artifact_key();
        let key = match kind {
            ObjectKind::Function => {
                StableObjectKey::function(&artifact, address, Some(16), Some(name))
            }
            ObjectKind::String => StableObjectKey::string(&artifact, address, Some(address), name),
            ObjectKind::Import => StableObjectKey::import(&artifact, None, name, None),
            ObjectKind::Xref => {
                let function = ObjectRef::new(
                    ObjectKind::Function,
                    StableObjectKey::function(&artifact, 0x401000, Some(16), Some("main")).unwrap(),
                );
                let import = ObjectRef::new(
                    ObjectKind::Import,
                    StableObjectKey::import(&artifact, None, "system", None).unwrap(),
                );
                StableObjectKey::xref(
                    &artifact,
                    &function,
                    &import,
                    EdgeKind::CallsImport.as_str(),
                    Some(address),
                )
            }
            _ => StableObjectKeyBuilder::new(kind)
                .component("name", name)
                .unwrap()
                .finish(),
        }
        .unwrap();
        ObjectRef::new(kind, key)
    }

    fn graph_with_system_collision() -> InMemoryObjectGraph {
        let string = object(ObjectKind::String, "system", 0x402000);
        let import = object(ObjectKind::Import, "system", 0);
        InMemoryObjectGraph::new()
            .add_object(ObjectSummary::new(string, "system"))
            .add_object(ObjectSummary::new(import, "system"))
    }

    #[test]
    fn command_parser_accepts_mvp_commands() {
        assert!(matches!(
            CommandParser::parse(":find string password").unwrap(),
            CommandAst::Find {
                kind: Some(ObjectKind::String),
                ..
            }
        ));
        assert!(matches!(
            CommandParser::parse(":xrefs system").unwrap(),
            CommandAst::Xrefs { .. }
        ));
        assert!(matches!(
            CommandParser::parse(":note current \"check auth path\"").unwrap(),
            CommandAst::Note { .. }
        ));
        assert!(matches!(
            CommandParser::parse(":finding new high \"command execution\"").unwrap(),
            CommandAst::FindingNew { .. }
        ));
        assert!(matches!(
            CommandParser::parse(":export markdown report.md").unwrap(),
            CommandAst::Export {
                format: ExportFormat::Markdown,
                ..
            }
        ));
    }

    #[test]
    fn command_parser_reports_invalid_input() {
        assert_eq!(
            CommandParser::parse(":").unwrap_err().kind,
            CommandDiagnosticKind::MissingArgument
        );
        assert_eq!(
            CommandParser::parse(":wat").unwrap_err().kind,
            CommandDiagnosticKind::UnknownCommand
        );
        assert_eq!(
            CommandParser::parse(":note current \"unterminated")
                .unwrap_err()
                .kind,
            CommandDiagnosticKind::InvalidSyntax
        );
    }

    #[test]
    fn command_resolver_reports_ambiguous_and_broken_targets() {
        let graph = graph_with_system_collision();
        let resolver = CommandResolver::new(&graph);
        let state = CommandState::default();
        let err = resolver
            .resolve(CommandParser::parse(":open system").unwrap(), &state)
            .unwrap_err();
        assert_eq!(err.kind, CommandDiagnosticKind::Ambiguous);
        assert_eq!(err.candidates.len(), 2);

        let broken = object(ObjectKind::Function, "missing", 0x401100);
        let err = resolver
            .resolve(
                CommandAst::Open {
                    target: CommandTarget::Ref(broken),
                },
                &state,
            )
            .unwrap_err();
        assert_eq!(err.kind, CommandDiagnosticKind::BrokenObject);

        let err = resolver
            .resolve(CommandParser::parse(":trace current").unwrap(), &state)
            .unwrap_err();
        assert_eq!(err.kind, CommandDiagnosticKind::UnsupportedInV01);
    }

    #[test]
    fn command_resolver_accepts_session_finding_draft_refs() {
        let graph = InMemoryObjectGraph::new();
        let resolver = CommandResolver::new(&graph);
        let mut state = CommandState::default();
        CommandExecutor::execute(
            &mut state,
            ResolvedCommand::FindingNew {
                severity: "high".to_string(),
                title: "command execution".to_string(),
            },
        )
        .unwrap();
        let draft = state.findings.keys().next().cloned().unwrap();

        let resolved = resolver
            .resolve(
                CommandAst::Open {
                    target: CommandTarget::Ref(draft.clone()),
                },
                &state,
            )
            .unwrap();

        assert_eq!(resolved, ResolvedCommand::Open { target: draft });
    }

    #[test]
    fn command_executor_no_mutation_on_error() {
        let graph = graph_with_system_collision();
        let resolver = CommandResolver::new(&graph);
        let mut state = CommandState::default();
        let before = state.clone();
        let ast = CommandParser::parse(":tag system suspicious").unwrap();
        let resolved = resolver.resolve(ast, &state);
        assert_eq!(resolved.unwrap_err().kind, CommandDiagnosticKind::Ambiguous);
        assert_eq!(state, before);

        let err = CommandExecutor::execute(&mut state, ResolvedCommand::Back).unwrap_err();
        assert_eq!(err.kind, CommandDiagnosticKind::Unresolved);
        assert_eq!(state, before);
    }
}
