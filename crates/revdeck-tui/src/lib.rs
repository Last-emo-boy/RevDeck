use anyhow::Context;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use revdeck_core::{
    pre_export_validation, render_json, render_markdown, CommandDiagnostic, CommandDiagnosticKind,
    CommandExecutor, CommandOutcome, CommandParser, CommandResolver, CommandState, ExportFormat,
    Finding, FindingEvidence, FindingSeverity, FindingStatus, FunctionRadarFilter,
    FunctionRadarViewModel, FunctionScore, InspectorViewModel, NavigationEntry, NavigationLens,
    ObjectGraphQuery, ObjectKind, ObjectRef, ObjectRelation, ObjectSearch, ObjectSummary,
    RelationDirection, ResolvedCommand, StableObjectKey, TriageBoardViewModel,
};
use revdeck_db::{
    ArtifactRepository, FindingRepository, IndexRepository, MemoryRepository,
    ObjectQueryRepository, ProjectDatabase, RadarRepository,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
    time::Duration,
};
use time::OffsetDateTime;

pub const WORKSPACE_LENSES: [NavigationLens; 10] = [
    NavigationLens::Overview,
    NavigationLens::TriageBoard,
    NavigationLens::BinaryMap,
    NavigationLens::FunctionRadar,
    NavigationLens::LocalGraph,
    NavigationLens::Functions,
    NavigationLens::Strings,
    NavigationLens::Imports,
    NavigationLens::Notes,
    NavigationLens::Findings,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneFocus {
    Workspace,
    Main,
    Inspector,
}

const PANE_FOCUS_ORDER: [PaneFocus; 3] =
    [PaneFocus::Workspace, PaneFocus::Main, PaneFocus::Inspector];

#[derive(Debug, Clone)]
pub struct WorkspaceSnapshot {
    pub overview: revdeck_core::OverviewViewModel,
    pub triage: TriageBoardViewModel,
    pub radar: FunctionRadarViewModel,
    pub scores: Vec<FunctionScore>,
    pub functions: Vec<ObjectSummary>,
    pub strings: Vec<ObjectSummary>,
    pub imports: Vec<ObjectSummary>,
    pub annotations: Vec<ObjectSummary>,
    pub findings: Vec<Finding>,
    pub objects: BTreeMap<ObjectRef, ObjectSummary>,
    pub relations_by_object: BTreeMap<ObjectRef, Vec<ObjectRelation>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersistSessionSummary {
    pub annotations: usize,
    pub findings: usize,
    pub exports: usize,
}

impl WorkspaceSnapshot {
    pub fn empty() -> Self {
        let overview = revdeck_core::OverviewViewModel::new(None, "No project loaded", "closed");
        let triage = TriageBoardViewModel::from_overview_and_scores(&overview, &[]);
        let radar = FunctionRadarViewModel::from_scores(None, &[], &FunctionRadarFilter::default());
        Self {
            overview,
            triage,
            radar,
            scores: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            imports: Vec::new(),
            annotations: Vec::new(),
            findings: Vec::new(),
            objects: BTreeMap::new(),
            relations_by_object: BTreeMap::new(),
        }
    }

    pub fn load_from_project(project: &ProjectDatabase) -> anyhow::Result<Self> {
        let connection = project.connection();
        let query = ObjectQueryRepository::new(connection);
        let artifacts = query
            .search_objects(&ObjectSearch::new(Some(ObjectKind::Artifact), "").with_limit(32))
            .map_err(|err| anyhow::anyhow!(err))?;
        let Some(artifact_summary) = artifacts.first().cloned() else {
            return Ok(Self::empty());
        };
        let artifact_ref = artifact_summary.object_ref.clone();
        let artifact = ArtifactRepository::new(connection)
            .get_artifact(&artifact_ref)
            .context("failed to load artifact metadata")?;
        let index_repo = IndexRepository::new(connection);
        let finding_repo = FindingRepository::new(connection);
        let findings = finding_repo
            .list_findings()
            .context("failed to load findings")?;
        let scores = RadarRepository::new(connection)
            .load_function_scores(&artifact_ref)
            .context("failed to load Function Radar scores")?;
        let radar = FunctionRadarViewModel::from_scores(
            Some(artifact_ref.clone()),
            &scores,
            &FunctionRadarFilter {
                include_zero_score: true,
                ..FunctionRadarFilter::default()
            },
        );
        let analysis_status = index_repo
            .latest_analysis_run(&artifact_ref)
            .context("failed to load latest analysis run")?
            .map(|run| run.status);
        let section_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::Section)
            .context("failed to count sections")? as usize;
        let function_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::Function)
            .context("failed to count functions")? as usize;
        let string_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::String)
            .context("failed to count strings")? as usize;
        let import_count = index_repo
            .count_kind(&artifact_ref, ObjectKind::Import)
            .context("failed to count imports")? as usize;
        let artifact_label = artifact
            .as_ref()
            .map(|artifact| artifact.display_name.clone())
            .or_else(|| artifact_summary.display_name.clone())
            .unwrap_or_else(|| artifact_ref.key.to_string());
        let import_status = artifact
            .as_ref()
            .map(|artifact| artifact.import_status.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let mut overview = revdeck_core::OverviewViewModel::new(
            Some(artifact_ref.clone()),
            artifact_label,
            import_status,
        )
        .with_counts(
            section_count,
            function_count,
            string_count,
            import_count,
            findings.len(),
        )
        .with_top_functions(&scores, 5);
        overview.analysis_status = analysis_status;
        overview
            .degraded_indexing_warnings
            .extend(radar.warnings.iter().cloned());
        let triage = TriageBoardViewModel::from_overview_and_scores(&overview, &scores);

        let functions = search_kind(&query, ObjectKind::Function, 500)?;
        let basic_blocks = search_kind(&query, ObjectKind::BasicBlock, 1000)?;
        let instructions = search_kind(&query, ObjectKind::Instruction, 1000)?;
        let strings = search_kind(&query, ObjectKind::String, 500)?;
        let imports = search_kind(&query, ObjectKind::Import, 500)?;
        let annotations = search_kind(&query, ObjectKind::Annotation, 500)?;
        let finding_objects = search_kind(&query, ObjectKind::Finding, 500)?;

        let mut objects = BTreeMap::new();
        for object in artifacts
            .into_iter()
            .chain(functions.iter().cloned())
            .chain(basic_blocks.into_iter())
            .chain(instructions.into_iter())
            .chain(strings.iter().cloned())
            .chain(imports.iter().cloned())
            .chain(annotations.iter().cloned())
            .chain(finding_objects.into_iter())
        {
            objects.insert(object.object_ref.clone(), object);
        }

        let mut relation_targets = objects.keys().cloned().collect::<BTreeSet<_>>();
        for score in &scores {
            relation_targets.insert(score.function_ref.clone());
            for reason in &score.reasons {
                relation_targets.extend(reason.evidence_refs.iter().cloned());
            }
        }
        let mut relations_by_object = BTreeMap::new();
        for object_ref in relation_targets {
            let relations = query
                .relations(&object_ref, RelationDirection::Both, None)
                .map_err(|err| anyhow::anyhow!(err))?;
            if !relations.is_empty() {
                relations_by_object.insert(object_ref, relations);
            }
        }

        Ok(Self {
            overview,
            triage,
            radar,
            scores,
            functions,
            strings,
            imports,
            annotations,
            findings,
            objects,
            relations_by_object,
        })
    }

    pub fn demo() -> Self {
        use revdeck_core::{EdgeKind, FunctionScoreInput, RadarEvidence, StableObjectKeyBuilder};

        let artifact = ObjectRef::artifact("abc123", "fixtures/sensitive_imports_elf")
            .expect("demo artifact ref");
        let function = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, 0x401000, Some(128), Some("main"))
                .expect("demo function ref"),
        );
        let import = ObjectRef::new(
            ObjectKind::Import,
            StableObjectKey::import(&artifact.key, Some("libc.so.6"), "system", None)
                .expect("demo import ref"),
        );
        let string = ObjectRef::new(
            ObjectKind::String,
            StableObjectKey::string(&artifact.key, 0x200, Some(0x402000), "admin password")
                .expect("demo string ref"),
        );
        let mut input = FunctionScoreInput::new(artifact.clone(), function.clone(), "main");
        input.virtual_address = Some(0x401000);
        input.size = Some(128);
        input.boundary_source = "symbol".to_string();
        input.boundary_confidence = "symbol".to_string();
        input.entrypoint = Some(0x401000);
        input.call_count = 2;
        input.string_count = 1;
        input.called_imports.push(RadarEvidence::new(
            import.clone(),
            "libc.so.6!system",
            "system",
        ));
        input.referenced_strings.push(RadarEvidence::new(
            string.clone(),
            "admin password",
            "admin password",
        ));
        let scores = revdeck_core::score_functions(vec![input]);
        let radar = FunctionRadarViewModel::from_scores(
            Some(artifact.clone()),
            &scores,
            &FunctionRadarFilter {
                include_zero_score: true,
                ..FunctionRadarFilter::default()
            },
        );
        let overview = revdeck_core::OverviewViewModel::new(
            Some(artifact.clone()),
            "sensitive_imports_elf",
            "indexed",
        )
        .with_counts(3, 1, 1, 1, 0)
        .with_top_functions(&scores, 5);
        let triage = TriageBoardViewModel::from_overview_and_scores(&overview, &scores);
        let mut function_summary = summary(function.clone(), "main", Some(0x401000), Some(128));
        function_summary.metadata_json = serde_json::json!({
            "boundary_source": "symbol",
            "boundary_confidence": "symbol",
            "frame_pointer": "rbp",
            "stack_frame_size": 32,
            "stack_cleanup_size": 32,
            "epilogue_kind": "stack-add-pop-rbp",
            "has_frame_epilogue": true,
            "calling_convention": "windows-x64",
            "argument_registers": [
                {"ordinal": 0, "register": "rcx"}
            ],
            "stack_slots": [
                {"base": "rbp", "offset": -8, "width_bits": 64, "accesses": ["read", "write"]}
            ]
        })
        .to_string();
        let functions = vec![function_summary];
        let strings = vec![summary(
            string.clone(),
            "admin password",
            Some(0x402000),
            Some(14),
        )];
        let imports = vec![summary(import.clone(), "system", None, None)];
        let mut objects = BTreeMap::new();
        for object in [
            summary(artifact.clone(), "sensitive_imports_elf", None, None),
            functions[0].clone(),
            strings[0].clone(),
            imports[0].clone(),
        ] {
            objects.insert(object.object_ref.clone(), object);
        }
        let edge_ref = ObjectRef::new(
            ObjectKind::Edge,
            StableObjectKeyBuilder::new(ObjectKind::Edge)
                .component("edge_kind", EdgeKind::CallsImport.as_str())
                .and_then(|builder| builder.component("source", function.key.as_str()))
                .and_then(|builder| builder.component("target", import.key.as_str()))
                .and_then(|builder| builder.finish())
                .expect("demo edge ref"),
        );
        let relation = ObjectRelation {
            edge_ref,
            source: function.clone(),
            target: import,
            kind: EdgeKind::CallsImport,
            confidence: 1.0,
            metadata_json: "{}".to_string(),
        };
        let mut relations_by_object = BTreeMap::new();
        relations_by_object.insert(function, vec![relation]);
        Self {
            overview,
            triage,
            radar,
            scores,
            functions,
            strings,
            imports,
            annotations: Vec::new(),
            findings: Vec::new(),
            objects,
            relations_by_object,
        }
    }

    pub fn rows_for_lens(&self, lens: NavigationLens) -> Vec<ObjectRef> {
        match lens {
            NavigationLens::Overview | NavigationLens::BinaryMap => {
                self.overview.artifact.iter().cloned().collect()
            }
            NavigationLens::TriageBoard => self
                .triage
                .rows
                .iter()
                .map(|row| row.target.clone())
                .collect(),
            NavigationLens::FunctionRadar => self
                .radar
                .rows
                .iter()
                .map(|row| row.function_ref.clone())
                .collect(),
            NavigationLens::Functions => self
                .functions
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Strings => self
                .strings
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Imports => self
                .imports
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Notes => self
                .annotations
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Findings => self
                .findings
                .iter()
                .map(|item| item.object_ref.clone())
                .collect(),
            NavigationLens::Inspector | NavigationLens::LocalGraph => Vec::new(),
        }
    }

    pub fn object_label(&self, object_ref: &ObjectRef) -> String {
        self.objects
            .get(object_ref)
            .map(|object| object.label().to_string())
            .or_else(|| {
                self.findings
                    .iter()
                    .find(|finding| finding.object_ref == *object_ref)
                    .map(|finding| finding.title.clone())
            })
            .unwrap_or_else(|| short_ref(object_ref))
    }

    pub fn score_for(&self, object_ref: &ObjectRef) -> Option<&FunctionScore> {
        self.scores
            .iter()
            .find(|score| score.function_ref == *object_ref)
    }

    pub fn inspector_for(&self, selected: Option<&ObjectRef>) -> Option<InspectorViewModel> {
        let selected = selected?;
        if let Some(score) = self.score_for(selected) {
            Some(InspectorViewModel::for_function(score))
        } else {
            Some(InspectorViewModel::for_object(
                selected.clone(),
                self.object_label(selected),
            ))
        }
    }

    pub fn relations_for(&self, selected: &ObjectRef) -> &[ObjectRelation] {
        self.relations_by_object
            .get(selected)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn relations_for_selected(&self, selected: Option<&ObjectRef>) -> &[ObjectRelation] {
        selected
            .and_then(|object_ref| self.relations_by_object.get(object_ref))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiAction {
    SwitchLens(NavigationLens),
    NextLens,
    PreviousLens,
    FocusNextPane,
    FocusPreviousPane,
    FocusRightPane,
    FocusLeftPane,
    FocusPane(PaneFocus),
    NextRow,
    PreviousRow,
    ActivateSelection,
    NavigateTo(ObjectRef),
    NavigateToReasonEvidence {
        reason_index: usize,
        evidence_index: usize,
    },
    Back,
    Forward,
    ToggleHelp,
    ToggleCommandDeck,
    EnterCommandMode,
    ExitCommandMode,
    PushCommandChar(char),
    BackspaceCommand,
    Quit,
}

#[derive(Debug, Clone)]
pub struct TuiShellState {
    pub selected: Option<ObjectRef>,
    pub active_lens: NavigationLens,
    pub focus: PaneFocus,
    pub nav_index: usize,
    pub main_cursor: usize,
    pub inspector_cursor: usize,
    pub inspector_scroll: u16,
    pub command_mode: bool,
    pub command_input: String,
    pub command_state: CommandState,
    pub status_line: String,
    pub last_error: Option<CommandDiagnostic>,
    pub show_help: bool,
    pub show_command_deck: bool,
    pub should_quit: bool,
}

impl Default for TuiShellState {
    fn default() -> Self {
        Self {
            selected: None,
            active_lens: NavigationLens::Overview,
            focus: PaneFocus::Main,
            nav_index: 0,
            main_cursor: 0,
            inspector_cursor: 0,
            inspector_scroll: 0,
            command_mode: false,
            command_input: String::new(),
            command_state: CommandState::default(),
            status_line: "ready".to_string(),
            last_error: None,
            show_help: false,
            show_command_deck: false,
            should_quit: false,
        }
    }
}

impl TuiShellState {
    pub fn from_snapshot(snapshot: &WorkspaceSnapshot) -> Self {
        let mut state = Self::default();
        state.sync_selection_from_cursor(snapshot);
        state
    }

    pub fn apply_action(
        &mut self,
        action: TuiAction,
        snapshot: &WorkspaceSnapshot,
    ) -> Result<Option<CommandOutcome>, CommandDiagnostic> {
        match action {
            TuiAction::SwitchLens(lens) => {
                self.switch_lens(lens, snapshot);
                Ok(None)
            }
            TuiAction::NextLens => {
                let next = (self.nav_index + 1) % WORKSPACE_LENSES.len();
                self.switch_lens(WORKSPACE_LENSES[next], snapshot);
                Ok(None)
            }
            TuiAction::PreviousLens => {
                let next = if self.nav_index == 0 {
                    WORKSPACE_LENSES.len() - 1
                } else {
                    self.nav_index - 1
                };
                self.switch_lens(WORKSPACE_LENSES[next], snapshot);
                Ok(None)
            }
            TuiAction::FocusNextPane => {
                self.focus_next_pane(1);
                Ok(None)
            }
            TuiAction::FocusPreviousPane => {
                self.focus_next_pane(-1);
                Ok(None)
            }
            TuiAction::FocusRightPane => {
                self.focus_directional(1);
                Ok(None)
            }
            TuiAction::FocusLeftPane => {
                self.focus_directional(-1);
                Ok(None)
            }
            TuiAction::FocusPane(focus) => {
                self.focus_pane(focus);
                Ok(None)
            }
            TuiAction::NextRow => {
                self.move_active_cursor(snapshot, 1);
                Ok(None)
            }
            TuiAction::PreviousRow => {
                self.move_active_cursor(snapshot, -1);
                Ok(None)
            }
            TuiAction::ActivateSelection => {
                match self.focus {
                    PaneFocus::Workspace => self.focus_pane(PaneFocus::Main),
                    PaneFocus::Main => {
                        if let Some(selected) = self.selected.clone() {
                            self.navigate_to(selected, snapshot);
                        }
                    }
                    PaneFocus::Inspector => {
                        if let Some(target) = inspector_target_at_cursor(self, snapshot) {
                            self.navigate_to(target, snapshot);
                        }
                    }
                }
                Ok(None)
            }
            TuiAction::NavigateTo(object_ref) => {
                self.navigate_to(object_ref, snapshot);
                Ok(None)
            }
            TuiAction::NavigateToReasonEvidence {
                reason_index,
                evidence_index,
            } => {
                let selected = self.selected.as_ref().ok_or_else(|| {
                    CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        "no current object is selected",
                    )
                })?;
                let score = snapshot.score_for(selected).ok_or_else(|| {
                    CommandDiagnostic::new(
                        CommandDiagnosticKind::Unresolved,
                        "selected object has no Function Radar score",
                    )
                })?;
                let target = score
                    .reasons
                    .get(reason_index)
                    .and_then(|reason| reason.evidence_refs.get(evidence_index))
                    .cloned()
                    .ok_or_else(|| {
                        CommandDiagnostic::new(
                            CommandDiagnosticKind::Unresolved,
                            "score reason evidence target is missing",
                        )
                    })?;
                self.navigate_to(target, snapshot);
                Ok(None)
            }
            TuiAction::Back => {
                let outcome =
                    CommandExecutor::execute(&mut self.command_state, ResolvedCommand::Back)?;
                self.sync_from_command_state();
                self.status_line = "history back".to_string();
                Ok(Some(outcome))
            }
            TuiAction::Forward => {
                let outcome =
                    CommandExecutor::execute(&mut self.command_state, ResolvedCommand::Forward)?;
                self.sync_from_command_state();
                self.status_line = "history forward".to_string();
                Ok(Some(outcome))
            }
            TuiAction::ToggleHelp => {
                self.show_command_deck = false;
                self.show_help = !self.show_help;
                self.status_line = if self.show_help {
                    "help overlay opened".to_string()
                } else {
                    "help overlay closed".to_string()
                };
                Ok(None)
            }
            TuiAction::ToggleCommandDeck => {
                self.show_help = false;
                self.show_command_deck = !self.show_command_deck;
                self.status_line = if self.show_command_deck {
                    "command deck opened".to_string()
                } else {
                    "command deck closed".to_string()
                };
                Ok(None)
            }
            TuiAction::EnterCommandMode => {
                self.show_help = false;
                self.show_command_deck = false;
                self.command_mode = true;
                self.command_input.clear();
                Ok(None)
            }
            TuiAction::ExitCommandMode => {
                self.command_mode = false;
                self.command_input.clear();
                Ok(None)
            }
            TuiAction::PushCommandChar(ch) => {
                self.command_input.push(ch);
                Ok(None)
            }
            TuiAction::BackspaceCommand => {
                self.command_input.pop();
                Ok(None)
            }
            TuiAction::Quit => {
                self.should_quit = true;
                Ok(None)
            }
        }
    }

    pub fn submit_command(
        &mut self,
        input: &str,
        query: &dyn ObjectGraphQuery,
    ) -> Result<CommandOutcome, CommandDiagnostic> {
        let ast = CommandParser::parse(input)?;
        let resolved = CommandResolver::new(query).resolve(ast, &self.command_state)?;
        let outcome = CommandExecutor::execute(&mut self.command_state, resolved)?;
        self.sync_after_outcome(&outcome);
        self.command_mode = false;
        self.command_input.clear();
        self.last_error = None;
        Ok(outcome)
    }

    pub fn handle_key_event(
        &mut self,
        key: KeyEvent,
        snapshot: &WorkspaceSnapshot,
        query: &dyn ObjectGraphQuery,
    ) -> Result<(), CommandDiagnostic> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.apply_action(TuiAction::Quit, snapshot)?;
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
            self.apply_action(TuiAction::ToggleCommandDeck, snapshot)?;
            return Ok(());
        }
        if self.command_mode {
            match key.code {
                KeyCode::Esc => {
                    self.apply_action(TuiAction::ExitCommandMode, snapshot)?;
                }
                KeyCode::Enter => {
                    let input = self.command_input.clone();
                    if let Err(err) = self.submit_command(&input, query) {
                        self.status_line = err.message.clone();
                        self.last_error = Some(err.clone());
                        return Err(err);
                    }
                }
                KeyCode::Backspace => {
                    self.apply_action(TuiAction::BackspaceCommand, snapshot)?;
                }
                KeyCode::Char(ch) => {
                    self.apply_action(TuiAction::PushCommandChar(ch), snapshot)?;
                }
                _ => {}
            }
            return Ok(());
        }

        if self.show_help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('q') => {
                    self.apply_action(TuiAction::ToggleHelp, snapshot)?;
                }
                _ => {
                    self.status_line = "help overlay open; press ?/h/Esc to close".to_string();
                }
            }
            return Ok(());
        }
        if self.show_command_deck {
            match key.code {
                KeyCode::Esc | KeyCode::Char('p') | KeyCode::Char('q') => {
                    self.apply_action(TuiAction::ToggleCommandDeck, snapshot)?;
                }
                KeyCode::Char(':') => {
                    self.apply_action(TuiAction::EnterCommandMode, snapshot)?;
                }
                _ => {
                    self.status_line = "command deck open; press p/Esc to close".to_string();
                }
            }
            return Ok(());
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.apply_action(TuiAction::Quit, snapshot)?;
            }
            KeyCode::Char('g') => self.switch_lens(NavigationLens::TriageBoard, snapshot),
            KeyCode::Char('G') => self.switch_lens(NavigationLens::LocalGraph, snapshot),
            KeyCode::Char('?') | KeyCode::Char('h') => {
                self.apply_action(TuiAction::ToggleHelp, snapshot)?;
            }
            KeyCode::Char('p') => {
                self.apply_action(TuiAction::ToggleCommandDeck, snapshot)?;
            }
            KeyCode::Char(':') => {
                self.apply_action(TuiAction::EnterCommandMode, snapshot)?;
            }
            KeyCode::Tab => {
                self.apply_action(TuiAction::FocusNextPane, snapshot)?;
            }
            KeyCode::BackTab => {
                self.apply_action(TuiAction::FocusPreviousPane, snapshot)?;
            }
            KeyCode::Right => {
                self.apply_action(TuiAction::FocusRightPane, snapshot)?;
            }
            KeyCode::Left => {
                self.apply_action(TuiAction::FocusLeftPane, snapshot)?;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.apply_action(TuiAction::NextRow, snapshot)?;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.apply_action(TuiAction::PreviousRow, snapshot)?;
            }
            KeyCode::Enter => {
                self.apply_action(TuiAction::ActivateSelection, snapshot)?;
            }
            KeyCode::Backspace | KeyCode::Char('[') => {
                if let Err(err) = self.apply_action(TuiAction::Back, snapshot) {
                    self.status_line = err.message.clone();
                    self.last_error = Some(err);
                }
            }
            KeyCode::Char(']') => {
                if let Err(err) = self.apply_action(TuiAction::Forward, snapshot) {
                    self.status_line = err.message.clone();
                    self.last_error = Some(err);
                }
            }
            KeyCode::Char('o') => self.switch_lens(NavigationLens::Overview, snapshot),
            KeyCode::Char('b') => self.switch_lens(NavigationLens::BinaryMap, snapshot),
            KeyCode::Char('r') => self.switch_lens(NavigationLens::FunctionRadar, snapshot),
            KeyCode::Char('f') => self.switch_lens(NavigationLens::Functions, snapshot),
            KeyCode::Char('s') => self.switch_lens(NavigationLens::Strings, snapshot),
            KeyCode::Char('i') => self.switch_lens(NavigationLens::Imports, snapshot),
            KeyCode::Char('n') => self.switch_lens(NavigationLens::Notes, snapshot),
            KeyCode::Char('F') => self.switch_lens(NavigationLens::Findings, snapshot),
            _ => {}
        }
        Ok(())
    }

    pub fn persist_session_to_project(
        &self,
        project: &ProjectDatabase,
    ) -> anyhow::Result<PersistSessionSummary> {
        let now = OffsetDateTime::now_utc();
        self.persist_session_to_connection(
            project.connection(),
            project.info().root_dir.as_path(),
            now,
        )
    }

    pub fn persist_session_to_connection(
        &self,
        connection: &rusqlite::Connection,
        project_root: &Path,
        now: OffsetDateTime,
    ) -> anyhow::Result<PersistSessionSummary> {
        let mut summary = PersistSessionSummary::default();
        let memory = MemoryRepository::new(connection);
        for (object_ref, tags) in &self.command_state.tags {
            for tag in tags {
                memory
                    .upsert_tag(object_ref, tag, now, now)
                    .context("failed to persist tag")?;
                summary.annotations += 1;
            }
        }
        for (object_ref, notes) in &self.command_state.notes {
            for note in notes {
                memory
                    .upsert_note(object_ref, note, now, now, Vec::new())
                    .context("failed to persist note")?;
                summary.annotations += 1;
            }
        }
        for (object_ref, renamed_to) in &self.command_state.renames {
            memory
                .upsert_rename(object_ref, renamed_to, now, now)
                .context("failed to persist rename")?;
            summary.annotations += 1;
        }
        for (object_ref, status) in &self.command_state.statuses {
            memory
                .upsert_status(object_ref, status, now, now)
                .context("failed to persist status")?;
            summary.annotations += 1;
        }

        let finding_repo = FindingRepository::new(connection);
        for draft in self.command_state.findings.values() {
            let severity = draft
                .severity
                .parse::<FindingSeverity>()
                .map_err(|err| anyhow::anyhow!(err))?;
            let evidence = self
                .command_state
                .finding_links
                .iter()
                .filter(|link| link.finding == draft.object_ref)
                .enumerate()
                .map(|(index, link)| {
                    FindingEvidence::new(
                        link.evidence.clone(),
                        link.role.clone(),
                        index as u64,
                        "linked from TUI session",
                        None,
                    )
                })
                .collect::<Vec<_>>();
            let finding = Finding {
                object_ref: draft.object_ref.clone(),
                title: draft.title.clone(),
                severity,
                status: FindingStatus::Draft,
                summary: draft.title.clone(),
                body: String::new(),
                tags: Vec::new(),
                evidence,
                created_at: now,
                updated_at: now,
            };
            finding_repo
                .upsert_finding(&finding)
                .context("failed to persist finding")?;
            summary.findings += 1;
        }

        for request in &self.command_state.export_requests {
            let context = finding_repo
                .export_context(now)
                .context("failed to load export context")?;
            pre_export_validation(&context).map_err(|err| {
                anyhow::anyhow!(
                    "{}",
                    serde_json::to_string_pretty(&err.report).unwrap_or_else(|_| err.to_string())
                )
            })?;
            let rendered = match request.format {
                ExportFormat::Markdown => render_markdown(&context),
                ExportFormat::Json => {
                    render_json(&context).context("failed to render JSON report")?
                }
            };
            let path = project_root.join(&request.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create export directory {}", parent.display())
                })?;
            }
            std::fs::write(&path, rendered)
                .with_context(|| format!("failed to write export {}", path.display()))?;
            summary.exports += 1;
        }

        Ok(summary)
    }

    fn switch_lens(&mut self, lens: NavigationLens, snapshot: &WorkspaceSnapshot) {
        self.active_lens = lens;
        if let Some(index) = WORKSPACE_LENSES
            .iter()
            .position(|candidate| *candidate == lens)
        {
            self.nav_index = index;
        }
        self.main_cursor = 0;
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
        self.command_state.current_lens = lens;
        self.sync_selection_from_cursor(snapshot);
        self.status_line = format!("lens {}", lens_label(lens));
    }

    fn focus_next_pane(&mut self, delta: isize) {
        let index = PANE_FOCUS_ORDER
            .iter()
            .position(|candidate| *candidate == self.focus)
            .unwrap_or(0) as isize;
        let next = (index + delta).rem_euclid(PANE_FOCUS_ORDER.len() as isize) as usize;
        self.focus_pane(PANE_FOCUS_ORDER[next]);
    }

    fn focus_directional(&mut self, delta: isize) {
        if delta > 0 {
            if self.focus == PaneFocus::Inspector {
                self.focus_pane(PaneFocus::Inspector);
            } else {
                self.focus_next_pane(1);
            }
        } else if self.focus == PaneFocus::Workspace {
            self.focus_pane(PaneFocus::Workspace);
        } else {
            self.focus_next_pane(-1);
        }
    }

    fn focus_pane(&mut self, focus: PaneFocus) {
        self.focus = focus;
        if self.focus != PaneFocus::Inspector {
            self.inspector_scroll = 0;
        }
        self.status_line = format!("focus {}", pane_focus_label(focus));
    }

    fn move_active_cursor(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        match self.focus {
            PaneFocus::Workspace => self.move_workspace_lens(snapshot, delta),
            PaneFocus::Main => self.move_row(snapshot, delta),
            PaneFocus::Inspector => self.move_inspector(snapshot, delta),
        }
    }

    fn move_workspace_lens(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        let len = WORKSPACE_LENSES.len() as isize;
        let next = (self.nav_index as isize + delta).rem_euclid(len) as usize;
        self.switch_lens(WORKSPACE_LENSES[next], snapshot);
    }

    fn move_row(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        let rows = snapshot.rows_for_lens(self.active_lens);
        if rows.is_empty() {
            self.main_cursor = 0;
            self.selected = None;
            self.command_state.current_object = None;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let len = rows.len() as isize;
        let next = (self.main_cursor as isize + delta).rem_euclid(len) as usize;
        self.main_cursor = next;
        self.selected = rows.get(next).cloned();
        self.command_state.current_object = self.selected.clone();
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
    }

    fn move_inspector(&mut self, snapshot: &WorkspaceSnapshot, delta: isize) {
        let indices = inspector_focusable_indices(self, snapshot);
        if indices.is_empty() {
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let next = if let Some(current) = indices
            .iter()
            .position(|index| *index == self.inspector_cursor)
        {
            (current as isize + delta).rem_euclid(indices.len() as isize) as usize
        } else if delta >= 0 {
            0
        } else {
            indices.len() - 1
        };
        self.inspector_cursor = indices[next];
        self.inspector_scroll = self.inspector_cursor.saturating_sub(1) as u16;
    }

    fn sync_selection_from_cursor(&mut self, snapshot: &WorkspaceSnapshot) {
        if self.active_lens == NavigationLens::LocalGraph && self.selected.is_some() {
            self.command_state.current_object = self.selected.clone();
            self.command_state.current_lens = self.active_lens;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
            return;
        }
        let rows = snapshot.rows_for_lens(self.active_lens);
        if rows.is_empty() {
            self.main_cursor = 0;
            self.selected = None;
            self.inspector_cursor = 0;
            self.inspector_scroll = 0;
        } else {
            if self.main_cursor >= rows.len() {
                self.main_cursor = rows.len() - 1;
            }
            self.selected = rows.get(self.main_cursor).cloned();
        }
        self.command_state.current_object = self.selected.clone();
        self.command_state.current_lens = self.active_lens;
    }

    fn navigate_to(&mut self, object_ref: ObjectRef, snapshot: &WorkspaceSnapshot) {
        let lens = NavigationLens::for_object_kind(object_ref.kind);
        self.command_state
            .navigation
            .navigate_to(NavigationEntry::new(lens, object_ref.clone()));
        self.command_state.current_lens = lens;
        self.command_state.current_object = Some(object_ref.clone());
        self.active_lens = lens;
        if let Some(index) = WORKSPACE_LENSES
            .iter()
            .position(|candidate| *candidate == lens)
        {
            self.nav_index = index;
        }
        self.selected = Some(object_ref.clone());
        self.main_cursor = cursor_for_selection(snapshot, lens, &object_ref).unwrap_or(0);
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
        self.status_line = format!("opened {}", short_ref(&object_ref));
    }

    fn sync_after_outcome(&mut self, outcome: &CommandOutcome) {
        match outcome {
            CommandOutcome::SearchResults(matches) => {
                self.main_cursor = 0;
                self.status_line = format!("{} search results", matches.len());
            }
            CommandOutcome::Xrefs(relations) => {
                self.status_line = format!("{} relations", relations.len());
            }
            CommandOutcome::Navigated(object_ref) | CommandOutcome::Mutated(object_ref) => {
                self.selected = Some(object_ref.clone());
                self.active_lens = self.command_state.current_lens;
                if let Some(index) = WORKSPACE_LENSES
                    .iter()
                    .position(|candidate| *candidate == self.active_lens)
                {
                    self.nav_index = index;
                }
                self.inspector_cursor = 0;
                self.inspector_scroll = 0;
                self.status_line = format!("updated {}", short_ref(object_ref));
            }
            CommandOutcome::FindingCreated(object_ref) => {
                self.selected = Some(object_ref.clone());
                self.active_lens = NavigationLens::Findings;
                self.nav_index = WORKSPACE_LENSES
                    .iter()
                    .position(|candidate| *candidate == NavigationLens::Findings)
                    .unwrap_or(self.nav_index);
                self.inspector_cursor = 0;
                self.inspector_scroll = 0;
                self.status_line = format!("finding draft {}", short_ref(object_ref));
            }
            CommandOutcome::FindingLinked(link) => {
                self.status_line = format!(
                    "linked {} -> {}",
                    short_ref(&link.finding),
                    short_ref(&link.evidence)
                );
            }
            CommandOutcome::ExportRequested(request) => {
                self.status_line = format!(
                    "export queued {} {}",
                    export_format_label(&request.format),
                    request.path
                );
            }
            CommandOutcome::Help(topic) => {
                self.status_line = topic
                    .as_ref()
                    .map(|topic| format!("help {topic}"))
                    .unwrap_or_else(|| {
                        "help: find xrefs open tag note rename status finding export".to_string()
                    });
            }
        }
    }

    fn sync_from_command_state(&mut self) {
        self.selected = self.command_state.current_object.clone();
        self.active_lens = self.command_state.current_lens;
        if let Some(index) = WORKSPACE_LENSES
            .iter()
            .position(|candidate| *candidate == self.active_lens)
        {
            self.nav_index = index;
        }
        self.inspector_cursor = 0;
        self.inspector_scroll = 0;
    }
}

pub fn run_project_tui(project_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let project = ProjectDatabase::open_existing(project_dir.as_ref()).with_context(|| {
        format!(
            "failed to open project at {}",
            project_dir.as_ref().display()
        )
    })?;
    let snapshot = WorkspaceSnapshot::load_from_project(&project)?;
    let mut app = TuiShellState::from_snapshot(&snapshot);
    let query = ObjectQueryRepository::new(project.connection());

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    let result = run_terminal_app(&mut terminal, &mut app, &snapshot, &query);
    let restore_result = restore_terminal(&mut terminal);
    result.and(restore_result)?;
    let summary = app.persist_session_to_project(&project)?;
    if summary.annotations > 0 || summary.findings > 0 || summary.exports > 0 {
        println!(
            "persisted annotations={} findings={} exports={}",
            summary.annotations, summary.findings, summary.exports
        );
    }
    Ok(())
}

pub fn run_terminal_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiShellState,
    snapshot: &WorkspaceSnapshot,
    query: &dyn ObjectGraphQuery,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| render_workspace(frame, app, snapshot))?;
        if app.should_quit {
            return Ok(());
        }
        if event::poll(Duration::from_millis(200)).context("failed to poll terminal events")? {
            if let Event::Key(key) = event::read().context("failed to read terminal event")? {
                if key.kind == KeyEventKind::Press {
                    let _ = app.handle_key_event(key, snapshot, query);
                }
            }
        }
    }
}

pub fn render_workspace(frame: &mut Frame<'_>, app: &TuiShellState, snapshot: &WorkspaceSnapshot) {
    let area = frame.size();
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(5),
        ])
        .split(area);
    render_header(frame, vertical[0], app, snapshot);
    if vertical[1].height < 10 || vertical[1].width < 72 {
        render_stacked_body(frame, vertical[1], app, snapshot);
    } else {
        render_three_pane_body(frame, vertical[1], app, snapshot);
    }
    render_command_bar(frame, vertical[2], app, snapshot);
    if app.show_help {
        render_help_overlay(frame, area, app, snapshot);
    }
    if app.show_command_deck {
        render_command_deck_overlay(frame, area, app, snapshot);
    }
}

fn render_header(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    let analysis_status = snapshot
        .overview
        .analysis_status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let line = Line::from(vec![
        Span::styled(
            " RevDeck ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            snapshot.overview.artifact_label.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  |  analysis={} import={}  |  view={} focus={}  funcs={} strings={} imports={} findings={}  |  selected={}",
            analysis_status,
            snapshot.overview.import_status,
            lens_label(app.active_lens),
            pane_focus_label(app.focus),
            snapshot.overview.function_count,
            snapshot.overview.string_count,
            snapshot.overview.import_count,
            snapshot.overview.finding_count,
            truncate(&selected, 34)
        )),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .title("Cockpit")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn render_help_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let width = area.width.saturating_sub(8).min(92);
    let height = area.height.saturating_sub(2).min(25);
    if width < 44 || height < 12 {
        return;
    }
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let overlay = Rect {
        x,
        y,
        width,
        height,
    };
    let lines = help_overlay_lines(app, snapshot);
    frame.render_widget(Clear, overlay);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Command Deck - ? / h closes")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta)),
            )
            .wrap(Wrap { trim: true }),
        overlay,
    );
}

fn render_command_deck_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let width = area.width.saturating_sub(10).min(88);
    let height = area.height.saturating_sub(4).min(22);
    if width < 48 || height < 12 {
        return;
    }
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let overlay = Rect {
        x,
        y,
        width,
        height,
    };
    frame.render_widget(Clear, overlay);
    frame.render_widget(
        Paragraph::new(command_deck_lines(app, snapshot))
            .block(
                Block::default()
                    .title("Command Deck - p / Esc closes, : edits command")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: true }),
        overlay,
    );
}

fn render_three_pane_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(20),
            Constraint::Min(40),
            Constraint::Length(32),
        ])
        .split(area);
    render_workspace_nav(frame, chunks[0], app);
    render_main_view(frame, chunks[1], app, snapshot);
    render_inspector(frame, chunks[2], app, snapshot);
}

fn render_stacked_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(5),
        ])
        .split(area);
    render_workspace_nav(frame, chunks[0], app);
    render_main_view(frame, chunks[1], app, snapshot);
    render_inspector(frame, chunks[2], app, snapshot);
}

fn render_workspace_nav(frame: &mut Frame<'_>, area: Rect, app: &TuiShellState) {
    let items = WORKSPACE_LENSES
        .iter()
        .enumerate()
        .map(|(index, lens)| {
            let marker = if index == app.nav_index { ">>" } else { "  " };
            let badge = lens_badge(*lens);
            ListItem::new(format!("{marker} {badge:<3} {}", lens_label(*lens))).style(
                if app.focus == PaneFocus::Workspace && index == app.nav_index {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else if index == app.nav_index {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            focused_block(app, PaneFocus::Workspace, "Workspace - lenses".to_string())
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_main_view(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    match app.active_lens {
        NavigationLens::Overview => render_overview(frame, area, app, snapshot),
        NavigationLens::TriageBoard => render_triage_board(frame, area, app, snapshot),
        NavigationLens::BinaryMap => render_binary_map(frame, area, app, snapshot),
        NavigationLens::FunctionRadar => render_function_radar(frame, area, app, snapshot),
        NavigationLens::Functions => {
            render_object_list(frame, area, "Functions", &snapshot.functions, app)
        }
        NavigationLens::Strings => {
            render_object_list(frame, area, "Strings", &snapshot.strings, app)
        }
        NavigationLens::Imports => {
            render_object_list(frame, area, "Imports", &snapshot.imports, app)
        }
        NavigationLens::Notes => render_notes(frame, area, app, snapshot),
        NavigationLens::Findings => render_findings(frame, area, app, snapshot),
        NavigationLens::LocalGraph => render_local_graph(frame, area, app, snapshot),
        NavigationLens::Inspector => render_inspector(frame, area, app, snapshot),
    }
}

fn render_triage_board(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let rows = snapshot
        .triage
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(row.priority.clone()),
                Cell::from(truncate(&row.title, 30)),
                Cell::from(truncate(&snapshot.object_label(&row.target), 16)),
                Cell::from(truncate(&row.rationale, 32)),
                Cell::from(truncate(&row.command_hints.join(" | "), 22)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(31),
            Constraint::Length(17),
            Constraint::Min(16),
            Constraint::Length(23),
        ],
    )
    .header(
        Row::new(vec!["prio", "next action", "target", "why", "commands"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::TriageBoard)
            .title(format!(
                "Main View - Triage Board | {} leads | findings gap: {} | {}",
                snapshot.triage.high_score_count,
                if snapshot.triage.finding_gap {
                    "yes"
                } else {
                    "no"
                },
                lens_help(NavigationLens::TriageBoard)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let overview = &snapshot.overview;
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(overview.artifact_label.clone()),
        ]),
        Line::from(format!("Status: {}", overview.import_status)),
        Line::from(format!(
            "Sections: {}  Functions: {}  Strings: {}  Imports: {}  Findings: {}",
            overview.section_count,
            overview.function_count,
            overview.string_count,
            overview.import_count,
            overview.finding_count
        )),
        Line::from(""),
        Line::from("Top Function Radar"),
    ];
    for row in &overview.top_functions {
        lines.push(Line::from(format!(
            "{:>3}  {:<24} {}",
            row.score,
            truncate(&row.name, 24),
            row.reason_labels.join(", ")
        )));
    }
    if !overview.degraded_indexing_warnings.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Warnings"));
        for warning in &overview.degraded_indexing_warnings {
            lines.push(Line::from(format!("- {warning}")));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::Overview).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_binary_map(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let lines = vec![
        Line::from(format!("Artifact: {}", snapshot.overview.artifact_label)),
        Line::from(format!(
            "Import status: {}",
            snapshot.overview.import_status
        )),
        Line::from(format!("Sections: {}", snapshot.overview.section_count)),
        Line::from(format!("Functions: {}", snapshot.overview.function_count)),
        Line::from(format!("Strings: {}", snapshot.overview.string_count)),
        Line::from(format!("Imports: {}", snapshot.overview.import_count)),
        Line::from(""),
        Line::from("Binary Map is backed by the shared object graph."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::BinaryMap).borders(Borders::ALL)),
        area,
    );
}

fn render_function_radar(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let rows = snapshot
        .radar
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(row.score.to_string()),
                Cell::from(truncate(&row.name, 22)),
                Cell::from(row.address.clone()),
                Cell::from(
                    row.size
                        .map(|size| size.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(row.call_count.to_string()),
                Cell::from(row.string_count.to_string()),
                Cell::from(truncate(&row.boundary_confidence, 12)),
                Cell::from(truncate(&row.reason_labels.join(", "), 30)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(24),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(12),
            Constraint::Min(16),
        ],
    )
    .header(
        Row::new(vec![
            "score", "function", "address", "size", "calls", "strings", "boundary", "reasons",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        main_view_block(app, NavigationLens::FunctionRadar)
            .title(format!(
                "Main View - Function Radar ({}/{}) | {}",
                snapshot.radar.visible_functions,
                snapshot.radar.total_functions,
                lens_help(NavigationLens::FunctionRadar)
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(table, area);
}

fn render_object_list(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    objects: &[ObjectSummary],
    app: &TuiShellState,
) {
    let items = objects
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let address = object
                .address
                .map(|address| format!("0x{address:016x}"))
                .unwrap_or_else(|| "-".to_string());
            let text = format!(
                "{:>3}  {:<18} {:<20} {}",
                index,
                object.object_ref.kind,
                address,
                object.label()
            );
            let style = if index == app.main_cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(text).style(style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            main_view_block(app, app.active_lens)
                .title(format!(
                    "Main View - {title} | {}",
                    lens_help(app.active_lens)
                ))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_notes(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let mut lines = snapshot
        .annotations
        .iter()
        .map(|annotation| {
            Line::from(format!(
                "{}  {}",
                annotation.object_ref.kind,
                annotation.label()
            ))
        })
        .collect::<Vec<_>>();
    if !app.command_state.notes.is_empty()
        || !app.command_state.tags.is_empty()
        || !app.command_state.statuses.is_empty()
        || !app.command_state.renames.is_empty()
    {
        lines.push(Line::from(""));
        lines.push(Line::from("Session Memory"));
    }
    for (object_ref, tags) in &app.command_state.tags {
        lines.push(Line::from(format!(
            "tag {} = {}",
            short_ref(object_ref),
            tags.join(", ")
        )));
    }
    for (object_ref, notes) in &app.command_state.notes {
        for note in notes {
            lines.push(Line::from(format!(
                "note {} = {}",
                short_ref(object_ref),
                note
            )));
        }
    }
    for (object_ref, renamed) in &app.command_state.renames {
        lines.push(Line::from(format!(
            "rename {} = {}",
            short_ref(object_ref),
            renamed
        )));
    }
    for (object_ref, status) in &app.command_state.statuses {
        lines.push(Line::from(format!(
            "status {} = {}",
            short_ref(object_ref),
            status
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from("No notes yet."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::Notes).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_findings(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let mut lines = snapshot
        .findings
        .iter()
        .map(|finding| {
            Line::from(format!(
                "{} [{}] {}",
                finding.severity, finding.status, finding.title
            ))
        })
        .collect::<Vec<_>>();
    for draft in app.command_state.findings.values() {
        lines.push(Line::from(format!(
            "{} [draft] {}",
            draft.severity, draft.title
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from("No findings yet."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::Findings).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_local_graph(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let mut lines = Vec::new();
    if !app.command_state.last_xrefs.is_empty() {
        lines.push(Line::from("Command Xrefs"));
        for relation in &app.command_state.last_xrefs {
            lines.push(Line::from(relation_line(relation, snapshot)));
        }
    } else if let Some(selected) = &app.selected {
        lines.push(Line::from(format!(
            "Relations for {}",
            snapshot.object_label(selected)
        )));
        for relation in snapshot.relations_for(selected) {
            lines.push(Line::from(relation_line(relation, snapshot)));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from("No local relations loaded."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(main_view_block(app, NavigationLens::LocalGraph).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_inspector(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let lines = inspector_lines(app, snapshot)
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            let is_selected = app.focus == PaneFocus::Inspector
                && item.target.is_some()
                && index == app.inspector_cursor;
            if is_selected {
                item.line
                    .style(Style::default().fg(Color::Black).bg(Color::Cyan))
            } else {
                item.line
            }
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.inspector_scroll, 0))
            .block(
                focused_block(
                    app,
                    PaneFocus::Inspector,
                    "Inspector - Up/Down evidence, Enter jump".to_string(),
                )
                .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_command_bar(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) {
    let prompt = if app.command_mode {
        format!("Command: :{}", app.command_input)
    } else {
        "Command: p deck  :find string password  :xrefs current  :tag suspicious  :export json report.json"
            .to_string()
    };
    let status = if let Some(error) = &app.last_error {
        format!("Status: {:?}: {}", error.kind, error.message)
    } else {
        format!("Status: {}", app.status_line)
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(prompt),
            Line::from(format!(
                "Trail: {} > {} > {}",
                lens_badge(app.active_lens),
                pane_focus_label(app.focus),
                app.selected
                    .as_ref()
                    .map(|object_ref| truncate(&snapshot.object_label(object_ref), 34))
                    .unwrap_or_else(|| "none".to_string())
            )),
            Line::from(status),
            Line::from(context_help(app, snapshot)),
        ])
        .block(
            Block::default()
                .title("Command / Status")
                .borders(Borders::ALL),
        ),
        area,
    );
}

#[derive(Debug, Clone)]
struct InspectorLine {
    line: Line<'static>,
    target: Option<ObjectRef>,
}

impl InspectorLine {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            line: Line::from(text.into()),
            target: None,
        }
    }

    fn jump(text: impl Into<String>, target: ObjectRef) -> Self {
        Self {
            line: Line::from(text.into()),
            target: Some(target),
        }
    }
}

fn inspector_lines(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<InspectorLine> {
    let mut lines = Vec::new();
    if let Some(inspector) = snapshot.inspector_for(app.selected.as_ref()) {
        lines.push(InspectorLine::plain(format!(
            "Selected: {}",
            inspector.title
        )));
        lines.push(InspectorLine::plain(format!(
            "Ref: {}",
            short_ref(&inspector.selected)
        )));
        if let Some(address) = inspector.address {
            lines.push(InspectorLine::plain(format!("Address: {address}")));
        }
        if let Some(size) = inspector.size {
            lines.push(InspectorLine::plain(format!("Size: {size}")));
        }
        if let Some(score) = inspector.radar_score {
            lines.push(InspectorLine::plain(format!("Radar score: {score}")));
        }
        if let Some(confidence) = inspector.boundary_confidence {
            lines.push(InspectorLine::plain(format!("Boundary: {confidence}")));
        }
        if let Some(source) = inspector.boundary_source {
            lines.push(InspectorLine::plain(format!("Boundary source: {source}")));
        }
        if let Some(selected) = app.selected.as_ref() {
            append_native_function_lines(&mut lines, snapshot, selected);
            append_native_instruction_lines(&mut lines, snapshot, selected);
        }
        if !inspector.score_reasons.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Score Reasons"));
            for reason in inspector.score_reasons.iter().take(5) {
                lines.push(InspectorLine::plain(format!(
                    "+{} {}",
                    reason.contribution, reason.label
                )));
                for (evidence_ref, evidence_label) in reason
                    .evidence_refs
                    .iter()
                    .zip(reason.evidence_labels.iter())
                    .take(2)
                {
                    lines.push(InspectorLine::jump(
                        format!("  > evidence {evidence_label}"),
                        evidence_ref.clone(),
                    ));
                }
            }
        }
        append_session_memory_lines(&mut lines, app, &inspector.selected);
        let relations = snapshot.relations_for(&inspector.selected);
        if !relations.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Backlinks / Relations"));
            for relation in relations.iter().take(4) {
                lines.push(InspectorLine::jump(
                    format!("> {}", relation_line(relation, snapshot)),
                    relation_jump_target(relation, &inspector.selected),
                ));
            }
        }
        if !inspector.warnings.is_empty() {
            lines.push(InspectorLine::plain(""));
            lines.push(InspectorLine::plain("Warnings"));
            for warning in inspector.warnings {
                lines.push(InspectorLine::plain(format!("- {warning}")));
            }
        }
    } else {
        lines.push(InspectorLine::plain("No object selected."));
    }

    lines
}

fn append_native_function_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::Function {
        return;
    }
    let Some(summary) = snapshot.objects.get(selected) else {
        return;
    };
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&summary.metadata_json) else {
        return;
    };
    let frame_pointer = metadata
        .get("frame_pointer")
        .and_then(serde_json::Value::as_str);
    let stack_frame_size = metadata
        .get("stack_frame_size")
        .and_then(serde_json::Value::as_u64);
    let stack_cleanup_size = metadata
        .get("stack_cleanup_size")
        .and_then(serde_json::Value::as_u64);
    let epilogue_kind = metadata
        .get("epilogue_kind")
        .and_then(serde_json::Value::as_str);
    let has_frame_epilogue = metadata
        .get("has_frame_epilogue")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let calling_convention = metadata
        .get("calling_convention")
        .and_then(serde_json::Value::as_str);
    let argument_registers = metadata
        .get("argument_registers")
        .and_then(serde_json::Value::as_array);
    if frame_pointer.is_none()
        && stack_frame_size.is_none()
        && stack_cleanup_size.is_none()
        && epilogue_kind.is_none()
        && calling_convention.is_none()
        && argument_registers.map(Vec::is_empty).unwrap_or(true)
        && !has_frame_epilogue
    {
        return;
    }
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Native Function"));
    if let Some(frame_pointer) = frame_pointer {
        lines.push(InspectorLine::plain(format!(
            "Frame pointer: {frame_pointer}"
        )));
    }
    if let Some(stack_frame_size) = stack_frame_size {
        lines.push(InspectorLine::plain(format!(
            "Stack frame: {stack_frame_size} bytes"
        )));
    }
    if let Some(stack_cleanup_size) = stack_cleanup_size {
        lines.push(InspectorLine::plain(format!(
            "Stack cleanup: {stack_cleanup_size} bytes"
        )));
    }
    if let Some(epilogue_kind) = epilogue_kind {
        lines.push(InspectorLine::plain(format!("Epilogue: {epilogue_kind}")));
    } else if has_frame_epilogue {
        lines.push(InspectorLine::plain("Epilogue: detected"));
    }
    if let Some(calling_convention) = calling_convention {
        lines.push(InspectorLine::plain(format!("ABI: {calling_convention}")));
    }
    if let Some(argument_registers) = argument_registers {
        let rendered = argument_registers
            .iter()
            .filter_map(render_argument_register)
            .take(6)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain(format!(
                "Args: {}",
                rendered.join(", ")
            )));
        }
    }
    if let Some(slots) = metadata
        .get("stack_slots")
        .and_then(serde_json::Value::as_array)
    {
        let rendered = slots
            .iter()
            .filter_map(render_stack_slot)
            .take(4)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain("Stack slots"));
            for slot in rendered {
                lines.push(InspectorLine::plain(format!("- {slot}")));
            }
        }
    }
}

fn render_argument_register(value: &serde_json::Value) -> Option<String> {
    let ordinal = value
        .get("ordinal")
        .and_then(serde_json::Value::as_u64)?
        .saturating_add(1);
    let register = value.get("register").and_then(serde_json::Value::as_str)?;
    Some(format!("arg{ordinal}: {register}"))
}

fn render_stack_slot(value: &serde_json::Value) -> Option<String> {
    let base = value.get("base").and_then(serde_json::Value::as_str)?;
    let offset = value.get("offset").and_then(serde_json::Value::as_i64)?;
    let text = if offset < 0 {
        format!("{base}-0x{:x}", offset.unsigned_abs())
    } else if offset == 0 {
        base.to_string()
    } else {
        format!("{base}+0x{offset:x}")
    };
    let mut details = Vec::new();
    if let Some(width_bits) = value.get("width_bits").and_then(serde_json::Value::as_u64) {
        details.push(format!("{width_bits}-bit"));
    }
    if let Some(accesses) = value.get("accesses").and_then(serde_json::Value::as_array) {
        let rendered = accesses
            .iter()
            .filter_map(serde_json::Value::as_str)
            .take(4)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            details.push(rendered.join("/"));
        }
    }
    if details.is_empty() {
        Some(text)
    } else {
        Some(format!("{text} ({})", details.join(", ")))
    }
}

fn append_native_instruction_lines(
    lines: &mut Vec<InspectorLine>,
    snapshot: &WorkspaceSnapshot,
    selected: &ObjectRef,
) {
    if selected.kind != ObjectKind::Instruction {
        return;
    }
    let Some(summary) = snapshot.objects.get(selected) else {
        return;
    };
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&summary.metadata_json) else {
        return;
    };
    let mnemonic = metadata
        .get("mnemonic")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let operands = metadata
        .get("operands")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    lines.push(InspectorLine::plain(""));
    lines.push(InspectorLine::plain("Native Instruction"));
    lines.push(InspectorLine::plain(format!(
        "Decoded: {} {}",
        mnemonic, operands
    )));
    if let Some(flow_kind) = metadata
        .get("flow_kind")
        .and_then(serde_json::Value::as_str)
    {
        lines.push(InspectorLine::plain(format!("Flow: {flow_kind}")));
    }
    if let Some(target) = metadata.get("target").and_then(serde_json::Value::as_u64) {
        lines.push(InspectorLine::plain(format!("Target: 0x{target:016x}")));
    }
    if let Some(data_target) = metadata
        .get("data_target")
        .and_then(serde_json::Value::as_u64)
    {
        lines.push(InspectorLine::plain(format!(
            "Data target: 0x{data_target:016x}"
        )));
    }
    if let Some(condition_summary) = metadata
        .get("condition_summary")
        .and_then(serde_json::Value::as_str)
    {
        lines.push(InspectorLine::plain(format!(
            "Condition: {condition_summary}"
        )));
    }
    if let Some(condition_source) = metadata
        .get("condition_source")
        .and_then(object_ref_from_json_value)
    {
        lines.push(InspectorLine::jump(
            format!(
                "Condition source: {}",
                snapshot.object_label(&condition_source)
            ),
            condition_source,
        ));
    }
    if let Some(reads) = render_string_array(metadata.get("register_reads")) {
        lines.push(InspectorLine::plain(format!("Reads: {reads}")));
    }
    if let Some(writes) = render_string_array(metadata.get("register_writes")) {
        lines.push(InspectorLine::plain(format!("Writes: {writes}")));
    }
    if let Some(constants) = metadata
        .get("constant_writes")
        .and_then(serde_json::Value::as_array)
        .map(|values| render_constant_writes(values))
        .filter(|value| !value.is_empty())
    {
        lines.push(InspectorLine::plain(format!("Constants: {constants}")));
    }
    if let Some(sources) = metadata
        .get("constant_sources")
        .and_then(serde_json::Value::as_array)
    {
        for source in sources.iter().filter_map(render_constant_source).take(3) {
            lines.push(source);
        }
    }
    if let Some(sources) = metadata
        .get("register_sources")
        .and_then(serde_json::Value::as_array)
    {
        for source in sources.iter().filter_map(render_register_source).take(3) {
            lines.push(source);
        }
    }
    if let Some(operands) = metadata
        .get("typed_operands")
        .and_then(serde_json::Value::as_array)
    {
        let rendered = operands
            .iter()
            .filter_map(render_typed_operand)
            .take(3)
            .collect::<Vec<_>>();
        if !rendered.is_empty() {
            lines.push(InspectorLine::plain("Operands"));
            for operand in rendered {
                lines.push(InspectorLine::plain(format!("- {operand}")));
            }
        }
    }
}

fn render_string_array(value: Option<&serde_json::Value>) -> Option<String> {
    let rendered = value?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .take(8)
        .collect::<Vec<_>>();
    (!rendered.is_empty()).then(|| rendered.join(", "))
}

fn render_constant_writes(values: &[serde_json::Value]) -> String {
    values
        .iter()
        .filter_map(|value| {
            let register = value.get("register").and_then(serde_json::Value::as_str)?;
            let constant = value.get("value").and_then(serde_json::Value::as_u64)?;
            Some(format!("{register}=0x{constant:x}"))
        })
        .take(4)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_register_source(value: &serde_json::Value) -> Option<InspectorLine> {
    let register = value.get("register").and_then(serde_json::Value::as_str)?;
    let source = value.get("source").and_then(object_ref_from_json_value)?;
    Some(InspectorLine::jump(
        format!("Register source {register}"),
        source,
    ))
}

fn render_constant_source(value: &serde_json::Value) -> Option<InspectorLine> {
    let register = value.get("register").and_then(serde_json::Value::as_str)?;
    let constant = value.get("value").and_then(serde_json::Value::as_u64)?;
    let source = value.get("source").and_then(object_ref_from_json_value)?;
    Some(InspectorLine::jump(
        format!("Constant source {register}=0x{constant:x}"),
        source,
    ))
}

fn object_ref_from_json_value(value: &serde_json::Value) -> Option<ObjectRef> {
    serde_json::from_value(value.clone()).ok()
}

fn render_typed_operand(value: &serde_json::Value) -> Option<String> {
    let role = value.get("role").and_then(serde_json::Value::as_str)?;
    let kind = value.get("kind").and_then(serde_json::Value::as_str)?;
    let text = value.get("text").and_then(serde_json::Value::as_str)?;
    Some(format!("{role} {kind} {text}"))
}

fn append_session_memory_lines(
    lines: &mut Vec<InspectorLine>,
    app: &TuiShellState,
    object_ref: &ObjectRef,
) {
    if let Some(tags) = app.command_state.tags.get(object_ref) {
        lines.push(InspectorLine::plain(""));
        lines.push(InspectorLine::plain(format!("Tags: {}", tags.join(", "))));
    }
    if let Some(status) = app.command_state.statuses.get(object_ref) {
        lines.push(InspectorLine::plain(format!("Status: {status}")));
    }
    if let Some(rename) = app.command_state.renames.get(object_ref) {
        lines.push(InspectorLine::plain(format!("Rename: {rename}")));
    }
    if let Some(notes) = app.command_state.notes.get(object_ref) {
        lines.push(InspectorLine::plain("Notes"));
        for note in notes {
            lines.push(InspectorLine::plain(format!("- {note}")));
        }
    }
}

fn inspector_focusable_indices(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<usize> {
    inspector_lines(app, snapshot)
        .iter()
        .enumerate()
        .filter(|(_, line)| line.target.is_some())
        .map(|(index, _)| index)
        .collect()
}

fn inspector_target_at_cursor(
    app: &TuiShellState,
    snapshot: &WorkspaceSnapshot,
) -> Option<ObjectRef> {
    inspector_lines(app, snapshot)
        .into_iter()
        .enumerate()
        .find(|(index, item)| *index == app.inspector_cursor && item.target.is_some())
        .and_then(|(_, item)| item.target)
}

fn relation_jump_target(relation: &ObjectRelation, selected: &ObjectRef) -> ObjectRef {
    if relation.source == *selected {
        relation.target.clone()
    } else {
        relation.source.clone()
    }
}

fn cursor_for_selection(
    snapshot: &WorkspaceSnapshot,
    lens: NavigationLens,
    selected: &ObjectRef,
) -> Option<usize> {
    snapshot
        .rows_for_lens(lens)
        .iter()
        .position(|candidate| candidate == selected)
}

fn restore_terminal<W: io::Write>(
    terminal: &mut Terminal<CrosstermBackend<W>>,
) -> anyhow::Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")
}

fn search_kind(
    query: &dyn ObjectGraphQuery,
    kind: ObjectKind,
    limit: usize,
) -> anyhow::Result<Vec<ObjectSummary>> {
    query
        .search_objects(&ObjectSearch::new(Some(kind), "").with_limit(limit))
        .map_err(|err| anyhow::anyhow!(err))
}

fn summary(
    object_ref: ObjectRef,
    display_name: &str,
    address: Option<u64>,
    size: Option<u64>,
) -> ObjectSummary {
    ObjectSummary {
        object_ref,
        artifact_key: None,
        display_name: Some(display_name.to_string()),
        address,
        size,
        metadata_json: "{}".to_string(),
    }
}

fn relation_line(relation: &ObjectRelation, snapshot: &WorkspaceSnapshot) -> String {
    if is_condition_source_relation(relation, snapshot) {
        return format!(
            "Condition source: {} depends on {}",
            snapshot.object_label(&relation.source),
            snapshot.object_label(&relation.target)
        );
    }
    if relation.kind == revdeck_core::EdgeKind::ControlFlow {
        if let Some(line) = control_flow_relation_line(relation, snapshot) {
            return line;
        }
    }
    format!(
        "{}: {} -> {}",
        relation.kind.label(),
        snapshot.object_label(&relation.source),
        snapshot.object_label(&relation.target)
    )
}

fn control_flow_relation_line(
    relation: &ObjectRelation,
    snapshot: &WorkspaceSnapshot,
) -> Option<String> {
    let metadata = serde_json::from_str::<serde_json::Value>(&relation.metadata_json).ok()?;
    let edge_kind = metadata
        .get("cfg_edge_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("edge");
    let condition = metadata
        .get("condition_summary")
        .and_then(serde_json::Value::as_str);
    let outcome = metadata
        .get("known_outcome")
        .and_then(serde_json::Value::as_str);
    let mut label = format!(
        "Control flow {edge_kind}: {} -> {}",
        snapshot.object_label(&relation.source),
        snapshot.object_label(&relation.target)
    );
    if let Some(outcome) = outcome {
        label.push_str(&format!(" ({})", outcome.replace('_', " ")));
    }
    if let Some(condition) = condition {
        label.push_str(&format!(" | {condition}"));
    }
    Some(label)
}

fn is_condition_source_relation(relation: &ObjectRelation, snapshot: &WorkspaceSnapshot) -> bool {
    relation.kind == revdeck_core::EdgeKind::References
        && relation.source.kind == ObjectKind::Instruction
        && relation.target.kind == ObjectKind::Instruction
        && snapshot
            .objects
            .get(&relation.source)
            .and_then(|summary| {
                serde_json::from_str::<serde_json::Value>(&summary.metadata_json).ok()
            })
            .and_then(|metadata| metadata.get("condition_source").cloned())
            .and_then(|value| object_ref_from_json_value(&value))
            .as_ref()
            == Some(&relation.target)
}

fn focused_block<'a>(app: &TuiShellState, focus: PaneFocus, title: String) -> Block<'a> {
    let style = if app.focus == focus {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::default().title(title).border_style(style)
}

fn main_view_block<'a>(app: &TuiShellState, lens: NavigationLens) -> Block<'a> {
    focused_block(
        app,
        PaneFocus::Main,
        format!("Main View - {} | {}", lens_label(lens), lens_help(lens)),
    )
}

fn lens_badge(lens: NavigationLens) -> &'static str {
    match lens {
        NavigationLens::Overview => "OVR",
        NavigationLens::TriageBoard => "TRI",
        NavigationLens::BinaryMap => "BIN",
        NavigationLens::FunctionRadar => "RAD",
        NavigationLens::Functions => "FUN",
        NavigationLens::Strings => "STR",
        NavigationLens::Imports => "IMP",
        NavigationLens::Notes => "MEM",
        NavigationLens::Findings => "FND",
        NavigationLens::Inspector => "INS",
        NavigationLens::LocalGraph => "REL",
    }
}

fn pane_focus_label(focus: PaneFocus) -> &'static str {
    match focus {
        PaneFocus::Workspace => "Workspace",
        PaneFocus::Main => "Main View",
        PaneFocus::Inspector => "Inspector",
    }
}

fn lens_label(lens: NavigationLens) -> &'static str {
    match lens {
        NavigationLens::Overview => "Overview",
        NavigationLens::TriageBoard => "Triage Board",
        NavigationLens::BinaryMap => "Binary Map",
        NavigationLens::FunctionRadar => "Function Radar",
        NavigationLens::Functions => "Functions",
        NavigationLens::Strings => "Strings",
        NavigationLens::Imports => "Imports",
        NavigationLens::Notes => "Notes",
        NavigationLens::Findings => "Findings",
        NavigationLens::Inspector => "Inspector",
        NavigationLens::LocalGraph => "Local Relations",
    }
}

fn lens_help(lens: NavigationLens) -> &'static str {
    match lens {
        NavigationLens::Overview => "project counts; o overview, g triage",
        NavigationLens::TriageBoard => "ranked next actions; Enter opens target",
        NavigationLens::BinaryMap => "binary structure and import status",
        NavigationLens::FunctionRadar => "prioritized functions; Enter opens current row",
        NavigationLens::Functions => "all discovered functions; Enter inspect",
        NavigationLens::Strings => "strings and addresses; :find string ...",
        NavigationLens::Imports => "imported APIs; :find import system",
        NavigationLens::Notes => "persisted and session analysis memory",
        NavigationLens::Findings => "reportable findings and drafts",
        NavigationLens::Inspector => "selected object context; Enter evidence",
        NavigationLens::LocalGraph => "xrefs and evidence paths; G opens current graph",
    }
}

fn focus_help(focus: PaneFocus) -> &'static str {
    match focus {
        PaneFocus::Workspace => "Up/Down switches lenses; Enter moves into Main View",
        PaneFocus::Main => "Up/Down moves rows; Enter opens selected object",
        PaneFocus::Inspector => "Up/Down selects evidence or relations; Enter jumps",
    }
}

fn lens_next_step(lens: NavigationLens) -> &'static str {
    match lens {
        NavigationLens::Overview => {
            "Confirm status, then press g for triage or r for Function Radar."
        }
        NavigationLens::TriageBoard => {
            "Work top-down; use suggested commands and turn strong leads into findings."
        }
        NavigationLens::BinaryMap => {
            "Check whether parsing degraded; inspect sections, strings, and imports next."
        }
        NavigationLens::FunctionRadar => {
            "Open high-score functions, then inspect evidence and xrefs."
        }
        NavigationLens::Functions => {
            "Browse indexed functions; tag, rename, or mark reviewed as you go."
        }
        NavigationLens::Strings => "Search suspicious strings, open one, then inspect references.",
        NavigationLens::Imports => "Open dangerous imports and use :xrefs current to find callers.",
        NavigationLens::Notes => "Review session memory before continuing or reporting.",
        NavigationLens::Findings => "Check drafts, link evidence, and queue report exports.",
        NavigationLens::Inspector => "Jump from evidence or relations into the linked object.",
        NavigationLens::LocalGraph => "Use relation context to move from source to sink evidence.",
    }
}

fn help_overlay_lines(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<Line<'static>> {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    let analysis_status = snapshot
        .overview
        .analysis_status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    vec![
        Line::from(vec![
            Span::styled(
                "RevDeck cockpit",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {}  analysis={} import={}",
                snapshot.overview.artifact_label, analysis_status, snapshot.overview.import_status
            )),
        ]),
        Line::from(format!(
            "View: {} ({})",
            lens_label(app.active_lens),
            lens_help(app.active_lens)
        )),
        Line::from(format!(
            "Focus: {} - {}",
            pane_focus_label(app.focus),
            focus_help(app.focus)
        )),
        Line::from(format!("Selected: {}", truncate(&selected, 72))),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("Tab/Shift+Tab panes; Left/Right columns; Up/Down or j/k moves; Enter opens or jumps."),
        Line::from("Lenses: g triage, G graph, o overview, b binary, r radar, f functions, s strings, i imports, n notes, F findings."),
        Line::from("History: [ back, ] forward. Commands: p deck, : command mode. Quit: q or Esc outside help."),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Commands",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(":find string password    :find import system    :xrefs current    :open current"),
        Line::from(":tag current suspicious  :note current reviewed path  :rename current name  :status current reviewed"),
        Line::from(":finding new high title  :finding link <finding> current evidence"),
        Line::from(":export markdown report.md  :export json report.json"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Current next step",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(lens_next_step(app.active_lens)),
    ]
}

fn command_deck_lines(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> Vec<Line<'static>> {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    let selected_ref = app
        .selected
        .as_ref()
        .map(short_ref)
        .unwrap_or_else(|| "none".to_string());
    let mut lines = vec![
        Line::from(vec![Span::styled(
            "Commands",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(":open current              navigate to selected object"),
        Line::from(":xrefs current             load local relations into Graph Lab"),
        Line::from(":find string <term>        search strings"),
        Line::from(":find import <term>        search imports"),
        Line::from(":tag current <tag>         add analysis memory"),
        Line::from(":note current <text>       add analyst note"),
        Line::from(":finding new high <title>  create finding draft"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Current Object",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("selected: {}", truncate(&selected, 64))),
        Line::from(format!("ref: {selected_ref}")),
        Line::from("preview: G opens Graph Lab, Enter opens, :xrefs current loads relations"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Recent / Context",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!(
            "view={} focus={} exports={} findings={} session-tags={}",
            lens_label(app.active_lens),
            pane_focus_label(app.focus),
            app.command_state.export_requests.len(),
            app.command_state.findings.len(),
            app.command_state.tags.len()
        )),
    ];
    if snapshot
        .relations_for_selected(app.selected.as_ref())
        .is_empty()
    {
        lines.push(Line::from("relations: none loaded for selected object"));
    } else {
        lines.push(Line::from(format!(
            "relations: {} local edges available",
            snapshot.relations_for_selected(app.selected.as_ref()).len()
        )));
    }
    lines
}

fn context_help(app: &TuiShellState, snapshot: &WorkspaceSnapshot) -> String {
    let selected = app
        .selected
        .as_ref()
        .map(|object_ref| snapshot.object_label(object_ref))
        .unwrap_or_else(|| "none".to_string());
    format!(
        "Focus: {} | View: {} | Selected: {} | ? help, p deck, Tab/Shift+Tab panes, Left/Right columns, Up/Down move, Enter open/jump, : commands, g triage, G graph, q quit",
        pane_focus_label(app.focus),
        lens_label(app.active_lens),
        truncate(&selected, 28)
    )
}

fn export_format_label(format: &ExportFormat) -> &'static str {
    match format {
        ExportFormat::Markdown => "markdown",
        ExportFormat::Json => "json",
    }
}

fn short_ref(object_ref: &ObjectRef) -> String {
    let key = object_ref.key.as_str();
    let key = truncate(key, 40);
    format!("{}:{key}", object_ref.kind)
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value
        .chars()
        .take(limit.saturating_sub(1))
        .collect::<String>()
        + "."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use ratatui::backend::TestBackend;
    use revdeck_core::{InMemoryObjectGraph, ObjectKind};

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<Vec<_>>()
            .join("")
    }

    fn graph(snapshot: &WorkspaceSnapshot) -> InMemoryObjectGraph {
        let mut graph = InMemoryObjectGraph::new();
        for object in snapshot.objects.values() {
            graph.insert_object(object.clone());
        }
        for relations in snapshot.relations_by_object.values() {
            for relation in relations {
                graph
                    .insert_relation(
                        relation.source.clone(),
                        relation.target.clone(),
                        relation.kind,
                    )
                    .unwrap();
            }
        }
        graph
    }

    #[test]
    fn reducer_navigation() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);

        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        let function = app.selected.clone().unwrap();
        app.apply_action(TuiAction::ActivateSelection, &snapshot)
            .unwrap();
        app.apply_action(
            TuiAction::NavigateToReasonEvidence {
                reason_index: 0,
                evidence_index: 0,
            },
            &snapshot,
        )
        .unwrap();

        assert_ne!(app.selected.as_ref(), Some(&function));
        assert!(matches!(
            app.selected.as_ref().map(|item| item.kind),
            Some(ObjectKind::Import | ObjectKind::String | ObjectKind::Artifact)
        ));
        assert!(app.command_state.navigation.len() >= 2);
    }

    #[test]
    fn reducer_command_results() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);
        let function = snapshot.radar.rows[0].function_ref.clone();

        app.submit_command(&format!("open {function}"), &graph)
            .unwrap();
        app.submit_command("tag current suspicious", &graph)
            .unwrap();
        app.submit_command("note current review command path", &graph)
            .unwrap();
        app.submit_command("finding new high command execution", &graph)
            .unwrap();
        app.submit_command("export json report.json", &graph)
            .unwrap();

        assert_eq!(
            app.command_state.tags.get(&function).unwrap(),
            &vec!["suspicious".to_string()]
        );
        assert!(app
            .command_state
            .notes
            .get(&function)
            .unwrap()
            .iter()
            .any(|note| note.contains("command path")));
        assert_eq!(app.command_state.findings.len(), 1);
        assert_eq!(app.command_state.export_requests.len(), 1);
        assert!(app.status_line.contains("export queued"));
    }

    #[test]
    fn render_workspace_three_pane() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Workspace"));
        assert!(text.contains("Cockpit"));
        assert!(text.contains("RevDeck"));
        assert!(text.contains("Main View"));
        assert!(text.contains("Inspector"));
        assert!(text.contains("Command / Status"));
        assert!(text.contains("Function Radar"));
    }

    #[test]
    fn render_help_overlay_with_current_context() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        app.apply_action(TuiAction::ToggleHelp, &snapshot).unwrap();
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Command Deck"));
        assert!(text.contains("RevDeck cockpit"));
        assert!(text.contains("Current next step"));
        assert!(text.contains(":finding new high title"));
    }

    #[test]
    fn triage_board_renders_prioritized_next_actions() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::TriageBoard),
            &snapshot,
        )
        .unwrap();
        let selected = app.selected.clone().unwrap();
        let backend = TestBackend::new(140, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Triage Board"));
        assert!(text.contains("Dangerous import path"));
        assert!(text.contains(":xrefs current"));
        assert_eq!(selected, snapshot.triage.rows[0].target);
    }

    #[test]
    fn render_small_terminal_fallback() {
        let snapshot = WorkspaceSnapshot::demo();
        let app = TuiShellState::from_snapshot(&snapshot);
        let backend = TestBackend::new(54, 12);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Command / Status"));
        assert!(text.contains("Workspace"));
    }

    #[test]
    fn function_radar_inspector_snapshot() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        let backend = TestBackend::new(120, 42);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render_workspace(frame, &app, &snapshot))
            .unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("Dangerous import"));
        assert!(text.contains("Sensitive string"));
        assert!(text.contains("Boundary"));
        assert!(text.contains("Boundary source"));
        assert!(text.contains("Native Function"));
        assert!(text.contains("Frame pointer: rbp"));
        assert!(text.contains("Stack frame: 32 bytes"));
        assert!(text.contains("Stack cleanup: 32 bytes"));
        assert!(text.contains("Epilogue: stack-add-pop-rbp"));
        assert!(text.contains("ABI: windows-x64"));
        assert!(text.contains("Args: arg1: rcx"));
        assert!(text.contains("arg1: rcx"));
        assert!(text.contains("Stack slots"));
        assert!(text.contains("rbp-0x8"));
        assert!(text.contains("read/write"));
        assert!(text.contains("evidence"));
    }

    #[test]
    fn tab_and_arrows_move_between_panes_without_switching_lens() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.focus, PaneFocus::Inspector);
        assert_eq!(app.active_lens, NavigationLens::Overview);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        app.handle_key_event(
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.focus, PaneFocus::Workspace);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.active_lens, NavigationLens::TriageBoard);
    }

    #[test]
    fn non_press_key_events_are_ignored() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);
        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        app.handle_key_event(key, &snapshot, &graph).unwrap();
        let after_press = app.main_cursor;

        let release =
            KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        app.handle_key_event(release, &snapshot, &graph).unwrap();

        assert_eq!(app.main_cursor, after_press);
    }

    #[test]
    fn help_overlay_traps_navigation_until_closed() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        let graph = graph(&snapshot);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert!(app.show_help);
        let cursor = app.main_cursor;

        app.handle_key_event(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert_eq!(app.main_cursor, cursor);
        assert!(app.show_help);

        app.handle_key_event(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &snapshot,
            &graph,
        )
        .unwrap();
        assert!(!app.show_help);
        assert!(!app.should_quit);
    }

    #[test]
    fn right_pane_can_select_and_open_evidence() {
        let snapshot = WorkspaceSnapshot::demo();
        let mut app = TuiShellState::from_snapshot(&snapshot);
        app.apply_action(
            TuiAction::SwitchLens(NavigationLens::FunctionRadar),
            &snapshot,
        )
        .unwrap();
        app.apply_action(TuiAction::FocusPane(PaneFocus::Inspector), &snapshot)
            .unwrap();
        let function = app.selected.clone().unwrap();

        app.apply_action(TuiAction::NextRow, &snapshot).unwrap();
        app.apply_action(TuiAction::ActivateSelection, &snapshot)
            .unwrap();

        assert_ne!(app.selected.as_ref(), Some(&function));
        assert!(matches!(
            app.selected.as_ref().map(|item| item.kind),
            Some(ObjectKind::Import | ObjectKind::String)
        ));
    }
}
