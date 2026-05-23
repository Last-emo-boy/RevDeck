use crate::{ObjectKind, ObjectRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabMaturity {
    Active,
    Preview,
    Planned,
}

impl LabMaturity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Preview => "preview",
            Self::Planned => "planned",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabId {
    BinaryTriage,
    WorkspaceJobs,
    HexViewer,
    Graph,
    Diff,
    Trace,
    Firmware,
    Crash,
    Protocol,
    Plugin,
    Report,
}

impl LabId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryTriage => "binary-triage",
            Self::WorkspaceJobs => "workspace-jobs",
            Self::HexViewer => "hex-viewer",
            Self::Graph => "graph",
            Self::Diff => "diff",
            Self::Trace => "trace",
            Self::Firmware => "firmware",
            Self::Crash => "crash",
            Self::Protocol => "protocol",
            Self::Plugin => "plugin",
            Self::Report => "report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabDescriptor {
    pub id: LabId,
    pub label: &'static str,
    pub badge: &'static str,
    pub purpose: &'static str,
    pub default_lens: NavigationLens,
    pub shortcut: Option<char>,
    pub maturity: LabMaturity,
}

impl LabDescriptor {
    pub const fn stable_id(self) -> &'static str {
        self.id.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NavigationLens {
    Overview,
    TriageBoard,
    Jobs,
    Hex,
    BinaryMap,
    FunctionRadar,
    Functions,
    Strings,
    Imports,
    Diff,
    Trace,
    Firmware,
    Crash,
    Protocol,
    Notes,
    Findings,
    Inspector,
    LocalGraph,
}

pub const WORKSPACE_LENSES: [NavigationLens; 17] = [
    NavigationLens::Overview,
    NavigationLens::TriageBoard,
    NavigationLens::Jobs,
    NavigationLens::Hex,
    NavigationLens::BinaryMap,
    NavigationLens::FunctionRadar,
    NavigationLens::LocalGraph,
    NavigationLens::Diff,
    NavigationLens::Trace,
    NavigationLens::Firmware,
    NavigationLens::Crash,
    NavigationLens::Protocol,
    NavigationLens::Functions,
    NavigationLens::Strings,
    NavigationLens::Imports,
    NavigationLens::Notes,
    NavigationLens::Findings,
];

pub const ALL_LABS: [LabDescriptor; 11] = [
    LabDescriptor {
        id: LabId::BinaryTriage,
        label: "Binary Triage Lab",
        badge: "BIN",
        purpose: "Import binaries, index objects, score risky functions, and drive evidence-backed triage.",
        default_lens: NavigationLens::Overview,
        shortcut: Some('o'),
        maturity: LabMaturity::Active,
    },
    LabDescriptor {
        id: LabId::WorkspaceJobs,
        label: "Workspace/Jobs Lab",
        badge: "JOB",
        purpose: "Inspect pass history, profile degradation, skipped work, failures, and analysis diagnostics.",
        default_lens: NavigationLens::Jobs,
        shortcut: Some('J'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::HexViewer,
        label: "Hex Viewer Lab",
        badge: "HEX",
        purpose: "Inspect raw artifact bytes in bounded read-only windows before full analysis finishes.",
        default_lens: NavigationLens::Hex,
        shortcut: Some('x'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Graph,
        label: "Graph Lab",
        badge: "REL",
        purpose: "Explore local relations, xrefs, calls, containment, and evidence paths around the current object.",
        default_lens: NavigationLens::LocalGraph,
        shortcut: Some('G'),
        maturity: LabMaturity::Active,
    },
    LabDescriptor {
        id: LabId::Diff,
        label: "Diff Lab",
        badge: "DIF",
        purpose: "Compare artifacts or projects across functions, imports, strings, findings, scores, and graph deltas.",
        default_lens: NavigationLens::Diff,
        shortcut: Some('D'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Trace,
        label: "Trace Lab",
        badge: "TRC",
        purpose: "Import execution traces, inspect timelines, and correlate events with binary evidence.",
        default_lens: NavigationLens::Trace,
        shortcut: Some('T'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Firmware,
        label: "Firmware Lab",
        badge: "FMW",
        purpose: "Inventory firmware file trees, nested artifacts, supported binaries, and path-based evidence.",
        default_lens: NavigationLens::Firmware,
        shortcut: Some('W'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Crash,
        label: "Crash Lab",
        badge: "CRS",
        purpose: "Normalize crash reports, cluster stack traces, and link frames to functions and findings.",
        default_lens: NavigationLens::Crash,
        shortcut: Some('C'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Protocol,
        label: "Protocol Lab",
        badge: "PRO",
        purpose: "Inspect samples, messages, fields, schema hypotheses, and links back to binary behavior.",
        default_lens: NavigationLens::Protocol,
        shortcut: Some('P'),
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Plugin,
        label: "Plugin Lab",
        badge: "PLG",
        purpose: "Validate, dry-run, audit, and commit plugin contributions through the host boundary.",
        default_lens: NavigationLens::Overview,
        shortcut: None,
        maturity: LabMaturity::Preview,
    },
    LabDescriptor {
        id: LabId::Report,
        label: "Report Lab",
        badge: "RPT",
        purpose: "Validate findings and export cross-lab evidence bundles as JSON or Markdown.",
        default_lens: NavigationLens::Findings,
        shortcut: Some('F'),
        maturity: LabMaturity::Active,
    },
];

impl NavigationLens {
    pub fn for_object_kind(kind: ObjectKind) -> Self {
        match kind {
            ObjectKind::Artifact | ObjectKind::File | ObjectKind::Binary | ObjectKind::Section => {
                Self::BinaryMap
            }
            ObjectKind::FirmwareFile => Self::Firmware,
            ObjectKind::Function | ObjectKind::Symbol | ObjectKind::Score => Self::FunctionRadar,
            ObjectKind::String => Self::Strings,
            ObjectKind::Import => Self::Imports,
            ObjectKind::DiffDelta => Self::Diff,
            ObjectKind::TraceSession | ObjectKind::TraceEvent => Self::Trace,
            ObjectKind::CrashReport | ObjectKind::CrashFrame => Self::Crash,
            ObjectKind::ProtocolSample
            | ObjectKind::ProtocolMessage
            | ObjectKind::ProtocolField => Self::Protocol,
            ObjectKind::Instruction
            | ObjectKind::BasicBlock
            | ObjectKind::Xref
            | ObjectKind::Edge
            | ObjectKind::PluginContribution => Self::LocalGraph,
            ObjectKind::Annotation => Self::Notes,
            ObjectKind::Finding => Self::Findings,
        }
    }

    pub const fn badge(self) -> &'static str {
        match self {
            Self::Overview => "OVR",
            Self::TriageBoard => "TRI",
            Self::Jobs => "JOB",
            Self::Hex => "HEX",
            Self::BinaryMap => "BIN",
            Self::FunctionRadar => "RAD",
            Self::Functions => "FUN",
            Self::Strings => "STR",
            Self::Imports => "IMP",
            Self::Diff => "DIF",
            Self::Trace => "TRC",
            Self::Firmware => "FMW",
            Self::Crash => "CRS",
            Self::Protocol => "PRO",
            Self::Notes => "MEM",
            Self::Findings => "FND",
            Self::Inspector => "INS",
            Self::LocalGraph => "REL",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::TriageBoard => "Triage Board",
            Self::Jobs => "Analysis Jobs",
            Self::Hex => "Hex Viewer",
            Self::BinaryMap => "Binary Map",
            Self::FunctionRadar => "Function Radar",
            Self::Functions => "Functions",
            Self::Strings => "Strings",
            Self::Imports => "Imports",
            Self::Diff => "Diff Lab",
            Self::Trace => "Trace Lab",
            Self::Firmware => "Firmware Lab",
            Self::Crash => "Crash Lab",
            Self::Protocol => "Protocol Lab",
            Self::Notes => "Notes",
            Self::Findings => "Findings",
            Self::Inspector => "Inspector",
            Self::LocalGraph => "Local Relations",
        }
    }

    pub const fn help(self) -> &'static str {
        match self {
            Self::Overview => "project counts; o overview, g triage",
            Self::TriageBoard => "ranked next actions; Enter opens target",
            Self::Jobs => "read-only pass history; J jobs",
            Self::Hex => "read-only bytes; x hex, j/k scroll",
            Self::BinaryMap => "binary structure and import status",
            Self::FunctionRadar => "prioritized functions; Enter opens current row",
            Self::Functions => "all discovered functions; Enter inspect",
            Self::Strings => "strings and addresses; :find string ...",
            Self::Imports => "imported APIs; :find import system",
            Self::Diff => "artifact deltas; Enter opens delta, G graphs evidence",
            Self::Trace => "timeline events; Enter opens event, G graphs correlation",
            Self::Firmware => "file inventory; Enter opens file, G graphs path evidence",
            Self::Crash => "crash clusters; Enter opens report/frame, G graphs correlation",
            Self::Protocol => "messages and fields; Enter opens field, G graphs evidence",
            Self::Notes => "persisted and session analysis memory",
            Self::Findings => "reportable findings and drafts",
            Self::Inspector => "selected object context; Enter evidence",
            Self::LocalGraph => "xrefs and evidence paths; G opens current graph",
        }
    }

    pub const fn next_step(self) -> &'static str {
        match self {
            Self::Overview => "Confirm status, then press g for triage or r for Function Radar.",
            Self::TriageBoard => {
                "Work top-down; use suggested commands and turn strong leads into findings."
            }
            Self::Jobs => "Review recent pass status for the active artifact before triage.",
            Self::Hex => {
                "Inspect raw bytes, then pivot to strings/imports once indexing catches up."
            }
            Self::BinaryMap => {
                "Check whether parsing degraded; inspect sections, strings, and imports next."
            }
            Self::FunctionRadar => "Open high-score functions, then inspect evidence and xrefs.",
            Self::Functions => "Browse indexed functions; tag, rename, or mark reviewed as you go.",
            Self::Strings => "Search suspicious strings, open one, then inspect references.",
            Self::Imports => "Open dangerous imports and use :xrefs current to find callers.",
            Self::Diff => {
                "Inspect changed rows, then use Graph Lab to pivot into before/after evidence."
            }
            Self::Trace => {
                "Follow timeline events, then pivot correlated calls into Function Radar."
            }
            Self::Firmware => {
                "Review file types, open suspicious paths, then graph nested evidence."
            }
            Self::Crash => {
                "Review top frames, cluster repeats, then link crash evidence to findings."
            }
            Self::Protocol => {
                "Inspect field slices, schema hypotheses, and linked binary evidence."
            }
            Self::Notes => "Review session memory before continuing or reporting.",
            Self::Findings => "Check drafts, link evidence, and queue report exports.",
            Self::Inspector => "Jump from evidence or relations into the linked object.",
            Self::LocalGraph => "Use relation context to move from source to sink evidence.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectionContext {
    pub cursor_row: Option<usize>,
    pub selection_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenObject {
    pub object_ref: ObjectRef,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationEntry {
    pub lens: NavigationLens,
    pub object_ref: ObjectRef,
    pub selection: SelectionContext,
    pub broken: Option<BrokenObject>,
}

impl NavigationEntry {
    pub fn new(lens: NavigationLens, object_ref: ObjectRef) -> Self {
        Self {
            lens,
            object_ref,
            selection: SelectionContext::default(),
            broken: None,
        }
    }

    pub fn with_selection(mut self, selection: SelectionContext) -> Self {
        self.selection = selection;
        self
    }

    pub fn broken(mut self, reason: impl Into<String>) -> Self {
        self.broken = Some(BrokenObject {
            object_ref: self.object_ref.clone(),
            reason: reason.into(),
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NavigationHistory {
    entries: Vec<NavigationEntry>,
    current_index: Option<usize>,
}

impl NavigationHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[NavigationEntry] {
        &self.entries
    }

    pub fn current(&self) -> Option<&NavigationEntry> {
        self.current_index.and_then(|index| self.entries.get(index))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn can_back(&self) -> bool {
        self.current_index.is_some_and(|index| index > 0)
    }

    pub fn can_forward(&self) -> bool {
        self.current_index
            .is_some_and(|index| index + 1 < self.entries.len())
    }

    pub fn navigate_to(&mut self, entry: NavigationEntry) -> &NavigationEntry {
        if let Some(index) = self.current_index {
            self.entries.truncate(index + 1);
        }
        self.entries.push(entry);
        self.current_index = Some(self.entries.len() - 1);
        self.current().expect("navigation entry was just pushed")
    }

    pub fn navigate_to_broken(
        &mut self,
        lens: NavigationLens,
        object_ref: ObjectRef,
        reason: impl Into<String>,
    ) -> &NavigationEntry {
        self.navigate_to(NavigationEntry::new(lens, object_ref).broken(reason))
    }

    pub fn back(&mut self) -> Option<&NavigationEntry> {
        if self.can_back() {
            self.current_index = self.current_index.map(|index| index - 1);
        }
        self.current()
    }

    pub fn forward(&mut self) -> Option<&NavigationEntry> {
        if self.can_forward() {
            self.current_index = self.current_index.map(|index| index + 1);
        }
        self.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectKind, ObjectRef, StableObjectKey};

    fn artifact() -> crate::StableObjectKey {
        crate::StableObjectKeyBuilder::new(ObjectKind::Artifact)
            .component("sha256", "abc123")
            .unwrap()
            .component("path", "fixture")
            .unwrap()
            .finish()
            .unwrap()
    }

    fn function(name: &str, address: u64) -> ObjectRef {
        ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact(), address, Some(16), Some(name)).unwrap(),
        )
    }

    fn string(value: &str, offset: u64) -> ObjectRef {
        ObjectRef::new(
            ObjectKind::String,
            StableObjectKey::string(&artifact(), offset, Some(0x402000 + offset), value).unwrap(),
        )
    }

    #[test]
    fn navigation_history_restores_back_forward_and_drops_branch() {
        let password = string("password", 0x20);
        let main = function("main", 0x401000);
        let helper = function("helper", 0x401100);
        let mut history = NavigationHistory::new();

        history.navigate_to(
            NavigationEntry::new(NavigationLens::Strings, password.clone()).with_selection(
                SelectionContext {
                    cursor_row: Some(3),
                    selection_key: Some("strings:3".to_string()),
                },
            ),
        );
        history.navigate_to(NavigationEntry::new(
            NavigationLens::FunctionRadar,
            main.clone(),
        ));

        assert_eq!(history.current().unwrap().object_ref, main);
        assert_eq!(history.back().unwrap().object_ref, password);
        assert_eq!(history.forward().unwrap().object_ref, main);

        history.back();
        history.navigate_to(NavigationEntry::new(
            NavigationLens::FunctionRadar,
            helper.clone(),
        ));
        assert_eq!(history.current().unwrap().object_ref, helper);
        assert!(!history.can_forward());
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn navigation_history_records_broken_object_diagnostics() {
        let missing = function("missing", 0x404000);
        let mut history = NavigationHistory::new();
        history.navigate_to_broken(
            NavigationLens::FunctionRadar,
            missing.clone(),
            "object was removed by re-index",
        );

        let current = history.current().unwrap();
        assert_eq!(current.object_ref, missing);
        assert_eq!(
            current.broken.as_ref().unwrap().reason,
            "object was removed by re-index"
        );
    }

    #[test]
    fn lab_registry_order_and_ids_are_stable() {
        let ids = ALL_LABS
            .iter()
            .map(|lab| lab.stable_id())
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![
                "binary-triage",
                "workspace-jobs",
                "hex-viewer",
                "graph",
                "diff",
                "trace",
                "firmware",
                "crash",
                "protocol",
                "plugin",
                "report"
            ]
        );
        assert_eq!(ALL_LABS[0].default_lens, NavigationLens::Overview);
        assert_eq!(ALL_LABS[1].shortcut, Some('J'));
        assert_eq!(ALL_LABS[2].label, "Hex Viewer Lab");
        assert_eq!(ALL_LABS[3].label, "Graph Lab");
        assert_eq!(ALL_LABS[8].default_lens, NavigationLens::Protocol);
        assert_eq!(ALL_LABS[8].shortcut, Some('P'));
    }

    #[test]
    fn workspace_lenses_keep_jobs_and_graph_discoverable() {
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Jobs));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Hex));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::LocalGraph));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Diff));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Trace));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Firmware));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Crash));
        assert!(WORKSPACE_LENSES.contains(&NavigationLens::Protocol));
        assert_eq!(NavigationLens::Jobs.label(), "Analysis Jobs");
        assert_eq!(NavigationLens::Hex.badge(), "HEX");
        assert_eq!(NavigationLens::LocalGraph.badge(), "REL");
        assert_eq!(NavigationLens::Diff.label(), "Diff Lab");
        assert_eq!(NavigationLens::Trace.badge(), "TRC");
        assert_eq!(NavigationLens::Firmware.label(), "Firmware Lab");
        assert_eq!(NavigationLens::Crash.label(), "Crash Lab");
        assert_eq!(NavigationLens::Protocol.badge(), "PRO");
    }

    #[test]
    fn lab_evidence_objects_route_to_shared_lenses() {
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::FirmwareFile),
            NavigationLens::Firmware
        );
        for kind in [ObjectKind::PluginContribution] {
            assert_eq!(
                NavigationLens::for_object_kind(kind),
                NavigationLens::LocalGraph
            );
        }
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::ProtocolSample),
            NavigationLens::Protocol
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::ProtocolMessage),
            NavigationLens::Protocol
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::ProtocolField),
            NavigationLens::Protocol
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::CrashReport),
            NavigationLens::Crash
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::CrashFrame),
            NavigationLens::Crash
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::DiffDelta),
            NavigationLens::Diff
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::TraceSession),
            NavigationLens::Trace
        );
        assert_eq!(
            NavigationLens::for_object_kind(ObjectKind::TraceEvent),
            NavigationLens::Trace
        );
    }
}
