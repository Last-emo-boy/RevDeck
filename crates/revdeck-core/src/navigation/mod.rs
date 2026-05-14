use crate::{ObjectKind, ObjectRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NavigationLens {
    Overview,
    TriageBoard,
    BinaryMap,
    FunctionRadar,
    Functions,
    Strings,
    Imports,
    Notes,
    Findings,
    Inspector,
    LocalGraph,
}

impl NavigationLens {
    pub fn for_object_kind(kind: ObjectKind) -> Self {
        match kind {
            ObjectKind::Artifact | ObjectKind::File | ObjectKind::Binary | ObjectKind::Section => {
                Self::BinaryMap
            }
            ObjectKind::Function | ObjectKind::Symbol | ObjectKind::Score => Self::FunctionRadar,
            ObjectKind::String => Self::Strings,
            ObjectKind::Import => Self::Imports,
            ObjectKind::Instruction
            | ObjectKind::BasicBlock
            | ObjectKind::Xref
            | ObjectKind::Edge => Self::LocalGraph,
            ObjectKind::Annotation => Self::Notes,
            ObjectKind::Finding => Self::Findings,
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
}
