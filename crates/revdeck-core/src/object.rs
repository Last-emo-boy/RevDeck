use crate::error::{RevDeckError, RevDeckResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Artifact,
    File,
    Binary,
    Section,
    Symbol,
    Function,
    String,
    Import,
    Instruction,
    BasicBlock,
    Xref,
    Edge,
    Score,
    Annotation,
    Finding,
}

impl ObjectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::File => "file",
            Self::Binary => "binary",
            Self::Section => "section",
            Self::Symbol => "symbol",
            Self::Function => "function",
            Self::String => "string",
            Self::Import => "import",
            Self::Instruction => "instruction",
            Self::BasicBlock => "basic_block",
            Self::Xref => "xref",
            Self::Edge => "edge",
            Self::Score => "score",
            Self::Annotation => "annotation",
            Self::Finding => "finding",
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ObjectKind {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "artifact" => Ok(Self::Artifact),
            "file" => Ok(Self::File),
            "binary" => Ok(Self::Binary),
            "section" => Ok(Self::Section),
            "symbol" => Ok(Self::Symbol),
            "function" => Ok(Self::Function),
            "string" => Ok(Self::String),
            "import" => Ok(Self::Import),
            "instruction" => Ok(Self::Instruction),
            "basic_block" => Ok(Self::BasicBlock),
            "xref" => Ok(Self::Xref),
            "edge" => Ok(Self::Edge),
            "score" => Ok(Self::Score),
            "annotation" => Ok(Self::Annotation),
            "finding" => Ok(Self::Finding),
            other => Err(RevDeckError::InvalidObjectKeyComponent {
                component: "object_kind".to_string(),
                reason: format!("unknown kind `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Contains,
    References,
    Calls,
    CallsImport,
    ControlFlow,
    HasXref,
    XrefFrom,
    Annotates,
    EvidenceFor,
    DerivedFrom,
}

impl EdgeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::References => "references",
            Self::Calls => "calls",
            Self::CallsImport => "calls_import",
            Self::ControlFlow => "control_flow",
            Self::HasXref => "has_xref",
            Self::XrefFrom => "xref_from",
            Self::Annotates => "annotates",
            Self::EvidenceFor => "evidence_for",
            Self::DerivedFrom => "derived_from",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Contains => "CONTAINS",
            Self::References => "REFERENCES",
            Self::Calls => "CALLS",
            Self::CallsImport => "CALLS_IMPORT",
            Self::ControlFlow => "CONTROL_FLOW",
            Self::HasXref => "HAS_XREF",
            Self::XrefFrom => "XREF_FROM",
            Self::Annotates => "ANNOTATES",
            Self::EvidenceFor => "EVIDENCE_FOR",
            Self::DerivedFrom => "DERIVED_FROM",
        }
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EdgeKind {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "contains" => Ok(Self::Contains),
            "references" => Ok(Self::References),
            "calls" => Ok(Self::Calls),
            "calls_import" => Ok(Self::CallsImport),
            "control_flow" => Ok(Self::ControlFlow),
            "has_xref" => Ok(Self::HasXref),
            "xref_from" => Ok(Self::XrefFrom),
            "annotates" => Ok(Self::Annotates),
            "evidence_for" => Ok(Self::EvidenceFor),
            "derived_from" => Ok(Self::DerivedFrom),
            other => Err(RevDeckError::InvalidObjectKeyComponent {
                component: "edge_kind".to_string(),
                reason: format!("unknown kind `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct StableObjectKey(String);

impl StableObjectKey {
    pub fn new(value: impl Into<String>) -> RevDeckResult<Self> {
        let value = value.into();
        validate_stable_key(&value)?;
        Ok(Self(value))
    }

    pub fn artifact(content_sha256: &str, normalized_path: &str) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::Artifact)
            .component("sha256", content_sha256)?
            .component("path", normalized_path)?
            .finish()
    }

    pub fn section(
        artifact_key: &StableObjectKey,
        name: &str,
        virtual_address: u64,
        size: u64,
    ) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::Section)
            .component("artifact", artifact_key.as_str())?
            .component("name", name)?
            .component("va", hex64(virtual_address))?
            .component("size", size.to_string())?
            .finish()
    }

    pub fn symbol(
        artifact_key: &StableObjectKey,
        name: &str,
        virtual_address: u64,
        size: Option<u64>,
    ) -> RevDeckResult<Self> {
        let mut builder = StableObjectKeyBuilder::new(ObjectKind::Symbol)
            .component("artifact", artifact_key.as_str())?
            .component("name", name)?
            .component("va", hex64(virtual_address))?;
        if let Some(size) = size {
            builder = builder.component("size", size.to_string())?;
        }
        builder.finish()
    }

    pub fn function(
        artifact_key: &StableObjectKey,
        virtual_address: u64,
        size: Option<u64>,
        source_name: Option<&str>,
    ) -> RevDeckResult<Self> {
        let mut builder = StableObjectKeyBuilder::new(ObjectKind::Function)
            .component("artifact", artifact_key.as_str())?
            .component("va", hex64(virtual_address))?;
        if let Some(size) = size {
            builder = builder.component("size", size.to_string())?;
        }
        if let Some(source_name) = source_name {
            builder = builder.component("name", source_name)?;
        }
        builder.finish()
    }

    pub fn string(
        artifact_key: &StableObjectKey,
        offset: u64,
        virtual_address: Option<u64>,
        value: &str,
    ) -> RevDeckResult<Self> {
        let value_hash = short_hash(value.as_bytes());
        let mut builder = StableObjectKeyBuilder::new(ObjectKind::String)
            .component("artifact", artifact_key.as_str())?
            .component("offset", hex64(offset))?;
        if let Some(virtual_address) = virtual_address {
            builder = builder.component("va", hex64(virtual_address))?;
        }
        builder.component("value", value_hash)?.finish()
    }

    pub fn import(
        artifact_key: &StableObjectKey,
        module: Option<&str>,
        symbol: &str,
        ordinal: Option<u64>,
    ) -> RevDeckResult<Self> {
        let mut builder = StableObjectKeyBuilder::new(ObjectKind::Import)
            .component("artifact", artifact_key.as_str())?;
        if let Some(module) = module {
            builder = builder.component("module", module)?;
        }
        builder = builder.component("symbol", symbol)?;
        if let Some(ordinal) = ordinal {
            builder = builder.component("ordinal", ordinal.to_string())?;
        }
        builder.finish()
    }

    pub fn instruction(
        artifact_key: &StableObjectKey,
        virtual_address: u64,
        ordinal: u64,
    ) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::Instruction)
            .component("artifact", artifact_key.as_str())?
            .component("va", hex64(virtual_address))?
            .component("ordinal", ordinal.to_string())?
            .finish()
    }

    pub fn basic_block(
        artifact_key: &StableObjectKey,
        function: &ObjectRef,
        virtual_address: u64,
        ordinal: u64,
    ) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::BasicBlock)
            .component("artifact", artifact_key.as_str())?
            .component("function", function.key.as_str())?
            .component("va", hex64(virtual_address))?
            .component("ordinal", ordinal.to_string())?
            .finish()
    }

    pub fn edge(kind: EdgeKind, source: &ObjectRef, target: &ObjectRef) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::Edge)
            .component("edge_kind", kind.as_str())?
            .component("source", source.key.as_str())?
            .component("target", target.key.as_str())?
            .finish()
    }

    pub fn xref(
        artifact_key: &StableObjectKey,
        source: &ObjectRef,
        target: &ObjectRef,
        relation: &str,
        address: Option<u64>,
    ) -> RevDeckResult<Self> {
        let mut builder = StableObjectKeyBuilder::new(ObjectKind::Xref)
            .component("artifact", artifact_key.as_str())?
            .component("source", source.key.as_str())?
            .component("target", target.key.as_str())?
            .component("relation", relation)?;
        if let Some(address) = address {
            builder = builder.component("address", hex64(address))?;
        }
        builder.finish()
    }

    pub fn score(
        subject: &ObjectRef,
        score_kind: &str,
        source_run_id: Option<i64>,
    ) -> RevDeckResult<Self> {
        let mut builder = StableObjectKeyBuilder::new(ObjectKind::Score)
            .component("subject", subject.key.as_str())?
            .component("score_kind", score_kind)?;
        if let Some(source_run_id) = source_run_id {
            builder = builder.component("run", source_run_id.to_string())?;
        }
        builder.finish()
    }

    pub fn annotation(
        subject: &ObjectRef,
        annotation_kind: &str,
        created_at: &str,
    ) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::Annotation)
            .component("subject", subject.key.as_str())?
            .component("kind", annotation_kind)?
            .component("created_at", created_at)?
            .finish()
    }

    pub fn finding(slug: &str, created_at: &str) -> RevDeckResult<Self> {
        StableObjectKeyBuilder::new(ObjectKind::Finding)
            .component("slug", slug)?
            .component("created_at", created_at)?
            .finish()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StableObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for StableObjectKey {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub key: StableObjectKey,
}

impl ObjectRef {
    pub fn new(kind: ObjectKind, key: StableObjectKey) -> Self {
        Self { kind, key }
    }

    pub fn artifact(content_sha256: &str, normalized_path: &str) -> RevDeckResult<Self> {
        Ok(Self::new(
            ObjectKind::Artifact,
            StableObjectKey::artifact(content_sha256, normalized_path)?,
        ))
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.key)
    }
}

impl FromStr for ObjectRef {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, key) =
            value
                .split_once(':')
                .ok_or_else(|| RevDeckError::InvalidObjectKeyComponent {
                    component: "object_ref".to_string(),
                    reason: "expected `<kind>:<stable-key>`".to_string(),
                })?;
        Ok(Self {
            kind: kind.parse()?,
            key: StableObjectKey::new(key)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StableObjectKeyBuilder {
    kind: ObjectKind,
    parts: Vec<(String, String)>,
}

impl StableObjectKeyBuilder {
    pub fn new(kind: ObjectKind) -> Self {
        Self {
            kind,
            parts: Vec::new(),
        }
    }

    pub fn component(
        mut self,
        name: impl Into<String>,
        value: impl AsRef<str>,
    ) -> RevDeckResult<Self> {
        let name = normalize_component_name(name.into())?;
        let value = normalize_component_value(value.as_ref())?;
        self.parts.push((name, value));
        Ok(self)
    }

    pub fn finish(self) -> RevDeckResult<StableObjectKey> {
        let mut value = self.kind.as_str().to_string();
        for (name, part) in self.parts {
            value.push('/');
            value.push_str(&name);
            value.push('=');
            value.push_str(&part);
        }
        StableObjectKey::new(value)
    }
}

fn validate_stable_key(value: &str) -> RevDeckResult<()> {
    if value.trim().is_empty() {
        return Err(RevDeckError::InvalidObjectKeyComponent {
            component: "stable_key".to_string(),
            reason: "key cannot be empty".to_string(),
        });
    }
    if value.contains('\\') {
        return Err(RevDeckError::InvalidObjectKeyComponent {
            component: "stable_key".to_string(),
            reason: "backslashes are not allowed".to_string(),
        });
    }
    Ok(())
}

fn normalize_component_name(value: String) -> RevDeckResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let is_valid = !normalized.is_empty()
        && normalized
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-');
    if is_valid {
        Ok(normalized)
    } else {
        Err(RevDeckError::InvalidObjectKeyComponent {
            component: "name".to_string(),
            reason: format!("invalid component name `{value}`"),
        })
    }
}

fn normalize_component_value(value: &str) -> RevDeckResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RevDeckError::InvalidObjectKeyComponent {
            component: "value".to_string(),
            reason: "component values cannot be empty".to_string(),
        });
    }
    Ok(trimmed
        .replace('\\', "/")
        .replace('|', "%7C")
        .replace(' ', "%20")
        .to_ascii_lowercase())
}

fn short_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex64(value: u64) -> String {
    format!("0x{value:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> StableObjectKey {
        StableObjectKey::artifact(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "fixtures/minimal-elf",
        )
        .unwrap()
    }

    #[test]
    fn object_ref_round_trips_through_display() {
        let key = StableObjectKey::function(&artifact(), 0x401000, Some(64), Some("main")).unwrap();
        let object_ref = ObjectRef::new(ObjectKind::Function, key);
        let encoded = object_ref.to_string();
        assert_eq!(encoded.parse::<ObjectRef>().unwrap(), object_ref);
    }

    #[test]
    fn object_ref_rejects_unknown_kind() {
        let err = "unknown:artifact/sha256=abc"
            .parse::<ObjectRef>()
            .unwrap_err();
        assert!(err.to_string().contains("unknown kind"));
    }

    #[test]
    fn stable_object_key_is_deterministic_for_artifacts() {
        let first = StableObjectKey::artifact("ABCDEF", "Samples\\Target Bin").unwrap();
        let second = StableObjectKey::artifact("abcdef", "Samples/Target Bin").unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.as_str(),
            "artifact/sha256=abcdef/path=samples/target%20bin"
        );
    }

    #[test]
    fn stable_object_key_builds_each_foundation_kind() {
        let artifact_ref = ObjectRef::new(ObjectKind::Artifact, artifact());
        let function_ref = ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact_ref.key, 0x401000, Some(16), Some("main")).unwrap(),
        );

        let keys = [
            StableObjectKey::section(&artifact_ref.key, ".text", 0x401000, 256).unwrap(),
            StableObjectKey::symbol(&artifact_ref.key, "main", 0x401000, Some(16)).unwrap(),
            function_ref.key.clone(),
            StableObjectKey::string(&artifact_ref.key, 0x120, Some(0x402120), "password").unwrap(),
            StableObjectKey::import(&artifact_ref.key, Some("libc.so.6"), "system", None).unwrap(),
            StableObjectKey::instruction(&artifact_ref.key, 0x401000, 0).unwrap(),
            StableObjectKey::basic_block(&artifact_ref.key, &function_ref, 0x401000, 0).unwrap(),
            StableObjectKey::edge(EdgeKind::Contains, &artifact_ref, &function_ref).unwrap(),
            StableObjectKey::xref(
                &artifact_ref.key,
                &function_ref,
                &artifact_ref,
                EdgeKind::References.as_str(),
                Some(0x401004),
            )
            .unwrap(),
            StableObjectKey::score(&function_ref, "function_radar", Some(7)).unwrap(),
            StableObjectKey::annotation(&function_ref, "note", "2026-05-13T00:00:00Z").unwrap(),
            StableObjectKey::finding("command-execution", "2026-05-13T00:00:00Z").unwrap(),
        ];

        for key in keys {
            assert!(!key.as_str().is_empty());
            assert!(!key.as_str().contains('\\'));
        }
    }
}
