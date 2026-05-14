use crate::{ObjectKind, ObjectRef};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const FUNCTION_RADAR_SCORE_KIND: &str = "function_radar";

pub const SIGNAL_DANGEROUS_IMPORT: &str = "dangerous_import";
pub const SIGNAL_SENSITIVE_STRING: &str = "sensitive_string";
pub const SIGNAL_ENTRYPOINT: &str = "entrypoint";
pub const SIGNAL_BOUNDARY_CONFIDENCE: &str = "boundary_confidence";
pub const SIGNAL_FUNCTION_SIZE: &str = "function_size";
pub const SIGNAL_CALL_COUNT: &str = "call_count";
pub const SIGNAL_XREF_COUNT: &str = "xref_count";
pub const SIGNAL_ANALYST_TAG: &str = "analyst_tag";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadarEvidence {
    pub object_ref: ObjectRef,
    pub label: String,
    pub value: String,
    pub address: Option<u64>,
}

impl RadarEvidence {
    pub fn new(object_ref: ObjectRef, label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            object_ref,
            label: label.into(),
            value: value.into(),
            address: None,
        }
    }

    pub fn with_address(mut self, address: Option<u64>) -> Self {
        self.address = address;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreReason {
    pub reason_code: String,
    pub signal_key: String,
    pub display_label: String,
    pub contribution: i32,
    pub weight: i32,
    pub evidence_refs: Vec<ObjectRef>,
    pub source_run_id: Option<i64>,
    pub metadata: BTreeMap<String, String>,
}

impl ScoreReason {
    pub fn new(
        signal_key: impl Into<String>,
        reason_code: impl Into<String>,
        display_label: impl Into<String>,
        contribution: i32,
        weight: i32,
        evidence_refs: Vec<ObjectRef>,
    ) -> Self {
        let mut evidence_refs = evidence_refs;
        evidence_refs.sort();
        evidence_refs.dedup();
        Self {
            reason_code: reason_code.into(),
            signal_key: signal_key.into(),
            display_label: display_label.into(),
            contribution,
            weight,
            evidence_refs,
            source_run_id: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn with_source_run_id(mut self, source_run_id: i64) -> Self {
        self.source_run_id = Some(source_run_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionScoreInput {
    pub artifact_ref: ObjectRef,
    pub function_ref: ObjectRef,
    pub name: String,
    pub virtual_address: Option<u64>,
    pub size: Option<u64>,
    pub boundary_source: String,
    pub boundary_confidence: String,
    pub call_count: u64,
    pub string_count: u64,
    pub xref_count: u64,
    pub entrypoint: Option<u64>,
    pub referenced_strings: Vec<RadarEvidence>,
    pub called_imports: Vec<RadarEvidence>,
    pub tags: Vec<String>,
    pub status: Option<String>,
}

impl FunctionScoreInput {
    pub fn new(artifact_ref: ObjectRef, function_ref: ObjectRef, name: impl Into<String>) -> Self {
        Self {
            artifact_ref,
            function_ref,
            name: name.into(),
            virtual_address: None,
            size: None,
            boundary_source: "unknown".to_string(),
            boundary_confidence: "unknown".to_string(),
            call_count: 0,
            string_count: 0,
            xref_count: 0,
            entrypoint: None,
            referenced_strings: Vec::new(),
            called_imports: Vec::new(),
            tags: Vec::new(),
            status: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionScore {
    pub artifact_ref: ObjectRef,
    pub function_ref: ObjectRef,
    pub name: String,
    pub virtual_address: Option<u64>,
    pub size: Option<u64>,
    pub boundary_source: String,
    pub boundary_confidence: String,
    pub call_count: u64,
    pub string_count: u64,
    pub xref_count: u64,
    pub tags: Vec<String>,
    pub status: Option<String>,
    pub score: i32,
    pub reasons: Vec<ScoreReason>,
}

impl FunctionScore {
    pub fn with_source_run_id(mut self, source_run_id: i64) -> Self {
        for reason in &mut self.reasons {
            reason.source_run_id = Some(source_run_id);
        }
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionRadarFilter {
    pub min_score: Option<i32>,
    pub reason_code: Option<String>,
    pub tag: Option<String>,
    pub status: Option<String>,
    pub include_zero_score: bool,
}

impl FunctionRadarFilter {
    pub fn matches(&self, score: &FunctionScore) -> bool {
        if !self.include_zero_score && score.score == 0 {
            return false;
        }
        if let Some(min_score) = self.min_score {
            if score.score < min_score {
                return false;
            }
        }
        if let Some(reason_code) = &self.reason_code {
            if !score
                .reasons
                .iter()
                .any(|reason| reason.reason_code == *reason_code)
            {
                return false;
            }
        }
        if let Some(tag) = &self.tag {
            let normalized = tag.to_ascii_lowercase();
            if !score
                .tags
                .iter()
                .any(|candidate| candidate.to_ascii_lowercase() == normalized)
            {
                return false;
            }
        }
        if let Some(status) = &self.status {
            if score.status.as_deref() != Some(status.as_str()) {
                return false;
            }
        }
        true
    }
}

pub fn score_function(input: FunctionScoreInput) -> FunctionScore {
    let mut reasons = Vec::new();

    let mut imports = input.called_imports.clone();
    imports.sort_by(|left, right| {
        left.value
            .cmp(&right.value)
            .then_with(|| left.object_ref.cmp(&right.object_ref))
    });
    for import in imports {
        if let Some(matched) = dangerous_import_match(&import.value) {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_DANGEROUS_IMPORT,
                    reason_code(SIGNAL_DANGEROUS_IMPORT, matched),
                    format!("Dangerous import {}", import.label),
                    40,
                    40,
                    vec![import.object_ref.clone()],
                )
                .with_metadata("matched", matched)
                .with_metadata("value", import.value),
            );
        }
    }

    let mut strings = input.referenced_strings.clone();
    strings.sort_by(|left, right| {
        left.value
            .cmp(&right.value)
            .then_with(|| left.object_ref.cmp(&right.object_ref))
    });
    for string in strings {
        if let Some(matched) = sensitive_string_match(&string.value) {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_SENSITIVE_STRING,
                    reason_code(SIGNAL_SENSITIVE_STRING, matched),
                    format!("Sensitive string contains {}", matched),
                    25,
                    25,
                    vec![string.object_ref.clone()],
                )
                .with_metadata("matched", matched)
                .with_metadata("value", string.value),
            );
        }
    }

    if let (Some(function_address), Some(entrypoint)) = (input.virtual_address, input.entrypoint) {
        let distance = function_address.abs_diff(entrypoint);
        if distance == 0 {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_ENTRYPOINT,
                    "entrypoint.exact",
                    "Function starts at binary entrypoint",
                    12,
                    12,
                    vec![input.artifact_ref.clone()],
                )
                .with_metadata("distance", "0"),
            );
        } else if distance <= 0x40 {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_ENTRYPOINT,
                    "entrypoint.near",
                    "Function is near binary entrypoint",
                    8,
                    8,
                    vec![input.artifact_ref.clone()],
                )
                .with_metadata("distance", distance.to_string()),
            );
        }
    }

    if let Some(reason) = boundary_confidence_reason(&input) {
        reasons.push(reason);
    }

    if let Some(size) = input.size {
        let (reason_suffix, contribution) = if size >= 1024 {
            ("huge", 15)
        } else if size >= 256 {
            ("large", 10)
        } else if size >= 96 {
            ("medium", 5)
        } else {
            ("", 0)
        };
        if contribution > 0 {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_FUNCTION_SIZE,
                    reason_code(SIGNAL_FUNCTION_SIZE, reason_suffix),
                    format!("Function span is {} bytes", size),
                    contribution,
                    contribution,
                    vec![input.function_ref.clone()],
                )
                .with_metadata("size", size.to_string()),
            );
        }
    }

    let effective_call_count = input.call_count + input.called_imports.len() as u64;
    if effective_call_count >= 3 {
        reasons.push(
            ScoreReason::new(
                SIGNAL_CALL_COUNT,
                "call_count.high",
                format!("Function has {} call/import edges", effective_call_count),
                6,
                6,
                vec![input.function_ref.clone()],
            )
            .with_metadata("call_count", effective_call_count.to_string()),
        );
    }

    let effective_xref_count = input.xref_count
        + input.referenced_strings.len() as u64
        + input.called_imports.len() as u64;
    if effective_xref_count >= 4 {
        reasons.push(
            ScoreReason::new(
                SIGNAL_XREF_COUNT,
                "xref_count.high",
                format!("Function has {} xref-backed signals", effective_xref_count),
                5,
                5,
                vec![input.function_ref.clone()],
            )
            .with_metadata("xref_count", effective_xref_count.to_string()),
        );
    }

    let mut tags = normalize_tags(&input.tags);
    for tag in &tags {
        if let Some(contribution) = tag_contribution(tag) {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_ANALYST_TAG,
                    reason_code(SIGNAL_ANALYST_TAG, tag),
                    format!("Analyst tag {}", tag),
                    contribution,
                    contribution.abs(),
                    vec![input.function_ref.clone()],
                )
                .with_metadata("tag", tag.clone()),
            );
        }
    }

    sort_reasons(&mut reasons);
    let score = reasons
        .iter()
        .map(|reason| reason.contribution)
        .sum::<i32>()
        .max(0);

    FunctionScore {
        artifact_ref: input.artifact_ref,
        function_ref: input.function_ref,
        name: input.name,
        virtual_address: input.virtual_address,
        size: input.size,
        boundary_source: input.boundary_source,
        boundary_confidence: input.boundary_confidence,
        call_count: input.call_count,
        string_count: input.string_count,
        xref_count: input.xref_count,
        tags: {
            tags.sort();
            tags
        },
        status: input.status,
        score,
        reasons,
    }
}

pub fn score_functions(inputs: Vec<FunctionScoreInput>) -> Vec<FunctionScore> {
    let mut scores = inputs.into_iter().map(score_function).collect::<Vec<_>>();
    sort_function_scores(&mut scores);
    scores
}

pub fn sort_function_scores(scores: &mut [FunctionScore]) {
    scores.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.artifact_ref.key.cmp(&right.artifact_ref.key))
            .then_with(|| {
                left.virtual_address
                    .unwrap_or(u64::MAX)
                    .cmp(&right.virtual_address.unwrap_or(u64::MAX))
            })
            .then_with(|| left.function_ref.key.cmp(&right.function_ref.key))
    });
}

pub fn filter_function_scores(
    scores: &[FunctionScore],
    filter: &FunctionRadarFilter,
) -> Vec<FunctionScore> {
    let mut filtered = scores
        .iter()
        .filter(|score| filter.matches(score))
        .cloned()
        .collect::<Vec<_>>();
    sort_function_scores(&mut filtered);
    filtered
}

pub fn dangerous_import_match(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    [
        "system", "popen", "execve", "execl", "exec", "strcpy", "sprintf", "gets", "recv", "read",
        "open",
    ]
    .into_iter()
    .find(|needle| lower.contains(needle))
}

pub fn sensitive_string_match(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    [
        "password", "passwd", "token", "secret", "key", "/bin/sh", "shell", "cmd", "admin", "auth",
        "http", "debug",
    ]
    .into_iter()
    .find(|needle| lower.contains(needle))
}

fn boundary_confidence_reason(input: &FunctionScoreInput) -> Option<ScoreReason> {
    let normalized = input.boundary_confidence.to_ascii_lowercase();
    let contribution = match normalized.as_str() {
        "external_adapter" => 3,
        "symbol" => 2,
        "entrypoint" => 1,
        _ => return None,
    };
    Some(
        ScoreReason::new(
            SIGNAL_BOUNDARY_CONFIDENCE,
            reason_code(SIGNAL_BOUNDARY_CONFIDENCE, &normalized),
            format!(
                "Boundary confidence {} from {}",
                input.boundary_confidence, input.boundary_source
            ),
            contribution,
            contribution,
            vec![input.function_ref.clone()],
        )
        .with_metadata("boundary_confidence", input.boundary_confidence.clone())
        .with_metadata("boundary_source", input.boundary_source.clone()),
    )
}

fn tag_contribution(tag: &str) -> Option<i32> {
    match tag {
        "suspicious" => Some(30),
        "interesting" => Some(12),
        "entrypoint" => Some(8),
        "reviewed" => Some(-5),
        "false_positive" => Some(-25),
        _ => None,
    }
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sort_reasons(reasons: &mut [ScoreReason]) {
    reasons.sort_by(|left, right| {
        right
            .contribution
            .cmp(&left.contribution)
            .then_with(|| left.reason_code.cmp(&right.reason_code))
            .then_with(|| left.evidence_refs.cmp(&right.evidence_refs))
    });
}

fn reason_code(signal_key: &str, matched: &str) -> String {
    let suffix = matched
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if suffix.is_empty() {
        signal_key.to_string()
    } else {
        format!("{signal_key}.{suffix}")
    }
}

pub fn format_address(address: Option<u64>) -> String {
    address
        .map(|value| format!("0x{value:016x}"))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn evidence_kind_label(object_ref: &ObjectRef) -> &'static str {
    match object_ref.kind {
        ObjectKind::String => "string",
        ObjectKind::Import => "import",
        ObjectKind::Xref => "xref",
        ObjectKind::Function => "function",
        ObjectKind::Artifact => "artifact",
        ObjectKind::Annotation => "annotation",
        _ => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectKind, StableObjectKey};

    fn artifact() -> ObjectRef {
        ObjectRef::artifact("abc123", "fixture").unwrap()
    }

    fn function(name: &str, address: u64) -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, address, Some(128), Some(name)).unwrap(),
        )
    }

    fn import(symbol: &str) -> RadarEvidence {
        let artifact = artifact();
        RadarEvidence::new(
            ObjectRef::new(
                ObjectKind::Import,
                StableObjectKey::import(&artifact.key, Some("libc.so.6"), symbol, None).unwrap(),
            ),
            symbol,
            symbol,
        )
    }

    fn string(value: &str) -> RadarEvidence {
        let artifact = artifact();
        RadarEvidence::new(
            ObjectRef::new(
                ObjectKind::String,
                StableObjectKey::string(&artifact.key, 0x200, Some(0x402000), value).unwrap(),
            ),
            value,
            value,
        )
    }

    fn input(name: &str, address: u64) -> FunctionScoreInput {
        let artifact = artifact();
        let mut input = FunctionScoreInput::new(artifact.clone(), function(name, address), name);
        input.virtual_address = Some(address);
        input.size = Some(128);
        input.boundary_source = "symbol".to_string();
        input.boundary_confidence = "symbol".to_string();
        input.entrypoint = Some(0x401000);
        input
    }

    #[test]
    fn radar_signal_dangerous_imports() {
        let mut input = input("main", 0x401000);
        input.called_imports.push(import("system"));

        let score = score_function(input);

        assert!(score.score >= 40);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.reason_code == "dangerous_import.system"
                && reason.contribution == 40
                && reason.evidence_refs[0].kind == ObjectKind::Import));
    }

    #[test]
    fn radar_signal_sensitive_strings() {
        let mut input = input("main", 0x401000);
        input
            .referenced_strings
            .push(string("admin password token"));

        let score = score_function(input);

        assert!(score.score >= 25);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.reason_code == "sensitive_string.password"
                && reason.contribution == 25
                && reason.evidence_refs[0].kind == ObjectKind::String));
    }

    #[test]
    fn radar_reason_object_refs() {
        let mut input = input("main", 0x401000);
        input.called_imports.push(import("popen"));
        input.referenced_strings.push(string("/bin/sh"));

        let score = score_function(input);

        for reason in score
            .reasons
            .iter()
            .filter(|reason| reason.contribution > 0)
        {
            assert!(
                !reason.evidence_refs.is_empty(),
                "reason {} has no evidence_refs",
                reason.reason_code
            );
        }
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.signal_key == SIGNAL_DANGEROUS_IMPORT));
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.signal_key == SIGNAL_SENSITIVE_STRING));
    }

    #[test]
    fn radar_stable_sort() {
        let mut first = input("alpha", 0x401100);
        first.called_imports.push(import("system"));
        let mut second = input("beta", 0x401000);
        second.called_imports.push(import("system"));
        let mut third = input("gamma", 0x401200);
        third.called_imports.push(import("system"));

        let scores = score_functions(vec![first, third, second]);
        let addresses = scores
            .iter()
            .map(|score| score.virtual_address.unwrap())
            .collect::<Vec<_>>();

        assert_eq!(addresses, vec![0x401000, 0x401100, 0x401200]);
    }
}
