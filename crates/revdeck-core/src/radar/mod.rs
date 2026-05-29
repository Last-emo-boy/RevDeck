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
pub const SIGNAL_IMPORT_FAMILY: &str = "import_family";
pub const SIGNAL_STRING_SIGNAL: &str = "string_signal";
pub const SIGNAL_KNOWN_LIBRARY_BASELINE: &str = "known_library_baseline";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFamily {
    Process,
    Filesystem,
    Registry,
    Network,
    Crypto,
    Memory,
    Loader,
    Ui,
    Libc,
    Uncategorized,
}

impl ImportFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Filesystem => "filesystem",
            Self::Registry => "registry",
            Self::Network => "network",
            Self::Crypto => "crypto",
            Self::Memory => "memory",
            Self::Loader => "loader",
            Self::Ui => "ui",
            Self::Libc => "libc",
            Self::Uncategorized => "uncategorized",
        }
    }

    pub const fn radar_contribution(self) -> i32 {
        match self {
            Self::Process => 10,
            Self::Network => 10,
            Self::Crypto => 8,
            Self::Registry => 7,
            Self::Memory => 6,
            Self::Loader => 6,
            Self::Filesystem => 5,
            Self::Libc => 3,
            Self::Ui | Self::Uncategorized => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringSignal {
    Url,
    FilePath,
    RegistryKey,
    Command,
    Credential,
    FormatString,
    UiText,
    Debug,
    Noise,
    Other,
}

impl StringSignal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::FilePath => "file_path",
            Self::RegistryKey => "registry_key",
            Self::Command => "command",
            Self::Credential => "credential",
            Self::FormatString => "format_string",
            Self::UiText => "ui_text",
            Self::Debug => "debug",
            Self::Noise => "noise",
            Self::Other => "other",
        }
    }

    pub const fn radar_contribution(self) -> i32 {
        match self {
            Self::Credential => 25,
            Self::Command => 18,
            Self::Url => 14,
            Self::RegistryKey => 10,
            Self::FilePath => 8,
            Self::FormatString => 6,
            Self::Debug => 4,
            Self::UiText | Self::Noise | Self::Other => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadarEvidence {
    pub object_ref: ObjectRef,
    pub label: String,
    pub value: String,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownLibraryBaselineHit {
    pub signature_id: String,
    pub label: String,
    pub category: String,
    pub confidence: f64,
    pub score_adjustment: i32,
}

#[derive(Debug, Clone, Copy)]
struct KnownLibrarySignature {
    signature_id: &'static str,
    name: &'static str,
    label: &'static str,
    category: &'static str,
    confidence: f64,
    score_adjustment: i32,
}

const KNOWN_LIBRARY_NAME_SIGNATURES: &[KnownLibrarySignature] = &[
    KnownLibrarySignature {
        signature_id: "elf.runtime._start",
        name: "_start",
        label: "ELF runtime entry stub",
        category: "runtime",
        confidence: 0.90,
        score_adjustment: -18,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime.__libc_start_main",
        name: "__libc_start_main",
        label: "libc process bootstrap",
        category: "runtime",
        confidence: 0.92,
        score_adjustment: -18,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime.deregister_tm_clones",
        name: "deregister_tm_clones",
        label: "GCC transactional memory clone cleanup",
        category: "compiler_runtime",
        confidence: 0.95,
        score_adjustment: -20,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime.register_tm_clones",
        name: "register_tm_clones",
        label: "GCC transactional memory clone setup",
        category: "compiler_runtime",
        confidence: 0.95,
        score_adjustment: -20,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime.__do_global_dtors_aux",
        name: "__do_global_dtors_aux",
        label: "GCC global destructor helper",
        category: "compiler_runtime",
        confidence: 0.95,
        score_adjustment: -20,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime.frame_dummy",
        name: "frame_dummy",
        label: "GCC frame registration helper",
        category: "compiler_runtime",
        confidence: 0.93,
        score_adjustment: -16,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime._init",
        name: "_init",
        label: "ELF init stub",
        category: "runtime",
        confidence: 0.88,
        score_adjustment: -12,
    },
    KnownLibrarySignature {
        signature_id: "elf.runtime._fini",
        name: "_fini",
        label: "ELF fini stub",
        category: "runtime",
        confidence: 0.88,
        score_adjustment: -12,
    },
    KnownLibrarySignature {
        signature_id: "msvc.runtime.__security_init_cookie",
        name: "__security_init_cookie",
        label: "MSVC security cookie initialization",
        category: "compiler_runtime",
        confidence: 0.90,
        score_adjustment: -14,
    },
    KnownLibrarySignature {
        signature_id: "msvc.runtime._scrt_common_main",
        name: "_scrt_common_main",
        label: "MSVC CRT main bootstrap",
        category: "runtime",
        confidence: 0.90,
        score_adjustment: -14,
    },
];

const COMMON_RUNTIME_IMPORTS: &[&str] = &[
    "__libc_start_main",
    "__cxa_finalize",
    "atexit",
    "exit",
    "malloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "strlen",
    "strcmp",
    "strncmp",
    "printf",
    "fprintf",
    "puts",
    "putchar",
];

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
        let family = classify_import_family(&import.label, &import.value);
        let family_contribution = family.radar_contribution();
        if family_contribution > 0 {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_IMPORT_FAMILY,
                    reason_code(SIGNAL_IMPORT_FAMILY, family.as_str()),
                    format!("Import family {} via {}", family.as_str(), import.label),
                    family_contribution,
                    family_contribution,
                    vec![import.object_ref.clone()],
                )
                .with_metadata("family", family.as_str())
                .with_metadata("value", import.value.clone()),
            );
        }
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
        let signal = classify_string_signal(&string.value);
        let signal_contribution = signal.radar_contribution();
        if signal_contribution > 0 {
            reasons.push(
                ScoreReason::new(
                    SIGNAL_STRING_SIGNAL,
                    reason_code(SIGNAL_STRING_SIGNAL, signal.as_str()),
                    format!("String signal {} in {}", signal.as_str(), string.label),
                    signal_contribution,
                    signal_contribution,
                    vec![string.object_ref.clone()],
                )
                .with_metadata("signal", signal.as_str())
                .with_metadata("value", string.value.clone()),
            );
        }
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

    for hit in classify_known_library_baseline(&input) {
        reasons.push(
            ScoreReason::new(
                SIGNAL_KNOWN_LIBRARY_BASELINE,
                reason_code(SIGNAL_KNOWN_LIBRARY_BASELINE, &hit.signature_id),
                hit.label.clone(),
                hit.score_adjustment,
                hit.score_adjustment.abs(),
                vec![input.function_ref.clone()],
            )
            .with_metadata("signature_id", hit.signature_id)
            .with_metadata("category", hit.category)
            .with_metadata("confidence", format!("{:.2}", hit.confidence)),
        );
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

pub fn classify_import_family(label: &str, value: &str) -> ImportFamily {
    let lower = format!("{label}!{value}").to_ascii_lowercase();
    if contains_any(
        &lower,
        &["regopen", "regset", "regquery", "regdelete", "registry"],
    ) {
        ImportFamily::Registry
    } else if contains_any(
        &lower,
        &[
            "createprocess",
            "shellexecute",
            "winexec",
            "system",
            "popen",
            "exec",
            "fork",
            "spawn",
            "terminateprocess",
            "openprocess",
        ],
    ) {
        ImportFamily::Process
    } else if contains_any(
        &lower,
        &[
            "createfile",
            "readfile",
            "writefile",
            "deletefile",
            "copyfile",
            "movefile",
            "findfirstfile",
            "fopen",
            "fread",
            "fwrite",
            "open",
            "read",
            "write",
        ],
    ) {
        ImportFamily::Filesystem
    } else if contains_any(
        &lower,
        &[
            "socket",
            "connect",
            "send",
            "recv",
            "internet",
            "winhttp",
            "wsastartup",
            "getaddrinfo",
            "urlmon",
        ],
    ) {
        ImportFamily::Network
    } else if contains_any(
        &lower,
        &[
            "crypt", "bcrypt", "cert", "hash", "encrypt", "decrypt", "ssl", "tls",
        ],
    ) {
        ImportFamily::Crypto
    } else if contains_any(
        &lower,
        &[
            "virtualalloc",
            "virtualprotect",
            "heapalloc",
            "rtlmove",
            "memcpy",
            "memset",
            "malloc",
            "free",
        ],
    ) {
        ImportFamily::Memory
    } else if contains_any(
        &lower,
        &[
            "loadlibrary",
            "getprocaddress",
            "dlopen",
            "dlsym",
            "ldrload",
        ],
    ) {
        ImportFamily::Loader
    } else if contains_any(
        &lower,
        &[
            "user32",
            "messagebox",
            "createwindow",
            "dialog",
            "dispatchmessage",
            "getmessage",
        ],
    ) {
        ImportFamily::Ui
    } else if contains_any(
        &lower,
        &[
            "libc", "msvcrt", "printf", "scanf", "strlen", "strcmp", "strcpy",
        ],
    ) {
        ImportFamily::Libc
    } else {
        ImportFamily::Uncategorized
    }
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

pub fn classify_string_signal(value: &str) -> StringSignal {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() <= 2 {
        StringSignal::Noise
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        StringSignal::Url
    } else if lower.starts_with("hkey_")
        || lower.starts_with("hkcu\\")
        || lower.starts_with("hklm\\")
        || lower.contains("\\software\\")
    {
        StringSignal::RegistryKey
    } else if contains_any(
        &lower,
        &[
            "password",
            "passwd",
            "token",
            "secret",
            "credential",
            "api_key",
            "apikey",
        ],
    ) {
        StringSignal::Credential
    } else if contains_any(
        &lower,
        &[
            "cmd.exe",
            "powershell",
            "/bin/sh",
            "/bin/bash",
            "rundll32",
            "regsvr32",
        ],
    ) {
        StringSignal::Command
    } else if looks_like_path(trimmed) {
        StringSignal::FilePath
    } else if looks_like_format_string(trimmed) {
        StringSignal::FormatString
    } else if contains_any(&lower, &["debug", "trace", "assert", "error:", "warning:"]) {
        StringSignal::Debug
    } else if looks_like_ui_text(trimmed) {
        StringSignal::UiText
    } else {
        StringSignal::Other
    }
}

pub fn classify_known_library_baseline(input: &FunctionScoreInput) -> Vec<KnownLibraryBaselineHit> {
    let normalized_name = normalize_symbol_name(&input.name);
    let mut hits = Vec::new();
    for signature in KNOWN_LIBRARY_NAME_SIGNATURES {
        if normalized_name == normalize_symbol_name(signature.name) {
            hits.push(KnownLibraryBaselineHit {
                signature_id: signature.signature_id.to_string(),
                label: signature.label.to_string(),
                category: signature.category.to_string(),
                confidence: signature.confidence,
                score_adjustment: signature.score_adjustment,
            });
        }
    }

    let runtime_import_count = input
        .called_imports
        .iter()
        .filter(|import| {
            let symbol = normalize_symbol_name(&import.value);
            COMMON_RUNTIME_IMPORTS
                .iter()
                .any(|candidate| symbol == normalize_symbol_name(candidate))
        })
        .count();
    if runtime_import_count >= 3
        && input
            .called_imports
            .iter()
            .all(|import| dangerous_import_match(&import.value).is_none())
    {
        hits.push(KnownLibraryBaselineHit {
            signature_id: "runtime.common_import_cluster".to_string(),
            label: "Common runtime import cluster".to_string(),
            category: "runtime_imports".to_string(),
            confidence: 0.70,
            score_adjustment: -8,
        });
    }

    hits
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn looks_like_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains(":\\")
        || lower.starts_with("\\\\")
        || lower.starts_with('/')
        || lower.contains("\\windows\\")
        || lower.contains("\\system32\\")
        || lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.ends_with(".ini")
        || lower.ends_with(".json")
}

fn looks_like_format_string(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != b'%' {
            return false;
        }
        let mut cursor = index + 1;
        while cursor < bytes.len()
            && matches!(
                bytes[cursor],
                b'0'..=b'9' | b'.' | b'-' | b'+' | b'#' | b' ' | b'l' | b'h' | b'z' | b't'
            )
        {
            cursor += 1;
        }
        cursor < bytes.len()
            && matches!(
                bytes[cursor].to_ascii_lowercase(),
                b's' | b'd' | b'i' | b'u' | b'x' | b'p' | b'f' | b'c'
            )
    })
}

fn looks_like_ui_text(value: &str) -> bool {
    let alpha = value.chars().filter(|ch| ch.is_alphabetic()).count();
    let whitespace = value.chars().filter(|ch| ch.is_whitespace()).count();
    alpha >= 4 && (whitespace > 0 || value.chars().any(|ch| ch.is_uppercase()))
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

fn normalize_symbol_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
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
    fn import_family_classifier_covers_common_win32_and_libc_groups() {
        assert_eq!(
            classify_import_family("KERNEL32.dll", "CreateProcessW"),
            ImportFamily::Process
        );
        assert_eq!(
            classify_import_family("KERNEL32.dll", "CreateFileW"),
            ImportFamily::Filesystem
        );
        assert_eq!(
            classify_import_family("ADVAPI32.dll", "RegOpenKeyExW"),
            ImportFamily::Registry
        );
        assert_eq!(
            classify_import_family("WS2_32.dll", "connect"),
            ImportFamily::Network
        );
        assert_eq!(
            classify_import_family("BCRYPT.dll", "BCryptEncrypt"),
            ImportFamily::Crypto
        );
        assert_eq!(
            classify_import_family("KERNEL32.dll", "VirtualAlloc"),
            ImportFamily::Memory
        );
        assert_eq!(
            classify_import_family("KERNEL32.dll", "LoadLibraryW"),
            ImportFamily::Loader
        );
        assert_eq!(
            classify_import_family("USER32.dll", "MessageBoxW"),
            ImportFamily::Ui
        );
        assert_eq!(
            classify_import_family("libc.so.6", "printf"),
            ImportFamily::Libc
        );
        assert_eq!(
            classify_import_family("unknown.dll", "PlainSymbol"),
            ImportFamily::Uncategorized
        );
    }

    #[test]
    fn string_signal_classifier_covers_high_value_and_low_value_strings() {
        assert_eq!(
            classify_string_signal("https://example.invalid/api"),
            StringSignal::Url
        );
        assert_eq!(
            classify_string_signal("C:\\Windows\\System32\\notepad.exe"),
            StringSignal::FilePath
        );
        assert_eq!(
            classify_string_signal("HKEY_CURRENT_USER\\Software\\Vendor"),
            StringSignal::RegistryKey
        );
        assert_eq!(
            classify_string_signal("cmd.exe /c whoami"),
            StringSignal::Command
        );
        assert_eq!(
            classify_string_signal("admin password token"),
            StringSignal::Credential
        );
        assert_eq!(
            classify_string_signal("value=%08x"),
            StringSignal::FormatString
        );
        assert_eq!(classify_string_signal("Open File"), StringSignal::UiText);
        assert_eq!(
            classify_string_signal("debug trace line"),
            StringSignal::Debug
        );
        assert_eq!(classify_string_signal("ok"), StringSignal::Noise);
    }

    #[test]
    fn radar_adds_family_and_string_signal_reasons_without_replacing_existing_signals() {
        let mut input = input("main", 0x401000);
        input.called_imports.push(RadarEvidence::new(
            import("CreateProcessW").object_ref,
            "KERNEL32!CreateProcessW",
            "CreateProcessW",
        ));
        input
            .referenced_strings
            .push(string("https://example.invalid/c2"));

        let score = score_function(input);

        assert!(score.reasons.iter().any(|reason| {
            reason.signal_key == SIGNAL_IMPORT_FAMILY
                && reason.metadata.get("family").map(String::as_str) == Some("process")
        }));
        assert!(score.reasons.iter().any(|reason| {
            reason.signal_key == SIGNAL_STRING_SIGNAL
                && reason.metadata.get("signal").map(String::as_str) == Some("url")
        }));
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.signal_key == SIGNAL_SENSITIVE_STRING));
    }

    #[test]
    fn known_library_baseline_marks_common_runtime_without_hiding_dangerous_imports() {
        let mut runtime = input("__libc_start_main", 0x401100);
        runtime.size = Some(64);
        let runtime_score = score_function(runtime);

        let baseline_reason = runtime_score
            .reasons
            .iter()
            .find(|reason| reason.signal_key == SIGNAL_KNOWN_LIBRARY_BASELINE)
            .expect("runtime function should have a known-library baseline reason");
        assert!(baseline_reason.contribution < 0);
        assert_eq!(
            baseline_reason
                .metadata
                .get("signature_id")
                .map(String::as_str),
            Some("elf.runtime.__libc_start_main")
        );

        let mut dangerous = input("runtime_wrapper", 0x401200);
        dangerous.called_imports.push(import("system"));
        dangerous.called_imports.push(import("__libc_start_main"));
        dangerous.called_imports.push(import("printf"));
        dangerous.called_imports.push(import("strlen"));
        let dangerous_score = score_function(dangerous);

        assert!(dangerous_score.score >= 40);
        assert!(dangerous_score
            .reasons
            .iter()
            .any(|reason| reason.signal_key == SIGNAL_DANGEROUS_IMPORT));
        assert!(!dangerous_score.reasons.iter().any(|reason| {
            reason.reason_code == "known_library_baseline.runtime_common_import_cluster"
        }));
    }

    #[test]
    fn known_library_baseline_cluster_lowers_common_library_noise_only() {
        let mut input = input("helper", 0x401300);
        input.called_imports.push(import("printf"));
        input.called_imports.push(import("strlen"));
        input.called_imports.push(import("memcpy"));

        let score = score_function(input);

        assert!(score.reasons.iter().any(|reason| {
            reason.signal_key == SIGNAL_KNOWN_LIBRARY_BASELINE
                && reason.contribution < 0
                && reason.metadata.get("category").map(String::as_str) == Some("runtime_imports")
        }));
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
