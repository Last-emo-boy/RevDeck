use crate::error::{RevDeckError, RevDeckResult};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Binary,
    Unsupported,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ArtifactKind {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "binary" => Ok(Self::Binary),
            "unsupported" => Ok(Self::Unsupported),
            other => Err(RevDeckError::InvalidObjectKeyComponent {
                component: "artifact_kind".to_string(),
                reason: format!("unknown kind `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Elf,
    Pe,
    Unknown,
}

impl ArtifactFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ArtifactFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ArtifactFormat {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "elf" => Ok(Self::Elf),
            "pe" => Ok(Self::Pe),
            "unknown" => Ok(Self::Unknown),
            other => Err(RevDeckError::InvalidObjectKeyComponent {
                component: "artifact_format".to_string(),
                reason: format!("unknown format `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Pending,
    Indexed,
    Failed,
    Unsupported,
}

impl ImportStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Indexed => "indexed",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ImportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImportStatus {
    type Err = RevDeckError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "indexed" => Ok(Self::Indexed),
            "failed" => Ok(Self::Failed),
            "unsupported" => Ok(Self::Unsupported),
            other => Err(RevDeckError::InvalidObjectKeyComponent {
                component: "import_status".to_string(),
                reason: format!("unknown status `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub kind: ArtifactKind,
    pub format: ArtifactFormat,
    pub architecture: String,
    pub import_status: ImportStatus,
}

impl ArtifactMetadata {
    pub fn new(
        kind: ArtifactKind,
        format: ArtifactFormat,
        architecture: impl Into<String>,
        import_status: ImportStatus,
    ) -> RevDeckResult<Self> {
        let architecture = architecture.into();
        if architecture.trim().is_empty() {
            return Err(RevDeckError::InvalidObjectKeyComponent {
                component: "architecture".to_string(),
                reason: "value cannot be empty".to_string(),
            });
        }
        Ok(Self {
            kind,
            format,
            architecture,
            import_status,
        })
    }
}
