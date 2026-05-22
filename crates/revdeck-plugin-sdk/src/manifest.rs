use crate::{permissions::PermissionSet, validation::ValidationReport};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginMetadata,
    #[serde(default)]
    pub capabilities: Vec<CapabilityDeclaration>,
    #[serde(default)]
    pub permissions: PermissionSet,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub ui: UiContribution,
}

impl PluginManifest {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn validate(&self) -> ValidationReport {
        let mut report = ValidationReport::default();
        validate_plugin_id(&self.plugin.id, &mut report);
        validate_non_empty("plugin.version", &self.plugin.version, &mut report);
        validate_non_empty("plugin.sdk_version", &self.plugin.sdk_version, &mut report);
        if Version::parse(&self.plugin.version).is_err() {
            report.error(
                "invalid_plugin_version",
                "plugin.version must be a valid semantic version",
            );
        }
        if Version::parse(&self.plugin.sdk_version).is_err() {
            report.error(
                "invalid_sdk_version",
                "plugin.sdk_version must be a valid semantic version",
            );
        }
        if let Some(requirement) = &self.plugin.revdeck_compat {
            if VersionReq::parse(requirement).is_err() {
                report.error(
                    "invalid_revdeck_compat",
                    "plugin.revdeck_compat must be a valid semantic version requirement",
                );
            }
        }
        if self.capabilities.is_empty() {
            report.error(
                "missing_capabilities",
                "at least one plugin capability must be declared",
            );
        }
        for capability in &self.capabilities {
            if capability.id.trim().is_empty() {
                report.error("missing_capability_id", "capability.id is required");
            }
        }
        if self.permissions.network {
            report.warning(
                "network_permission",
                "network permission is disabled by default and should be granted explicitly per project",
            );
        }
        if self.permissions.process_spawn {
            report.warning(
                "process_spawn_permission",
                "process_spawn permission requires explicit analyst approval",
            );
        }
        report
    }

    pub fn summary(&self) -> ManifestSummary {
        ManifestSummary {
            id: self.plugin.id.clone(),
            version: self.plugin.version.clone(),
            sdk_version: self.plugin.sdk_version.clone(),
            revdeck_compat: self.plugin.revdeck_compat.clone(),
            capabilities: self
                .capabilities
                .iter()
                .map(|capability| capability.kind)
                .collect(),
            permissions: self.permissions.clone(),
            validation: self.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub id: String,
    pub version: String,
    pub sdk_version: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub revdeck_compat: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    pub id: String,
    pub kind: CapabilityKind,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub experimental: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Importer,
    Adapter,
    Analyzer,
    Scorer,
    ViewDataProvider,
    Exporter,
    ReportContributor,
    RulePack,
    Lens,
    Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UiContribution {
    pub commands: Vec<String>,
    pub lenses: Vec<String>,
    pub inspector_cards: Vec<String>,
    pub cockpit_chips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSummary {
    pub id: String,
    pub version: String,
    pub sdk_version: String,
    pub revdeck_compat: Option<String>,
    pub capabilities: Vec<CapabilityKind>,
    pub permissions: PermissionSet,
    pub validation: ValidationReport,
}

fn validate_plugin_id(id: &str, report: &mut ValidationReport) {
    let valid = !id.trim().is_empty()
        && id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-');
    if !valid {
        report.error(
            "invalid_plugin_id",
            "plugin.id must contain only lowercase ASCII letters, digits, dots, or hyphens",
        );
    }
}

fn validate_non_empty(code: &str, value: &str, report: &mut ValidationReport) {
    if value.trim().is_empty() {
        report.error(code, format!("{code} is required"));
    }
}
