use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PermissionSet {
    pub artifact_read: Vec<String>,
    pub project_read: Vec<String>,
    pub project_write: Vec<String>,
    pub lab_read: Vec<String>,
    pub lab_write: Vec<String>,
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    pub network: bool,
    pub process_spawn: bool,
    pub secrets: bool,
    pub environment: bool,
}

impl PermissionSet {
    pub fn is_default_deny(&self) -> bool {
        self.artifact_read.is_empty()
            && self.project_read.is_empty()
            && self.project_write.is_empty()
            && self.lab_read.is_empty()
            && self.lab_write.is_empty()
            && self.filesystem_read.is_empty()
            && self.filesystem_write.is_empty()
            && !self.network
            && !self.process_spawn
            && !self.secrets
            && !self.environment
    }

    pub fn risky_grants(&self) -> Vec<&'static str> {
        let mut grants = Vec::new();
        if self.network {
            grants.push("network");
        }
        if self.process_spawn {
            grants.push("process_spawn");
        }
        if self.secrets {
            grants.push("secrets");
        }
        if self.environment {
            grants.push("environment");
        }
        if !self.filesystem_write.is_empty() {
            grants.push("filesystem_write");
        }
        grants
    }
}
