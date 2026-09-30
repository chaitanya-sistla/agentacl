//! Agent sessions: one `agentacl run` = one session with its own identity.

use crate::identity::{AgentIdentity, Human};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub human: Human,
    pub machine: String,
    pub agent: AgentIdentity,
    pub pid: Option<i32>,
    pub parent_pid: i32,
    pub project: PathBuf,
    pub tmpdir: PathBuf,
    pub policy: PolicyRef,
    pub backend: String,
    pub started_at: String,
    /// Version of the supervisor; `restart` requires one that handles SIGUSR1.
    #[serde(default)]
    pub agentacl_version: Option<String>,
    /// Supervisor capabilities, e.g. "restart", "ui-port-deny".
    #[serde(default)]
    pub features: Vec<String>,
    /// Policy files this session was built from (for stale detection).
    #[serde(default)]
    pub policy_sources: Vec<PolicyInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInput {
    pub path: PathBuf,
    /// sha256 of the file bytes; None if the file did not exist.
    pub sha256: Option<String>,
}

impl PolicyInput {
    pub fn is_stale(&self, paths: &crate::config::Paths) -> bool {
        crate::supervisor::input_sha(paths, &self.path) != self.sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub name: String,
    pub sha256: String,
    pub disabled_builtin_groups: Vec<String>,
}

/// `agt_` + a ULID (Crockford base32, 26 chars).
pub fn new_session_id() -> String {
    format!("agt_{}", ulid::Ulid::new())
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_id_shape() {
        let id = super::new_session_id();
        assert!(regex::Regex::new(r"^agt_[0-9A-HJKMNP-TV-Z]{26}$").unwrap().is_match(&id), "{id}");
    }
}
