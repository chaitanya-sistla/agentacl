//! The `EnforcementBackend` boundary (macos-enforcement §1).

pub mod baseline;
pub mod endpoint_security;
pub mod sbpl;
pub mod seatbelt;

use agentacl_policy::set::{Matcher, PolicySet, Rule, Section};
use agentacl_policy::Effect;
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;

pub use endpoint_security::MacOSEndpointSecurityBackend;
pub use sbpl::CompileInput;
pub use seatbelt::SeatbeltBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Enforceability {
    Enforced,
    EnforcedCoarse,
    Observed,
    RequiresEs,
}

impl Enforceability {
    pub fn as_str(self) -> &'static str {
        match self {
            Enforceability::Enforced => "enforced",
            Enforceability::EnforcedCoarse => "enforced-coarse",
            Enforceability::Observed => "observed",
            Enforceability::RequiresEs => "requires-es",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleView {
    pub policy: String,
    pub id: String,
    pub section: &'static str,
    pub effect: Effect,
    pub pattern: String,
    pub excepts: Vec<String>,
    pub reason: String,
    pub enforceability: Enforceability,
}

impl RuleView {
    pub fn new(r: &Rule, e: Enforceability) -> Self {
        RuleView {
            policy: r.policy.clone(),
            id: r.id.clone(),
            section: r.section.as_str(),
            effect: r.effect,
            pattern: r.written.clone(),
            excepts: r.excepts.iter().map(|x| x.source().to_string()).collect(),
            reason: r.reason.clone(),
            enforceability: e,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub profile_path: PathBuf,
    pub profile_text: String,
}

pub trait EnforcementBackend {
    fn name(&self) -> &'static str;
    /// Err explains why the backend cannot be used on this machine.
    fn available(&self) -> Result<(), String>;
    fn classify(&self, rule: &Rule) -> Enforceability;
    /// Writes the profile to `profile_path` and returns how to launch `argv` under it.
    fn prepare(&self, policy: &PolicySet, input: &CompileInput, profile_path: PathBuf, argv: &[String]) -> Result<LaunchPlan>;
}

/// How the Seatbelt backend enforces each rule shape (policy-model §7).
pub fn classify_seatbelt(r: &Rule) -> Enforceability {
    match (&r.matcher, r.section) {
        (Matcher::Path(_), _) => Enforceability::Enforced,
        (Matcher::Cmd(c), Section::Exec) => match r.effect {
            Effect::Allow => Enforceability::Enforced,
            _ if c.is_executable_only() && (c.exe_basename_glob().is_some() || c.exe_abs().is_some()) => Enforceability::EnforcedCoarse,
            _ => Enforceability::Observed,
        },
        (Matcher::Net(_), _) => Enforceability::Enforced,
        _ => Enforceability::Observed,
    }
}

pub fn rule_views(backend: &dyn EnforcementBackend, policy: &PolicySet, agent_id: &str, project: &str) -> Vec<RuleView> {
    policy.rules_for(agent_id, project).into_iter().map(|r| RuleView::new(r, backend.classify(r))).collect()
}

#[cfg(test)]
mod tests;
