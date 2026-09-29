//! Placeholder for the Endpoint Security backend (macos-enforcement §3).
//! It never claims capabilities it does not have: `available()` always fails
//! until the entitlement-bearing system extension exists.

use super::{CompileInput, EnforcementBackend, Enforceability, LaunchPlan};
use agentfence_policy::set::{PolicySet, Rule};
use anyhow::{bail, Result};
use std::path::PathBuf;

pub const UNAVAILABLE: &str = "requires the com.apple.developer.endpoint-security.client entitlement and the AgentFence system extension (not yet implemented)";

pub struct MacOSEndpointSecurityBackend;

impl EnforcementBackend for MacOSEndpointSecurityBackend {
    fn name(&self) -> &'static str {
        "endpoint-security"
    }
    fn available(&self) -> Result<(), String> {
        Err(UNAVAILABLE.into())
    }
    fn classify(&self, _rule: &Rule) -> Enforceability {
        Enforceability::RequiresEs
    }
    fn prepare(&self, _: &PolicySet, _: &CompileInput, _: PathBuf, _: &[String]) -> Result<LaunchPlan> {
        bail!("endpoint-security backend unavailable: {UNAVAILABLE}")
    }
}
