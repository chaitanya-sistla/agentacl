//! What a Mac and the AgentACL fleet server exchange (docs/design/fleet.md).
//!
//! Platform-neutral: the server builds on Linux. Every request from a Mac
//! after enrollment carries `Authorization: Bearer <device key>`.

use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySet, PolicySource};
use agentacl_policy::Layer;
use serde::{Deserialize, Serialize};

pub const ENROLL: &str = "/api/v1/enroll";
pub const REPORT: &str = "/api/v1/report";
pub const POLICY: &str = "/api/v1/policy";

/// The root-owned `agentacl` the package installs: the only copy whose
/// sessions the ES daemon leaves to Seatbelt, and the one the console
/// trusts as "under AgentACL".
pub const MANAGED_AGENTACL: &str = "/Library/Application Support/AgentACL/bin/agentacl";

/// Request bodies larger than this are refused (both sides).
pub const MAX_BODY: usize = 8 * 1024 * 1024;
/// Events per user per report batch.
pub const MAX_EVENTS: usize = 1000;

/// Who the Mac says it is. Self-reported: the server never trusts it to
/// identify an existing device (a new enrollment is always a new device).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIdentity {
    pub machine_id: String,
    pub hostname: String,
    #[serde(default)]
    pub serial: Option<String>,
    pub os_version: String,
    pub agentacl_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub machine: MachineIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: String,
    pub device_key: String,
    /// The company policy, written before the Mac counts as enrolled.
    #[serde(default)]
    pub policy: PolicyResponse,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    /// The Endpoint Security LaunchDaemon is running.
    pub es_daemon: bool,
    /// The Endpoint Security system extension is activated.
    pub es_extension: bool,
    /// The user whose agents Endpoint Security covers (it serves one).
    #[serde(default)]
    pub es_user: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MachineStatus {
    pub identity: MachineIdentity,
    pub enforcement: Enforcement,
    /// Version of the company policy in force on the Mac.
    pub policy_version: Option<u64>,
    /// Why the last company policy wasn't applied, if it wasn't.
    pub policy_error: Option<String>,
}

/// An agent process, from the process table (read by root).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningAgent {
    pub pid: i32,
    pub user: String,
    pub agent: String,
    pub agent_name: String,
    pub exe: String,
    /// The executable of the `agentacl` supervising it, if any (the
    /// root-owned copy, or another one).
    pub supervisor: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledAgent {
    pub agent: String,
    pub agent_name: String,
    pub path: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent: String,
    pub project: String,
    pub backend: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub agentacl_version: Option<String>,
    /// The session loaded the company rules.
    pub company_rules: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventInfo {
    /// Row id in the user's audit log (with [`UserReport::log_id`], unique).
    pub rowid: i64,
    pub ts: String,
    pub session: String,
    pub agent: String,
    /// enforced (Seatbelt, the proxy, ES) or observed.
    pub kind: String,
    pub source: String,
    pub action: String,
    pub resource: String,
    /// allow, deny or ask.
    pub decision: Option<String>,
    pub policy: Option<String>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

/// What a user's own AgentACL files say (collected as that user, so
/// reported by the user, not verified by the Mac).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserReport {
    pub user: String,
    pub uid: u32,
    /// Sent every 10 minutes; `None` in between.
    pub installed: Option<Vec<InstalledAgent>>,
    pub sessions: Vec<SessionInfo>,
    /// Random id of the user's audit log (a recreated log gets a new one).
    pub log_id: Option<String>,
    pub events: Vec<EventInfo>,
    /// Why this user's data couldn't be read, if it couldn't.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub machine: MachineStatus,
    pub running: Vec<RunningAgent>,
    pub users: Vec<UserReport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportResponse {
    /// The company policy version the Mac should have.
    pub policy_version: u64,
    /// Events the server didn't keep (over the device's daily quota).
    #[serde(default)]
    pub dropped: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub version: u64,
    pub yaml: String,
}

/// Checks a company policy as every Mac will: the company-rules format
/// (explicit denies only), then a full load with the built-ins and sample
/// values. The Mac also compiles it to a Seatbelt profile before applying.
pub fn validate_company_policy(yaml: &str) -> Result<(), String> {
    if yaml.trim().is_empty() {
        return Ok(());
    }
    let vars = Vars {
        home: "/Users/example".into(),
        project: "/Users/example/src/project".into(),
        tmpdir: "/private/var/folders/xx/agentacl/session/tmp".into(),
        agent_state: None,
        agentacl_state: "/Users/example/Library/Application Support/AgentACL".into(),
        agentacl_config: "/Users/example/.config/agentacl".into(),
    };
    let mut src = builtin_sources(true);
    src.push(PolicySource { layer: Layer::Org, name: "company policy".into(), yaml: yaml.into() });
    PolicySet::load(src, &vars, &LoadOptions::default()).map(|_| ()).map_err(|e| e.to_string())
}

/// What the admin should know about a (valid) company policy: rules that
/// do less than they seem to, depending on how each Mac enforces
/// (docs/security-guarantees.md).
pub fn company_policy_warnings(yaml: &str) -> Vec<String> {
    let Ok(doc) = agentacl_policy::raw::parse_doc(yaml, Layer::Org, "company policy") else { return vec![] };
    let mut w = vec![];
    let with_args: Vec<&str> = doc.process.deny.iter().map(|r| r.pattern.as_str()).filter(|p| p.split_whitespace().count() > 1).collect();
    if !with_args.is_empty() {
        w.push(format!("Program rules with arguments ({}) are only logged in `agentacl run` sessions (Seatbelt can't see arguments); Macs with Endpoint Security refuse them.", with_args.join(", ")));
    }
    if !doc.process.deny.is_empty() {
        w.push("Program rules match a program's name or path: a renamed copy of the program isn't matched.".into());
    }
    if doc.network.deny.iter().any(|r| r.pattern.chars().any(|c| c.is_ascii_alphabetic())) {
        w.push("Host rules match names, not addresses: an agent connecting by IP address isn't matched. Deny address ranges too. Network rules apply in `agentacl run` sessions only.".into());
    }
    if doc.filesystem.deny_read.iter().chain(&doc.filesystem.deny_write).any(|r| matches!(r.pattern.trim_end_matches('/'), "${HOME}/**" | "${HOME}" | "/Users/**" | "/**")) {
        w.push("A rule covering the whole home folder also covers projects inside it: agents may be unable to work.".into());
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn company_policies_are_validated_as_the_mac_will() {
        assert!(validate_company_policy("").is_ok());
        assert!(validate_company_policy("version: v1\nfilesystem:\n  deny_read: [\"${HOME}/company/**\"]\nnetwork:\n  deny: [\"*.pastebin.com\"]\n").is_ok());
        let e = validate_company_policy("version: v1\nnetwork:\n  allow: [\"evil.example\"]\n").unwrap_err();
        assert!(e.contains("network.allow"), "{e}");
        assert!(validate_company_policy("version: v1\nfilesystem:\n  deny_read: [\"${NOPE}/x\"]\n").is_err());
        assert!(validate_company_policy("not yaml: [").is_err());
    }

    #[test]
    fn warns_about_rules_weaker_than_they_look() {
        let w = company_policy_warnings("version: v1\nprocess:\n  deny: [\"git push *\"]\nnetwork:\n  deny: [\"*.pastebin.com\"]\nfilesystem:\n  deny_read: [\"${HOME}/**\"]\n");
        assert_eq!(w.len(), 4, "{w:?}");
        assert!(company_policy_warnings("version: v1\nnetwork:\n  deny: [\"10.0.0.0/8\"]\n").is_empty());
    }
}
