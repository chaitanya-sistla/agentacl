//! Request/decision vocabulary shared by every engine and backend.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

impl Effect {
    /// deny > ask > allow
    pub fn restrictiveness(self) -> u8 {
        match self {
            Effect::Allow => 0,
            Effect::Ask => 1,
            Effect::Deny => 2,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Ask => "ask",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Builtin,
    /// Company rules from the fleet server (docs/design/fleet.md): explicit
    /// denies only, applying to every agent and project.
    Org,
    User,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Filesystem,
    Network,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteOp {
    Write,
    Create,
    Unlink,
    Rename,
    Link,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    FsRead,
    FsWrite(WriteOp),
    Exec,
    NetConnect,
    NetListen,
}

impl Action {
    /// Event vocabulary: `filesystem.read`, `filesystem.write`, `process.exec`, …
    pub fn event_name(self) -> &'static str {
        match self {
            Action::FsRead => "filesystem.read",
            Action::FsWrite(_) => "filesystem.write",
            Action::Exec => "process.exec",
            Action::NetConnect => "network.connect",
            Action::NetListen => "network.listen",
        }
    }
    pub fn category(self) -> Category {
        match self {
            Action::FsRead | Action::FsWrite(_) => Category::Filesystem,
            Action::Exec => Category::Process,
            Action::NetConnect | Action::NetListen => Category::Network,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    Path(String),
    Exec { exe: String, argv: Vec<String> },
    Host { host: String, port: u16 },
    Addr { ip: IpAddr, port: u16 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub human: String,
    pub machine: String,
    pub agent_id: String,
    pub agent_version: Option<String>,
    pub team_id: Option<String>,
    pub session: String,
    pub project: String,
    pub delegation_chain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub subject: Subject,
    pub action: Action,
    pub resource: Resource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub policy: String,
    pub rule_id: String,
    pub reason: String,
    pub trace: Vec<String>,
}

/// The only integration point for policy engines (native now, OPA later).
pub trait PolicyEngine {
    fn evaluate(&self, req: &Request) -> Decision;
}
