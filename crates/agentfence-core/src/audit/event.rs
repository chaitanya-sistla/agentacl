//! Authorization and lifecycle events (architecture §8).
//!
//! Honesty invariant (threat-model §5.4): an event is `enforcement=enforced`
//! only if it came from a kernel sandbox report or a proxy decision. That is
//! enforced by construction: [`EnforcedEvent`] has only crate-private
//! constructors used by those two paths; everything else can produce only
//! [`ObservedEvent`] or [`LifecycleEvent`].

use agentfence_policy::{Decision, Effect};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    Enforced,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventSource {
    SandboxLog,
    Proxy,
    ProcMonitor,
    Supervisor,
    Es,
    Ui,
}

impl EventSource {
    pub fn as_str(self) -> &'static str {
        match self {
            EventSource::SandboxLog => "sandbox-log",
            EventSource::Proxy => "proxy",
            EventSource::ProcMonitor => "proc-monitor",
            EventSource::Supervisor => "supervisor",
            EventSource::Es => "es",
            EventSource::Ui => "ui",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "sandbox-log" => EventSource::SandboxLog,
            "proxy" => EventSource::Proxy,
            "proc-monitor" => EventSource::ProcMonitor,
            "supervisor" => EventSource::Supervisor,
            "es" => EventSource::Es,
            "ui" => EventSource::Ui,
            _ => return None,
        })
    }
}

/// A stored event, exactly as `agentfence events --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub human: String,
    pub machine: String,
    pub agent: String,
    pub agent_version: Option<String>,
    pub session: String,
    pub pid: Option<i32>,
    pub delegation_chain: Vec<String>,
    pub action: String,
    pub resource: String,
    pub decision: Option<Effect>,
    pub enforcement: Option<Enforcement>,
    pub backend: String,
    pub source: EventSource,
    pub policy: Option<String>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub count: u32,
}

/// Who an event is about. Shared by every event of a session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContext {
    pub human: String,
    pub machine: String,
    pub agent: String,
    pub agent_version: Option<String>,
    pub session: String,
    pub backend: String,
}

/// A policy evaluation of *observed* activity. It was not prevented.
#[derive(Debug, Clone)]
pub struct ObservedEvent {
    pub pid: Option<i32>,
    pub delegation_chain: Vec<String>,
    pub action: String,
    pub resource: String,
    pub decision: Decision,
}

/// A decision that actually took effect. Construct only via the crate-private
/// constructors used by the sandbox-log observer and the proxy.
#[derive(Debug, Clone)]
pub struct EnforcedEvent {
    pub(crate) source: EventSource,
    pub(crate) pid: Option<i32>,
    pub(crate) delegation_chain: Vec<String>,
    pub(crate) action: String,
    pub(crate) resource: String,
    pub(crate) decision: Decision,
    pub(crate) count: u32,
}

impl EnforcedEvent {
    /// Kernel sandbox report. Requires a parsed [`KernelDenial`], which only
    /// the log parser can construct: the denial happened in the kernel.
    pub(crate) fn from_kernel(d: &crate::observe::sandbox_log::KernelDenial, chain: Vec<String>, decision: Decision, count: u32) -> Self {
        let (action, resource) = crate::observe::sandbox_log::describe(d);
        EnforcedEvent { source: EventSource::SandboxLog, pid: Some(d.pid()), delegation_chain: chain, action, resource, decision, count }
    }
    /// Proxy decision (the proxy connected or refused).
    pub(crate) fn proxy(action: String, resource: String, decision: Decision) -> Self {
        EnforcedEvent { source: EventSource::Proxy, pid: None, delegation_chain: vec![], action, resource, decision, count: 1 }
    }
    pub fn decision(&self) -> &Decision {
        &self.decision
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
}

/// Session lifecycle and backend health; carries no decision.
#[derive(Debug, Clone)]
pub struct LifecycleEvent {
    pub kind: LifecycleKind,
    pub pid: Option<i32>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    SessionStart,
    SessionEnd,
    BackendWarning,
    /// The policy files (path + sha) a session was built from.
    PolicyInputs,
}

impl LifecycleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleKind::SessionStart => "session_start",
            LifecycleKind::SessionEnd => "session_end",
            LifecycleKind::BackendWarning => "backend_warning",
            LifecycleKind::PolicyInputs => "policy.inputs",
        }
    }
}

pub fn new_event_id() -> String {
    format!("evt_{}", ulid::Ulid::new())
}

/// RFC 3339 UTC with milliseconds, e.g. `2026-09-29T10:14:22.311Z`.
pub fn now_rfc3339() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format_rfc3339(d.as_secs() as i64, d.subsec_millis())
}

pub fn format_rfc3339(secs: i64, millis: u32) -> String {
    // Civil-from-days (Howard Hinnant), valid for the proleptic Gregorian calendar.
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", sod / 3600, (sod / 60) % 60, sod % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(1_790_000_000, 311), "2026-09-21T14:13:20.311Z");
        assert_eq!(format_rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
    }

    #[test]
    fn ids() {
        assert!(new_event_id().starts_with("evt_"));
        assert_eq!(new_event_id().len(), 30);
    }
}
