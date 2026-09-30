//! Desktop notifications, shared by every supervisor so several agents don't
//! add up to a stream (docs/design/access-requests.md §4).
//!
//! - The first site an agent waits on after a quiet minute notifies at once:
//!   the agent is stuck until you answer.
//! - Everything else (more waiting sites, refused files and sites) goes into a
//!   digest, sent at most once every [`DIGEST_EVERY`] seconds.
//! - A refused file or site counts once: retries of the same thing don't
//!   notify again.
//! - Quiet mode (on, or until a time) drops notifications; requests still
//!   appear in the console.
//!
//! State lives in `notify.json` in the state directory (agents can't write
//! it), under an exclusive `flock` so concurrent supervisors don't race.

use crate::fsafe;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::path::Path;

pub const DIGEST_EVERY: i64 = 60;
const FILE: &str = "notify.json";
const LOCK: &str = "notify.lock";
/// Refused resources remembered for deduplication.
const SEEN_MAX: usize = 2000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Unix seconds of the last notification sent.
    pub last_sent: i64,
    pub quiet: bool,
    /// Quiet until this Unix time.
    pub quiet_until: Option<i64>,
    /// Pending digest.
    pub waiting: u32,
    pub refused: u32,
    pub agents: Vec<String>,
    /// Refused resources already counted (`agent|action|resource`).
    pub seen: Vec<String>,
}

impl State {
    pub fn is_quiet(&self, now: i64) -> bool {
        self.quiet || self.quiet_until.is_some_and(|u| now < u)
    }

    fn add_agent(&mut self, agent: &str) {
        if !self.agents.iter().any(|a| a == agent) {
            self.agents.push(agent.to_string());
        }
    }

    fn digest_text(&self) -> Option<String> {
        if self.waiting == 0 && self.refused == 0 {
            return None;
        }
        let who = match self.agents.len() {
            0 => "An agent".to_string(),
            1 => self.agents[0].clone(),
            2 => format!("{} and {}", self.agents[0], self.agents[1]),
            n => format!("{} and {} other agents", self.agents[0], n - 1),
        };
        let plural = |n: u32, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
        let mut parts = vec![];
        if self.waiting > 0 {
            parts.push(format!("waiting on {}", plural(self.waiting, "site", "sites")));
        }
        if self.refused > 0 {
            parts.push(format!("{} refused", plural(self.refused, "request", "requests")));
        }
        Some(format!("{who}: {}. Review in the AgentACL console (agentacl ui).", parts.join(" · ")))
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Runs `f` on the state under the cross-process lock and saves it.
fn with_state<T>(state_dir: &Path, f: impl FnOnce(&mut State) -> T) -> Result<T> {
    let dir = crate::supervisor::canon_or(state_dir);
    crate::config::ensure_private_dir(&dir)?;
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(LOCK))?;
    // SAFETY: flock on a descriptor we own; released when `lock` is dropped.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let d = fsafe::open_dir(&dir)?;
    let before: State = fsafe::read_regular(&d, FILE)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let mut st = before.clone();
    let out = f(&mut st);
    if st != before {
        fsafe::write_atomic(&d, FILE, &serde_json::to_vec(&st)?)?;
    }
    Ok(out)
}

pub fn read(state_dir: &Path) -> State {
    let dir = crate::supervisor::canon_or(state_dir);
    fsafe::open_dir(&dir).ok().and_then(|d| fsafe::read_regular(&d, FILE).ok().flatten()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// An agent is waiting on `host`. Returns the text to send now, if any.
pub fn on_waiting(state_dir: &Path, agent: &str, host: &str, now: i64) -> Result<Option<String>> {
    with_state(state_dir, |st| {
        if st.is_quiet(now) {
            return None;
        }
        if now - st.last_sent >= DIGEST_EVERY {
            // Anything already queued rides along.
            let also = std::mem::take(st);
            let more = also.digest_text().map(|t| format!(" Also: {t}")).unwrap_or_default();
            *st = State { last_sent: now, quiet: also.quiet, quiet_until: also.quiet_until, seen: also.seen, ..Default::default() };
            return Some(format!("{agent} is waiting to reach {host}. Allow or block it in the AgentACL console (agentacl ui).{more}"));
        }
        st.waiting += 1;
        st.add_agent(agent);
        None
    })
}

/// A request was refused (`key` identifies what, for deduplication).
pub fn on_refused(state_dir: &Path, agent: &str, key: &str, now: i64) -> Result<()> {
    with_state(state_dir, |st| {
        if st.is_quiet(now) {
            return;
        }
        let k = format!("{agent}|{key}");
        if st.seen.contains(&k) {
            return;
        }
        st.seen.push(k);
        if st.seen.len() > SEEN_MAX {
            let n = st.seen.len() - SEEN_MAX;
            st.seen.drain(..n);
        }
        st.refused += 1;
        st.add_agent(agent);
    })
}

/// The digest to send now, if one is due.
pub fn flush(state_dir: &Path, now: i64) -> Result<Option<String>> {
    with_state(state_dir, |st| {
        if now - st.last_sent < DIGEST_EVERY {
            return None;
        }
        if st.is_quiet(now) {
            // Nothing piles up for after the quiet period.
            st.waiting = 0;
            st.refused = 0;
            st.agents.clear();
            return None;
        }
        let text = st.digest_text()?;
        st.last_sent = now;
        st.waiting = 0;
        st.refused = 0;
        st.agents.clear();
        Some(text)
    })
}

pub fn set_quiet(state_dir: &Path, quiet: bool, until: Option<i64>) -> Result<()> {
    with_state(state_dir, |st| {
        st.quiet = quiet;
        st.quiet_until = until;
    })
}

/// Whether a refused request is worth a notification: something the human
/// can allow from the console. That is a site or a file in their home that
/// no rule named (a default denial). Built-in protections and the human's
/// own blocks can't be allowed there, and the macOS baseline's system lookups
/// aren't requests.
pub fn actionable(action: &str, resource: &str, policy: &str, rule: &str, home: &str) -> bool {
    if rule != "default" {
        return false;
    }
    match action {
        "network.connect" => policy != "console",
        a if a.starts_with("filesystem.") => {
            let in_home = !home.is_empty() && resource.starts_with(home) && resource[home.len()..].starts_with('/');
            in_home && !resource[home.len()..].starts_with("/Library/")
        }
        _ => false,
    }
}

/// Sends a notification unless `AGENTACL_NO_NOTIFY` is set (tests, demos).
pub fn send(text: &str) {
    if std::env::var_os("AGENTACL_NO_NOTIFY").is_some() {
        return;
    }
    crate::netlive::notify("AgentACL", text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_wait_is_immediate_then_digests_once_a_minute() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path();
        let t0 = 1_000_000;
        let first = on_waiting(s, "Claude Code", "pypi.org", t0).unwrap().unwrap();
        assert!(first.contains("Claude Code is waiting to reach pypi.org"), "{first}");
        assert_eq!(on_waiting(s, "Claude Code", "npmjs.org", t0 + 5).unwrap(), None, "within the minute: digest");
        on_refused(s, "Codex", "filesystem.read|/Users/u/o2/a", t0 + 6).unwrap();
        on_refused(s, "Codex", "filesystem.read|/Users/u/o2/a", t0 + 7).unwrap();
        on_refused(s, "Codex", "filesystem.read|/Users/u/o2/b", t0 + 8).unwrap();
        assert_eq!(flush(s, t0 + 30).unwrap(), None, "not due yet");
        let d = flush(s, t0 + 61).unwrap().unwrap();
        assert_eq!(d, "Claude Code and Codex: waiting on 1 site · 2 requests refused. Review in the AgentACL console (agentacl ui).");
        assert_eq!(flush(s, t0 + 200).unwrap(), None, "nothing new");
        on_refused(s, "Codex", "filesystem.read|/Users/u/o2/a", t0 + 201).unwrap();
        assert_eq!(flush(s, t0 + 300).unwrap(), None, "a repeat never counts again");
    }

    #[test]
    fn quiet_mode_drops_notifications() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path();
        let t0 = 2_000_000;
        set_quiet(s, false, Some(t0 + 3600)).unwrap();
        assert_eq!(on_waiting(s, "Claude Code", "pypi.org", t0).unwrap(), None);
        on_refused(s, "Claude Code", "filesystem.read|/x", t0 + 1).unwrap();
        assert_eq!(flush(s, t0 + 100).unwrap(), None);
        assert!(on_waiting(s, "Claude Code", "pypi.org", t0 + 3601).unwrap().is_some(), "quiet period over");
        set_quiet(s, true, None).unwrap();
        assert_eq!(on_waiting(s, "Claude Code", "x.org", t0 + 9999).unwrap(), None);
    }

    #[test]
    fn only_actionable_refusals_count() {
        let h = "/Users/u";
        assert!(actionable("filesystem.read", "/Users/u/o2/src", "seatbelt-baseline", "default", h));
        assert!(!actionable("filesystem.read", "/Users/u/.aws/credentials", "protect-secrets", "aws", h), "built-in protections can't be allowed");
        assert!(!actionable("filesystem.read", "/Library/Application Support", "seatbelt-baseline", "default", h));
        assert!(!actionable("filesystem.read", "/Users/u/Library/Caches/x", "seatbelt-baseline", "default", h));
        assert!(!actionable("filesystem.read", "/Users/uu/x", "seatbelt-baseline", "default", h));
        assert!(actionable("network.connect", "pypi.org:443", "user", "default", h));
        assert!(!actionable("network.connect", "evil.com:443", "user", "network.deny/0", h), "your own block");
        assert!(!actionable("network.connect", "pypi.org:443", "console", "ask", h), "an unanswered prompt already notified");
        assert!(!actionable("ipc.mach-lookup", "com.apple.x", "seatbelt-baseline", "default", h));
    }
}
