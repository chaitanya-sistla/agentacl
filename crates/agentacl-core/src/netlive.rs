//! Console-driven network decisions for running sessions (ui.md §4.8).
//!
//! The proxy is in the path of every agent connection, so network decisions
//! can change while an agent runs. Two files in the state directory, which
//! agents can't write (`agentacl-self`), carry them from the console to every
//! supervisor:
//!
//! - `network-live.json`: the mode for sites no rule names (block or ask) and
//!   host rules made in the console. A console **block** applies to every
//!   session at once. A console **allow** only lifts a *default* denial, never
//!   an explicit or built-in one, and only for sessions started before it was
//!   made: newer sessions load it from the policy file the console also
//!   writes, so removing the rule there removes it everywhere.
//! - `approvals/<id>.json` / `<id>.answer`: a connection waiting for the
//!   human (mode `ask`). The proxy holds it up to [`ASK_TIMEOUT`]; no answer
//!   means blocked.

use crate::config::ensure_private_dir;
use crate::fsafe;
use crate::netproxy::{NetDecider, PolicyNetDecider};
use agentacl_policy::{Decision, Effect};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const LIVE_FILE: &str = "network-live.json";
pub const APPROVALS_DIR: &str = "approvals";
/// How long a connection waits for the human unless the console chose
/// another of [`WAIT_CHOICES`].
pub const ASK_TIMEOUT: Duration = Duration::from_secs(30);
/// Waits the console offers, in seconds.
pub const WAIT_CHOICES: [u64; 4] = [30, 60, 120, 300];
/// Each "+1 min" from the console adds this, at most [`MAX_EXTENSIONS`] times.
pub const EXTENSION: Duration = Duration::from_secs(60);
pub const MAX_EXTENSIONS: u32 = 5;
/// Approval files are kept until the longest possible wait is over, plus a minute.
const PRUNE_AFTER: Duration = Duration::from_secs(300 + 5 * 60 + 60);
/// A session can't queue more than this many prompts at once…
const MAX_PENDING: usize = 8;
/// …nor hold more than this many connections waiting (per site / in total);
/// the rest are refused at once instead of tying up proxy threads.
const MAX_WAITERS_PER_SITE: usize = 16;
const MAX_WAITERS_TOTAL: usize = 64;

/// Serializes read-modify-write of the live file within one process.
static LIVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Sites no rule names are refused (the policy default).
    #[default]
    Block,
    /// Sites no rule names wait for the human in the console.
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRule {
    pub host: String,
    pub effect: Effect,
    /// RFC 3339; an allow applies to sessions started before this.
    pub at: String,
    /// Only sessions of this agent (all agents if absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Only sessions in this project (all projects if absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The access file that holds the durable rule (`access:<name>`); absent
    /// for rules mirrored from the user policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl LiveRule {
    pub fn applies(&self, agent: &str, project: &str) -> bool {
        self.agent.as_deref().is_none_or(|a| a == agent) && self.project.as_deref().is_none_or(|p| p == project)
    }
}

/// An allow removed from the user policy (or, with `policy`, from that access
/// document). Sessions that started before `at` may have loaded it; for them
/// the host is treated as not allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub host: String,
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Live {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub rules: Vec<LiveRule>,
    #[serde(default)]
    pub revoked: Vec<Revocation>,
    /// How long a connection waits for an answer (one of [`WAIT_CHOICES`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_timeout_secs: Option<u64>,
}

/// Lowercase, no trailing dot, no port.
pub fn host_key(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Hosts the console can decide on: names, not IP literals or localhost
/// (those are governed by address rules).
pub fn is_named_host(host: &str) -> bool {
    let h = host_key(host);
    !h.is_empty() && h != "localhost" && h.parse::<IpAddr>().is_err() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// The state dir in canonical form (`fsafe` refuses symlinked components,
/// e.g. `/var` → `/private/var`).
fn canon(state_dir: &Path) -> PathBuf {
    crate::supervisor::canon_or(state_dir)
}

pub fn read_live(state_dir: &Path) -> Live {
    let Ok(dir) = fsafe::open_dir(&canon(state_dir)) else { return Live::default() };
    match fsafe::read_regular(&dir, LIVE_FILE) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => Live::default(),
    }
}

pub fn write_live(state_dir: &Path, live: &Live) -> Result<()> {
    ensure_private_dir(state_dir)?;
    let dir = fsafe::open_dir(&canon(state_dir))?;
    fsafe::write_atomic(&dir, LIVE_FILE, serde_json::to_string_pretty(live)?.as_bytes())
}

/// Sets (or with `None` removes) the console rule for `host`.
pub fn set_rule(state_dir: &Path, host: &str, effect: Option<Effect>) -> Result<()> {
    if !is_named_host(host) {
        bail!("{host:?} is not a host name");
    }
    let key = host_key(host);
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    live.rules.retain(|r| !(r.host == key && r.source.is_none()));
    if let Some(e) = effect {
        if e == Effect::Ask {
            bail!("a site rule is allow or block");
        }
        live.rules.push(LiveRule { host: key, effect: e, at: crate::audit::now_rfc3339(), agent: None, project: None, source: None });
    }
    write_live(state_dir, &live)
}

/// A console rule whose durable copy is in access document `source`
/// (`access:<name>`), for `agent` / `project` only when given. Replaces the
/// rule for the same host from the same source.
pub fn set_scoped_rule(state_dir: &Path, host: &str, effect: Effect, agent: Option<&str>, project: Option<&str>, source: &str) -> Result<()> {
    if !is_named_host(host) {
        bail!("{host:?} is not a host name");
    }
    if effect == Effect::Ask {
        bail!("a site rule is allow or block");
    }
    let key = host_key(host);
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    live.rules.retain(|r| !(r.host == key && r.source.as_deref() == Some(source)));
    live.rules.push(LiveRule { host: key, effect, at: crate::audit::now_rfc3339(), agent: agent.map(str::to_string), project: project.map(str::to_string), source: Some(source.into()) });
    write_live(state_dir, &live)
}

/// Removes the console rule for `host` that came from access document
/// `source`, and revokes that document's allow for sessions that loaded it.
pub fn remove_scoped_rule(state_dir: &Path, host: &str, source: &str) -> Result<()> {
    let key = host_key(host);
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    live.rules.retain(|r| !(r.host == key && r.source.as_deref() == Some(source)));
    live.revoked.retain(|r| !(r.host == key && r.policy.as_deref() == Some(source)));
    live.revoked.push(Revocation { host: key, at: crate::audit::now_rfc3339(), policy: Some(source.into()) });
    cap_revoked(&mut live);
    write_live(state_dir, &live)
}

/// Drops console rules from access documents that no longer allow them, and
/// revokes those documents' allows for sessions that loaded them. `present`
/// holds `(source, host)` for every site an access file allows.
pub fn retain_access_rules(state_dir: &Path, present: &std::collections::BTreeSet<(String, String)>) -> Result<()> {
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    let gone: Vec<(String, String)> = live.rules.iter().filter_map(|r| r.source.clone().map(|s| (s, r.host.clone()))).filter(|k| !present.contains(k)).collect();
    if gone.is_empty() {
        return Ok(());
    }
    live.rules.retain(|r| r.source.as_ref().is_none_or(|s| present.contains(&(s.clone(), r.host.clone()))));
    let now = crate::audit::now_rfc3339();
    for (source, host) in gone {
        live.revoked.retain(|r| !(r.host == host && r.policy.as_deref() == Some(source.as_str())));
        live.revoked.push(Revocation { host, at: now.clone(), policy: Some(source) });
    }
    cap_revoked(&mut live);
    write_live(state_dir, &live)
}

/// A revocation only matters to sessions older than it; keep a bounded list.
fn cap_revoked(live: &mut Live) {
    let len = live.revoked.len();
    if len > 500 {
        live.revoked.drain(..len - 500);
    }
}

/// Sets how long a connection waits for an answer.
pub fn set_wait(state_dir: &Path, secs: u64) -> Result<()> {
    if !WAIT_CHOICES.contains(&secs) {
        bail!("the wait must be one of {WAIT_CHOICES:?} seconds");
    }
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    live.ask_timeout_secs = Some(secs);
    write_live(state_dir, &live)
}

/// Drops console rules the user policy no longer agrees with, so deleting a
/// rule in the policy file removes it for running sessions too. `allow` and
/// `deny` are the host patterns now in the policy's network lists.
pub fn reconcile(state_dir: &Path, allow: &std::collections::BTreeSet<String>, deny: &std::collections::BTreeSet<String>) -> Result<()> {
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    let before = live.rules.len();
    // Rules from access documents are kept: those files aren't the policy file.
    live.rules.retain(|r| {
        r.source.is_some()
            || match r.effect {
                Effect::Allow => allow.contains(&r.host),
                _ => deny.contains(&r.host),
            }
    });
    if live.rules.len() != before {
        write_live(state_dir, &live)?;
    }
    Ok(())
}

/// Records that allows for `hosts` were removed from the user policy now.
pub fn revoke(state_dir: &Path, hosts: &[String]) -> Result<()> {
    if hosts.is_empty() {
        return Ok(());
    }
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    let now = crate::audit::now_rfc3339();
    for h in hosts.iter().map(|h| host_key(h)).filter(|h| is_named_host(h)) {
        live.revoked.retain(|r| !(r.host == h && r.policy.is_none()));
        live.rules.retain(|r| !(r.host == h && r.effect == Effect::Allow && r.source.is_none()));
        live.revoked.push(Revocation { host: h, at: now.clone(), policy: None });
    }
    cap_revoked(&mut live);
    write_live(state_dir, &live)
}

pub fn set_mode(state_dir: &Path, mode: Mode) -> Result<()> {
    let _g = LIVE_LOCK.lock().unwrap();
    let mut live = read_live(state_dir);
    live.mode = mode;
    write_live(state_dir, &live)
}

// ---- approvals ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub session: String,
    pub agent: String,
    pub project: String,
    pub host: String,
    pub port: u16,
    pub created: String,
    pub expires: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Answer {
    /// This connection only.
    Once,
    /// This host, for the rest of the session.
    Session,
    /// The console also saved an allow rule.
    Always,
    /// Refuse this connection.
    Block,
    /// The console also saved a block rule.
    BlockAlways,
}

fn approvals_dir(state_dir: &Path) -> PathBuf {
    canon(state_dir).join(APPROVALS_DIR)
}

fn valid_id(id: &str) -> bool {
    id.starts_with("apr_") && id.len() <= 64 && id[4..].chars().all(|c| c.is_ascii_alphanumeric())
}

pub fn new_id() -> String {
    format!("apr_{}", ulid::Ulid::new())
}

pub fn request(state_dir: &Path, a: &Approval) -> Result<()> {
    let d = approvals_dir(state_dir);
    ensure_private_dir(&d)?;
    let dir = fsafe::open_dir(&d)?;
    fsafe::write_atomic(&dir, &format!("{}.json", a.id), serde_json::to_vec(a)?.as_slice())
}

/// Approvals still waiting: unanswered and not expired.
pub fn pending(state_dir: &Path) -> Vec<Approval> {
    let d = approvals_dir(state_dir);
    let Ok(dir) = fsafe::open_dir(&d) else { return vec![] };
    let Ok(rd) = std::fs::read_dir(&d) else { return vec![] };
    let now = crate::audit::now_rfc3339();
    let mut out: Vec<Approval> = rd
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_string))
        .filter(|id| valid_id(id))
        .filter(|id| !matches!(fsafe::read_regular(&dir, &format!("{id}.answer")), Ok(Some(_))))
        .filter_map(|id| fsafe::read_regular(&dir, &format!("{id}.json")).ok().flatten())
        .filter_map(|b| serde_json::from_slice::<Approval>(&b).ok())
        .filter(|a| a.expires > now)
        .collect();
    out.sort_by(|a, b| a.created.cmp(&b.created));
    out
}

pub fn answer(state_dir: &Path, id: &str, ans: Answer) -> Result<Approval> {
    if !valid_id(id) {
        bail!("invalid approval id");
    }
    let dir = fsafe::open_dir(&approvals_dir(state_dir))?;
    let a: Approval = match fsafe::read_regular(&dir, &format!("{id}.json"))? {
        Some(b) => serde_json::from_slice(&b)?,
        None => bail!("no such request (it may have timed out)"),
    };
    if a.expires <= crate::audit::now_rfc3339() {
        bail!("this request timed out; the connection was already refused");
    }
    if matches!(fsafe::read_regular(&dir, &format!("{id}.answer")), Ok(Some(_))) {
        bail!("this request was already answered");
    }
    fsafe::write_atomic(&dir, &format!("{id}.answer"), serde_json::to_vec(&ans)?.as_slice())?;
    Ok(a)
}

/// Gives a waiting request one more [`EXTENSION`] (at most
/// [`MAX_EXTENSIONS`] times). Returns the request with its new expiry.
pub fn extend(state_dir: &Path, id: &str) -> Result<Approval> {
    if !valid_id(id) {
        bail!("invalid approval id");
    }
    // Concurrent "+1 min"s must not share a count (the console is threaded).
    static EXTEND_LOCK: Mutex<()> = Mutex::new(());
    let _g = EXTEND_LOCK.lock().unwrap();
    let dir = fsafe::open_dir(&approvals_dir(state_dir))?;
    let mut a: Approval = match fsafe::read_regular(&dir, &format!("{id}.json"))? {
        Some(b) => serde_json::from_slice(&b)?,
        None => bail!("no such request (it may have timed out)"),
    };
    if a.expires <= crate::audit::now_rfc3339() {
        bail!("this request timed out; the connection was already refused");
    }
    if matches!(fsafe::read_regular(&dir, &format!("{id}.answer")), Ok(Some(_))) {
        bail!("this request was already answered");
    }
    let n = read_extensions(state_dir, id);
    if n >= MAX_EXTENSIONS {
        bail!("this request can't wait any longer");
    }
    let secs = crate::audit::parse_ts(&a.expires).unwrap_or(0) + EXTENSION.as_secs() as i64;
    let millis = a.expires.get(20..23).and_then(|m| m.parse().ok()).unwrap_or(0);
    a.expires = crate::audit::format_rfc3339(secs, millis);
    fsafe::write_atomic(&dir, &format!("{id}.json"), serde_json::to_vec(&a)?.as_slice())?;
    fsafe::write_atomic(&dir, &format!("{id}.extend"), (n + 1).to_string().as_bytes())?;
    Ok(a)
}

fn read_extensions(state_dir: &Path, id: &str) -> u32 {
    let Ok(dir) = fsafe::open_dir(&approvals_dir(state_dir)) else { return 0 };
    fsafe::read_regular(&dir, &format!("{id}.extend")).ok().flatten().and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.trim().parse().ok()).unwrap_or(0).min(MAX_EXTENSIONS)
}

fn read_answer(state_dir: &Path, id: &str) -> Option<Answer> {
    let dir = fsafe::open_dir(&approvals_dir(state_dir)).ok()?;
    fsafe::read_regular(&dir, &format!("{id}.answer")).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok())
}

/// Removes approval files a minute after they expire (called by the console).
pub fn prune(state_dir: &Path) {
    let d = approvals_dir(state_dir);
    let Ok(rd) = std::fs::read_dir(&d) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with("apr_") || !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let age = e.metadata().and_then(|m| m.modified()).map(|t| t.elapsed().unwrap_or_default()).unwrap_or_default();
        // Files are written when the prompt is created (answered, extended);
        // after the longest possible wait plus a minute nothing reads them.
        if age > PRUNE_AFTER {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Posts a macOS notification. The text goes in as an argument, never into
/// the AppleScript source, so a hostile host name can't inject script.
pub fn notify(title: &str, text: &str) {
    let _ = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, text])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|mut c| std::thread::spawn(move || c.wait()));
}

// ---- the decider --------------------------------------------------------------

struct Waiting {
    id: String,
    deadline: Instant,
    waiters: usize,
}

/// Policy decisions, adjusted by the console's live rules and answers.
pub struct LiveNetDecider {
    pub inner: PolicyNetDecider,
    pub state_dir: PathBuf,
    pub session: String,
    pub agent: String,
    pub agent_name: String,
    pub project: String,
    /// RFC 3339 session start.
    pub started_at: String,
    pub notify: bool,
    /// How long a connection waits for an answer when the console hasn't
    /// chosen a wait ([`ASK_TIMEOUT`]).
    pub ask_timeout: Duration,
    /// `host:port` approved for this session.
    session_allow: Mutex<HashSet<String>>,
    /// `host:port` → the prompt connections to it are waiting on.
    waiting: Mutex<HashMap<String, Waiting>>,
}

impl LiveNetDecider {
    pub fn new(inner: PolicyNetDecider, state_dir: PathBuf, session: String, agent: String, agent_name: String, project: String, started_at: String) -> Self {
        LiveNetDecider {
            inner,
            state_dir,
            session,
            agent,
            agent_name,
            project,
            started_at,
            notify: true,
            ask_timeout: ASK_TIMEOUT,
            session_allow: Mutex::new(HashSet::new()),
            waiting: Mutex::new(HashMap::new()),
        }
    }

    fn console(effect: Effect, rule: &str, reason: String) -> Decision {
        Decision { effect, policy: "console".into(), rule_id: rule.into(), reason, trace: vec![] }
    }

    fn ask(&self, key: &str, port: u16) -> Decision {
        let refuse = |why: String| Self::console(Effect::Deny, "ask", why);
        let site = format!("{key}:{port}");
        let timeout = read_live(&self.state_dir).ask_timeout_secs.filter(|s| WAIT_CHOICES.contains(s)).map(Duration::from_secs).unwrap_or(self.ask_timeout);
        // One prompt per host:port however many connections wait on it; all of
        // them share the prompt's deadline.
        let (id, deadline) = {
            let mut w = self.waiting.lock().unwrap();
            if w.values().map(|x| x.waiters).sum::<usize>() >= MAX_WAITERS_TOTAL {
                return refuse("too many connections are already waiting for an answer".into());
            }
            if let Some(x) = w.get_mut(&site) {
                if x.waiters >= MAX_WAITERS_PER_SITE {
                    return refuse(format!("too many connections to {site} are already waiting"));
                }
                x.waiters += 1;
                (x.id.clone(), x.deadline)
            } else {
                if w.len() >= MAX_PENDING {
                    return refuse("too many sites are already waiting for an answer".into());
                }
                let now = std::time::SystemTime::now();
                let stamp = |t: std::time::SystemTime| {
                    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    crate::audit::format_rfc3339(d.as_secs() as i64, d.subsec_millis())
                };
                let a = Approval {
                    id: new_id(),
                    session: self.session.clone(),
                    agent: self.agent.clone(),
                    project: self.project.clone(),
                    host: key.to_string(),
                    port,
                    created: stamp(now),
                    expires: stamp(now + timeout),
                };
                if request(&self.state_dir, &a).is_err() {
                    return refuse("could not queue the request for the console".into());
                }
                let deadline = Instant::now() + timeout;
                w.insert(site.clone(), Waiting { id: a.id.clone(), deadline, waiters: 1 });
                if self.notify {
                    // Shared across sessions: immediate if nothing was sent
                    // in the last minute, otherwise into the digest.
                    if let Ok(Some(text)) = crate::notify::on_waiting(&self.state_dir, &self.agent_name, key, crate::notify::now()) {
                        crate::notify::send(&text);
                    }
                }
                (a.id, deadline)
            }
        };
        let ans = loop {
            if let Some(a) = read_answer(&self.state_dir, &id) {
                break Some(a);
            }
            // "+1 min" in the console moves every waiter's deadline.
            if Instant::now() >= deadline + EXTENSION * read_extensions(&self.state_dir, &id) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        {
            // Only clear our own prompt: a newer one for the same site may exist.
            let mut w = self.waiting.lock().unwrap();
            if w.get(&site).is_some_and(|x| x.id == id) {
                w.remove(&site);
            }
        }
        match ans {
            // "once" releases the connections waiting on this prompt now.
            Some(Answer::Once) => Self::console(Effect::Allow, "approved-once", format!("{site} approved in the AgentACL console")),
            Some(Answer::Session | Answer::Always) => {
                self.session_allow.lock().unwrap().insert(site.clone());
                Self::console(Effect::Allow, "approved", format!("{site} approved in the AgentACL console"))
            }
            Some(Answer::Block | Answer::BlockAlways) => refuse(format!("{site} was blocked in the AgentACL console")),
            None => refuse(format!("no answer in the AgentACL console within {} s", (timeout + EXTENSION * read_extensions(&self.state_dir, &id)).as_secs())),
        }
    }
}

impl NetDecider for LiveNetDecider {
    fn host(&self, host: &str, port: u16) -> Decision {
        let d = self.inner.host(host, port);
        if !is_named_host(host) {
            return d;
        }
        let key = host_key(host);
        let live = read_live(&self.state_dir);
        // A console block only restricts, so it applies to every session now.
        let scoped = |r: &&LiveRule| r.host == key && r.applies(&self.agent, &self.project);
        if live.rules.iter().filter(scoped).any(|r| r.effect == Effect::Deny) {
            return Self::console(Effect::Deny, "blocked", format!("{key} is blocked in the AgentACL console"));
        }
        // An allow the user has since removed from their policy no longer
        // counts for sessions that loaded it (the agent's own needs stay).
        let revoked = d.effect == Effect::Allow
            && !d.policy.starts_with("provider:")
            && !matches!(d.policy.as_str(), "runtime" | "builtin")
            && live.revoked.iter().any(|r| r.host == key && self.started_at < r.at && r.policy.as_deref().is_none_or(|p| p == d.policy));
        if d.effect == Effect::Allow && !revoked {
            return d;
        }
        // Only a default decision (or a revoked allow) can be lifted; explicit
        // and built-in denials stand.
        if d.rule_id != "default" && !revoked {
            return d;
        }
        if self.session_allow.lock().unwrap().contains(&format!("{key}:{port}")) {
            return Self::console(Effect::Allow, "approved", format!("{key} approved in the AgentACL console"));
        }
        if live.rules.iter().filter(scoped).any(|r| r.effect == Effect::Allow && self.started_at < r.at) {
            return Self::console(Effect::Allow, "allowed", format!("{key} allowed in the AgentACL console"));
        }
        if d.effect == Effect::Ask || live.mode == Mode::Ask {
            return self.ask(&key, port);
        }
        if revoked {
            return Self::console(Effect::Deny, "revoked", format!("{key} is no longer allowed (removed from your rules)"));
        }
        d
    }

    fn addr(&self, ip: IpAddr, port: u16) -> Decision {
        self.inner.addr(ip, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentacl_policy::set::PolicySet;
    use agentacl_policy::Subject;
    use std::sync::Arc;

    fn decider(state: &Path, yaml: &str, started_at: &str) -> LiveNetDecider {
        let src = vec![agentacl_policy::set::PolicySource { layer: agentacl_policy::Layer::User, name: "user".into(), yaml: yaml.into() }];
        let mut all = agentacl_policy::set::builtin_sources(false);
        all.extend(src);
        let vars = agentacl_policy::expand::Vars { home: "/Users/t".into(), project: "/p".into(), tmpdir: "/tmp".into(), agent_state: None, agentacl_state: "/s".into(), agentacl_config: "/c".into() };
        let set = PolicySet::load(all, &vars, &Default::default()).unwrap();
        let inner = PolicyNetDecider { policy: Arc::new(set), subject: Subject { agent_id: "claude-code".into(), project: "/p".into(), ..Default::default() } };
        let mut d = LiveNetDecider::new(inner, state.to_path_buf(), "agt_1".into(), "claude-code".into(), "Claude Code".into(), "/p".into(), started_at.into());
        d.notify = false;
        d
    }

    const POLICY: &str = "version: v1\ndefaults: {network: deny}\nnetwork:\n  allow: [\"ok.example.com\"]\n  deny: [\"evil.example.com\"]\n";

    /// A decider for `agent`, with an access document granting `acc.example.com` to Claude.
    fn decider_for(state: &Path, agent: &str, started_at: &str) -> LiveNetDecider {
        let mut all = agentacl_policy::set::builtin_sources(false);
        all.push(agentacl_policy::set::PolicySource { layer: agentacl_policy::Layer::User, name: "user".into(), yaml: POLICY.into() });
        all.push(agentacl_policy::set::PolicySource {
            layer: agentacl_policy::Layer::User,
            name: "access:claude-code".into(),
            yaml: "version: v1\nname: access:claude-code\nmatch: {agents: [claude-code]}\nnetwork:\n  allow: [\"acc.example.com\"]\n".into(),
        });
        let vars = agentacl_policy::expand::Vars { home: "/Users/t".into(), project: "/p".into(), tmpdir: "/tmp".into(), agent_state: None, agentacl_state: "/s".into(), agentacl_config: "/c".into() };
        let set = PolicySet::load(all, &vars, &Default::default()).unwrap();
        let inner = PolicyNetDecider { policy: Arc::new(set), subject: Subject { agent_id: agent.into(), project: "/p".into(), ..Default::default() } };
        let mut d = LiveNetDecider::new(inner, state.to_path_buf(), "agt_x".into(), agent.into(), agent.into(), "/p".into(), started_at.into());
        d.notify = false;
        d
    }

    #[test]
    fn scoped_rules_apply_to_their_agent_only() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path();
        let old = "2026-01-01T00:00:00.000Z";
        let (claude, codex) = (decider_for(s, "claude-code", old), decider_for(s, "codex", old));
        assert_eq!(claude.host("acc.example.com", 443).effect, Effect::Allow, "access document applies to Claude");
        assert_eq!(codex.host("acc.example.com", 443).effect, Effect::Deny, "…and not to Codex");

        set_scoped_rule(s, "new.example.com", Effect::Allow, Some("claude-code"), None, "access:claude-code").unwrap();
        assert_eq!(claude.host("new.example.com", 443).effect, Effect::Allow);
        assert_eq!(codex.host("new.example.com", 443).effect, Effect::Deny);
        set_scoped_rule(s, "ok.example.com", Effect::Deny, Some("codex"), None, "access:codex").unwrap();
        assert_eq!(codex.host("ok.example.com", 443).effect, Effect::Deny, "scoped block");
        assert_eq!(claude.host("ok.example.com", 443).effect, Effect::Allow, "another agent's block doesn't apply");
        set_scoped_rule(s, "other.example.com", Effect::Allow, None, Some("/elsewhere"), "access:all@x").unwrap();
        assert_eq!(claude.host("other.example.com", 443).effect, Effect::Deny, "another project's allow");

        // The policy-file reconciliation leaves access rules alone.
        reconcile(s, &Default::default(), &Default::default()).unwrap();
        assert_eq!(claude.host("new.example.com", 443).effect, Effect::Allow);

        // Removing an access grant revokes that document's allow only.
        remove_scoped_rule(s, "acc.example.com", "access:claude-code").unwrap();
        assert_eq!(claude.host("acc.example.com", 443).effect, Effect::Deny, "revoked for a running session");
        remove_scoped_rule(s, "ok.example.com", "access:claude-code").unwrap();
        assert_eq!(claude.host("ok.example.com", 443).effect, Effect::Allow, "a user-policy allow of the same host stands");
        let newer = decider_for(s, "claude-code", "2999-01-01T00:00:00.000Z");
        assert_eq!(newer.host("acc.example.com", 443).effect, Effect::Allow, "a newer session's own policy decides");
    }

    #[test]
    fn wait_is_configurable_and_extendable() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path().to_path_buf();
        set_mode(&s, Mode::Ask).unwrap();
        assert!(set_wait(&s, 45).is_err(), "only the offered waits");
        set_wait(&s, 60).unwrap();
        let d = decider(&s, POLICY, "2026-01-01T00:00:00.000Z");
        let waiting = std::thread::spawn(move || d.host("slow.example.com", 443));
        let t0 = Instant::now();
        let a = loop {
            if let Some(a) = pending(&s).into_iter().next() {
                break a;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "no prompt appeared");
            std::thread::sleep(Duration::from_millis(10));
        };
        let secs = |t: &str| crate::audit::parse_ts(t).unwrap();
        assert_eq!(secs(&a.expires) - secs(&a.created), 60, "the chosen wait");
        let e = extend(&s, &a.id).unwrap();
        assert_eq!(secs(&e.expires) - secs(&a.expires), 60, "+1 min");
        for _ in 1..MAX_EXTENSIONS {
            extend(&s, &a.id).unwrap();
        }
        assert!(extend(&s, &a.id).is_err(), "capped");
        answer(&s, &a.id, Answer::Once).unwrap();
        assert_eq!(waiting.join().unwrap().effect, Effect::Allow);
        assert!(extend(&s, &a.id).is_err(), "answered requests can't be extended");
    }

    #[test]
    fn extension_moves_the_waiting_deadline() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path().to_path_buf();
        set_mode(&s, Mode::Ask).unwrap();
        let mut d = decider(&s, POLICY, "2026-01-01T00:00:00.000Z");
        d.ask_timeout = Duration::from_secs(2);
        let waiting = std::thread::spawn(move || d.host("later.example.com", 443));
        let t0 = Instant::now();
        let id = loop {
            if let Some(a) = pending(&s).into_iter().next() {
                break a.id;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "no prompt appeared");
            std::thread::sleep(Duration::from_millis(10));
        };
        extend(&s, &id).unwrap();
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!waiting.is_finished(), "still waiting past the original deadline");
        answer(&s, &id, Answer::Once).unwrap();
        assert_eq!(waiting.join().unwrap().effect, Effect::Allow);
    }

    #[test]
    fn console_block_applies_now_and_allow_only_lifts_defaults() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path();
        let d = decider(s, POLICY, "2026-01-01T00:00:00.000Z");
        assert_eq!(d.host("ok.example.com", 443).effect, Effect::Allow);
        set_rule(s, "ok.example.com", Some(Effect::Deny)).unwrap();
        assert_eq!(d.host("OK.example.com.", 443).effect, Effect::Deny, "console block wins at once");
        set_rule(s, "evil.example.com", Some(Effect::Allow)).unwrap();
        assert_eq!(d.host("evil.example.com", 443).effect, Effect::Deny, "explicit policy deny stands");
        assert_eq!(d.host("new.example.com", 443).effect, Effect::Deny);
        set_rule(s, "new.example.com", Some(Effect::Allow)).unwrap();
        assert_eq!(d.host("new.example.com", 443).effect, Effect::Allow, "default deny lifted for an older session");
        // A session started after the console allow relies on its policy file.
        let later = decider(s, POLICY, "2999-01-01T00:00:00.000Z");
        assert_eq!(later.host("new.example.com", 443).effect, Effect::Deny);
        // Removing an allow from the policy revokes it for sessions that loaded it.
        assert_eq!(d.host("ok.example.com", 443).effect, Effect::Deny, "still console-blocked");
        set_rule(s, "ok.example.com", None).unwrap();
        assert_eq!(d.host("ok.example.com", 443).effect, Effect::Allow);
        revoke(s, &["ok.example.com".into()]).unwrap();
        assert_eq!(d.host("ok.example.com", 443).effect, Effect::Deny, "revoked for an older session");
        assert_eq!(later.host("ok.example.com", 443).effect, Effect::Allow, "a newer session's own policy decides");
        // Built-in reserved ranges are address rules; hosts that are IPs are never lifted.
        set_rule(s, "169.254.169.254", Some(Effect::Allow)).unwrap_err();
    }

    #[test]
    fn ask_waits_for_an_answer() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path().to_path_buf();
        set_mode(&s, Mode::Ask).unwrap();
        let d = Arc::new(decider(&s, POLICY, "2026-01-01T00:00:00.000Z"));
        let d2 = d.clone();
        let h = std::thread::spawn(move || d2.host("pkg.example.com", 443));
        let id = loop {
            if let Some(a) = pending(&s).into_iter().next() {
                assert_eq!(a.host, "pkg.example.com");
                break a.id;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        answer(&s, &id, Answer::Session).unwrap();
        assert_eq!(h.join().unwrap().effect, Effect::Allow);
        assert!(pending(&s).is_empty());
        // remembered for the session, on that port only
        assert_eq!(d.host("pkg.example.com", 443).effect, Effect::Allow);
        assert!(pending(&s).is_empty());
        // answering again, or after expiry, is refused
        assert!(answer(&s, &id, Answer::Once).is_err());
        // another port on the same host is a new question
        let d3 = d.clone();
        let h = std::thread::spawn(move || d3.host("pkg.example.com", 22));
        let id22 = loop {
            if let Some(a) = pending(&s).into_iter().next() {
                assert_eq!(a.port, 22);
                break a.id;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        answer(&s, &id22, Answer::Block).unwrap();
        assert_eq!(h.join().unwrap().effect, Effect::Deny);
        // explicit denies never prompt
        assert_eq!(d.host("evil.example.com", 443).effect, Effect::Deny);
        assert!(pending(&s).is_empty());
    }

    #[test]
    fn ask_times_out_to_blocked_and_never_resolves_first() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path().to_path_buf();
        set_mode(&s, Mode::Ask).unwrap();
        let mut d = decider(&s, POLICY, "2026-01-01T00:00:00.000Z");
        d.ask_timeout = Duration::from_secs(3);
        // The prompt is raised on the name alone: a name that can't resolve
        // still gets one, so no DNS answer is needed (or used) before asking.
        let started = Instant::now();
        let waiting = std::thread::spawn(move || d.host("agentbreak-unresolvable.invalid", 443));
        let mut seen = vec![];
        while seen.is_empty() && !waiting.is_finished() {
            seen = pending(&s);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen.len(), 1, "a prompt exists while the connection waits");
        assert_eq!((seen[0].host.as_str(), seen[0].port), ("agentbreak-unresolvable.invalid", 443));
        let r = waiting.join().unwrap();
        assert_eq!(r.effect, Effect::Deny);
        assert!(r.reason.contains("no answer"), "{}", r.reason);
        assert!(started.elapsed() >= Duration::from_secs(3), "waited for the answer");
        // Expired prompts are no longer offered.
        assert!(pending(&s).is_empty());
    }

    #[test]
    fn ask_rate_limits_prompts() {
        let t = tempfile::tempdir().unwrap();
        let s = t.path().to_path_buf();
        set_mode(&s, Mode::Ask).unwrap();
        let mut d = decider(&s, POLICY, "2026-01-01T00:00:00.000Z");
        d.ask_timeout = Duration::from_secs(5);
        let d = Arc::new(d);
        let waiting: Vec<_> = (0..MAX_PENDING)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || d.host(&format!("site{i}.example.com"), 443))
            })
            .collect();
        while pending(&s).len() < MAX_PENDING {
            std::thread::sleep(Duration::from_millis(20));
        }
        // One more site is refused at once, without a prompt.
        let started = Instant::now();
        let r = d.host("one-too-many.example.com", 443);
        assert_eq!(r.effect, Effect::Deny);
        assert!(r.reason.contains("too many"), "{}", r.reason);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(pending(&s).len(), MAX_PENDING);
        for a in pending(&s) {
            answer(&s, &a.id, Answer::Block).unwrap();
        }
        for h in waiting {
            assert_eq!(h.join().unwrap().effect, Effect::Deny);
        }
    }

    #[test]
    fn host_names_are_validated() {
        assert!(is_named_host("api.github.com"));
        for bad in ["", "localhost", "10.0.0.1", "::1", "a\"b", "x y", "a;b"] {
            assert!(!is_named_host(bad), "{bad}");
        }
        assert!(answer(Path::new("/nonexistent"), "../../etc/passwd", Answer::Once).is_err());
    }
}
