//! Which processes belong to which agent session, system-wide.
//!
//! A session starts when a process execs an agent binary, identified by its
//! code signature (or install path) with the same provider registry
//! `agentacl run` uses. Every process forked or exec'd from a member is a
//! member, by audit token: never by environment variable or name, which the
//! agent controls. Membership is checked per message, with the parent's audit
//! token as a fallback, because a fork notification can arrive after the
//! child's first request (docs/macos-enforcement.md §3.3).

use crate::model::{Proc, ProcKey};
use agentacl_core::agents;
use agentacl_core::proc::{CodeSignature, ProcessFacts};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

/// Stand-in project when the agent's working directory isn't a project
/// (the same placeholder the console uses).
pub const NO_PROJECT: &str = "/private/var/empty";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub project: PathBuf,
    pub root: ProcKey,
}

/// How many exited processes are remembered, to adopt children whose fork
/// notification arrives after their parent exited.
const GRAVEYARD: usize = 4096;

#[derive(Default)]
pub struct Tracker {
    members: HashMap<ProcKey, String>,
    sessions: HashMap<String, Session>,
    /// Recently exited members, oldest first.
    exited: HashMap<ProcKey, String>,
    exited_order: VecDeque<ProcKey>,
}

/// What a tracker update means for the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Started(Session),
    Ended(Session),
}

fn nonempty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// The agent a just-exec'd image is, if any.
pub fn identify(target: &Proc, argv: &[String]) -> Option<(String, String)> {
    let facts = ProcessFacts { pid: target.key().pid, ppid: target.ppid, pgid: 0, uid: target.uid, start_time_us: 0, exe: Some(target.exe.clone()), argv: argv.to_vec(), name: String::new() };
    let sig = CodeSignature { team_id: nonempty(&target.team_id), signing_id: nonempty(&target.signing_id), authority: vec![] };
    let sig = (sig.team_id.is_some() || sig.signing_id.is_some()).then_some(sig);
    agents::identify(&facts, sig.as_ref()).map(|i| (i.id, i.display_name))
}

/// The project for an agent started in `cwd`: its repository, or `cwd`
/// itself. Never runs git: the daemon answers within an ES deadline.
pub fn project_for(cwd: Option<&str>, home: &Path) -> PathBuf {
    cwd.map(Path::new)
        .and_then(|c| {
            let root = agentacl_core::identity::repo_root(c).unwrap_or_else(|| c.to_path_buf());
            agentacl_core::identity::resolve_project(c, Some(&root), home).ok()
        })
        .unwrap_or_else(|| PathBuf::from(NO_PROJECT))
}

impl Tracker {
    /// The session of a known process (no adoption).
    pub fn session_of(&self, key: Option<ProcKey>) -> Option<&Session> {
        self.members.get(&key?).and_then(|id| self.sessions.get(id))
    }

    /// The session `p` belongs to, adopting it through its parent if needed
    /// (also a parent that already exited).
    pub fn member(&mut self, p: &Proc) -> Option<Session> {
        let key = p.key?;
        if let Some(id) = self.members.get(&key) {
            return self.sessions.get(id).cloned();
        }
        if self.exited.contains_key(&key) {
            return None;
        }
        let pk = p.parent?;
        let id = self.members.get(&pk).or_else(|| self.exited.get(&pk)).cloned()?;
        let s = self.sessions.get(&id).cloned()?;
        self.members.insert(key, id);
        Some(s)
    }

    pub fn on_fork(&mut self, parent: &Proc, child: &Proc) {
        let Some(ck) = child.key else { return };
        if self.exited.contains_key(&ck) {
            return; // a late notification for a child that already exited
        }
        if let Some(s) = self.member(parent) {
            self.members.insert(ck, s.id);
        }
    }

    /// A member is about to exec: the new image joins the session. The old
    /// audit token stays until the exec happened ([`Tracker::on_exec_done`]),
    /// so a refused or failed exec leaves the process enforced.
    pub fn add_image(&mut self, target: &Proc, session: &str) {
        if let Some(tk) = target.key {
            self.members.insert(tk, session.to_string());
        }
    }

    /// The exec happened: the old audit token is gone (but remembered, to
    /// adopt a child whose first request names it as its parent).
    pub fn on_exec_done(&mut self, p: &Proc, target: &Proc) {
        if let (Some(old), Some(new)) = (p.key, target.key) {
            if old != new && self.members.contains_key(&new) {
                if let Some(id) = self.members.remove(&old) {
                    self.bury(old, id);
                }
            }
        }
    }

    fn bury(&mut self, key: ProcKey, id: String) {
        self.exited.insert(key, id);
        self.exited_order.push_back(key);
        if self.exited_order.len() > GRAVEYARD {
            if let Some(old) = self.exited_order.pop_front() {
                self.exited.remove(&old);
            }
        }
    }

    /// A non-member exec'd `target`: if it is an agent, a session starts.
    pub fn start(&mut self, target: &Proc, argv: &[String], cwd: Option<&str>, home: &Path) -> Option<Change> {
        let tk = target.key?;
        let (agent_id, agent_name) = identify(target, argv)?;
        let s = Session { id: agentacl_core::session::new_session_id(), agent_id, agent_name, project: project_for(cwd, home), root: tk };
        Some(self.insert(s, &[tk]))
    }

    /// A session for processes that were already running (daemon start).
    pub fn insert(&mut self, s: Session, keys: &[ProcKey]) -> Change {
        for k in keys {
            self.members.insert(*k, s.id.clone());
        }
        self.sessions.insert(s.id.clone(), s.clone());
        Change::Started(s)
    }

    pub fn on_exit(&mut self, p: &Proc) -> Option<Change> {
        let key = p.key?;
        let id = self.members.remove(&key)?;
        self.bury(key, id.clone());
        if self.members.values().any(|m| *m == id) {
            return None;
        }
        self.sessions.remove(&id).map(Change::Ended)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
