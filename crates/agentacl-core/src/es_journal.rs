//! The Endpoint Security daemon's journal (docs/design/endpoint-security.md).
//!
//! `agentacl-esd` runs as root, so it doesn't write the user's audit database
//! (files it created there would be root-owned and lock the user out).
//! Instead it appends one JSON record per line to `es/events.ndjson` in the
//! user's state directory, writing as the user (mode 0600); agents can't
//! write there (`agentacl-self`). The console and `agentacl events` ingest new
//! records into the audit log, so ES decisions appear next to Seatbelt and
//! proxy ones.

use crate::audit::{EnforcedEvent, EventContext, ObservedEvent, SessionRecord, Store};
use crate::config::Paths;
use crate::fsafe;
use agentacl_policy::Decision;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

pub const DIR: &str = "es";
pub const FILE: &str = "events.ndjson";
const OFFSET: &str = "ingested.offset";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    SessionStart,
    SessionEnd,
    /// A request the daemon refused.
    Denied,
    /// A request the daemon let through but that a rule names (audit only;
    /// not written by the daemon yet).
    Observed,
    /// The daemon (re)started: sessions it tracked before are gone from its
    /// memory, so they end here (it adopts running agents anew).
    DaemonStart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsRecord {
    pub ts: String,
    pub kind: Kind,
    pub session: String,
    pub agent: String,
    pub agent_name: String,
    pub project: String,
    pub pid: Option<i32>,
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub resource: String,
    pub decision: Option<Decision>,
}

pub fn dir(paths: &Paths) -> PathBuf {
    crate::supervisor::canon_or(&paths.state_dir).join(DIR)
}

fn ctx(r: &EsRecord, human: &str, machine: &str) -> EventContext {
    EventContext { human: human.into(), machine: machine.into(), agent: r.agent.clone(), agent_version: None, session: r.session.clone(), backend: "endpoint-security".into() }
}

/// Who and where, for the records' context (looked up once: `machine_id`
/// runs a program).
fn who() -> &'static (String, String) {
    static WHO: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    WHO.get_or_init(|| (crate::identity::human().map(|h| h.user).unwrap_or_default(), crate::proc::machine_id().unwrap_or_else(|_| "mch_unknown".into())))
}

/// "inode:offset" of the file read last.
fn saved(fd: &std::os::fd::OwnedFd) -> (u64, u64) {
    let s = fsafe::read_regular(fd, OFFSET).ok().flatten().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
    s.trim().split_once(':').and_then(|(i, o)| Some((i.parse().ok()?, o.parse().ok()?))).unwrap_or((0, 0))
}

/// Moves new journal records into the audit store. Cheap when there is
/// nothing new (two stats and a small read). Returns how many records were
/// ingested.
pub fn ingest(paths: &Paths, store: &Store) -> Result<usize> {
    let d = dir(paths);
    let Ok(fd) = fsafe::open_dir(&d) else { return Ok(0) };
    // Opened first, then examined: a rotation in between can't pair the
    // old offset with the new file.
    let Ok(file) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(d.join(FILE)) else { return Ok(0) };
    let meta = file.metadata()?;
    if !meta.is_file() || saved(&fd) == (meta.ino(), meta.len()) {
        return Ok(0);
    }
    // The console and `agentacl events` both ingest: one at a time, or a
    // record would be stored twice.
    // SAFETY: flock on a descriptor we own; released when `fd` is dropped.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let (ino, offset) = saved(&fd);
    let (human, machine) = who();
    let mut n = 0;
    let mut from = 0;
    if ino == meta.ino() {
        from = if offset > meta.len() { 0 } else { offset };
    } else if let Ok(old) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(d.join(format!("{FILE}.1"))) {
        // Rotated since: finish the old file first.
        if old.metadata().is_ok_and(|m| m.is_file() && m.ino() == ino) {
            n += read_from(old, offset, store, human, machine)?.0;
        }
    }
    let (m, consumed) = read_from(file, from, store, human, machine)?;
    fsafe::write_atomic(&fd, OFFSET, format!("{}:{consumed}", meta.ino()).as_bytes())?;
    Ok(n + m)
}

/// Ingests the complete lines of `f` after `offset`; returns how many
/// records, and the offset after the last line read. A record that can't be
/// stored is skipped (and reported), so it never blocks the ones after it.
fn read_from(mut f: std::fs::File, offset: u64, store: &Store, human: &str, machine: &str) -> Result<(usize, u64)> {
    let len = f.metadata()?.len();
    if offset >= len {
        return Ok((0, offset.min(len)));
    }
    f.seek(SeekFrom::Start(offset))?;
    let mut reader = std::io::BufReader::new(f.take(len - offset));
    let (mut n, mut consumed) = (0usize, offset);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 || !line.ends_with('\n') {
            break; // a partial last line is read next time
        }
        consumed += read as u64;
        let Ok(r) = serde_json::from_str::<EsRecord>(line.trim_end()) else { continue };
        if let Err(e) = store_record(store, &r, human, machine) {
            eprintln!("agentacl: skipping an Endpoint Security record: {e:#}");
            continue;
        }
        n += 1;
    }
    Ok((n, consumed))
}

fn store_record(store: &Store, r: &EsRecord, human: &str, machine: &str) -> Result<()> {
    let c = ctx(r, human, machine);
    match r.kind {
        Kind::SessionStart => {
            let _ = store.insert_session(&SessionRecord {
                session_id: r.session.clone(),
                identity_json: serde_json::json!({ "backend": "endpoint-security", "agent": r.agent, "project": r.project }).to_string(),
                agent: r.agent.clone(),
                project: r.project.clone(),
                policy_name: "endpoint-security".into(),
                policy_sha256: String::new(),
                backend: "endpoint-security".into(),
                supervisor_pid: 0,
                agent_pid: r.pid,
                started_at: r.ts.clone(),
                ended_at: None,
                exit_code: None,
            });
        }
        Kind::SessionEnd => store.end_session(&r.session, &r.ts, None)?,
        Kind::DaemonStart => {
            for s in store.active_sessions()? {
                if s.backend == "endpoint-security" {
                    store.end_session(&s.session_id, &r.ts, None)?;
                }
            }
        }
        Kind::Denied => {
            if let Some(d) = r.decision.clone() {
                store.record_enforced(&c, EnforcedEvent::endpoint_security(r.pid, r.chain.clone(), r.action.clone(), r.resource.clone(), d))?;
            }
        }
        Kind::Observed => {
            if let Some(d) = r.decision.clone() {
                store.record_observed(&c, ObservedEvent { pid: r.pid, delegation_chain: r.chain.clone(), action: r.action.clone(), resource: r.resource.clone(), decision: d })?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentacl_policy::Effect;
    use std::io::Write;

    fn rec(kind: Kind, action: &str) -> EsRecord {
        EsRecord {
            ts: "2026-10-09T10:00:00.000Z".into(),
            kind,
            session: "agt_ES1".into(),
            agent: "claude-code".into(),
            agent_name: "Claude Code".into(),
            project: "/p".into(),
            pid: Some(42),
            chain: vec!["claude".into(), "cat".into()],
            action: action.into(),
            resource: "/Users/u/.aws/credentials".into(),
            decision: Some(Decision { effect: Effect::Deny, policy: "protect-secrets".into(), rule_id: "aws".into(), reason: "AWS credentials are protected".into(), trace: vec![] }),
        }
    }

    #[test]
    fn ingests_new_records_once() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let paths = Paths::with_dirs(root.join("home"), root.join("state"), root.join("config"));
        crate::config::ensure_private_dir(&paths.state_dir).unwrap();
        let store = Store::open(&paths.db_path).unwrap();
        assert_eq!(ingest(&paths, &store).unwrap(), 0, "no journal yet");
        let d = dir(&paths);
        std::fs::create_dir_all(&d).unwrap();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(d.join(FILE)).unwrap();
        for r in [rec(Kind::SessionStart, ""), rec(Kind::Denied, "filesystem.read")] {
            writeln!(f, "{}", serde_json::to_string(&r).unwrap()).unwrap();
        }
        write!(f, "{{\"partial").unwrap(); // a line still being written
        f.flush().unwrap();
        assert_eq!(ingest(&paths, &store).unwrap(), 2);
        assert_eq!(ingest(&paths, &store).unwrap(), 0, "nothing new: not ingested twice");
        let ev = store.events(&crate::audit::EventQuery { session: Some("agt_ES1".into()), ..Default::default() }).unwrap();
        let e = &ev.iter().find(|(_, e)| e.action == "filesystem.read").unwrap().1;
        assert_eq!((e.decision, e.source.as_str()), (Some(Effect::Deny), "es"));
        assert!(store.active_sessions().unwrap().iter().any(|s| s.session_id == "agt_ES1" && s.backend == "endpoint-security"));
        // Finishing the partial line is picked up later; a session end closes it.
        writeln!(f, "\",\"x\":1}}").unwrap();
        writeln!(f, "{}", serde_json::to_string(&rec(Kind::SessionEnd, "")).unwrap()).unwrap();
        assert_eq!(ingest(&paths, &store).unwrap(), 1, "the malformed line is skipped, the end is read");
        assert!(!store.active_sessions().unwrap().iter().any(|s| s.session_id == "agt_ES1"));
        // Rotated: the old file's unread tail, then the new file from its
        // start (even once it is longer than the old offset).
        writeln!(f, "{}", serde_json::to_string(&rec(Kind::Denied, "filesystem.unlink")).unwrap()).unwrap();
        std::fs::rename(d.join(FILE), d.join(format!("{FILE}.1"))).unwrap();
        let mut g = std::fs::OpenOptions::new().create(true).append(true).open(d.join(FILE)).unwrap();
        let mut r = rec(Kind::Denied, "filesystem.write");
        r.resource = format!("/Users/u/{}", "x".repeat(2000));
        writeln!(g, "{}", serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(ingest(&paths, &store).unwrap(), 2);
        // A daemon restart ends the sessions it tracked.
        let mut s2 = rec(Kind::SessionStart, "");
        s2.session = "agt_ES2".into();
        writeln!(g, "{}", serde_json::to_string(&s2).unwrap()).unwrap();
        writeln!(g, "{}", serde_json::to_string(&rec(Kind::DaemonStart, "")).unwrap()).unwrap();
        assert_eq!(ingest(&paths, &store).unwrap(), 2);
        assert!(!store.active_sessions().unwrap().iter().any(|s| s.backend == "endpoint-security"));
    }
}
