//! Local SQLite audit store (WAL). One file shared by all sessions.

use super::event::*;
use agentfence_policy::Effect;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub identity_json: String,
    pub agent: String,
    pub project: String,
    pub policy_name: String,
    pub policy_sha256: String,
    pub backend: String,
    pub supervisor_pid: i32,
    pub agent_pid: Option<i32>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub session: Option<String>,
    pub decision: Option<Effect>,
    /// Only rows with rowid greater than this (for `--follow`).
    pub after_rowid: Option<i64>,
    /// Most recent N (returned oldest first). Default 200.
    pub limit: Option<usize>,
}

pub struct Store {
    conn: Connection,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  identity_json TEXT NOT NULL,
  agent TEXT NOT NULL,
  project TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL,
  backend TEXT NOT NULL,
  supervisor_pid INTEGER NOT NULL,
  agent_pid INTEGER,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  exit_code INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  human TEXT NOT NULL,
  machine TEXT NOT NULL,
  agent TEXT NOT NULL,
  agent_version TEXT,
  session_id TEXT NOT NULL,
  pid INTEGER,
  delegation_chain_json TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  decision TEXT,
  enforcement TEXT,
  backend TEXT NOT NULL,
  source TEXT NOT NULL,
  policy TEXT,
  rule_id TEXT,
  reason TEXT,
  count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS events_session_ts ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS events_decision_ts ON events(decision, ts);
PRAGMA user_version = 1;
"#;

fn effect_str(e: Option<Effect>) -> Option<&'static str> {
    e.map(|e| e.as_str())
}

fn parse_effect(s: Option<String>) -> Option<Effect> {
    match s.as_deref() {
        Some("allow") => Some(Effect::Allow),
        Some("deny") => Some(Effect::Deny),
        Some("ask") => Some(Effect::Ask),
        _ => None,
    }
}

fn row_event(r: &Row) -> rusqlite::Result<(i64, Event)> {
    let chain: String = r.get("delegation_chain_json")?;
    let enforcement: Option<String> = r.get("enforcement")?;
    let source: String = r.get("source")?;
    Ok((
        r.get("rowid")?,
        Event {
            id: r.get("id")?,
            timestamp: r.get("ts")?,
            human: r.get("human")?,
            machine: r.get("machine")?,
            agent: r.get("agent")?,
            agent_version: r.get("agent_version")?,
            session: r.get("session_id")?,
            pid: r.get("pid")?,
            delegation_chain: serde_json::from_str(&chain).unwrap_or_default(),
            action: r.get("action")?,
            resource: r.get("resource")?,
            decision: parse_effect(r.get("decision")?),
            enforcement: match enforcement.as_deref() {
                Some("enforced") => Some(Enforcement::Enforced),
                Some("observed") => Some(Enforcement::Observed),
                _ => None,
            },
            backend: r.get("backend")?,
            source: EventSource::parse(&source).unwrap_or(EventSource::Supervisor),
            policy: r.get("policy")?,
            rule_id: r.get("rule_id")?,
            reason: r.get("reason")?,
            count: r.get("count")?,
        },
    ))
}

fn row_session(r: &Row) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        session_id: r.get("session_id")?,
        identity_json: r.get("identity_json")?,
        agent: r.get("agent")?,
        project: r.get("project")?,
        policy_name: r.get("policy_name")?,
        policy_sha256: r.get("policy_sha256")?,
        backend: r.get("backend")?,
        supervisor_pid: r.get("supervisor_pid")?,
        agent_pid: r.get("agent_pid")?,
        started_at: r.get("started_at")?,
        ended_at: r.get("ended_at")?,
        exit_code: r.get("exit_code")?,
    })
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            crate::config::ensure_private_dir(dir)?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Store { conn })
    }

    pub fn insert_session(&self, s: &SessionRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (session_id, identity_json, agent, project, policy_name, policy_sha256, backend, supervisor_pid, agent_pid, started_at, ended_at, exit_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![s.session_id, s.identity_json, s.agent, s.project, s.policy_name, s.policy_sha256, s.backend, s.supervisor_pid, s.agent_pid, s.started_at, s.ended_at, s.exit_code],
        )?;
        Ok(())
    }

    pub fn set_agent_pid(&self, session_id: &str, pid: i32) -> Result<()> {
        self.conn.execute("UPDATE sessions SET agent_pid = ?2 WHERE session_id = ?1", params![session_id, pid])?;
        Ok(())
    }

    pub fn end_session(&self, session_id: &str, ended_at: &str, exit_code: Option<i32>) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET ended_at = ?2, exit_code = ?3 WHERE session_id = ?1 AND ended_at IS NULL",
            params![session_id, ended_at, exit_code],
        )?;
        Ok(())
    }

    pub fn session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        Ok(self
            .conn
            .query_row("SELECT * FROM sessions WHERE session_id = ?1", params![session_id], row_session)
            .optional()?)
    }

    pub fn active_sessions(&self) -> Result<Vec<SessionRecord>> {
        let mut st = self.conn.prepare("SELECT * FROM sessions WHERE ended_at IS NULL ORDER BY started_at")?;
        let rows = st.query_map([], row_session)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub(crate) fn insert_event(&self, e: &Event) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (id, ts, human, machine, agent, agent_version, session_id, pid, delegation_chain_json, action, resource, decision, enforcement, backend, source, policy, rule_id, reason, count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                e.id,
                e.timestamp,
                e.human,
                e.machine,
                e.agent,
                e.agent_version,
                e.session,
                e.pid,
                serde_json::to_string(&e.delegation_chain)?,
                e.action,
                e.resource,
                effect_str(e.decision),
                e.enforcement.map(|x| match x {
                    Enforcement::Enforced => "enforced",
                    Enforcement::Observed => "observed",
                }),
                e.backend,
                e.source.as_str(),
                e.policy,
                e.rule_id,
                e.reason,
                e.count,
            ],
        )?;
        Ok(())
    }

    fn base(ctx: &EventContext, source: EventSource) -> Event {
        Event {
            id: new_event_id(),
            timestamp: now_rfc3339(),
            human: ctx.human.clone(),
            machine: ctx.machine.clone(),
            agent: ctx.agent.clone(),
            agent_version: ctx.agent_version.clone(),
            session: ctx.session.clone(),
            pid: None,
            delegation_chain: vec![],
            action: String::new(),
            resource: String::new(),
            decision: None,
            enforcement: None,
            backend: ctx.backend.clone(),
            source,
            policy: None,
            rule_id: None,
            reason: None,
            count: 1,
        }
    }

    /// Records activity that was evaluated but **not** prevented.
    pub fn record_observed(&self, ctx: &EventContext, o: ObservedEvent) -> Result<Event> {
        let mut e = Self::base(ctx, EventSource::ProcMonitor);
        e.pid = o.pid;
        e.delegation_chain = o.delegation_chain;
        e.action = o.action;
        e.resource = o.resource;
        e.decision = Some(o.decision.effect);
        e.enforcement = Some(Enforcement::Observed);
        e.policy = Some(o.decision.policy);
        e.rule_id = Some(o.decision.rule_id);
        e.reason = Some(o.decision.reason);
        self.insert_event(&e)?;
        Ok(e)
    }

    /// Records a decision that took effect (kernel report or proxy).
    pub fn record_enforced(&self, ctx: &EventContext, x: EnforcedEvent) -> Result<Event> {
        let mut e = Self::base(ctx, x.source);
        e.pid = x.pid;
        e.delegation_chain = x.delegation_chain;
        e.action = x.action;
        e.resource = x.resource;
        e.decision = Some(x.decision.effect);
        e.enforcement = Some(Enforcement::Enforced);
        e.policy = Some(x.decision.policy);
        e.rule_id = Some(x.decision.rule_id);
        e.reason = Some(x.decision.reason);
        e.count = x.count.max(1);
        self.insert_event(&e)?;
        Ok(e)
    }

    pub fn record_lifecycle(&self, ctx: &EventContext, l: LifecycleEvent) -> Result<Event> {
        let mut e = Self::base(ctx, EventSource::Supervisor);
        e.pid = l.pid;
        e.action = l.kind.as_str().into();
        e.resource = l.detail;
        self.insert_event(&e)?;
        Ok(e)
    }

    pub fn bump_count(&self, event_id: &str, n: u32) -> Result<()> {
        self.conn.execute("UPDATE events SET count = count + ?2 WHERE id = ?1", params![event_id, n])?;
        Ok(())
    }

    /// Returns (rowid, event), oldest first.
    pub fn events(&self, q: &EventQuery) -> Result<Vec<(i64, Event)>> {
        let mut sql = String::from("SELECT * FROM events WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![];
        if let Some(s) = &q.session {
            args.push(Box::new(s.clone()));
            sql.push_str(&format!(" AND session_id = ?{}", args.len()));
        }
        if let Some(d) = q.decision {
            args.push(Box::new(d.as_str()));
            sql.push_str(&format!(" AND decision = ?{}", args.len()));
        }
        if let Some(r) = q.after_rowid {
            args.push(Box::new(r));
            sql.push_str(&format!(" AND rowid > ?{}", args.len()));
        }
        let limit = q.limit.unwrap_or(200) as i64;
        args.push(Box::new(limit));
        sql.push_str(&format!(" ORDER BY rowid DESC LIMIT ?{}", args.len()));
        let mut st = self.conn.prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let mut rows = st.query_map(refs.as_slice(), row_event)?.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_policy::Decision;

    fn ctx() -> EventContext {
        EventContext { human: "u".into(), machine: "mch_1".into(), agent: "claude-code".into(), agent_version: Some("2.1.2".into()), session: "agt_1".into(), backend: "seatbelt".into() }
    }
    fn decision(effect: Effect) -> Decision {
        Decision { effect, policy: "protect-secrets".into(), rule_id: "env-files".into(), reason: "r".into(), trace: vec![] }
    }
    fn kd(pid: i32, path: &str) -> crate::observe::sandbox_log::KernelDenial {
        let line = format!(r#"{{"eventMessage":"Sandbox: cat({pid}) deny(1) file-read-data {path}","processID":0}}"#);
        match crate::observe::sandbox_log::parse_ndjson_line(&line) {
            crate::observe::sandbox_log::LogLine::Denial(d) => d,
            other => panic!("{other:?}"),
        }
    }
    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("state/agentfence.db")).unwrap();
        (d, s)
    }

    #[test]
    fn roundtrip_and_query() {
        let (_d, s) = store();
        let c = ctx();
        s.record_lifecycle(&c, LifecycleEvent { kind: LifecycleKind::SessionStart, pid: Some(1), detail: "x".into() }).unwrap();
        s.record_enforced(&c, EnforcedEvent::from_kernel(&kd(5, "/p/.env"), vec!["claude-code".into(), "cat".into()], decision(Effect::Deny), 1)).unwrap();
        s.record_observed(&c, ObservedEvent { pid: Some(6), delegation_chain: vec![], action: "process.exec".into(), resource: "git push".into(), decision: decision(Effect::Ask) }).unwrap();
        let all = s.events(&EventQuery { limit: Some(2), ..Default::default() }).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1.action, "filesystem.read");
        assert_eq!(all[1].1.action, "process.exec");
        let denies = s.events(&EventQuery { decision: Some(Effect::Deny), ..Default::default() }).unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].1.enforcement, Some(Enforcement::Enforced));
        assert_eq!(denies[0].1.delegation_chain, vec!["claude-code", "cat"]);
        let other = s.events(&EventQuery { session: Some("nope".into()), ..Default::default() }).unwrap();
        assert!(other.is_empty());
        let after = s.events(&EventQuery { after_rowid: Some(all[0].0), ..Default::default() }).unwrap();
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn observed_is_never_enforced_and_lifecycle_has_none() {
        let (_d, s) = store();
        let e = s.record_observed(&ctx(), ObservedEvent { pid: None, delegation_chain: vec![], action: "process.exec".into(), resource: "x".into(), decision: decision(Effect::Deny) }).unwrap();
        assert_eq!(e.enforcement, Some(Enforcement::Observed));
        let l = s.record_lifecycle(&ctx(), LifecycleEvent { kind: LifecycleKind::SessionEnd, pid: None, detail: String::new() }).unwrap();
        assert_eq!(l.enforcement, None);
        assert_eq!(l.decision, None);
    }

    #[test]
    fn bump_count() {
        let (_d, s) = store();
        let e = s.record_enforced(&ctx(), EnforcedEvent::from_kernel(&kd(5, "/x"), vec![], decision(Effect::Deny), 1)).unwrap();
        s.bump_count(&e.id, 3).unwrap();
        let got = s.events(&EventQuery::default()).unwrap();
        assert_eq!(got[0].1.count, 4);
    }

    #[test]
    fn json_shape() {
        let (_d, s) = store();
        let e = s.record_enforced(&ctx(), EnforcedEvent::proxy("network.connect".into(), "evil.com:443".into(), decision(Effect::Deny))).unwrap();
        let v = serde_json::to_value(&e).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            ["action", "agent", "agent_version", "backend", "count", "decision", "delegation_chain", "enforcement", "human", "id", "machine", "pid", "policy", "reason", "resource", "rule_id", "session", "source", "timestamp"]
        );
        assert_eq!(v["source"], "proxy");
        assert_eq!(v["enforcement"], "enforced");
        assert_eq!(v["decision"], "deny");
    }

    #[test]
    fn sessions_lifecycle_and_concurrent_writers() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("agentfence.db");
        let a = Store::open(&path).unwrap();
        let b = Store::open(&path).unwrap();
        let rec = SessionRecord {
            session_id: "agt_1".into(),
            identity_json: "{}".into(),
            agent: "claude-code".into(),
            project: "/p".into(),
            policy_name: "default".into(),
            policy_sha256: "ab".into(),
            backend: "seatbelt".into(),
            supervisor_pid: 1,
            agent_pid: None,
            started_at: now_rfc3339(),
            ended_at: None,
            exit_code: None,
        };
        a.insert_session(&rec).unwrap();
        b.set_agent_pid("agt_1", 42).unwrap();
        assert_eq!(a.active_sessions().unwrap()[0].agent_pid, Some(42));
        let t = std::thread::spawn(move || {
            for _ in 0..50 {
                b.record_lifecycle(&ctx(), LifecycleEvent { kind: LifecycleKind::BackendWarning, pid: None, detail: "b".into() }).unwrap();
            }
        });
        for _ in 0..50 {
            a.record_lifecycle(&ctx(), LifecycleEvent { kind: LifecycleKind::BackendWarning, pid: None, detail: "a".into() }).unwrap();
        }
        t.join().unwrap();
        assert_eq!(a.events(&EventQuery { limit: Some(1000), ..Default::default() }).unwrap().len(), 100);
        a.end_session("agt_1", &now_rfc3339(), Some(0)).unwrap();
        assert!(a.active_sessions().unwrap().is_empty());
        assert_eq!(a.session("agt_1").unwrap().unwrap().exit_code, Some(0));
    }
}
