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

/// Seconds since the epoch of an RFC 3339 UTC timestamp we wrote.
pub fn parse_ts(s: &str) -> Option<i64> {
    let (y, m, d) = (s.get(0..4)?.parse::<i64>().ok()?, s.get(5..7)?.parse::<i64>().ok()?, s.get(8..10)?.parse::<i64>().ok()?);
    let (hh, mm, ss) = (s.get(11..13)?.parse::<i64>().ok()?, s.get(14..16)?.parse::<i64>().ok()?, s.get(17..19)?.parse::<i64>().ok()?);
    // days from civil (Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400 + hh * 3600 + mm * 60 + ss)
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

    /// Records an action taken through the local UI (`source: ui`).
    pub fn record_ui(&self, ctx: &EventContext, action: &str, resource: &str, reason: &str) -> Result<Event> {
        let mut e = Self::base(ctx, EventSource::Ui);
        e.action = action.into();
        e.resource = resource.into();
        e.reason = Some(reason.into());
        self.insert_event(&e)?;
        Ok(e)
    }

    /// Distinct projects of recent sessions, newest first.
    pub fn recent_projects(&self, limit: usize) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT project, MAX(started_at) AS t FROM sessions GROUP BY project ORDER BY t DESC LIMIT ?1")?;
        let rows = st.query_map(params![limit as i64], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
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

    /// One page of events, newest first, with the total matching count.
    pub fn events_page(&self, p: &EventPage) -> Result<(u64, Vec<(i64, Event)>)> {
        let mut filter = String::from(" WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![];
        if let Some(s) = &p.session {
            args.push(Box::new(s.clone()));
            filter.push_str(&format!(" AND session_id = ?{}", args.len()));
        }
        if let Some(a) = &p.agent {
            args.push(Box::new(a.clone()));
            filter.push_str(&format!(" AND agent = ?{}", args.len()));
        }
        if let Some(pr) = &p.project {
            args.push(Box::new(pr.clone()));
            filter.push_str(&format!(" AND session_id IN (SELECT session_id FROM sessions WHERE project = ?{})", args.len()));
        }
        if let Some(since) = &p.since {
            args.push(Box::new(since.clone()));
            filter.push_str(&format!(" AND ts >= ?{}", args.len()));
        }
        if let Some(policy) = &p.policy {
            args.push(Box::new(policy.clone()));
            filter.push_str(&format!(" AND policy = ?{}", args.len()));
        }
        match p.kind.as_str() {
            "blocked" => filter.push_str(" AND enforcement = 'enforced' AND decision IN ('deny','ask')"),
            "observed" => filter.push_str(" AND enforcement = 'observed'"),
            "allowed" => filter.push_str(" AND decision = 'allow'"),
            "system" => filter.push_str(" AND decision IS NULL"),
            _ => {}
        }
        if !p.search.is_empty() {
            args.push(Box::new(format!("%{}%", p.search.replace('%', "\\%").replace('_', "\\_"))));
            let n = args.len();
            filter.push_str(&format!(" AND (resource LIKE ?{n} ESCAPE '\\' OR action LIKE ?{n} ESCAPE '\\' OR IFNULL(rule_id,'') LIKE ?{n} ESCAPE '\\' OR IFNULL(policy,'') LIKE ?{n} ESCAPE '\\' OR agent LIKE ?{n} ESCAPE '\\')"));
        }
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let total: i64 = self.conn.query_row(&format!("SELECT COUNT(*) FROM events{filter}"), refs.as_slice(), |r| r.get(0))?;
        let sql = format!("SELECT * FROM events{filter} ORDER BY rowid DESC LIMIT {} OFFSET {}", p.limit.clamp(1, 500), p.offset);
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(refs.as_slice(), row_event)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((total as u64, rows))
    }

    /// Per-project summary of every project any session ran in.
    pub fn project_summaries(&self, since: &str) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT s.project,
                    COUNT(*) AS sessions,
                    SUM(CASE WHEN s.ended_at IS NULL THEN 1 ELSE 0 END) AS active,
                    MAX(s.started_at) AS last_seen,
                    (SELECT IFNULL(SUM(e.count),0) FROM events e JOIN sessions s2 ON e.session_id = s2.session_id
                       WHERE s2.project = s.project AND e.ts >= ?1 AND e.enforcement = 'enforced' AND e.decision IN ('deny','ask')) AS blocked
             FROM sessions s GROUP BY s.project ORDER BY last_seen DESC",
        )?;
        let rows = st
            .query_map(params![since], |r| {
                Ok(serde_json::json!({
                    "path": r.get::<_, String>(0)?,
                    "sessions": r.get::<_, i64>(1)?,
                    "active_sessions": r.get::<_, i64>(2)?,
                    "last_seen": r.get::<_, Option<String>>(3)?,
                    "blocked_24h": r.get::<_, i64>(4)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Enforced denials per hour for the last 24 h (oldest first), 24 buckets.
    pub fn blocked_timeline(&self, now_secs: i64) -> Result<Vec<i64>> {
        let mut out = vec![0i64; 24];
        let since = super::event::format_rfc3339(now_secs - 24 * 3600, 0);
        let mut st = self.conn.prepare("SELECT ts, count FROM events WHERE ts >= ?1 AND enforcement = 'enforced' AND decision IN ('deny','ask')")?;
        let rows = st.query_map(params![since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows.flatten() {
            if let Some(t) = parse_ts(&row.0) {
                let age_h = (now_secs - t) / 3600;
                if (0..24).contains(&age_h) {
                    out[23 - age_h as usize] += row.1;
                }
            }
        }
        Ok(out)
    }

    /// Most-blocked resources since `since`.
    pub fn top_blocked(&self, since: &str, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut st = self.conn.prepare(
            "SELECT resource, action, policy, rule_id, SUM(count) AS n FROM events
             WHERE ts >= ?1 AND enforcement = 'enforced' AND decision IN ('deny','ask')
             GROUP BY resource, action ORDER BY n DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![since, limit as i64], |r| {
                Ok(serde_json::json!({ "resource": r.get::<_, String>(0)?, "action": r.get::<_, String>(1)?, "policy": r.get::<_, Option<String>>(2)?, "rule_id": r.get::<_, Option<String>>(3)?, "count": r.get::<_, i64>(4)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Counts for the overview cards since `since` (RFC 3339).
    pub fn counts_since(&self, since: &str) -> Result<serde_json::Value> {
        let q = |w: &str| -> rusqlite::Result<i64> { self.conn.query_row(&format!("SELECT IFNULL(SUM(count),0) FROM events WHERE ts >= ?1 AND {w}"), params![since], |r| r.get(0)) };
        Ok(serde_json::json!({
            "blocked": q("enforcement = 'enforced' AND decision IN ('deny','ask')")?,
            "secrets": q("enforcement = 'enforced' AND decision IN ('deny','ask') AND policy = 'protect-secrets'")?,
            "observed": q("enforcement = 'observed'")?,
            "allowed": q("decision = 'allow'")?,
        }))
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventPage {
    pub session: Option<String>,
    pub agent: Option<String>,
    /// Events of sessions in this project.
    pub project: Option<String>,
    /// RFC 3339 lower bound.
    pub since: Option<String>,
    /// Only events decided by this policy (e.g. `protect-secrets`).
    pub policy: Option<String>,
    /// all | blocked | observed | allowed | system
    pub kind: String,
    pub search: String,
    pub offset: u64,
    pub limit: u64,
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
    fn paging_and_filters() {
        let (_d, s) = store();
        for i in 0..30 {
            let e = if i % 3 == 0 {
                EnforcedEvent::from_kernel(&kd(i, &format!("/p/{i}.env")), vec![], decision(Effect::Deny), 1)
            } else {
                EnforcedEvent::proxy("network.connect".into(), format!("h{i}.com:443"), decision(Effect::Allow))
            };
            s.record_enforced(&ctx(), e).unwrap();
        }
        let (total, rows) = s.events_page(&EventPage { kind: "all".into(), limit: 7, offset: 0, ..Default::default() }).unwrap();
        assert_eq!((total, rows.len()), (30, 7));
        assert!(rows[0].0 > rows[6].0, "newest first");
        let (total, _) = s.events_page(&EventPage { kind: "blocked".into(), limit: 50, ..Default::default() }).unwrap();
        assert_eq!(total, 10);
        let (total, rows) = s.events_page(&EventPage { kind: "all".into(), search: "h4.com".into(), limit: 50, ..Default::default() }).unwrap();
        assert_eq!((total, rows[0].1.resource.as_str()), (1, "h4.com:443"));
        let (_, last) = s.events_page(&EventPage { kind: "all".into(), limit: 7, offset: 28, ..Default::default() }).unwrap();
        assert_eq!(last.len(), 2);
        assert_eq!(s.counts_since("1970-01-01T00:00:00.000Z").unwrap()["blocked"], 10);
    }

    #[test]
    fn timestamp_roundtrip() {
        for t in [0i64, 951_782_400, 1_790_000_000] {
            assert_eq!(parse_ts(&format_rfc3339(t, 0)), Some(t));
        }
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
