//! The server's SQLite store: devices, what they report, company policy
//! versions, enrollment tokens and admin sessions.

use agentacl_fleet::{EventInfo, MachineIdentity, PolicyResponse, Report};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enroll_tokens (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, max_uses INTEGER NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, machine_id TEXT NOT NULL,
  hostname TEXT NOT NULL, serial TEXT, os_version TEXT NOT NULL,
  agentacl_version TEXT NOT NULL, token_id INTEGER, enrolled_at INTEGER NOT NULL,
  last_seen INTEGER, revoked INTEGER NOT NULL DEFAULT 0,
  status_json TEXT, running_json TEXT, dropped INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS devices_machine ON devices(machine_id);
CREATE TABLE IF NOT EXISTS blocked_machines (machine_id TEXT PRIMARY KEY, since INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_users (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user TEXT NOT NULL, uid INTEGER NOT NULL, installed_json TEXT,
  sessions_json TEXT NOT NULL, error TEXT, updated INTEGER NOT NULL,
  PRIMARY KEY (device_id, user));
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user TEXT NOT NULL, log_id TEXT NOT NULL, rowid_ INTEGER NOT NULL,
  ts TEXT NOT NULL, session TEXT NOT NULL, agent TEXT NOT NULL, kind TEXT NOT NULL,
  source TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL,
  decision TEXT, policy TEXT, rule_id TEXT, reason TEXT, received INTEGER NOT NULL,
  UNIQUE (device_id, user, log_id, rowid_));
CREATE INDEX IF NOT EXISTS events_received ON events(received);
CREATE INDEX IF NOT EXISTS events_device ON events(device_id, received);
CREATE TABLE IF NOT EXISTS policy_versions (
  version INTEGER PRIMARY KEY, yaml TEXT NOT NULL, created INTEGER NOT NULL);
";

pub struct Db {
    pub conn: Connection,
}

#[derive(Debug, Clone, Default)]
pub struct Device {
    pub id: String,
    pub machine_id: String,
    pub hostname: String,
    pub serial: Option<String>,
    pub os_version: String,
    pub agentacl_version: String,
    pub enrolled_at: i64,
    pub last_seen: Option<i64>,
    pub revoked: bool,
    pub report: Option<Report>,
    /// Events not kept because the device went over its daily quota.
    pub dropped: i64,
}

#[derive(Debug, Clone)]
pub struct DeviceUser {
    pub user: String,
    pub uid: u32,
    pub installed: Option<Vec<agentacl_fleet::InstalledAgent>>,
    pub sessions: Vec<agentacl_fleet::SessionInfo>,
    pub error: Option<String>,
    pub updated: i64,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub id: i64,
    pub name: String,
    pub created: i64,
    pub expires: i64,
    pub max_uses: i64,
    pub uses: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub device_id: String,
    pub hostname: String,
    pub user: String,
    pub event: EventInfo,
}

#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub device: Option<String>,
    pub user: Option<String>,
    pub agent: Option<String>,
    pub decision: Option<String>,
    pub limit: usize,
}

/// Why an enrollment was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollError {
    BadToken,
    Blocked,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(SCHEMA)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Db { conn })
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }

    // ---- admin sessions ----

    pub fn add_session(&self, id_hash: &str, csrf: &str, expires: i64) -> Result<()> {
        self.conn.execute("INSERT INTO admin_sessions (id_hash, csrf, expires) VALUES (?1, ?2, ?3)", params![id_hash, csrf, expires])?;
        Ok(())
    }

    /// The CSRF token of a live session.
    pub fn session_csrf(&self, id_hash: &str, now: i64) -> Result<Option<String>> {
        self.conn.execute("DELETE FROM admin_sessions WHERE expires <= ?1", [now])?;
        Ok(self.conn.query_row("SELECT csrf FROM admin_sessions WHERE id_hash = ?1", [id_hash], |r| r.get(0)).optional()?)
    }

    pub fn delete_session(&self, id_hash: &str) -> Result<()> {
        self.conn.execute("DELETE FROM admin_sessions WHERE id_hash = ?1", [id_hash])?;
        Ok(())
    }

    // ---- enrollment ----

    pub fn add_token(&self, name: &str, token_hash: &str, now: i64, expires: i64, max_uses: i64) -> Result<i64> {
        self.conn.execute("INSERT INTO enroll_tokens (name, token_hash, created, expires, max_uses) VALUES (?1, ?2, ?3, ?4, ?5)", params![name, token_hash, now, expires, max_uses])?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn tokens(&self) -> Result<Vec<Token>> {
        let mut st = self.conn.prepare("SELECT id, name, created, expires, max_uses, uses, revoked FROM enroll_tokens ORDER BY id DESC")?;
        let rows =
            st.query_map([], |r| Ok(Token { id: r.get(0)?, name: r.get(1)?, created: r.get(2)?, expires: r.get(3)?, max_uses: r.get(4)?, uses: r.get(5)?, revoked: r.get::<_, i64>(6)? != 0 }))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn revoke_token(&self, id: i64) -> Result<()> {
        if self.conn.execute("UPDATE enroll_tokens SET revoked = 1 WHERE id = ?1", [id])? == 0 {
            anyhow::bail!("no such token");
        }
        Ok(())
    }

    /// Creates a new device for a valid token. Never touches an existing
    /// device: a Mac enrolling again is a second device.
    pub fn enroll(&mut self, token_hash: &str, m: &MachineIdentity, device_id: &str, key_hash: &str, now: i64) -> Result<std::result::Result<(), EnrollError>> {
        let tx = self.conn.transaction()?;
        let token: Option<i64> =
            tx.query_row("SELECT id FROM enroll_tokens WHERE token_hash = ?1 AND revoked = 0 AND expires > ?2 AND uses < max_uses", params![token_hash, now], |r| r.get(0)).optional()?;
        let Some(token) = token else { return Ok(Err(EnrollError::BadToken)) };
        let blocked: bool = tx.query_row("SELECT COUNT(*) FROM blocked_machines WHERE machine_id = ?1", [&m.machine_id], |r| r.get::<_, i64>(0))? > 0;
        if blocked {
            return Ok(Err(EnrollError::Blocked));
        }
        tx.execute("UPDATE enroll_tokens SET uses = uses + 1 WHERE id = ?1", [token])?;
        tx.execute(
            "INSERT INTO devices (id, key_hash, machine_id, hostname, serial, os_version, agentacl_version, token_id, enrolled_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![device_id, key_hash, m.machine_id, m.hostname, m.serial, m.os_version, m.agentacl_version, token, now],
        )?;
        tx.commit()?;
        Ok(Ok(()))
    }

    /// The device a key belongs to, if it isn't revoked.
    pub fn device_for_key(&self, key_hash: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT id FROM devices WHERE key_hash = ?1 AND revoked = 0", [key_hash], |r| r.get(0)).optional()?)
    }

    pub fn revoke_device(&mut self, id: &str, now: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        let machine: Option<String> = tx.query_row("SELECT machine_id FROM devices WHERE id = ?1", [id], |r| r.get(0)).optional()?;
        if machine.is_none() {
            anyhow::bail!("no such machine");
        }
        tx.execute("UPDATE devices SET revoked = 1 WHERE id = ?1", [id])?;
        if let Some(m) = machine {
            tx.execute("INSERT OR IGNORE INTO blocked_machines (machine_id, since) VALUES (?1, ?2)", params![m, now])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn is_blocked(&self, machine_id: &str) -> Result<bool> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM blocked_machines WHERE machine_id = ?1", [machine_id], |r| r.get::<_, i64>(0))? > 0)
    }

    pub fn unblock_machine(&self, machine_id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM blocked_machines WHERE machine_id = ?1", [machine_id])?;
        Ok(())
    }

    // ---- reports ----

    /// Stores a report: the device's latest state, each user's, and new
    /// events (a resent event is ignored). Returns how many events were new.
    pub fn store_report(&mut self, device: &str, r: &Report, now: i64) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let m = &r.machine.identity;
        tx.execute(
            "UPDATE devices SET last_seen = ?2, hostname = ?3, os_version = ?4, agentacl_version = ?5, serial = COALESCE(?6, serial), status_json = ?7, running_json = ?8 WHERE id = ?1",
            params![device, now, m.hostname, m.os_version, m.agentacl_version, m.serial, serde_json::to_string(&r.machine)?, serde_json::to_string(&r.running)?],
        )?;
        let mut new = 0;
        for u in &r.users {
            let installed: Option<String> = match &u.installed {
                Some(i) => Some(serde_json::to_string(i)?),
                None => tx.query_row("SELECT installed_json FROM device_users WHERE device_id = ?1 AND user = ?2", params![device, u.user], |r| r.get(0)).optional()?.flatten(),
            };
            tx.execute(
                "INSERT INTO device_users (device_id, user, uid, installed_json, sessions_json, error, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(device_id, user) DO UPDATE SET uid = excluded.uid, installed_json = excluded.installed_json, sessions_json = excluded.sessions_json, error = excluded.error, updated = excluded.updated",
                params![device, u.user, u.uid, installed, serde_json::to_string(&u.sessions)?, u.error, now],
            )?;
            let Some(log) = &u.log_id else { continue };
            let mut ins = tx.prepare_cached(
                "INSERT OR IGNORE INTO events (device_id, user, log_id, rowid_, ts, session, agent, kind, source, action, resource, decision, policy, rule_id, reason, received)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )?;
            for e in u.events.iter().take(agentacl_fleet::MAX_EVENTS) {
                new += ins.execute(params![device, u.user, log, e.rowid, e.ts, e.session, e.agent, e.kind, e.source, e.action, e.resource, e.decision, e.policy, e.rule_id, e.reason, now])?;
            }
        }
        tx.commit()?;
        Ok(new)
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        let mut st = self.conn.prepare(
            "SELECT id, machine_id, hostname, serial, os_version, agentacl_version, enrolled_at, last_seen, revoked, status_json, running_json, dropped FROM devices ORDER BY hostname COLLATE NOCASE, id",
        )?;
        let rows = st.query_map([], row_device)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn device(&self, id: &str) -> Result<Option<Device>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, machine_id, hostname, serial, os_version, agentacl_version, enrolled_at, last_seen, revoked, status_json, running_json, dropped FROM devices WHERE id = ?1",
                [id],
                row_device,
            )
            .optional()?)
    }

    pub fn device_users(&self, id: &str) -> Result<Vec<DeviceUser>> {
        let mut st = self.conn.prepare("SELECT user, uid, installed_json, sessions_json, error, updated FROM device_users WHERE device_id = ?1 ORDER BY user")?;
        let rows = st.query_map([id], |r| {
            let installed: Option<String> = r.get(2)?;
            let sessions: String = r.get(3)?;
            Ok(DeviceUser {
                user: r.get(0)?,
                uid: r.get(1)?,
                installed: installed.and_then(|s| serde_json::from_str(&s).ok()),
                sessions: serde_json::from_str(&sessions).unwrap_or_default(),
                error: r.get(4)?,
                updated: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Refusals since `since`, per device.
    pub fn denials_since(&self, since: i64) -> Result<std::collections::HashMap<String, i64>> {
        let mut st = self.conn.prepare("SELECT device_id, COUNT(*) FROM events WHERE received >= ?1 AND decision = 'deny' GROUP BY device_id")?;
        let rows = st.query_map([since], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn events(&self, f: &EventFilter) -> Result<Vec<StoredEvent>> {
        let mut sql = String::from(
            "SELECT e.device_id, d.hostname, e.user, e.rowid_, e.ts, e.session, e.agent, e.kind, e.source, e.action, e.resource, e.decision, e.policy, e.rule_id, e.reason
             FROM events e JOIN devices d ON d.id = e.device_id WHERE 1=1",
        );
        let mut args: Vec<String> = vec![];
        for (col, v) in [("e.device_id", &f.device), ("e.user", &f.user), ("e.agent", &f.agent), ("e.decision", &f.decision)] {
            if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
                args.push(v.clone());
                sql.push_str(&format!(" AND {col} = ?{}", args.len()));
            }
        }
        sql.push_str(&format!(" ORDER BY e.id DESC LIMIT {}", f.limit.clamp(1, 1000)));
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(StoredEvent {
                device_id: r.get(0)?,
                hostname: r.get(1)?,
                user: r.get(2)?,
                event: EventInfo {
                    rowid: r.get(3)?,
                    ts: r.get(4)?,
                    session: r.get(5)?,
                    agent: r.get(6)?,
                    kind: r.get(7)?,
                    source: r.get(8)?,
                    action: r.get(9)?,
                    resource: r.get(10)?,
                    decision: r.get(11)?,
                    policy: r.get(12)?,
                    rule_id: r.get(13)?,
                    reason: r.get(14)?,
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_dropped(&self, device: &str, n: u64) -> Result<()> {
        self.conn.execute("UPDATE devices SET dropped = dropped + ?2 WHERE id = ?1", params![device, n as i64])?;
        Ok(())
    }

    pub fn prune_events(&self, before: i64) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM events WHERE received < ?1", [before])?)
    }

    // ---- company policy ----

    pub fn policy(&self) -> Result<PolicyResponse> {
        Ok(self
            .conn
            .query_row("SELECT version, yaml FROM policy_versions ORDER BY version DESC LIMIT 1", [], |r| Ok(PolicyResponse { version: r.get::<_, i64>(0)? as u64, yaml: r.get(1)? }))
            .optional()?
            .unwrap_or_default())
    }

    pub fn policy_history(&self) -> Result<Vec<(u64, i64)>> {
        let mut st = self.conn.prepare("SELECT version, created FROM policy_versions ORDER BY version DESC LIMIT 20")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Saves a (validated) company policy as the next version.
    pub fn save_policy(&self, yaml: &str, now: i64) -> Result<u64> {
        let next = self.policy()?.version + 1;
        self.conn.execute("INSERT INTO policy_versions (version, yaml, created) VALUES (?1, ?2, ?3)", params![next as i64, yaml, now])?;
        Ok(next)
    }
}

fn row_device(r: &rusqlite::Row) -> rusqlite::Result<Device> {
    let status: Option<String> = r.get(9)?;
    let running: Option<String> = r.get(10)?;
    let report = status.and_then(|s| serde_json::from_str(&s).ok()).map(|machine| Report { machine, running: running.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(), users: vec![] });
    Ok(Device {
        id: r.get(0)?,
        machine_id: r.get(1)?,
        hostname: r.get(2)?,
        serial: r.get(3)?,
        os_version: r.get(4)?,
        agentacl_version: r.get(5)?,
        enrolled_at: r.get(6)?,
        last_seen: r.get(7)?,
        revoked: r.get::<_, i64>(8)? != 0,
        report,
        dropped: r.get(11)?,
    })
}
