//! The device API (docs/design/fleet.md): enroll, report, policy.

use crate::auth::{now, random_hex, sha256_hex};
use crate::db::EnrollError;
use crate::App;
use agentacl_fleet::{EnrollRequest, EnrollResponse, Report, ReportResponse};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Failed enrollments allowed per client per minute (a valid token is never
/// held up by someone else's junk).
const ENROLL_FAILURES_PER_MINUTE: usize = 10;
/// Report requests per device per minute (a cycle sends up to 10).
const REPORTS_PER_MINUTE: usize = 12;
/// Events stored per device, and per user of a device, per day; more are
/// dropped (and counted), so one user can't use up the others' share.
const EVENTS_PER_DAY: i64 = 50_000;
const EVENTS_PER_USER_DAY: i64 = 20_000;
/// Caps on one report's lists.
const MAX_USERS: usize = 100;
const MAX_SESSIONS: usize = 500;
const MAX_RUNNING: usize = 500;

#[derive(Default)]
pub struct Rates {
    enroll_failures: std::collections::HashMap<String, Vec<Instant>>,
    reports: std::collections::HashMap<String, Vec<Instant>>,
}

impl Rates {
    #[cfg(test)]
    pub fn clear(&mut self) {
        *self = Rates::default();
    }
}

pub type Reply = (u16, Value);

fn err(status: u16, msg: &str) -> Reply {
    (status, json!({ "error": msg }))
}

/// Whether a request carries a working device key (checked before its body
/// is read).
pub fn known_device(app: &App, auth: Option<&str>) -> bool {
    device(app, auth).is_ok()
}

/// The device a request's `Authorization: Bearer <key>` belongs to.
fn device(app: &App, auth: Option<&str>) -> Result<String, Reply> {
    let key = auth.and_then(|a| a.strip_prefix("Bearer ")).map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| err(401, "missing device key"))?;
    let db = app.db.lock().unwrap_or_else(|p| p.into_inner());
    match db.device_for_key(&sha256_hex(key)) {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(err(401, "unknown or revoked device")),
        Err(e) => Err(err(500, &e.to_string())),
    }
}

pub fn handle(app: &App, method: &str, path: &str, auth: Option<&str>, body: &[u8], client: &str) -> Reply {
    match (method, path) {
        ("POST", agentacl_fleet::ENROLL) => {
            {
                let mut r = app.rates.lock().unwrap_or_else(|p| p.into_inner());
                let f = r.enroll_failures.entry(client.to_string()).or_default();
                f.retain(|t| t.elapsed() < Duration::from_secs(60));
                if f.len() >= ENROLL_FAILURES_PER_MINUTE {
                    return err(429, "too many failed enrollments; try again in a minute");
                }
            }
            let reply = enroll(app, body);
            if reply.0 != 200 {
                let mut r = app.rates.lock().unwrap_or_else(|p| p.into_inner());
                r.enroll_failures.retain(|_, v| v.iter().any(|t| t.elapsed() < Duration::from_secs(60)));
                r.enroll_failures.entry(client.to_string()).or_default().push(Instant::now());
            }
            reply
        }
        ("POST", agentacl_fleet::REPORT) => report(app, auth, body),
        ("GET", agentacl_fleet::POLICY) => match device(app, auth) {
            Ok(_) => match app.db.lock().unwrap_or_else(|p| p.into_inner()).policy() {
                Ok(p) => (200, serde_json::to_value(p).unwrap_or_default()),
                Err(e) => err(500, &e.to_string()),
            },
            Err(r) => r,
        },
        _ => err(404, "not found"),
    }
}

fn enroll(app: &App, body: &[u8]) -> Reply {
    let Ok(req) = serde_json::from_slice::<EnrollRequest>(body) else { return err(400, "bad enrollment request") };
    let m = &req.machine;
    if [&m.machine_id, &m.hostname, &m.os_version, &m.agentacl_version].iter().any(|v| v.is_empty() || v.len() > 256) || m.serial.as_ref().is_some_and(|s| s.len() > 256) {
        return err(400, "bad machine identity");
    }
    let device_id = format!("dev_{}", &random_hex()[..20]);
    let key = random_hex();
    let mut db = app.db.lock().unwrap_or_else(|p| p.into_inner());
    match db.enroll(&sha256_hex(req.token.trim()), m, &device_id, &sha256_hex(&key), now()) {
        Ok(Ok(())) => match db.policy() {
            Ok(policy) => (200, serde_json::to_value(EnrollResponse { device_id, device_key: key, policy }).unwrap_or_default()),
            Err(e) => err(500, &e.to_string()),
        },
        Ok(Err(EnrollError::BadToken)) => err(403, "the enrollment token is unknown, expired, revoked or used up"),
        Ok(Err(EnrollError::Blocked)) => err(403, "this machine was revoked; an administrator must allow it to enroll again"),
        Err(e) => err(500, &e.to_string()),
    }
}

/// A device decides what it sends: every string is cut to a sane length.
fn cap_strings(r: &mut Report) {
    fn cap(s: &mut String, n: usize) {
        if let Some((i, _)) = s.char_indices().nth(n) {
            s.truncate(i);
        }
    }
    fn cap_opt(s: &mut Option<String>, n: usize) {
        if let Some(s) = s {
            cap(s, n);
        }
    }
    let id = &mut r.machine.identity;
    for s in [&mut id.machine_id, &mut id.hostname, &mut id.os_version, &mut id.agentacl_version] {
        cap(s, 256);
    }
    cap_opt(&mut id.serial, 256);
    cap_opt(&mut r.machine.policy_error, 2048);
    for a in &mut r.running {
        for s in [&mut a.user, &mut a.agent, &mut a.agent_name] {
            cap(s, 256);
        }
        cap(&mut a.exe, 1024);
        cap_opt(&mut a.supervisor, 1024);
    }
    for u in &mut r.users {
        cap(&mut u.user, 256);
        cap_opt(&mut u.log_id, 64);
        cap_opt(&mut u.error, 2048);
        if let Some(inst) = &mut u.installed {
            inst.truncate(100);
            for i in inst {
                for s in [&mut i.agent, &mut i.agent_name] {
                    cap(s, 256);
                }
                cap(&mut i.path, 1024);
                cap_opt(&mut i.version, 64);
            }
        }
        for s in &mut u.sessions {
            for f in [&mut s.session_id, &mut s.agent, &mut s.backend, &mut s.started_at] {
                cap(f, 256);
            }
            cap(&mut s.project, 1024);
            cap_opt(&mut s.ended_at, 64);
            cap_opt(&mut s.agentacl_version, 64);
        }
        for e in &mut u.events {
            for f in [&mut e.ts, &mut e.session, &mut e.agent, &mut e.kind, &mut e.source, &mut e.action] {
                cap(f, 256);
            }
            cap(&mut e.resource, 4096);
            for f in [&mut e.decision, &mut e.policy, &mut e.rule_id] {
                cap_opt(f, 256);
            }
            cap_opt(&mut e.reason, 1024);
        }
    }
}

fn report(app: &App, auth: Option<&str>, body: &[u8]) -> Reply {
    let id = match device(app, auth) {
        Ok(id) => id,
        Err(r) => return r,
    };
    {
        let mut r = app.rates.lock().unwrap_or_else(|p| p.into_inner());
        let times = r.reports.entry(id.clone()).or_default();
        times.retain(|t| t.elapsed() < Duration::from_secs(60));
        if times.len() >= REPORTS_PER_MINUTE {
            return err(429, "reporting too often");
        }
        times.push(Instant::now());
    }
    let Ok(mut rep) = serde_json::from_slice::<Report>(body) else { return err(400, "bad report") };
    rep.users.truncate(MAX_USERS);
    rep.running.truncate(MAX_RUNNING);
    cap_strings(&mut rep);
    let now = now();
    let mut db = app.db.lock().unwrap_or_else(|p| p.into_inner());
    let today: i64 = db.conn.query_row("SELECT COUNT(*) FROM events WHERE device_id = ?1 AND received >= ?2", rusqlite::params![id, now - 86_400], |r| r.get(0)).unwrap_or(0);
    let mut room = (EVENTS_PER_DAY - today).max(0) as usize;
    let mut dropped = 0;
    for u in &mut rep.users {
        u.sessions.truncate(MAX_SESSIONS);
        u.events.truncate(agentacl_fleet::MAX_EVENTS);
        let user_today: i64 =
            db.conn.query_row("SELECT COUNT(*) FROM events WHERE device_id = ?1 AND user = ?2 AND received >= ?3", rusqlite::params![id, u.user, now - 86_400], |r| r.get(0)).unwrap_or(0);
        let user_room = (EVENTS_PER_USER_DAY - user_today).max(0) as usize;
        let keep = u.events.len().min(room).min(user_room);
        dropped += u.events.len() - keep;
        u.events.truncate(keep);
        room -= keep;
    }
    if let Err(e) = db.store_report(&id, &rep, now) {
        return err(500, &e.to_string());
    }
    if dropped > 0 {
        let _ = db.add_dropped(&id, dropped as u64);
    }
    let policy_version = db.policy().map(|p| p.version).unwrap_or(0);
    (200, serde_json::to_value(ReportResponse { policy_version, dropped: dropped as u64 }).unwrap_or_default())
}
