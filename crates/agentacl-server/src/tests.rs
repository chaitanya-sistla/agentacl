//! The server's flows, without a network: device API and console.

use super::*;
use crate::auth::{hash_password, sha256_hex};
use agentacl_fleet::{EnrollResponse, EventInfo, MachineIdentity, PolicyResponse, Report, ReportResponse, RunningAgent, UserReport};
use std::collections::HashMap;

const PASSWORD: &str = "a long admin password";

fn app() -> (tempfile::TempDir, App) {
    let t = tempfile::tempdir().unwrap();
    let d = db::Db::open(&t.path().join("s.db")).unwrap();
    d.set_meta("admin_password", &hash_password(PASSWORD)).unwrap();
    let config = Config { public_url: "https://fleet.test".into(), trusted_proxies: vec!["127.0.0.1".into()], insecure_cookies: false, retention_days: 90 };
    (t, App { db: Mutex::new(d), throttle: Mutex::default(), rates: Mutex::default(), password_check: Mutex::default(), config })
}

fn token(app: &App, max: i64) -> String {
    let t = format!("aet_{}", auth::random_hex());
    let now = auth::now();
    app.db.lock().unwrap().add_token("test", &sha256_hex(&t), now, now + 86_400, max).unwrap();
    t
}

fn machine(id: &str, host: &str) -> MachineIdentity {
    MachineIdentity { machine_id: id.into(), hostname: host.into(), serial: None, os_version: "26.6".into(), agentacl_version: "0.6.0".into() }
}

fn enroll(app: &App, token: &str, m: &MachineIdentity) -> (u16, serde_json::Value) {
    api::handle(app, "POST", agentacl_fleet::ENROLL, None, serde_json::json!({ "token": token, "machine": m }).to_string().as_bytes(), "198.51.100.1")
}

fn report(app: &App, key: &str, r: &Report) -> (u16, serde_json::Value) {
    api::handle(app, "POST", agentacl_fleet::REPORT, Some(&format!("Bearer {key}")), serde_json::to_string(r).unwrap().as_bytes(), "198.51.100.1")
}

fn event(rowid: i64, resource: &str) -> EventInfo {
    EventInfo {
        rowid,
        ts: "2026-10-09T10:00:00Z".into(),
        session: "agt_1".into(),
        agent: "claude-code".into(),
        kind: "enforced".into(),
        source: "sandbox".into(),
        action: "filesystem.read".into(),
        resource: resource.into(),
        decision: Some("deny".into()),
        ..Default::default()
    }
}

#[test]
fn enrollment_reports_and_policy() {
    let (_t, app) = app();
    let tok = token(&app, 2);
    let m = machine("mid-1", "alice-mbp");
    assert_eq!(enroll(&app, "aet_wrong", &m).0, 403);
    let (s, v) = enroll(&app, &tok, &m);
    assert_eq!(s, 200, "{v}");
    let e: EnrollResponse = serde_json::from_value(v).unwrap();
    assert!(e.device_id.starts_with("dev_") && e.device_key.len() == 64);
    assert_eq!(e.policy, PolicyResponse::default(), "no company policy yet");
    // Only the hash is stored.
    let stored: String = app.db.lock().unwrap().conn.query_row("SELECT key_hash FROM devices", [], |r| r.get(0)).unwrap();
    assert_eq!(stored, sha256_hex(&e.device_key));

    // A report: users, running agents, events; a resent event isn't stored twice.
    let mut r = Report::default();
    r.machine.identity = m.clone();
    r.running.push(RunningAgent { pid: 7, user: "alice".into(), agent: "claude-code".into(), agent_name: "Claude Code".into(), exe: "/x/claude".into(), supervisor: None });
    r.users.push(UserReport { user: "alice".into(), uid: 501, log_id: Some("log1".into()), events: vec![event(1, "/Users/alice/.aws/credentials"), event(2, "/x")], ..Default::default() });
    let (s, v) = report(&app, &e.device_key, &r);
    assert_eq!(s, 200, "{v}");
    let rr: ReportResponse = serde_json::from_value(v).unwrap();
    assert_eq!((rr.policy_version, rr.dropped), (0, 0));
    report(&app, &e.device_key, &r);
    let n: i64 = app.db.lock().unwrap().conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 2);
    assert_eq!(report(&app, "nope", &r).0, 401);

    // Company policy: only explicit denies; the Mac gets it.
    let v = app.db.lock().unwrap().save_policy("version: v1\nfilesystem:\n  deny_read: [\"${HOME}/x/**\"]\n", 1).unwrap();
    let (s, p) = api::handle(&app, "GET", agentacl_fleet::POLICY, Some(&format!("Bearer {}", e.device_key)), b"", "198.51.100.1");
    assert_eq!((s, p["version"].as_u64()), (200, Some(v)));
    assert_eq!(api::handle(&app, "GET", agentacl_fleet::POLICY, None, b"", "198.51.100.1").0, 401);
}

#[test]
fn enrolling_again_never_takes_over_a_device_and_revocation_sticks() {
    let (_t, app) = app();
    let tok = token(&app, 10);
    let m = machine("mid-1", "alice-mbp");
    let first: EnrollResponse = serde_json::from_value(enroll(&app, &tok, &m).1).unwrap();
    let second: EnrollResponse = serde_json::from_value(enroll(&app, &tok, &m).1).unwrap();
    assert_ne!(first.device_id, second.device_id, "a second device");
    let mut r = Report::default();
    r.machine.identity = m.clone();
    assert_eq!(report(&app, &first.device_key, &r).0, 200, "the first key still works");
    app.db.lock().unwrap().revoke_device(&first.device_id, 1).unwrap();
    assert_eq!(report(&app, &first.device_key, &r).0, 401);
    assert_eq!(enroll(&app, &tok, &m).0, 403, "the machine id is blocked");
    app.db.lock().unwrap().unblock_machine("mid-1").unwrap();
    assert_eq!(enroll(&app, &tok, &m).0, 200);
    // A used-up token.
    let one = token(&app, 1);
    assert_eq!(enroll(&app, &one, &machine("mid-2", "b")).0, 200);
    assert_eq!(enroll(&app, &one, &machine("mid-3", "c")).0, 403);
}

#[test]
fn rate_limits() {
    let (_t, app) = app();
    let tok = token(&app, 100);
    for i in 0..12 {
        assert_eq!(enroll(&app, &tok, &machine(&format!("m{i}"), "h")).0, 200, "valid enrollments aren't limited");
    }
    let junk: Vec<u16> = (0..11).map(|_| enroll(&app, "aet_junk", &machine("j", "h")).0).collect();
    assert_eq!(junk[9], 403);
    assert_eq!(junk[10], 429, "the 11th failure in a minute, from this client");
    let other = api::handle(&app, "POST", agentacl_fleet::ENROLL, None, serde_json::json!({ "token": tok, "machine": machine("k", "h") }).to_string().as_bytes(), "203.0.113.50");
    assert_eq!(other.0, 200, "another client isn't held up");
    app.rates.lock().unwrap().clear();
    let e: EnrollResponse = serde_json::from_value(enroll(&app, &tok, &machine("mx", "h")).1).unwrap();
    let r = Report::default();
    let codes: Vec<u16> = (0..13).map(|_| report(&app, &e.device_key, &r).0).collect();
    assert_eq!(codes.iter().filter(|c| **c == 200).count(), 12);
    assert_eq!(codes[12], 429);
}

fn req<'a>(method: &'a str, path: &'a str, form: &[(&str, &str)], cookie: Option<&str>) -> web::Req<'a> {
    web::Req { method, path, query: HashMap::new(), form: form.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), cookie: cookie.map(str::to_string), client: "203.0.113.9".into() }
}

/// Signs in; returns the session cookie value and the CSRF token.
fn sign_in(app: &App) -> (String, String) {
    let r = web::handle(app, &req("POST", "/login", &[("password", PASSWORD)], None));
    assert_eq!(r.status, 303);
    let set = &r.headers.iter().find(|(k, _)| k == "Set-Cookie").unwrap().1;
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict") && set.contains("Secure"), "{set}");
    let id = set.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
    let csrf = app.db.lock().unwrap().session_csrf(&sha256_hex(&id), auth::now()).unwrap().unwrap();
    (id, csrf)
}

#[test]
fn console_access_csrf_and_escaping() {
    let (_t, app) = app();
    assert_eq!(web::handle(&app, &req("GET", "/", &[], None)).status, 303, "signed out: to the login page");
    assert_eq!(web::handle(&app, &req("POST", "/login", &[("password", "wrong")], None)).status, 401);
    assert_eq!(web::handle(&app, &req("POST", "/login", &[("password", PASSWORD)], None)).status, 429, "slowed after a failure");
    app.throttle.lock().unwrap().succeeded("203.0.113.9");
    let (id, csrf) = sign_in(&app);

    // A hostile Mac: everything it sends is escaped.
    let tok = token(&app, 5);
    let evil = machine("mid-x", "<script>alert(1)</script>");
    let e: EnrollResponse = serde_json::from_value(enroll(&app, &tok, &evil).1).unwrap();
    let mut r = Report::default();
    r.machine.identity = evil;
    r.users.push(UserReport { user: "<img src=x onerror=alert(2)>".into(), uid: 501, log_id: Some("l".into()), events: vec![event(1, "\"><script>x</script>")], ..Default::default() });
    report(&app, &e.device_key, &r);
    for path in ["/", &format!("/machines/{}", e.device_id), "/events"] {
        let page = web::handle(&app, &req("GET", path, &[], Some(&id))).body;
        assert!(!page.contains("<script>") && !page.contains("<img"), "{path}: {page}");
        assert!(page.contains("&lt;script&gt;"), "{path}");
    }

    // POSTs need the CSRF token, and publishing needs the password again.
    let bad = req("POST", "/policy", &[("yaml", "version: v1\n"), ("password", PASSWORD)], Some(&id));
    assert_eq!(web::handle(&app, &bad).status, 403);
    let no_pw = web::handle(&app, &req("POST", "/policy", &[("csrf", &csrf), ("yaml", "version: v1\n"), ("password", "x")], Some(&id)));
    assert!(no_pw.body.contains("Wrong admin password"));
    // A wrong password counts like a failed sign-in (slowed); wait it out.
    app.throttle.lock().unwrap().succeeded("203.0.113.9");
    let allow = web::handle(&app, &req("POST", "/policy", &[("csrf", &csrf), ("yaml", "version: v1\nnetwork:\n  allow: [\"x.com\"]\n"), ("password", PASSWORD)], Some(&id)));
    assert!(allow.body.contains("Not published") && allow.body.contains("network.allow"), "company rules only forbid");
    let ok = web::handle(&app, &req("POST", "/policy", &[("csrf", &csrf), ("yaml", "version: v1\nprocess:\n  deny: [\"git push *\"]\n"), ("password", PASSWORD)], Some(&id)));
    assert!(ok.body.contains("Published as version 1") && ok.body.contains("only logged"), "{}", ok.body);

    // A token is shown once; logout ends the session.
    let t = web::handle(&app, &req("POST", "/tokens", &[("csrf", &csrf), ("name", "Eng"), ("days", "30"), ("max", "5"), ("password", PASSWORD)], Some(&id)));
    assert!(t.body.contains("aet_") && t.body.contains("sudo agentacl fleet enroll --server https://fleet.test"));
    assert!(!web::handle(&app, &req("GET", "/tokens", &[], Some(&id))).body.contains("aet_"));
    web::handle(&app, &req("POST", "/logout", &[("csrf", &csrf)], Some(&id)));
    assert_eq!(web::handle(&app, &req("GET", "/", &[], Some(&id))).status, 303);
}

#[test]
fn client_address_comes_from_the_proxy_only_when_trusted() {
    let c = Config { public_url: String::new(), trusted_proxies: vec!["127.0.0.1".into()], insecure_cookies: false, retention_days: 1 };
    let proxy = Some("127.0.0.1:5000".parse().unwrap());
    let direct = Some("198.51.100.7:5000".parse().unwrap());
    assert_eq!(client(&c, proxy, Some("1.1.1.1, 203.0.113.9")), "203.0.113.9");
    assert_eq!(client(&c, direct, Some("203.0.113.9")), "198.51.100.7", "spoofed header ignored");
}
