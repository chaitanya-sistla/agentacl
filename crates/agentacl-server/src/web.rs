//! The admin console: server-rendered pages, no scripts. Every value that
//! came from a Mac is escaped with [`esc`].

use crate::auth::{constant_eq, now, random_hex, sha256_hex, verify_password, SESSION_SECS};
use crate::db::{Device, EventFilter};
use crate::html::{ago, csrf_field, enc, esc, page, time};
use crate::App;
use std::collections::HashMap;

pub const COOKIE: &str = "aacl_session";
/// A Mac that hasn't reported for this long is flagged.
const STALE_SECS: i64 = 15 * 60;

pub struct Req<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: HashMap<String, String>,
    pub form: HashMap<String, String>,
    pub cookie: Option<String>,
    pub client: String,
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

fn html(status: u16, body: String) -> Resp {
    Resp { status, content_type: "text/html; charset=utf-8", body, headers: vec![] }
}

fn redirect(to: &str) -> Resp {
    Resp { status: 303, content_type: "text/plain", body: String::new(), headers: vec![("Location".into(), to.into())] }
}

fn cookie(app: &App, value: &str, max_age: i64) -> (String, String) {
    let secure = if app.config.insecure_cookies { "" } else { "; Secure" };
    ("Set-Cookie".into(), format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"))
}

fn notice(kind: &str, text: &str) -> String {
    format!("<p class=\"notice {kind}\">{}</p>", esc(text))
}

pub fn handle(app: &App, r: &Req) -> Resp {
    match (r.method, r.path) {
        ("GET", "/static/app.css") => Resp { status: 200, content_type: "text/css", body: include_str!("../static/app.css").into(), headers: vec![] },
        ("GET", "/login") => html(200, login_page(None)),
        ("POST", "/login") => login(app, r),
        _ => {
            let Some(csrf) = session(app, r) else { return redirect("/login") };
            if r.method == "POST" && !r.form.get("csrf").is_some_and(|c| constant_eq(c.as_bytes(), csrf.as_bytes())) {
                return html(403, page("Refused", "", Some(&csrf), &notice("bad", "This form expired. Go back, reload the page and try again.")));
            }
            routes(app, r, &csrf)
        }
    }
}

/// The CSRF token of the request's live admin session.
fn session(app: &App, r: &Req) -> Option<String> {
    let id = r.cookie.as_deref()?;
    app.db.lock().unwrap_or_else(|p| p.into_inner()).session_csrf(&sha256_hex(id), now()).ok().flatten()
}

fn login_page(msg: Option<&str>) -> String {
    let m = msg.map(|t| notice("bad", t)).unwrap_or_default();
    page(
        "Sign in",
        "",
        None,
        &format!("<section class=\"narrow\"><h1>Sign in</h1>{m}<form method=\"post\" action=\"/login\"><label>Admin password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus required></label><button>Sign in</button></form></section>"),
    )
}

fn login(app: &App, r: &Req) -> Resp {
    if let Some(wait) = app.throttle.lock().unwrap_or_else(|p| p.into_inner()).blocked(&r.client) {
        return html(429, login_page(Some(&format!("Too many attempts. Try again in {} s.", wait.as_secs().max(1)))));
    }
    let ok = check_password(app, r);
    let mut t = app.throttle.lock().unwrap_or_else(|p| p.into_inner());
    if !ok {
        t.failed(&r.client);
        return html(401, login_page(Some("Wrong password.")));
    }
    t.succeeded(&r.client);
    drop(t);
    // A new session id at every login.
    let id = random_hex();
    if app.db.lock().unwrap_or_else(|p| p.into_inner()).add_session(&sha256_hex(&id), &random_hex(), now() + SESSION_SECS).is_err() {
        return html(500, login_page(Some("Couldn't start a session.")));
    }
    let mut resp = redirect("/");
    resp.headers.push(cookie(app, &id, SESSION_SECS));
    resp
}

/// Checks the form's password, one check at a time (each costs 600,000
/// hash iterations; parallel guesses mustn't multiply that).
fn check_password(app: &App, r: &Req) -> bool {
    let _one = app.password_check.lock().unwrap_or_else(|p| p.into_inner());
    let stored = app.db.lock().unwrap_or_else(|p| p.into_inner()).meta("admin_password").ok().flatten();
    stored.is_some_and(|h| verify_password(r.form.get("password").map(String::as_str).unwrap_or(""), &h))
}

/// The admin password again, for the actions that change every Mac;
/// throttled like signing in.
fn reauth(app: &App, r: &Req) -> bool {
    if app.throttle.lock().unwrap_or_else(|p| p.into_inner()).blocked(&r.client).is_some() {
        return false;
    }
    let ok = check_password(app, r);
    let mut t = app.throttle.lock().unwrap_or_else(|p| p.into_inner());
    if ok {
        t.succeeded(&r.client);
    } else {
        t.failed(&r.client);
    }
    ok
}

fn routes(app: &App, r: &Req, csrf: &str) -> Resp {
    let segs: Vec<&str> = r.path.trim_matches('/').split('/').collect();
    match (r.method, segs.as_slice()) {
        ("POST", ["logout"]) => {
            if let Some(id) = &r.cookie {
                let _ = app.db.lock().unwrap_or_else(|p| p.into_inner()).delete_session(&sha256_hex(id));
            }
            let mut resp = redirect("/login");
            resp.headers.push(cookie(app, "", 0));
            resp
        }
        ("GET", [""]) => machines(app, csrf),
        ("GET", ["machines", id]) => machine(app, csrf, id, None),
        ("POST", ["machines", id, "revoke"]) => {
            let r2 = app.db.lock().unwrap_or_else(|p| p.into_inner()).revoke_device(id, now());
            machine(app, csrf, id, Some(r2.map(|_| "Revoked. This Mac's key no longer works; it keeps its last company rules.".into()).map_err(|e| e.to_string())))
        }
        ("POST", ["machines", id, "unblock"]) => {
            let db = app.db.lock().unwrap_or_else(|p| p.into_inner());
            let res = db.device(id).map_err(|e| e.to_string()).and_then(|d| d.ok_or_else(|| "unknown machine".to_string())).and_then(|d| db.unblock_machine(&d.machine_id).map_err(|e| e.to_string()));
            drop(db);
            machine(app, csrf, id, Some(res.map(|_| "This machine may enroll again (as a new device).".into())))
        }
        ("GET", ["events"]) => events(app, r, csrf),
        ("GET", ["policy"]) => policy(app, csrf, None, None),
        ("POST", ["policy"]) => save_policy(app, r, csrf),
        ("GET", ["tokens"]) => tokens(app, csrf, None),
        ("POST", ["tokens"]) => create_token(app, r, csrf),
        ("POST", ["tokens", id, "revoke"]) => {
            let res = id.parse::<i64>().map_err(|e| e.to_string()).and_then(|id| app.db.lock().unwrap_or_else(|p| p.into_inner()).revoke_token(id).map_err(|e| e.to_string()));
            tokens(
                app,
                csrf,
                Some(match res {
                    Ok(()) => notice("good", "Token revoked."),
                    Err(e) => notice("bad", &e),
                }),
            )
        }
        _ => html(404, page("Not found", "", Some(csrf), &notice("bad", "Not found."))),
    }
}

fn enforcement(d: &Device) -> String {
    match d.report.as_ref().map(|r| &r.machine.enforcement) {
        Some(e) if e.es_daemon || e.es_extension => format!("<span class=\"ok\">Endpoint Security</span> <span class=\"muted\">({})</span>", esc(e.es_user.as_deref().unwrap_or("one user"))),
        Some(_) => "<span class=\"warn\">AgentACL sessions only</span>".into(),
        None => "<span class=\"muted\">not reported yet</span>".into(),
    }
}

/// Things an admin should look at, per Mac.
fn warnings(d: &Device, all: &[Device], users: &[crate::db::DeviceUser], current_policy: u64, now: i64) -> Vec<String> {
    let mut w = vec![];
    if d.revoked {
        w.push("revoked".into());
    }
    if let Some(other) = all.iter().find(|o| o.id != d.id && o.machine_id == d.machine_id) {
        w.push(format!("same machine id as {}", other.hostname));
    }
    match d.last_seen {
        Some(t) if now - t > STALE_SECS && !d.revoked => w.push(format!("not reporting ({})", ago(t, now))),
        None if !d.revoked => w.push("never reported".into()),
        _ => {}
    }
    if let Some(r) = &d.report {
        if let Some(e) = &r.machine.policy_error {
            w.push(format!("company policy not applied: {e}"));
        } else if r.machine.policy_version.unwrap_or(0) < current_policy {
            w.push(format!("company policy v{} (current v{current_policy})", r.machine.policy_version.unwrap_or(0)));
        }
        let e = &r.machine.enforcement;
        let es_covers = |user: &str| (e.es_daemon || e.es_extension) && e.es_user.as_deref() == Some(user);
        // Under AgentACL: the packaged copy supervises it, or Endpoint
        // Security covers its user. Another `agentacl` doesn't count.
        let outside = r.running.iter().filter(|a| a.supervisor.as_deref() != Some(agentacl_fleet::MANAGED_AGENTACL) && !es_covers(&a.user)).count();
        if outside > 0 {
            w.push(format!("{outside} agent(s) running outside AgentACL"));
        }
    }
    if d.dropped > 0 {
        w.push(format!("{} event(s) over the daily quota weren't kept", d.dropped));
    }
    let without = users.iter().flat_map(|u| &u.sessions).filter(|s| s.ended_at.is_none() && !s.company_rules).count();
    if without > 0 {
        w.push(format!("{without} session(s) without the company rules"));
    }
    w
}

fn machines(app: &App, csrf: &str) -> Resp {
    let db = app.db.lock().unwrap_or_else(|p| p.into_inner());
    let (devices, denials, current) = match (db.devices(), db.denials_since(now() - 86_400), db.policy()) {
        (Ok(d), Ok(x), Ok(p)) => (d, x, p.version),
        _ => return html(500, page("Machines", "Machines", Some(csrf), &notice("bad", "Couldn't read the database."))),
    };
    let now = now();
    let mut rows = String::new();
    for d in &devices {
        let users = db.device_users(&d.id).unwrap_or_default();
        let running = d.report.as_ref().map(|r| r.running.len()).unwrap_or(0);
        let w = warnings(d, &devices, &users, current, now);
        rows.push_str(&format!(
            "<tr><td><a href=\"/machines/{}\">{}</a><div class=\"muted\">{}</div></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            enc(&d.id),
            esc(&d.hostname),
            esc(&d.os_version),
            esc(&users.iter().map(|u| u.user.as_str()).collect::<Vec<_>>().join(", ")),
            running,
            enforcement(d),
            denials.get(&d.id).copied().unwrap_or(0),
            esc(&d.agentacl_version),
            d.last_seen.map(|t| esc(&ago(t, now))).unwrap_or_else(|| "never".into()),
            if w.is_empty() { "<span class=\"ok\">OK</span>".into() } else { format!("<span class=\"warn\">{}</span>", esc(&w.join("; "))) },
        ));
    }
    let body = if devices.is_empty() {
        "<h1>Machines</h1><p>No Mac has enrolled yet. Create an enrollment token under <a href=\"/tokens\">Enrollment</a>.</p>".to_string()
    } else {
        format!("<h1>Machines</h1><p class=\"muted\">Users, sessions and refusals are reported by each Mac's users' AgentACL; running agents and enforcement by its root service.</p><div class=\"scroll\"><table><thead><tr><th>Mac</th><th>Users</th><th>Agents running</th><th>Enforcement</th><th>Refusals 24 h</th><th>AgentACL</th><th>Last report</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>")
    };
    html(200, page("Machines", "Machines", Some(csrf), &body))
}

fn machine(app: &App, csrf: &str, id: &str, result: Option<Result<String, String>>) -> Resp {
    let db = app.db.lock().unwrap_or_else(|p| p.into_inner());
    let Ok(Some(d)) = db.device(id) else { return html(404, page("Not found", "Machines", Some(csrf), &notice("bad", "No such machine."))) };
    let users = db.device_users(id).unwrap_or_default();
    let all = db.devices().unwrap_or_default();
    let current = db.policy().map(|p| p.version).unwrap_or(0);
    let blocked = db.is_blocked(&d.machine_id).unwrap_or(false);
    let recent = db.events(&EventFilter { device: Some(d.id.clone()), limit: 50, ..Default::default() }).unwrap_or_default();
    drop(db);
    let now = now();
    let mut b = String::new();
    if let Some(r) = result {
        b.push_str(&match r {
            Ok(m) => notice("good", &m),
            Err(e) => notice("bad", &e),
        });
    }
    b.push_str(&format!("<h1>{}</h1>", esc(&d.hostname)));
    let w = warnings(&d, &all, &users, current, now);
    if !w.is_empty() {
        b.push_str(&notice("warnbox", &w.join("; ")));
    }
    let r = d.report.as_ref();
    b.push_str(&format!(
        "<dl class=\"facts\"><dt>Enforcement</dt><dd>{}</dd><dt>Company policy</dt><dd>{}</dd><dt>macOS</dt><dd>{}</dd><dt>AgentACL</dt><dd>{}</dd><dt>Serial</dt><dd>{}</dd><dt>Machine id</dt><dd>{}</dd><dt>Enrolled</dt><dd>{}</dd><dt>Last report</dt><dd>{}</dd></dl>",
        enforcement(&d),
        r.and_then(|r| r.machine.policy_version).map(|v| format!("v{v}")).unwrap_or_else(|| "none".into()),
        esc(&d.os_version),
        esc(&d.agentacl_version),
        esc(d.serial.as_deref().unwrap_or("")),
        esc(&d.machine_id),
        esc(&time(d.enrolled_at)),
        d.last_seen.map(|t| esc(&format!("{} ({})", time(t), ago(t, now)))).unwrap_or_else(|| "never".into()),
    ));
    // Running agents (from the root service).
    let running = r.map(|r| r.running.clone()).unwrap_or_default();
    b.push_str("<h2>Agents running</h2>");
    if running.is_empty() {
        b.push_str("<p class=\"muted\">None at the last report.</p>");
    } else {
        b.push_str("<div class=\"scroll\"><table><thead><tr><th>Agent</th><th>User</th><th>pid</th><th>Program</th><th>Under AgentACL</th></tr></thead><tbody>");
        for a in &running {
            let sup = match &a.supervisor {
                Some(s) if s == agentacl_fleet::MANAGED_AGENTACL => "<span class=\"ok\">yes</span>".to_string(),
                Some(s) => format!("<span class=\"warn\">another copy: {}</span>", esc(s)),
                None => "<span class=\"warn\">no</span>".into(),
            };
            b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"path\">{}</td><td>{}</td></tr>", esc(&a.agent_name), esc(&a.user), a.pid, esc(&a.exe), sup));
        }
        b.push_str("</tbody></table></div>");
    }
    // Per user (reported by the user's AgentACL).
    for u in &users {
        b.push_str(&format!("<h2>{} <span class=\"muted\">(uid {}, reported {})</span></h2>", esc(&u.user), u.uid, esc(&ago(u.updated, now))));
        if let Some(e) = &u.error {
            b.push_str(&notice("bad", e));
        }
        if let Some(inst) = &u.installed {
            let list = inst.iter().map(|i| format!("{} {}", i.agent_name, i.version.as_deref().unwrap_or(""))).collect::<Vec<_>>().join(", ");
            b.push_str(&format!("<p><strong>Installed:</strong> {}</p>", esc(if list.is_empty() { "no agent found" } else { &list })));
        }
        if u.sessions.is_empty() {
            b.push_str("<p class=\"muted\">No AgentACL sessions.</p>");
        } else {
            b.push_str("<div class=\"scroll\"><table><thead><tr><th>Agent</th><th>Project</th><th>How</th><th>Started</th><th>Ended</th><th>AgentACL</th><th>Company rules</th></tr></thead><tbody>");
            for s in &u.sessions {
                b.push_str(&format!(
                    "<tr><td>{}</td><td class=\"path\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&s.agent),
                    esc(&s.project),
                    esc(&s.backend),
                    esc(&s.started_at),
                    esc(s.ended_at.as_deref().unwrap_or("running")),
                    esc(s.agentacl_version.as_deref().unwrap_or("")),
                    if s.company_rules { "<span class=\"ok\">yes</span>" } else { "<span class=\"warn\">no</span>" },
                ));
            }
            b.push_str("</tbody></table></div>");
        }
    }
    b.push_str(&format!("<h2>Recent events</h2>{}<p><a href=\"/events?device={}\">All events from this Mac</a></p>", events_table(&recent), enc(&d.id)));
    // Revoke / allow again.
    if !d.revoked {
        b.push_str(&format!(
            "<h2>Revoke</h2><form method=\"post\" action=\"/machines/{}/revoke\" class=\"inline\">{}<button class=\"danger\">Revoke this Mac</button></form><p class=\"muted\">Its key stops working and its machine id can't enroll again until you allow it. The Mac keeps its last company rules.</p>",
            enc(&d.id),
            csrf_field(csrf)
        ));
    } else if blocked {
        b.push_str(&format!("<form method=\"post\" action=\"/machines/{}/unblock\" class=\"inline\">{}<button>Allow this machine to enroll again</button></form>", enc(&d.id), csrf_field(csrf)));
    }
    html(200, page(&d.hostname, "Machines", Some(csrf), &b))
}

fn events_table(ev: &[crate::db::StoredEvent]) -> String {
    if ev.is_empty() {
        return "<p class=\"muted\">No events.</p>".into();
    }
    let mut t =
        String::from("<div class=\"scroll\"><table><thead><tr><th>When</th><th>Mac</th><th>User</th><th>Agent</th><th>Decision</th><th>Action</th><th>Resource</th><th>Rule</th></tr></thead><tbody>");
    for e in ev {
        let d = e.event.decision.as_deref().unwrap_or("");
        let class = match d {
            "deny" => "bad",
            "ask" => "warn",
            _ => "",
        };
        t.push_str(&format!(
            "<tr><td>{}</td><td><a href=\"/machines/{}\">{}</a></td><td>{}</td><td>{}</td><td class=\"{class}\">{}{}</td><td>{}</td><td class=\"path\">{}</td><td title=\"{}\">{}</td></tr>",
            esc(&e.event.ts),
            enc(&e.device_id),
            esc(&e.hostname),
            esc(&e.user),
            esc(&e.event.agent),
            esc(d),
            if e.event.kind == "observed" { " <span class=\"muted\">(logged)</span>" } else { "" },
            esc(&e.event.action),
            esc(&e.event.resource),
            esc(e.event.reason.as_deref().unwrap_or("")),
            esc(&format!("{}/{}", e.event.policy.as_deref().unwrap_or(""), e.event.rule_id.as_deref().unwrap_or(""))),
        ));
    }
    t.push_str("</tbody></table></div>");
    t
}

fn events(app: &App, r: &Req, csrf: &str) -> Resp {
    let q = |k: &str| r.query.get(k).cloned().filter(|v| !v.is_empty());
    let f = EventFilter { device: q("device"), user: q("user"), agent: q("agent"), decision: q("decision"), limit: 500 };
    let ev = app.db.lock().unwrap_or_else(|p| p.into_inner()).events(&f).unwrap_or_default();
    let field = |name: &str, label: &str, v: &Option<String>| format!("<label>{label} <input name=\"{name}\" value=\"{}\"></label>", esc(v.as_deref().unwrap_or("")));
    let sel = |v: &str| if f.decision.as_deref() == Some(v) { " selected" } else { "" };
    let body = format!(
        "<h1>Events</h1><p class=\"muted\">The newest 500. Paths, hosts and command lines as reported by each Mac (command lines are shortened and obvious secrets replaced on the Mac).</p><form method=\"get\" action=\"/events\" class=\"filters\">{}{}{}<label>Decision <select name=\"decision\"><option value=\"\">any</option><option{} value=\"deny\">deny</option><option{} value=\"ask\">ask</option><option{} value=\"allow\">allow</option></select></label><button>Filter</button></form>{}",
        field("device", "Mac id", &f.device),
        field("user", "User", &f.user),
        field("agent", "Agent", &f.agent),
        sel("deny"),
        sel("ask"),
        sel("allow"),
        events_table(&ev)
    );
    html(200, page("Events", "Events", Some(csrf), &body))
}

const POLICY_HELP: &str = "<p>Company rules apply to every agent on every enrolled Mac, and nothing on a Mac can lift them. They can only forbid: <code>filesystem.deny_read</code>, <code>filesystem.deny_write</code>, <code>process.deny</code>, <code>network.deny</code>, with absolute paths or <code>${HOME}</code>.</p><pre class=\"example\">version: v1\nfilesystem:\n  deny_read: [\"${HOME}/Company Shared/**\"]\n  deny_write: [\"/Library/Company/**\"]\nprocess:\n  deny: [\"terraform apply *\"]\nnetwork:\n  deny: [\"*.pastebin.com\", \"203.0.113.0/24\"]</pre>";

fn policy(app: &App, csrf: &str, draft: Option<&str>, result: Option<Result<(String, Vec<String>), String>>) -> Resp {
    let db = app.db.lock().unwrap_or_else(|p| p.into_inner());
    let current = db.policy().unwrap_or_default();
    let history = db.policy_history().unwrap_or_default();
    drop(db);
    let mut b = String::from("<h1>Company policy</h1>");
    match result {
        Some(Ok((m, warns))) => {
            b.push_str(&notice("good", &m));
            for w in warns {
                b.push_str(&notice("warnbox", &w));
            }
        }
        Some(Err(e)) => b.push_str(&notice("bad", &e)),
        None => {}
    }
    b.push_str(POLICY_HELP);
    let text = draft.unwrap_or(if current.version == 0 { "version: v1\n" } else { &current.yaml });
    b.push_str(&format!(
        "<form method=\"post\" action=\"/policy\">{}<label>Policy (version {} in force)<textarea name=\"yaml\" rows=\"18\" spellcheck=\"false\">{}</textarea></label><label>Admin password (to change every Mac) <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label><button>Validate and publish</button></form>",
        csrf_field(csrf),
        current.version,
        esc(text)
    ));
    if !history.is_empty() {
        b.push_str("<h2>History</h2><ul>");
        for (v, t) in history {
            b.push_str(&format!("<li>v{v}, {}</li>", esc(&time(t))));
        }
        b.push_str("</ul>");
    }
    html(200, page("Company policy", "Company policy", Some(csrf), &b))
}

fn save_policy(app: &App, r: &Req, csrf: &str) -> Resp {
    let yaml = r.form.get("yaml").map(|y| y.replace("\r\n", "\n")).unwrap_or_default();
    if !reauth(app, r) {
        return policy(app, csrf, Some(&yaml), Some(Err("Wrong admin password; nothing was published.".into())));
    }
    let yaml = if yaml.trim().is_empty() { "version: v1\n".to_string() } else { yaml };
    if let Err(e) = agentacl_fleet::validate_company_policy(&yaml) {
        return policy(app, csrf, Some(&yaml), Some(Err(format!("Not published: {e}"))));
    }
    let warns = agentacl_fleet::company_policy_warnings(&yaml);
    let res = app.db.lock().unwrap_or_else(|p| p.into_inner()).save_policy(&yaml, now());
    match res {
        Ok(v) => policy(app, csrf, None, Some(Ok((format!("Published as version {v}. Each Mac applies it at its next report (within about a minute)."), warns)))),
        Err(e) => policy(app, csrf, Some(&yaml), Some(Err(e.to_string()))),
    }
}

fn tokens(app: &App, csrf: &str, msg: Option<String>) -> Resp {
    let list = app.db.lock().unwrap_or_else(|p| p.into_inner()).tokens().unwrap_or_default();
    let now = now();
    let mut b = String::from("<h1>Enrollment</h1>");
    if let Some(m) = msg {
        b.push_str(&m);
    }
    b.push_str(&format!(
        "<form method=\"post\" action=\"/tokens\" class=\"filters\">{}<label>Name <input name=\"name\" required placeholder=\"Engineering Macs\"></label><label>Valid for (days) <input name=\"days\" type=\"number\" min=\"1\" max=\"365\" value=\"30\"></label><label>Macs <input name=\"max\" type=\"number\" min=\"1\" max=\"100000\" value=\"50\"></label><label>Admin password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label><button>Create token</button></form>",
        csrf_field(csrf)
    ));
    if !list.is_empty() {
        b.push_str("<div class=\"scroll\"><table><thead><tr><th>Name</th><th>Created</th><th>Expires</th><th>Macs enrolled</th><th></th></tr></thead><tbody>");
        for t in list {
            let state = if t.revoked {
                "<span class=\"muted\">revoked</span>".to_string()
            } else if t.expires <= now {
                "<span class=\"muted\">expired</span>".into()
            } else {
                format!("<form method=\"post\" action=\"/tokens/{}/revoke\" class=\"inline\">{}<button class=\"danger\">Revoke</button></form>", t.id, csrf_field(csrf))
            };
            b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{} of {}</td><td>{state}</td></tr>", esc(&t.name), esc(&time(t.created)), esc(&time(t.expires)), t.uses, t.max_uses));
        }
        b.push_str("</tbody></table></div>");
    }
    html(200, page("Enrollment", "Enrollment", Some(csrf), &b))
}

fn create_token(app: &App, r: &Req, csrf: &str) -> Resp {
    if !reauth(app, r) {
        return tokens(app, csrf, Some(notice("bad", "Wrong admin password; no token was created.")));
    }
    let name = r.form.get("name").map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && s.len() <= 100).unwrap_or_else(|| "Macs".into());
    let days = r.form.get("days").and_then(|d| d.parse::<i64>().ok()).unwrap_or(30).clamp(1, 365);
    let max = r.form.get("max").and_then(|d| d.parse::<i64>().ok()).unwrap_or(50).clamp(1, 100_000);
    let token = format!("aet_{}", random_hex());
    let now = now();
    let res = app.db.lock().unwrap_or_else(|p| p.into_inner()).add_token(&name, &sha256_hex(&token), now, now + days * 86_400, max);
    let server = esc(&app.config.public_url);
    let msg = match res {
        Ok(_) => format!(
            "{}<div class=\"token\"><p><strong>Copy it now; it won't be shown again.</strong></p><pre>{}</pre><p>On a Mac (as an administrator):</p><pre>echo '{}' | sudo agentacl fleet enroll --server {}</pre><p>Or build a package for your device management:</p><pre>echo '{}' | scripts/fleet/build-pkg.sh --server {}</pre><p class=\"muted\">Anyone with this token can enroll up to {max} Macs until it expires. Revoke it when you are done.</p></div>",
            notice("good", &format!("Token “{name}” created, valid {days} days.")),
            esc(&token),
            esc(&token),
            server,
            esc(&token),
            server
        ),
        Err(e) => notice("bad", &e.to_string()),
    };
    tokens(app, csrf, Some(msg))
}
