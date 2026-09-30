//! UI API handlers (ui.md §4.1). Every handler reuses the CLI's code paths;
//! the UI adds no authority.

use super::{files, UiState};
use agentacl_core::draft::{self, SaveError, Scope};
use agentacl_core::escape::term_safe;
use agentacl_core::{identity, proc, supervisor};
use agentacl_policy::emit::to_yaml;
use agentacl_policy::raw::{parse_doc, RawDoc};
use agentacl_policy::{Action, Layer, PolicyEngine, Request, Resource, Subject, WriteOp};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tiny_http::Method;

type Reply = Result<(u16, Value)>;

pub fn dispatch(st: &Arc<UiState>, m: &Method, path: &str, q: &HashMap<String, String>, body: &Value) -> Reply {
    match (m, path) {
        (Method::Get, "/api/overview") => overview(st),
        (Method::Get, "/api/status") => status(st),
        (Method::Get, "/api/agents") => agents(st, q),
        (Method::Get, "/api/projects") => projects(st),
        (Method::Post, "/api/projects/add") => project_add(st, body),
        (Method::Post, "/api/projects/remove") => project_remove(st, body),
        (Method::Get, "/api/stats") => stats(st),
        (Method::Get, "/api/builtins") => builtins(st),
        (Method::Post, "/api/sessions/stop") => stop(st, body),
        (Method::Post, "/api/reveal") => reveal(body),
        (Method::Get, "/api/sessions") => sessions(st),
        (Method::Post, "/api/sessions/restart") => restart(st, body),
        (Method::Get, "/api/sessions/restart-status") => restart_status(st, q),
        (Method::Get, "/api/events") => events(st, q),
        (Method::Get, "/api/policy") => get_policy(st, q),
        (Method::Post, "/api/policy/preview") => preview(st, body),
        (Method::Post, "/api/policy/save") => save(st, body),
        (Method::Post, "/api/fs/list") => fs_list(st, body),
        (Method::Post, "/api/map") => map(st, body),
        (Method::Post, "/api/pick-folder") => pick_folder(body),
        (Method::Post, "/api/fs/node") => fs_node(st, body),
        (Method::Post, "/api/evaluate") => evaluate(st, body),
        (Method::Get, "/api/network") => super::network::network(st, q),
        (Method::Post, "/api/network/rule") => super::network::network_rule(st, body),
        (Method::Post, "/api/network/mode") => super::network::network_mode(st, body),
        (Method::Get, "/api/approvals") => super::network::approvals(st),
        (Method::Post, "/api/approvals/answer") => super::network::approval_answer(st, body),
        (Method::Get, "/api/requests") => super::network::requests(st, q),
        (Method::Get, "/api/access") => super::access::list(st, q),
        (Method::Post, "/api/access/allow") => super::access::allow(st, body),
        (Method::Post, "/api/access/remove") => super::access::remove(st, body),
        (Method::Post, "/api/approvals/extend") => super::access::extend(st, body),
        (Method::Post, "/api/network/wait") => super::access::set_wait(st, body),
        (Method::Get, "/api/notify") => super::access::notify_get(st),
        (Method::Post, "/api/notify") => super::access::notify_set(st, body),
        (Method::Post, "/api/requests/dismiss") => super::network::request_dismiss(st, body),
        _ => Ok((404, json!({ "error": "not found" }))),
    }
}

fn home() -> Result<PathBuf> {
    Ok(identity::human()?.home)
}

fn scope_of(v: Option<&str>) -> Result<Scope> {
    match v.unwrap_or("user") {
        "user" => Ok(Scope::User),
        "project" => Ok(Scope::Project),
        o => bail!("unknown scope {o:?}"),
    }
}

/// Projects always go through the same resolution as `run` (git toplevel,
/// $HOME and its ancestors refused). With no project given, a neutral empty
/// placeholder (`/private/var/empty`, canonical: `/var` is a symlink) stands in for `${PROJECT}`: nothing depends on
/// the directory the console was started from.
pub fn project_of(v: Option<&str>) -> Result<PathBuf> {
    match v.filter(|s| !s.is_empty()) {
        Some(p) => identity::resolve_project(Path::new(p), None, &home()?),
        None => Ok(PathBuf::from(NO_PROJECT)),
    }
}

/// A new user policy starts from the built-in default, renamed so the saved
/// file reads as the user's own rules.
pub fn seed_user_policy() -> String {
    agentacl_policy::set::builtin_sources(true).into_iter().find(|s| s.name == "default").map(|s| s.yaml.replacen("\nname: default\n", "\nname: user\n", 1)).unwrap_or_default()
}

pub const NO_PROJECT: &str = "/private/var/empty";

/// Project-scope operations need a real project, never the placeholder.
fn scoped_project(scope: Scope, v: Option<&str>) -> Result<PathBuf> {
    let p = project_of(v)?;
    if scope == Scope::Project && p == Path::new(NO_PROJECT) {
        bail!("choose a project first");
    }
    Ok(p)
}

fn agent_of(v: Option<&str>) -> String {
    v.filter(|s| !s.is_empty()).unwrap_or("claude-code").to_string()
}

/// The draft as YAML: `yaml` wins; else a structured `doc` is emitted
/// server-side (and re-parsed by validation).
fn draft_yaml(body: &Value, scope: Scope) -> Result<Option<String>> {
    if let Some(y) = body["yaml"].as_str() {
        return Ok(Some(y.to_string()));
    }
    if body["doc"].is_object() {
        let mut d: RawDoc = serde_json::from_value(body["doc"].clone()).context("invalid structured policy")?;
        d.layer = if scope == Scope::Project { Layer::Project } else { Layer::User };
        return Ok(Some(to_yaml(&d)));
    }
    Ok(None)
}

fn doc_json(yaml: &str, scope: Scope) -> Value {
    let layer = if scope == Scope::Project { Layer::Project } else { Layer::User };
    match parse_doc(yaml, layer, if scope == Scope::Project { "project" } else { "user" }) {
        Ok(d) => serde_json::to_value(d).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
fn since_24h() -> String {
    agentacl_core::audit::format_rfc3339(now_secs() - 86_400, 0)
}

/// Machine, backend and health information for the console header/settings.
fn status(st: &Arc<UiState>) -> Reply {
    let h = identity::human()?;
    let old = super::old_supervisor_sessions(st);
    let mut warnings = vec![];
    if !old.is_empty() {
        warnings.push(json!({ "kind": "old-supervisor", "sessions": old, "message": "Some agents were started by an older AgentACL. Restart them to get the latest protections." }));
    }
    if let Ok(t) = agentacl_core::trust::load(&st.paths) {
        if t.legacy_ignored > 0 {
            warnings.push(json!({ "kind": "legacy-trust", "message": format!("{} old-style trust entries are ignored; re-trust those projects with `agentacl policy trust`.", t.legacy_ignored) }));
        }
    }
    Ok((
        200,
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "human": h.user,
            "home": h.home,
            "machine": proc::machine_id().unwrap_or_default(),
            "hostname": std::process::Command::new("/bin/hostname").arg("-s").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()),
            "backend": { "name": "seatbelt", "available": true, "description": "macOS kernel sandbox (Seatbelt), applied to the agent and everything it starts" },
            "endpoint_security": { "available": false, "description": agentacl_core::enforce::endpoint_security::UNAVAILABLE },
            "paths": { "state": st.paths.state_dir, "config": st.paths.config_dir, "user_policy": st.paths.user_policy, "database": st.paths.db_path },
            "warnings": warnings,
        }),
    ))
}

fn discover_json(st: &Arc<UiState>, refresh: bool) -> Result<Value> {
    {
        let c = st.discover_cache.lock().unwrap();
        if let Some((t, v)) = c.as_ref() {
            if !refresh && t.elapsed() < std::time::Duration::from_secs(30) {
                return Ok(v.clone());
            }
        }
    }
    let home = home()?;
    let (installed, running) = agentacl_core::agents::discover(&home);
    let v = json!({ "installed": installed, "running": running, "discovered_at": agentacl_core::audit::now_rfc3339() });
    *st.discover_cache.lock().unwrap() = Some((std::time::Instant::now(), v.clone()));
    Ok(v)
}

/// Installed + running agents, each running one marked supervised or not and
/// linked to its project.
fn agents(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let mut d = discover_json(st, q.get("refresh").is_some_and(|v| v == "1"))?;
    // Live (not cached) process state for the running list.
    let running = agentacl_core::agents::running_agents(&proc::snapshot());
    let sessions = session_list(st)?;
    let home = home()?;
    let run_json: Vec<Value> = running
        .into_iter()
        .map(|r| {
            let session = session_of(&sessions, r.pid).cloned();
            let project = r.cwd.as_deref().and_then(|c| identity::resolve_project(Path::new(c), None, &home).ok());
            json!({
                "id": r.id, "name": r.display_name, "pid": r.pid, "exe": r.exe, "version": r.version,
                "cwd": r.cwd, "project": project, "started_us": r.started_us,
                "supervised": session.is_some(), "session": session,
            })
        })
        .collect();
    d["running"] = json!(run_json);
    Ok((200, d))
}

/// The supervised session a process belongs to: the process or one of its
/// ancestors is a session's agent or supervisor.
fn session_of(sessions: &[Value], pid: i32) -> Option<&Value> {
    let chain: Vec<i64> = proc::resolve_ancestry(pid).iter().map(|f| f.pid as i64).collect();
    sessions.iter().find(|s| chain.iter().any(|p| s["pid"].as_i64() == Some(*p) || s["supervisor_pid"].as_i64() == Some(*p)))
}

fn saved_projects(st: &Arc<UiState>) -> Vec<String> {
    let dir = supervisor::canon_or(&st.paths.state_dir);
    agentacl_core::fsafe::open_dir(&dir)
        .ok()
        .and_then(|fd| agentacl_core::fsafe::read_regular(&fd, "ui-projects.json").ok().flatten())
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .unwrap_or_default()
}
fn write_saved_projects(st: &Arc<UiState>, list: &[String]) -> Result<()> {
    let dir = agentacl_core::fsafe::open_dir(&supervisor::canon_or(&st.paths.state_dir))?;
    agentacl_core::fsafe::write_atomic(&dir, "ui-projects.json", serde_json::to_string_pretty(list)?.as_bytes())
}

/// Every project AgentACL knows about: from sessions, running agents and
/// projects added in the console.
fn projects(st: &Arc<UiState>) -> Reply {
    let home = home()?;
    let mut by_path: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for p in st.store.lock().unwrap().project_summaries(&since_24h())? {
        by_path.insert(p["path"].as_str().unwrap_or_default().to_string(), p);
    }
    for p in saved_projects(st) {
        by_path.entry(p.clone()).or_insert_with(|| json!({ "path": p, "sessions": 0, "active_sessions": 0, "last_seen": null, "blocked_24h": 0 }));
    }
    let running = agentacl_core::agents::running_agents(&proc::snapshot());
    let sessions = session_list(st)?;
    for r in &running {
        let Some(proj) = r.cwd.as_deref().and_then(|c| identity::resolve_project(Path::new(c), None, &home).ok()) else { continue };
        let key = proj.to_string_lossy().into_owned();
        let supervised = session_of(&sessions, r.pid).is_some();
        let e = by_path.entry(key.clone()).or_insert_with(|| json!({ "path": key, "sessions": 0, "active_sessions": 0, "last_seen": null, "blocked_24h": 0 }));
        if !supervised {
            e["unprotected_agents"] = json!(e["unprotected_agents"].as_i64().unwrap_or(0) + 1);
        }
    }
    let trust_for = |p: &Path| agentacl_core::trust::hashes_for(&st.paths, p).unwrap_or_default();
    let list: Vec<Value> = by_path
        .into_values()
        .map(|mut v| {
            let p = PathBuf::from(v["path"].as_str().unwrap_or_default());
            // Same safe read as `run` (no symlinks, regular files only, non-blocking).
            let bytes = if p.is_dir() { draft::read_policy(&st.paths, Scope::Project, &p).ok().flatten() } else { None };
            v["name"] = json!(p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            v["exists"] = json!(p.is_dir());
            v["has_project_rules"] = json!(bytes.is_some());
            v["trusted"] = json!(bytes.as_deref().is_some_and(|b| trust_for(&p).contains(&agentacl_policy::set::sha256_hex(b))));
            v["unprotected_agents"] = json!(v["unprotected_agents"].as_i64().unwrap_or(0));
            v["saved"] = json!(saved_projects(st).contains(&v["path"].as_str().unwrap_or_default().to_string()));
            v
        })
        .collect();
    Ok((200, json!({ "projects": list })))
}

fn project_add(st: &Arc<UiState>, body: &Value) -> Reply {
    let p = project_of(body["path"].as_str())?;
    let s = p.to_string_lossy().into_owned();
    let mut list = saved_projects(st);
    if !list.contains(&s) {
        list.push(s.clone());
        write_saved_projects(st, &list)?;
    }
    Ok((200, json!({ "path": s })))
}

fn project_remove(st: &Arc<UiState>, body: &Value) -> Reply {
    let s = body["path"].as_str().context("path required")?;
    let list: Vec<String> = saved_projects(st).into_iter().filter(|p| p != s).collect();
    write_saved_projects(st, &list)?;
    Ok((200, json!({ "ok": true })))
}

/// Dashboard numbers: 24 h counts, hourly blocked timeline, top blocked.
fn stats(st: &Arc<UiState>) -> Reply {
    let since = since_24h();
    let mut v = {
        let store = st.store.lock().unwrap();
        json!({
            "counts_24h": store.counts_since(&since)?,
            "timeline_24h": store.blocked_timeline(now_secs())?,
            "top_blocked": store.top_blocked(&since, 8)?.into_iter().map(|mut v| { v["resource"] = json!(term_safe(v["resource"].as_str().unwrap_or_default())); v }).collect::<Vec<_>>(),
        })
    };
    let extra = super::network::stats_extra(st, now_secs(), &since)?;
    for (k, x) in extra.as_object().into_iter().flatten() {
        v[k] = x.clone();
    }
    Ok((200, v))
}

/// Built-in protections, grouped, in plain words.
fn builtins(st: &Arc<UiState>) -> Reply {
    let project = project_of(None).unwrap_or_else(|_| PathBuf::from("/nonexistent"));
    let c = draft::check(&st.paths, "claude-code", &project, Scope::User, None);
    let disabled = c.as_ref().map(|c| c.policy.disabled_groups("claude-code", &project.to_string_lossy())).unwrap_or_default();
    let raw = agentacl_policy::raw::parse_doc(
        &agentacl_policy::set::builtin_sources(false).into_iter().find(|s| s.name == "protect-secrets").map(|s| s.yaml).unwrap_or_default(),
        Layer::Builtin,
        "protect-secrets",
    )?;
    let mut groups: Vec<(String, String, Vec<String>)> = vec![];
    for r in &raw.filesystem.deny_read {
        let id = r.id.clone().unwrap_or_default();
        match groups.iter_mut().find(|g| g.0 == id) {
            Some(g) => g.2.push(r.pattern.clone()),
            None => groups.push((id, r.reason.clone().unwrap_or_default(), vec![r.pattern.clone()])),
        }
    }
    Ok((
        200,
        json!({
            "groups": groups.into_iter().map(|(id, reason, patterns)| json!({ "id": id, "reason": reason, "patterns": patterns, "enabled": !disabled.contains(&id), "can_disable": true })).collect::<Vec<_>>(),
            "always_on": [
                { "id": "exec-persistence", "reason": "Git config, git hooks, shell startup files, launch agents and agent settings can't be changed — they would run code outside the sandbox later." },
                { "id": "agentacl-self", "reason": "Agents can't change AgentACL's rules, trust settings or audit log." },
                { "id": "network", "reason": "All traffic goes through AgentACL's proxy; local and private network addresses are blocked unless a rule names them." },
                { "id": "environment", "reason": "Secret-looking environment variables (tokens, keys, passwords) are withheld from agents." },
            ],
        }),
    ))
}

/// Stops a supervised agent (the supervisor forwards SIGTERM to it).
fn stop(st: &Arc<UiState>, body: &Value) -> Reply {
    let id = body["session"].as_str().context("session required")?;
    let s = st.store.lock().unwrap().active_sessions()?.into_iter().find(|s| s.session_id == id).ok_or_else(|| anyhow!("no active session {id}"))?;
    // Same checks and signal as `agentacl stop`.
    supervisor::request_stop(supervisor::verified_supervisor(&s)?)?;
    st.store.lock().unwrap().record_ui(&st.ctx, "session.stop_requested", id, "stop requested from the console")?;
    Ok((200, json!({ "ok": true })))
}

/// Shows a path in Finder.
fn reveal(body: &Value) -> Reply {
    let p = body["path"].as_str().context("path required")?;
    let path = std::fs::canonicalize(p)?;
    let _ = std::process::Command::new("/usr/bin/open").arg("-R").arg(&path).status();
    Ok((200, json!({ "ok": true })))
}

fn overview(st: &Arc<UiState>) -> Reply {
    let h = identity::human()?;
    let recent = st.store.lock().unwrap().recent_projects(20).unwrap_or_default();
    Ok((
        200,
        json!({
            "human": h.user,
            "home": h.home,
            "backend": "seatbelt",
            "endpoint_security": agentacl_core::enforce::endpoint_security::UNAVAILABLE,
            "state_dir": st.paths.state_dir,
            "config_dir": st.paths.config_dir,
            "user_policy": st.paths.user_policy,
            "projects": recent.into_iter().collect::<BTreeSet<_>>(),
            "agents": agentacl_core::agents::registry().iter().map(|p| json!({ "id": p.id(), "name": p.display_name() })).collect::<Vec<_>>(),
        }),
    ))
}

fn session_list(st: &Arc<UiState>) -> Result<Vec<Value>> {
    let store = st.store.lock().unwrap();
    let mut out = vec![];
    for s in store.active_sessions()? {
        if proc::facts(s.supervisor_pid).is_none() {
            store.end_session(&s.session_id, &agentacl_core::audit::now_rfc3339(), None)?;
            continue;
        }
        let ident: agentacl_core::session::Session = match serde_json::from_str(&s.identity_json) {
            Ok(i) => i,
            Err(_) => {
                out.push(json!({ "session": s.session_id, "agent": s.agent, "pid": s.agent_pid, "supervisor_pid": s.supervisor_pid, "project": s.project, "stale": "unknown", "restartable": false, "sources": [] }));
                continue;
            }
        };
        let stale = if ident.policy_sources.is_empty() { json!("unknown") } else { json!(ident.policy_sources.iter().any(|i| i.is_stale(&st.paths))) };
        out.push(json!({
            "session": s.session_id,
            "agent": s.agent,
            "agent_name": agentacl_core::agents::provider(&s.agent).map(|p| p.display_name().to_string()).unwrap_or(s.agent.clone()),
            "pid": s.agent_pid,
            "supervisor_pid": s.supervisor_pid,
            "project": s.project,
            "policy": s.policy_name,
            "started_at": s.started_at,
            "stale": stale,
            "restartable": ident.features.iter().any(|f| f == "restart"),
            "sources": ident.policy_sources.iter().map(|i| i.path.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        }));
    }
    Ok(out)
}

fn sessions(st: &Arc<UiState>) -> Reply {
    Ok((200, json!({ "sessions": session_list(st)? })))
}

/// How a restart requested at `since` went: `restarted` (with the new
/// session), `refused` (the new rules were invalid; the agent keeps running),
/// `exited` (the agent ended without a relaunch) or still `restarting`.
pub fn restart_state(store: &agentacl_core::audit::Store, old: &str, since: &str, supervisor_alive: impl Fn(i32) -> bool) -> Result<Value> {
    if since.is_empty() {
        bail!("since (the restart request time) is required");
    }
    let s = store.session(old)?.context("unknown session")?;
    // The relaunch is prepared (and stamped) before the old session ends, so
    // compare with the request time, not the old session's end.
    if let Some(n) = store.successor_session(s.supervisor_pid, old, since)? {
        return Ok(json!({ "state": "restarted", "session": n.session_id }));
    }
    if let Some(detail) = store.last_event_since(old, "restart.refused", since)? {
        return Ok(json!({ "state": "refused", "detail": detail }));
    }
    if s.ended_at.is_some() && !supervisor_alive(s.supervisor_pid) {
        return Ok(json!({ "state": "exited" }));
    }
    Ok(json!({ "state": "restarting" }))
}

fn restart_status(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let id = q.get("session").context("session required")?;
    let since = q.get("since").map(String::as_str).unwrap_or("");
    let store = st.store.lock().unwrap();
    Ok((200, restart_state(&store, id, since, |pid| proc::facts(pid).is_some())?))
}

fn restart(st: &Arc<UiState>, body: &Value) -> Reply {
    let id = body["session"].as_str().context("session required")?;
    let s = {
        let store = st.store.lock().unwrap();
        store.active_sessions()?.into_iter().find(|s| s.session_id == id).ok_or_else(|| anyhow!("no active session {id}"))?
    };
    let ident: Value = serde_json::from_str(&s.identity_json).unwrap_or_default();
    if !ident["features"].as_array().is_some_and(|f| f.iter().any(|x| x == "restart")) {
        bail!("this session was started by an older agentacl without restart support; exit the agent and run it again");
    }
    // Stamped before the signal: the relaunch may be prepared at once.
    let requested_at = agentacl_core::audit::now_rfc3339();
    supervisor::request_restart(supervisor::verified_supervisor(&s)?)?;
    st.store.lock().unwrap().record_ui(&st.ctx, "session.restart_requested", id, "relaunch under current policy requested from the UI")?;
    Ok((
        200,
        json!({ "ok": true, "requested_at": requested_at, "note": "The supervisor validates the new policy first; if it is invalid the agent keeps running and a restart.refused event appears." }),
    ))
}

fn events(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let size: u64 = q.get("size").and_then(|v| v.parse().ok()).unwrap_or(25).clamp(1, 200);
    let page: u64 = q.get("page").and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let p = agentacl_core::audit::EventPage {
        session: q.get("session").cloned().filter(|s| !s.is_empty()),
        agent: q.get("agent").cloned().filter(|s| !s.is_empty()),
        project: q.get("project").cloned().filter(|s| !s.is_empty()),
        policy: q.get("policy").cloned().filter(|s| !s.is_empty()),
        since: q.get("since").cloned().filter(|s| !s.is_empty()),
        kind: q.get("kind").cloned().unwrap_or_else(|| "all".into()),
        search: q.get("q").cloned().unwrap_or_default(),
        offset: (page - 1) * size,
        limit: size,
    };
    let store = st.store.lock().unwrap();
    let (total, rows) = store.events_page(&p)?;
    let since = {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        agentacl_core::audit::format_rfc3339(d.as_secs() as i64 - 86_400, 0)
    };
    let counts = store.counts_since(&since)?;
    drop(store);
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(rowid, e)| {
            let mut v = serde_json::to_value(&e).unwrap_or(Value::Null);
            v["rowid"] = json!(rowid);
            // Display-safe copies of attacker-influenced fields.
            v["resource_display"] = json!(term_safe(&e.resource));
            v["reason_display"] = json!(term_safe(e.reason.as_deref().unwrap_or("")));
            v["chain_display"] = json!(term_safe(&e.delegation_chain.join(" → ")));
            v
        })
        .collect();
    Ok((200, json!({ "events": list, "total": total, "page": page, "size": size, "pages": total.div_ceil(size).max(1), "counts_24h": counts })))
}

fn effective(check: &draft::DraftCheck) -> Value {
    json!({ "rules": check.rules, "warnings": check.warnings, "project_unreadable": check.project_unreadable })
}

fn is_trusted(st: &Arc<UiState>, scope: Scope, project: &Path, bytes: Option<&[u8]>) -> bool {
    scope == Scope::Project && bytes.is_some_and(|b| agentacl_core::trust::hashes_for(&st.paths, project).unwrap_or_default().contains(&agentacl_policy::set::sha256_hex(b)))
}

fn get_policy(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let scope = scope_of(q.get("scope").map(String::as_str))?;
    let project = scoped_project(scope, q.get("project").map(String::as_str))?;
    let agent = agent_of(q.get("agent").map(String::as_str));
    let bytes = draft::read_policy(&st.paths, scope, &project)?;
    let exists = bytes.is_some();
    let sha = bytes.as_deref().map(agentacl_policy::set::sha256_hex);
    let yaml = match (&bytes, scope) {
        (Some(b), _) => String::from_utf8_lossy(b).into_owned(),
        // Seed a new user policy from the built-in default (policy-model §3).
        // Renamed so the saved file reads as the user's own rules, not the built-in.
        (None, Scope::User) => seed_user_policy(),
        (None, Scope::Project) => "version: v1\n".to_string(),
    };
    let check = draft::check(&st.paths, &agent, &project, scope, bytes.as_ref().map(|_| yaml.as_str()));
    Ok((
        200,
        json!({
            "scope": scope,
            "project": project,
            "agent": agent,
            "file": draft::policy_file(&st.paths, scope, &project),
            "exists": exists,
            "sha256": sha,
            "yaml": yaml,
            "doc": doc_json(&yaml, scope),
            "trusted": is_trusted(st, scope, &project, bytes.as_deref()),
            "effective": check.as_ref().map(effective).unwrap_or(Value::Null),
            "error": check.err().map(|e| format!("{e:#}")),
        }),
    ))
}

/// Line diff (LCS) for the save preview.
fn line_diff(old: &str, new: &str) -> Vec<Value> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] { dp[i + 1][j + 1] + 1 } else { dp[i + 1][j].max(dp[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, vec![]);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            out.push(json!({ "op": " ", "line": term_safe(a[i]) }));
            i += 1;
            j += 1;
        } else if j < m && (i == n || dp[i][j + 1] >= dp[i + 1][j]) {
            out.push(json!({ "op": "+", "line": term_safe(b[j]) }));
            j += 1;
        } else {
            out.push(json!({ "op": "-", "line": term_safe(a[i]) }));
            i += 1;
        }
    }
    out
}

/// What agents can do, independent of which file a rule lives in (so saving
/// the seeded starter rules as the user policy is not reported as a change).
fn rule_keys(rules: &[agentacl_core::enforce::RuleView]) -> BTreeSet<String> {
    rules
        .iter()
        .map(|r| {
            let except = if r.excepts.is_empty() { String::new() } else { format!(" except {}", r.excepts.join(", ")) };
            format!("{} {} {} {}{except}", r.effect.as_str(), r.section, r.pattern, r.enforceability.as_str())
        })
        .collect()
}

/// Effective-rule changes for every known agent: `[{key, agents}]`, where
/// `agents` is empty when the change applies to all of them.
fn effective_diff(st: &Arc<UiState>, project: &Path, scope: Scope, yaml: &str) -> Value {
    let ids: Vec<String> = agentacl_core::agents::registry().iter().map(|p| p.id().to_string()).collect();
    let mut added: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut removed: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for id in &ids {
        let (Ok(b), Ok(a)) = (draft::check(&st.paths, id, project, scope, None), draft::check(&st.paths, id, project, scope, Some(yaml))) else { continue };
        let (x, y) = (rule_keys(&b.rules), rule_keys(&a.rules));
        for k in y.difference(&x) {
            added.entry(k.clone()).or_default().push(id.clone());
        }
        for k in x.difference(&y) {
            removed.entry(k.clone()).or_default().push(id.clone());
        }
    }
    let list =
        |m: std::collections::BTreeMap<String, Vec<String>>| -> Vec<Value> { m.into_iter().map(|(k, a)| json!({ "key": k, "agents": if a.len() == ids.len() { vec![] } else { a } })).collect() };
    json!({ "added": list(added), "removed": list(removed) })
}

/// Known projects where the draft user policy would leave some agent unable
/// to read the project (policy-model §3), as "path (agent)".
fn unreadable_elsewhere(st: &Arc<UiState>, yaml: &str) -> Vec<String> {
    let mut projects: BTreeSet<String> = saved_projects(st).into_iter().collect();
    if let Ok(v) = st.store.lock().unwrap().project_summaries("1970-01-01T00:00:00.000Z") {
        projects.extend(v.into_iter().filter_map(|p| p["path"].as_str().map(str::to_string)));
    }
    let mut out = vec![];
    for p in projects.into_iter().take(50) {
        let path = PathBuf::from(&p);
        if !path.is_dir() {
            continue;
        }
        for prov in agentacl_core::agents::registry() {
            if draft::check(&st.paths, prov.id(), &path, Scope::User, Some(yaml)).is_ok_and(|c| c.project_unreadable) {
                out.push(format!("{p} ({})", prov.display_name()));
            }
        }
    }
    out
}

fn preview(st: &Arc<UiState>, body: &Value) -> Reply {
    let scope = scope_of(body["scope"].as_str())?;
    let project = scoped_project(scope, body["project"].as_str())?;
    let agent = agent_of(body["agent"].as_str());
    let yaml = draft_yaml(body, scope)?.context("yaml or doc required")?;
    let current = draft::read_policy(&st.paths, scope, &project)?;
    let cur_text = current.as_deref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
    let comments_lost = body["doc"].is_object() && cur_text.lines().any(|l| l.trim_start().starts_with('#'));
    match draft::check(&st.paths, &agent, &project, scope, Some(&yaml)) {
        Ok(c) => {
            let elsewhere = if scope == Scope::User { unreadable_elsewhere(st, &yaml) } else { vec![] };
            Ok((
                200,
                json!({
                    "ok": true,
                    "yaml": yaml,
                    "doc": doc_json(&yaml, scope),
                    "effective": effective(&c),
                    "effective_diff": effective_diff(st, &project, scope, &yaml),
                    "unreadable_projects": elsewhere,
                    "current_sha256": current.as_deref().map(agentacl_policy::set::sha256_hex),
                    "file_diff": line_diff(&cur_text, &yaml),
                    "comments_lost": comments_lost,
                }),
            ))
        }
        Err(e) => Ok((200, json!({ "ok": false, "yaml": yaml, "error": format!("{e:#}") }))),
    }
}

fn save(st: &Arc<UiState>, body: &Value) -> Reply {
    let scope = scope_of(body["scope"].as_str())?;
    let project = scoped_project(scope, body["project"].as_str())?;
    let agent = agent_of(body["agent"].as_str());
    let yaml = draft_yaml(body, scope)?.context("yaml or doc required")?;
    let base = body["base_sha256"].as_str();
    let confirm = body["confirm"].as_array().is_some_and(|c| c.iter().any(|x| x == "project-unreadable"));
    let file = draft::policy_file(&st.paths, scope, &project);
    let before_hosts = if scope == Scope::User { super::network::policy_hosts(st).ok() } else { None };
    if scope == Scope::User && !confirm {
        let elsewhere = unreadable_elsewhere(st, &yaml);
        if !elsewhere.is_empty() {
            return Ok((
                409,
                json!({ "ok": false, "needs_confirm": ["project-unreadable"], "unreadable_projects": elsewhere, "error": "Saving this would stop agents from reading some projects. Confirm to save anyway." }),
            ));
        }
    }
    match draft::save(&st.paths, &agent, &project, scope, &yaml, base, confirm) {
        Ok(sha) => {
            st.store.lock().unwrap().record_ui(&st.ctx, "policy.saved", &file.to_string_lossy(), &format!("{} -> {sha}", base.unwrap_or("absent")))?;
            if scope == Scope::User {
                // Keep running sessions' live site rules in line with the file.
                super::network::reconcile_live(st, before_hosts.as_ref())?;
            }
            // Sessions that loaded this file, plus sessions that didn't record
            // their inputs (older AgentACL), which may have.
            let affected: Vec<Value> = session_list(st)?
                .into_iter()
                .filter_map(|mut s| {
                    let uses = s["sources"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|p| p.as_str().is_some_and(|p| Path::new(p) == file || supervisor::canon_or(Path::new(p)) == supervisor::canon_or(&file))));
                    let unknown = s["stale"] == "unknown";
                    s["maybe"] = json!(!uses && unknown);
                    (uses || unknown).then_some(s)
                })
                .collect();
            Ok((200, json!({ "ok": true, "sha256": sha, "affected_sessions": affected })))
        }
        Err(SaveError::NeedsConfirm(what)) => Ok((409, json!({ "ok": false, "needs_confirm": [what], "error": "Saving this would stop agents from reading the project. Confirm to save anyway." }))),
        Err(SaveError::Conflict(cur)) => {
            let current = draft::read_policy(&st.paths, scope, &project).ok().flatten().map(|b| String::from_utf8_lossy(&b).into_owned());
            Ok((
                409,
                json!({ "ok": false, "conflict": true, "current_sha256": cur, "current_yaml": current, "error": "The file changed on disk since you loaded it. Your draft is kept; review the current version." }),
            ))
        }
        Err(SaveError::Invalid(e)) => Ok((400, json!({ "ok": false, "error": format!("{e:#}") }))),
    }
}

fn policy_for(st: &Arc<UiState>, body: &Value) -> Result<(agentacl_policy::set::PolicySet, String, PathBuf, Scope)> {
    let scope = scope_of(body["scope"].as_str())?;
    let project = scoped_project(scope, body["project"].as_str())?;
    let agent = agent_of(body["agent"].as_str());
    let yaml = draft_yaml(body, scope)?;
    let c = draft::check(&st.paths, &agent, &project, scope, yaml.as_deref())?;
    Ok((c.policy, agent, project, scope))
}

fn fs_list(st: &Arc<UiState>, body: &Value) -> Reply {
    let (set, agent, project, scope) = policy_for(st, body)?;
    let home = home()?;
    let ctx = files::Ctx { set: &set, agent: &agent, project: &project, home: &home, scope };
    let dir = body["path"].as_str().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| project.clone());
    let offset = body["offset"].as_u64().unwrap_or(0) as usize;
    let limit = body["limit"].as_u64().unwrap_or(100) as usize;
    Ok((200, files::children(&ctx, &dir, offset, limit, body["force"].as_bool().unwrap_or(false))?))
}

/// Access map roots (project, home, protected secrets, system).
fn map(st: &Arc<UiState>, body: &Value) -> Reply {
    let (set, agent, project, scope) = policy_for(st, body)?;
    let home = home()?;
    let ctx = files::Ctx { set: &set, agent: &agent, project: &project, home: &home, scope };
    let mut v = files::map_roots(&ctx);
    v["project"] = json!(project);
    v["no_project"] = json!(project == Path::new(NO_PROJECT));
    Ok((200, v))
}

/// One path's node (decisions + rule actions), e.g. after picking it in Finder.
fn fs_node(st: &Arc<UiState>, body: &Value) -> Reply {
    let (set, agent, project, scope) = policy_for(st, body)?;
    let home = home()?;
    let ctx = files::Ctx { set: &set, agent: &agent, project: &project, home: &home, scope };
    let raw = PathBuf::from(body["path"].as_str().context("path required")?);
    if !raw.is_absolute() {
        bail!("path must be absolute");
    }
    // Canonicalize the folder (what the kernel checks); keep the leaf so a
    // symlink leaf is still shown as a link.
    let p = match (raw.parent(), raw.file_name()) {
        (Some(dir), Some(name)) => std::fs::canonicalize(dir).map(|d| d.join(name)).unwrap_or(raw.clone()),
        _ => raw.clone(),
    };
    let parent_link = p.parent().is_some_and(files::has_symlink_component);
    Ok((200, files::node(&ctx, &p, None, parent_link)))
}

/// Native macOS picker (the UI server runs locally as the user). `purpose`:
/// "project" (default; resolved like `run`), "folder" or "file" (returned
/// as chosen, for rule paths).
fn pick_folder(body: &Value) -> Reply {
    let purpose = body["purpose"].as_str().unwrap_or("project");
    let script = match purpose {
        "project" => "POSIX path of (choose folder with prompt \"Choose a project folder for AgentACL\")",
        "folder" => "POSIX path of (choose folder with prompt \"Choose a folder for this rule\")",
        "file" => "POSIX path of (choose file with prompt \"Choose a file for this rule\" with invisibles)",
        o => bail!("unknown purpose {o:?}"),
    };
    let out = std::process::Command::new("/usr/bin/osascript").args(["-e", script]).output()?;
    if !out.status.success() {
        return Ok((200, json!({ "cancelled": true })));
    }
    let chosen = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if purpose != "project" {
        let p = chosen.trim_end_matches('/');
        return Ok((200, json!({ "path": if p.is_empty() { "/" } else { p } })));
    }
    match identity::resolve_project(Path::new(&chosen), None, &home()?) {
        Ok(p) => Ok((200, json!({ "path": p }))),
        Err(e) => Ok((200, json!({ "error": format!("{e:#}") }))),
    }
}

fn evaluate(st: &Arc<UiState>, body: &Value) -> Reply {
    let (set, agent, project, _) = policy_for(st, body)?;
    let subject = Subject { agent_id: agent, project: project.to_string_lossy().into(), ..Default::default() };
    let r = &body["request"];
    let req = match r["kind"].as_str() {
        Some("path") => {
            let p = r["path"].as_str().context("path required")?;
            let abs = supervisor::canon_or(Path::new(p));
            let action = match r["action"].as_str().unwrap_or("read") {
                "read" => Action::FsRead,
                "write" => Action::FsWrite(WriteOp::Write),
                "rename" => Action::FsWrite(WriteOp::Rename),
                o => bail!("unknown action {o}"),
            };
            Request { subject, action, resource: Resource::Path(abs.to_string_lossy().into()) }
        }
        Some("exec") => {
            let argv: Vec<String> = r["command"].as_str().context("command required")?.split_whitespace().map(str::to_string).collect();
            let exe = argv
                .first()
                .and_then(|c| agentacl_core::agents::path_lookup(c))
                .map(|p| supervisor::canon_or(&p).to_string_lossy().into_owned())
                .unwrap_or_else(|| argv.first().cloned().unwrap_or_default());
            Request { subject, action: Action::Exec, resource: Resource::Exec { exe, argv } }
        }
        Some("host") => {
            let hp = r["host"].as_str().context("host required")?;
            let (h, p) = hp.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443))).unwrap_or((hp.to_string(), 443));
            Request { subject, action: Action::NetConnect, resource: Resource::Host { host: h, port: p } }
        }
        _ => bail!("request.kind must be path, exec or host"),
    };
    let d = set.evaluate(&req);
    Ok((200, json!({ "effect": d.effect, "policy": d.policy, "rule_id": d.rule_id, "reason": term_safe(&d.reason), "trace": d.trace.iter().map(|t| term_safe(t)).collect::<Vec<_>>() })))
}
