//! UI API handlers (ui.md §4.1). Every handler reuses the CLI's code paths;
//! the UI adds no authority.

use super::{files, UiState};
use agentfence_core::audit::EventQuery;
use agentfence_core::draft::{self, Scope, SaveError};
use agentfence_core::escape::term_safe;
use agentfence_core::{identity, proc, supervisor};
use agentfence_policy::emit::to_yaml;
use agentfence_policy::raw::{parse_doc, RawDoc};
use agentfence_policy::{Action, Layer, PolicyEngine, Request, Resource, Subject, WriteOp};
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
        (Method::Get, "/api/sessions") => sessions(st),
        (Method::Post, "/api/sessions/restart") => restart(st, body),
        (Method::Get, "/api/events") => events(st, q),
        (Method::Get, "/api/policy") => get_policy(st, q),
        (Method::Post, "/api/policy/preview") => preview(st, body),
        (Method::Post, "/api/policy/save") => save(st, body),
        (Method::Post, "/api/fs/list") => fs_list(st, body),
        (Method::Post, "/api/evaluate") => evaluate(st, body),
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
/// $HOME and its ancestors refused).
fn project_of(v: Option<&str>) -> Result<PathBuf> {
    let p = v.filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or(std::env::current_dir()?);
    identity::resolve_project(&p, None, &home()?)
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

fn overview(st: &Arc<UiState>) -> Reply {
    let h = identity::human()?;
    let recent = st.store.lock().unwrap().recent_projects(20).unwrap_or_default();
    let cwd_project = project_of(None).ok();
    Ok((200, json!({
        "human": h.user,
        "home": h.home,
        "backend": "seatbelt",
        "endpoint_security": agentfence_core::enforce::endpoint_security::UNAVAILABLE,
        "state_dir": st.paths.state_dir,
        "config_dir": st.paths.config_dir,
        "user_policy": st.paths.user_policy,
        "projects": cwd_project.into_iter().map(|p| p.to_string_lossy().into_owned()).chain(recent).collect::<BTreeSet<_>>(),
        "agents": agentfence_core::agents::registry().iter().map(|p| json!({ "id": p.id(), "name": p.display_name() })).collect::<Vec<_>>(),
    })))
}

fn session_list(st: &Arc<UiState>) -> Result<Vec<Value>> {
    let store = st.store.lock().unwrap();
    let mut out = vec![];
    for s in store.active_sessions()? {
        if proc::facts(s.supervisor_pid).is_none() {
            store.end_session(&s.session_id, &agentfence_core::audit::now_rfc3339(), None)?;
            continue;
        }
        let ident: agentfence_core::session::Session = match serde_json::from_str(&s.identity_json) {
            Ok(i) => i,
            Err(_) => {
                out.push(json!({ "session": s.session_id, "agent": s.agent, "pid": s.agent_pid, "project": s.project, "stale": "unknown", "restartable": false }));
                continue;
            }
        };
        let stale = if ident.policy_sources.is_empty() { json!("unknown") } else { json!(ident.policy_sources.iter().any(|i| i.is_stale(&st.paths))) };
        out.push(json!({
            "session": s.session_id,
            "agent": s.agent,
            "agent_name": agentfence_core::agents::provider(&s.agent).map(|p| p.display_name().to_string()).unwrap_or(s.agent.clone()),
            "pid": s.agent_pid,
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

fn restart(st: &Arc<UiState>, body: &Value) -> Reply {
    let id = body["session"].as_str().context("session required")?;
    let s = {
        let store = st.store.lock().unwrap();
        store.active_sessions()?.into_iter().find(|s| s.session_id == id).ok_or_else(|| anyhow!("no active session {id}"))?
    };
    let ident: Value = serde_json::from_str(&s.identity_json).unwrap_or_default();
    if !ident["features"].as_array().is_some_and(|f| f.iter().any(|x| x == "restart")) {
        bail!("this session was started by an older agentfence without restart support; exit the agent and run it again");
    }
    let exe = proc::facts(s.supervisor_pid).and_then(|f| f.exe).unwrap_or_default();
    if !exe.ends_with("/agentfence") {
        bail!("pid {} is no longer an agentfence supervisor", s.supervisor_pid);
    }
    supervisor::request_restart(s.supervisor_pid)?;
    st.store.lock().unwrap().record_ui(&st.ctx, "session.restart_requested", id, "relaunch under current policy requested from the UI")?;
    Ok((200, json!({ "ok": true, "note": "The supervisor validates the new policy first; if it is invalid the agent keeps running and a restart.refused event appears." })))
}

fn events(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let after = q.get("after").and_then(|v| v.parse().ok());
    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(200).min(1000);
    let rows = st.store.lock().unwrap().events(&EventQuery { session: q.get("session").cloned(), decision: None, after_rowid: after, limit: Some(limit) })?;
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
    Ok((200, json!({ "events": list })))
}

fn effective(check: &draft::DraftCheck) -> Value {
    json!({ "rules": check.rules, "warnings": check.warnings, "project_unreadable": check.project_unreadable })
}

fn is_trusted(st: &Arc<UiState>, scope: Scope, project: &Path, bytes: Option<&[u8]>) -> bool {
    scope == Scope::Project
        && bytes.is_some_and(|b| agentfence_core::trust::hashes_for(&st.paths, project).unwrap_or_default().contains(&agentfence_policy::set::sha256_hex(b)))
}

fn get_policy(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let scope = scope_of(q.get("scope").map(String::as_str))?;
    let project = project_of(q.get("project").map(String::as_str))?;
    let agent = agent_of(q.get("agent").map(String::as_str));
    let bytes = draft::read_policy(&st.paths, scope, &project)?;
    let exists = bytes.is_some();
    let sha = bytes.as_deref().map(agentfence_policy::set::sha256_hex);
    let yaml = match (&bytes, scope) {
        (Some(b), _) => String::from_utf8_lossy(b).into_owned(),
        // Seed a new user policy from the built-in default (policy-model §3).
        (None, Scope::User) => agentfence_policy::set::builtin_sources(true).into_iter().find(|s| s.name == "default").map(|s| s.yaml).unwrap_or_default(),
        (None, Scope::Project) => "version: v1\n".to_string(),
    };
    let check = draft::check(&st.paths, &agent, &project, scope, bytes.as_ref().map(|_| yaml.as_str()));
    Ok((200, json!({
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
    })))
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

fn rule_keys(rules: &[agentfence_core::enforce::RuleView]) -> BTreeSet<String> {
    rules.iter().map(|r| format!("{} {} {} {} ({})", r.effect.as_str(), r.section, r.pattern, r.enforceability.as_str(), r.policy)).collect()
}

fn preview(st: &Arc<UiState>, body: &Value) -> Reply {
    let scope = scope_of(body["scope"].as_str())?;
    let project = project_of(body["project"].as_str())?;
    let agent = agent_of(body["agent"].as_str());
    let yaml = draft_yaml(body, scope)?.context("yaml or doc required")?;
    let current = draft::read_policy(&st.paths, scope, &project)?;
    let cur_text = current.as_deref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
    let comments_lost = body["doc"].is_object() && cur_text.lines().any(|l| l.trim_start().starts_with('#'));
    let before = draft::check(&st.paths, &agent, &project, scope, None).ok();
    match draft::check(&st.paths, &agent, &project, scope, Some(&yaml)) {
        Ok(c) => {
            let (added, removed) = match &before {
                Some(b) => {
                    let (x, y) = (rule_keys(&b.rules), rule_keys(&c.rules));
                    (y.difference(&x).cloned().collect::<Vec<_>>(), x.difference(&y).cloned().collect::<Vec<_>>())
                }
                None => (vec![], vec![]),
            };
            Ok((200, json!({
                "ok": true,
                "yaml": yaml,
                "doc": doc_json(&yaml, scope),
                "effective": effective(&c),
                "effective_diff": { "added": added, "removed": removed },
                "file_diff": line_diff(&cur_text, &yaml),
                "comments_lost": comments_lost,
            })))
        }
        Err(e) => Ok((200, json!({ "ok": false, "yaml": yaml, "error": format!("{e:#}") }))),
    }
}

fn save(st: &Arc<UiState>, body: &Value) -> Reply {
    let scope = scope_of(body["scope"].as_str())?;
    let project = project_of(body["project"].as_str())?;
    let agent = agent_of(body["agent"].as_str());
    let yaml = draft_yaml(body, scope)?.context("yaml or doc required")?;
    let base = body["base_sha256"].as_str();
    let confirm = body["confirm"].as_array().is_some_and(|c| c.iter().any(|x| x == "project-unreadable"));
    let file = draft::policy_file(&st.paths, scope, &project);
    match draft::save(&st.paths, &agent, &project, scope, &yaml, base, confirm) {
        Ok(sha) => {
            st.store.lock().unwrap().record_ui(&st.ctx, "policy.saved", &file.to_string_lossy(), &format!("{} -> {sha}", base.unwrap_or("absent")))?;
            let affected: Vec<Value> = session_list(st)?
                .into_iter()
                .filter(|s| s["sources"].as_array().is_some_and(|a| a.iter().any(|p| p.as_str().is_some_and(|p| Path::new(p) == file || supervisor::canon_or(Path::new(p)) == supervisor::canon_or(&file)))))
                .collect();
            Ok((200, json!({ "ok": true, "sha256": sha, "affected_sessions": affected })))
        }
        Err(SaveError::NeedsConfirm(what)) => Ok((409, json!({ "ok": false, "needs_confirm": [what], "error": "Saving this would stop agents from reading the project. Confirm to save anyway." }))),
        Err(SaveError::Conflict(cur)) => {
            let current = draft::read_policy(&st.paths, scope, &project).ok().flatten().map(|b| String::from_utf8_lossy(&b).into_owned());
            Ok((409, json!({ "ok": false, "conflict": true, "current_sha256": cur, "current_yaml": current, "error": "The file changed on disk since you loaded it. Your draft is kept; review the current version." })))
        }
        Err(SaveError::Invalid(e)) => Ok((400, json!({ "ok": false, "error": format!("{e:#}") }))),
    }
}

fn policy_for(st: &Arc<UiState>, body: &Value) -> Result<(agentfence_policy::set::PolicySet, String, PathBuf, Scope)> {
    let scope = scope_of(body["scope"].as_str())?;
    let project = project_of(body["project"].as_str())?;
    let agent = agent_of(body["agent"].as_str());
    let yaml = draft_yaml(body, scope)?;
    let c = draft::check(&st.paths, &agent, &project, scope, yaml.as_deref())?;
    Ok((c.policy, agent, project, scope))
}

fn fs_list(st: &Arc<UiState>, body: &Value) -> Reply {
    let (set, agent, project, scope) = policy_for(st, body)?;
    let dir = body["path"].as_str().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| project.clone());
    let force = body["force"].as_bool().unwrap_or(false);
    Ok((200, files::list(&set, &agent, &project, &home()?, scope, &dir, force)?))
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
            let exe = argv.first().and_then(|c| agentfence_core::agents::path_lookup(c)).map(|p| supervisor::canon_or(&p).to_string_lossy().into_owned()).unwrap_or_else(|| argv.first().cloned().unwrap_or_default());
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
