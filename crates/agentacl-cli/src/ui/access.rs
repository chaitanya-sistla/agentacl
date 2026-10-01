//! Access granted from requests, per agent and per place
//! (docs/design/access-requests.md). Each grant goes to an access document
//! (`agentacl_core::access`), validated against the complete policy first;
//! a site grant also becomes a scoped live rule, so running agents get it
//! now.

use super::UiState;
use agentacl_core::access::{self, Grant, Scope};
use agentacl_core::draft;
use agentacl_core::escape::term_safe;
use agentacl_core::netlive;
use agentacl_policy::{Action, Effect, PolicyEngine, Request, Resource, Subject, WriteOp};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Reply = Result<(u16, Value)>;

/// Serializes read-modify-write of access files (the console is threaded).
static ACCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A project for an access scope: the exact folder the session uses (not its
/// git root, which `run --project` may differ from).
fn scope_project(p: &str) -> Result<PathBuf> {
    let c = std::fs::canonicalize(p).with_context(|| format!("no such project folder {p}"))?;
    if !c.is_dir() {
        bail!("{} is not a folder", c.display());
    }
    let home = agentacl_core::identity::human()?.home;
    if home.starts_with(&c) {
        bail!("{} can't be a project", c.display());
    }
    Ok(c)
}

/// Keeps the live site rules in step with the access files: drops rules a
/// file no longer has, and re-adds (with a fresh time) the rule of every file
/// that still allows `host`, so removing one grant never takes a site that
/// another grant, or the policy file, still allows.
pub fn sync_live(st: &Arc<UiState>, host: Option<&str>) -> Result<()> {
    let sd = state_dir(st);
    let docs = access::list(&st.paths)?;
    let live = netlive::read_live(&sd);
    let mut present = std::collections::BTreeSet::new();
    for (file, _, doc) in &docs {
        let source = format!("access:{}", file.trim_end_matches(".yaml"));
        for r in &doc.network.allow {
            present.insert((source.clone(), r.pattern.clone()));
            // Re-added for `host`; added for a site written in by hand.
            let missing = !live.rules.iter().any(|l| l.host == r.pattern && l.source.as_deref() == Some(source.as_str()));
            if missing || host.is_some_and(|h| netlive::host_key(h) == r.pattern) {
                let s = access::scope_of(doc);
                netlive::set_scoped_rule(&sd, &r.pattern, Effect::Allow, s.agent.as_deref(), s.project.as_deref().and_then(|p| p.to_str()), &source)?;
            }
        }
    }
    netlive::retain_access_rules(&sd, &present)?;
    if let Some(h) = host {
        if super::network::policy_allows(st, h) {
            netlive::set_rule(&sd, h, Some(Effect::Allow))?;
        }
    }
    Ok(())
}

fn state_dir(st: &Arc<UiState>) -> PathBuf {
    agentacl_core::supervisor::canon_or(&st.paths.state_dir)
}

fn representable(p: &str) -> bool {
    p.starts_with('/')
        && !(p.contains(['*', '?', '"', '\\'])
            || p.contains("${")
            || p.contains("//")
            || p.contains("/./")
            || p.ends_with("/.")
            || p.contains("/../")
            || p.ends_with("/..")
            || p.chars().any(char::is_control))
}

/// `p` as matching sees it: lowercase (APFS and path rules are
/// case-insensitive), without the `/private` and data-volume prefixes that
/// name the same places as `/var`, `/etc`, `/tmp` and `/Users`.
fn fold_path(p: &str) -> String {
    let mut s = p.to_ascii_lowercase();
    for pre in ["/system/volumes/data", "/private"] {
        if let Some(rest) = s.strip_prefix(pre) {
            if rest.is_empty() || rest.starts_with('/') {
                s = if rest.is_empty() { "/".into() } else { rest.to_string() };
            }
        }
    }
    s
}

/// Your home folder, anything above it, and top-level folders (under any of
/// their names) are too broad to grant from a request.
fn too_broad(t: &str, home: &str) -> bool {
    let (t, h) = (fold_path(t), fold_path(home));
    t == h || h.starts_with(&format!("{}/", t.trim_end_matches('/'))) || t.matches('/').count() < 2
}

fn agent_name(id: &str) -> String {
    agentacl_core::agents::provider(id).map(|p| p.display_name().to_string()).unwrap_or(id.to_string())
}

/// `POST /api/access/allow`
/// `{kind: read|write|site, target, dir?, agent: id|null, project: path|null, for_agent}`
/// `for_agent` is the agent that asked (used to check the grant takes effect).
pub fn allow(st: &Arc<UiState>, body: &Value) -> Reply {
    let kind = body["kind"].as_str().context("kind required")?;
    let for_agent = body["for_agent"].as_str().filter(|s| !s.is_empty()).context("for_agent required")?;
    let agent = body["agent"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    let project = match body["project"].as_str().filter(|s| !s.is_empty()) {
        Some(p) => Some(scope_project(p)?),
        None => None,
    };
    if agent.as_deref().is_some_and(|a| a != for_agent) {
        bail!("a grant for one agent must be for the agent that asked");
    }
    if !access::valid_agent(for_agent) {
        bail!("unsupported agent id {for_agent:?}");
    }
    let _g = ACCESS_LOCK.lock().unwrap();
    let scope = Scope { agent, project: project.clone() };
    let probe_project = project.clone().unwrap_or_else(|| PathBuf::from(super::api::NO_PROJECT));
    // `targets`: exact files (the default in the console). `target` + `dir`:
    // one file, or a whole folder when the human chose it.
    let (grant, patterns, probes): (Grant, Vec<String>, Vec<(Action, Resource)>) = match kind {
        "site" => {
            let target = body["target"].as_str().context("target required")?.trim();
            if !netlive::is_named_host(target) {
                bail!("{target:?} is not a host name");
            }
            let h = netlive::host_key(target);
            (Grant::Site, vec![h.clone()], vec![(Action::NetConnect, Resource::Host { host: h, port: 443 })])
        }
        "read" | "write" => {
            let (list, dir): (Vec<String>, bool) = match body["targets"].as_array() {
                Some(a) => (a.iter().map(|v| v.as_str().map(str::to_string).context("targets must be strings")).collect::<Result<_>>()?, false),
                None => (vec![body["target"].as_str().context("target or targets required")?.to_string()], body["dir"].as_bool().unwrap_or(false)),
            };
            if list.is_empty() || list.len() > 50 {
                bail!("between 1 and 50 paths, please");
            }
            let home = agentacl_core::identity::human()?.home;
            let (mut patterns, mut probes) = (vec![], vec![]);
            let action = if kind == "read" { Action::FsRead } else { Action::FsWrite(WriteOp::Write) };
            for raw in &list {
                // No trimming: the agent names refused files, and "x.txt " is
                // not "x.txt".
                if raw.trim() != raw.as_str() {
                    bail!("{raw:?} starts or ends with whitespace; allow it from Policies instead");
                }
                let t = raw.trim_end_matches('/');
                if !representable(t) || t.is_empty() {
                    bail!("{raw:?} can't be written as a rule");
                }
                // The keychain database: the login keychain can be cracked offline.
                if fold_path(t).contains("/library/keychains") {
                    bail!("{t} is a keychain database; keychain files can't be allowed from a request");
                }
                // Not your whole home, nor a top-level system folder, in one click.
                if too_broad(t, &home.to_string_lossy()) {
                    bail!("{t} is too broad to allow from a request: allow the files it needs (Policies has the full access map)");
                }
                patterns.push(if dir { format!("{t}/**") } else { t.to_string() });
                probes.push((action, Resource::Path(if dir { format!("{t}/.agentacl-probe") } else { t.to_string() })));
            }
            (if kind == "read" { Grant::Read } else { Grant::Write }, patterns, probes)
        }
        o => bail!("unknown kind {o:?}"),
    };
    let Some((name, yaml)) = access::with_rules(&st.paths, &scope, grant, &patterns)? else {
        return Ok((200, json!({ "ok": true, "file": access::file_name(&scope), "unchanged": true })));
    };
    // The complete policy must still load and compile, and every grant must
    // actually take effect (a built-in protection wins over any allow).
    let chk = draft::check_access(&st.paths, for_agent, &probe_project, &name, Some(&yaml)).map_err(|e| e.context("the grant was refused"))?;
    for (action, resource) in probes {
        let subject = Subject { agent_id: for_agent.into(), project: probe_project.to_string_lossy().into(), ..Default::default() };
        let shown = match &resource {
            Resource::Path(p) => p.trim_end_matches("/.agentacl-probe").to_string(),
            Resource::Host { host, .. } => host.clone(),
            _ => String::new(),
        };
        let d = chk.policy.evaluate(&Request { subject, action, resource });
        if d.effect != Effect::Allow {
            match d.policy.as_str() {
                "user" | "project" => bail!("{shown} is still blocked by your own rule ({}): change it in Network or Policies", d.reason),
                "protect-secrets" | "exec-persistence" | "agentacl-self" | "builtin" => {
                    bail!("{shown} is protected by the built-in {} rule ({}): built-in protections can't be allowed from a request", d.policy, d.reason)
                }
                _ => bail!("{shown} is still blocked ({}): {}", d.rule_id, d.reason),
            }
        }
    }
    access::store(&st.paths, &name, Some(&yaml))?;
    let source = format!("access:{}", name.trim_end_matches(".yaml"));
    if grant == Grant::Site {
        netlive::set_scoped_rule(&state_dir(st), &patterns[0], Effect::Allow, scope.agent.as_deref(), scope.project.as_deref().map(|p| p.to_str().unwrap_or_default()), &source)?;
    }
    let who = scope.agent.as_deref().map(agent_name).unwrap_or_else(|| "every agent".into());
    let where_ = scope.project.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "every project".into());
    for pattern in &patterns {
        st.store.lock().unwrap().record_ui(&st.ctx, "access.granted", pattern, &format!("{kind} for {who} in {where_} ({name})"))?;
    }
    Ok((200, json!({ "ok": true, "file": name, "patterns": patterns, "applies_now": grant == Grant::Site })))
}

/// `GET /api/access[?agent=]`: the access documents and their rules.
pub fn list(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let want = q.get("agent").filter(|s| !s.is_empty());
    // Hand edits of access files reach the live rules too.
    sync_live(st, None)?;
    let (docs, broken) = access::scan(&st.paths)?;
    let mut out = vec![];
    for (file, _, doc) in docs {
        let m = doc.match_.clone().unwrap_or_default();
        let agent = m.agents.first().cloned();
        if let Some(w) = want {
            if agent.as_deref().is_some_and(|a| a != w) {
                continue;
            }
        }
        let mut rules = vec![];
        for (section, list) in [("allow_read", &doc.filesystem.allow_read), ("allow_write", &doc.filesystem.allow_write), ("network.allow", &doc.network.allow)] {
            for r in list {
                rules.push(json!({ "section": section, "pattern": r.pattern, "display": term_safe(&r.pattern) }));
            }
        }
        out.push(json!({
            "file": file,
            "agent": agent,
            "agent_name": agent.as_deref().map(agent_name),
            "project": m.projects.first(),
            "rules": rules,
        }));
    }
    let broken: Vec<Value> = broken.into_iter().map(|(file, why)| json!({ "file": file, "error": term_safe(&why) })).collect();
    Ok((200, json!({ "access": out, "broken": broken, "dir": access::dir(&st.paths) })))
}

/// `POST /api/access/remove {file, section, pattern}`
pub fn remove(st: &Arc<UiState>, body: &Value) -> Reply {
    let file = body["file"].as_str().context("file required")?;
    // A broken access file (left out of every session) is removed whole.
    if body["broken"].as_bool() == Some(true) {
        let _g = ACCESS_LOCK.lock().unwrap();
        if !access::scan(&st.paths)?.1.iter().any(|(n, _)| n == file) {
            bail!("{file} isn't a broken access file");
        }
        access::store(&st.paths, file, None)?;
        st.store.lock().unwrap().record_ui(&st.ctx, "access.removed", file, "broken access file")?;
        sync_live(st, None)?;
        return Ok((200, json!({ "ok": true })));
    }
    let section = body["section"].as_str().context("section required")?;
    let pattern = body["pattern"].as_str().context("pattern required")?;
    let _g = ACCESS_LOCK.lock().unwrap();
    let yaml = access::without_rule(&st.paths, file, section, pattern)?;
    // Removing can only restrict, but the result must still load.
    draft::check_access(&st.paths, "claude-code", Path::new(super::api::NO_PROJECT), file, yaml.as_deref()).map_err(|e| e.context("the change was refused"))?;
    access::store(&st.paths, file, yaml.as_deref())?;
    if section == "network.allow" {
        netlive::remove_scoped_rule(&state_dir(st), pattern, &format!("access:{}", file.trim_end_matches(".yaml")))?;
        sync_live(st, Some(pattern))?;
    }
    st.store.lock().unwrap().record_ui(&st.ctx, "access.removed", pattern, &format!("{section} in {file}"))?;
    Ok((200, json!({ "ok": true })))
}

/// `POST /api/approvals/extend {id}`: one more minute for a waiting request.
pub fn extend(st: &Arc<UiState>, body: &Value) -> Reply {
    let id = body["id"].as_str().context("id required")?;
    let a = netlive::extend(&state_dir(st), id)?;
    Ok((200, json!({ "ok": true, "expires": a.expires })))
}

/// `POST /api/network/wait {secs}`: how long agents wait for an answer.
pub fn set_wait(st: &Arc<UiState>, body: &Value) -> Reply {
    let secs = body["secs"].as_u64().context("secs required")?;
    netlive::set_wait(&state_dir(st), secs)?;
    st.store.lock().unwrap().record_ui(&st.ctx, "network.wait", &secs.to_string(), "wait for an answer changed")?;
    Ok((200, json!({ "ok": true, "secs": secs })))
}

/// `GET /api/notify`: quiet mode and the wait for answers.
pub fn notify_get(st: &Arc<UiState>) -> Reply {
    let n = agentacl_core::notify::read(&state_dir(st));
    let now = agentacl_core::notify::now();
    let until = n.quiet_until.filter(|u| *u > now);
    let live = netlive::read_live(&state_dir(st));
    Ok((
        200,
        json!({
            "quiet": n.quiet,
            "quiet_until": until.map(|u| agentacl_core::audit::format_rfc3339(u, 0)),
            "wait_secs": live.ask_timeout_secs.unwrap_or(netlive::ASK_TIMEOUT.as_secs()),
            "wait_choices": netlive::WAIT_CHOICES,
        }),
    ))
}

/// `POST /api/notify {quiet: bool, minutes?: n}`: quiet on/off, or quiet for
/// `minutes` (1 to 1440).
pub fn notify_set(st: &Arc<UiState>, body: &Value) -> Reply {
    let quiet = body["quiet"].as_bool().context("quiet required")?;
    let until = match body["minutes"].as_u64() {
        Some(m) if (1..=1440).contains(&m) => Some(agentacl_core::notify::now() + m as i64 * 60),
        Some(_) => bail!("minutes must be between 1 and 1440"),
        None => None,
    };
    // "Quiet for N minutes" is temporary: it doesn't switch quiet on for good.
    let permanent = quiet && until.is_none();
    agentacl_core::notify::set_quiet(&state_dir(st), permanent, until)?;
    notify_get(st)
}
