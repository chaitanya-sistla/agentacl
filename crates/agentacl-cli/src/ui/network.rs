//! Network sites, live approvals and the requests inbox (ui.md §4.8).
//!
//! Site rules are written twice: to the user policy (durable, reviewable, used
//! by new sessions) and to the live file every running proxy reads
//! (`agentacl_core::netlive`), so a block applies immediately.

use super::UiState;
use agentacl_core::draft::{self, Scope};
use agentacl_core::escape::term_safe;
use agentacl_core::netcat::{categorize, Category};
use agentacl_core::netlive::{self, Answer, Mode};
use agentacl_core::{fsafe, supervisor};
use agentacl_policy::emit::to_yaml;
use agentacl_policy::raw::{parse_doc, RawRule, RuleKind};
use agentacl_policy::{Effect, Layer};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Reply = Result<(u16, Value)>;

const DISMISSED_FILE: &str = "ui-dismissed.json";
/// Serializes read-modify-write of the dismissed list across request threads.
static DISMISSED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What a host resolves to for an agent right now: policy (machine-wide, no
/// project) adjusted by the console's live rules. PolicySets are cached per agent.
struct SiteEval<'a> {
    st: &'a Arc<UiState>,
    sets: HashMap<String, Option<agentacl_policy::set::PolicySet>>,
    live: netlive::Live,
    allow: BTreeSet<String>,
    deny: BTreeSet<String>,
}

impl<'a> SiteEval<'a> {
    fn new(st: &'a Arc<UiState>) -> Self {
        let (allow, deny) = policy_hosts(st).unwrap_or_default();
        SiteEval { st, sets: HashMap::new(), live: netlive::read_live(&state_dir(st)), allow, deny }
    }

    /// `{effect, policy, rule_id, reason, by, allowable}`. `by`: you | console |
    /// agent | builtin | default | other. `allowable`: an Allow from the console
    /// would make it reachable (it is only blocked by the default, or by your
    /// own block rule).
    fn eval(&mut self, host: &str, agents: &[String], port: u16) -> Value {
        let agent = agents.iter().find(|a| agentacl_core::agents::provider(a).is_some()).cloned().unwrap_or_else(|| "claude-code".into());
        let paths = &self.st.paths;
        let set = self.sets.entry(agent.clone()).or_insert_with(|| draft::check(paths, &agent, Path::new(super::api::NO_PROJECT), Scope::User, None).ok().map(|c| c.policy));
        let key = netlive::host_key(host);
        if self.live.rules.iter().any(|r| r.host == key && r.effect == Effect::Deny) || self.deny.contains(&key) {
            // Would an Allow work? Evaluate as if your block were an allow.
            let allowable = netlive::is_named_host(&key) && without_own_block(self.st, &key, &agent, port);
            return json!({ "effect": "deny", "by": "you", "reason": "You blocked this site", "allowable": allowable });
        }
        let Some(set) = set else { return json!({ "effect": "deny", "by": "other", "reason": "Your policy has a problem", "allowable": false }) };
        use agentacl_policy::PolicyEngine;
        let subject = agentacl_policy::Subject { agent_id: agent, project: super::api::NO_PROJECT.into(), ..Default::default() };
        let d = set.evaluate(&agentacl_policy::Request { subject, action: agentacl_policy::Action::NetConnect, resource: agentacl_policy::Resource::Host { host: key.clone(), port } });
        let by = if d.effect == Effect::Allow && self.allow.contains(&key) {
            "you"
        } else if d.policy.starts_with("provider:") {
            "agent"
        } else if d.rule_id == "default" {
            if self.live.rules.iter().any(|r| r.host == key && r.effect == Effect::Allow) {
                "console"
            } else {
                "default"
            }
        } else if matches!(d.policy.as_str(), "protect-secrets" | "exec-persistence" | "agentacl-self" | "runtime" | "builtin") {
            "builtin"
        } else {
            "other"
        };
        let allowable = netlive::is_named_host(&key) && (d.rule_id == "default" || d.effect == Effect::Allow);
        json!({ "effect": d.effect, "policy": d.policy, "rule_id": d.rule_id, "reason": term_safe(&d.reason), "by": by, "allowable": allowable })
    }
}

fn state_dir(st: &Arc<UiState>) -> PathBuf {
    supervisor::canon_or(&st.paths.state_dir)
}

fn since_days(q: &HashMap<String, String>) -> (u64, String) {
    let days = q.get("days").and_then(|d| d.parse::<u64>().ok()).unwrap_or(7).clamp(1, 90);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    (days, agentacl_core::audit::format_rfc3339(now - days as i64 * 86_400, 0))
}

fn host_of(resource: &str) -> String {
    // "host:port" or "[v6]:port"
    let h = match resource.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => resource,
    };
    h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase()
}

fn category_json(host: &str) -> Value {
    let c = if netlive::is_named_host(host) { categorize(host) } else { Category::Unknown };
    json!({ "id": c, "label": c.label(), "advice": c.advice() })
}

type HostSets = (BTreeSet<String>, BTreeSet<String>);

/// Host patterns in the user policy's network.allow / network.deny (empty
/// when there is no user policy; an error when it can't be read or parsed).
pub fn policy_hosts(st: &Arc<UiState>) -> Result<HostSets> {
    let Some(bytes) = draft::read_policy(&st.paths, Scope::User, Path::new(super::api::NO_PROJECT))? else { return Ok(Default::default()) };
    let doc = parse_doc(&String::from_utf8_lossy(&bytes), Layer::User, "user")?;
    let set = |v: &[RawRule]| v.iter().map(|r| r.pattern.to_ascii_lowercase()).collect::<BTreeSet<_>>();
    Ok((set(&doc.network.allow), set(&doc.network.deny)))
}

/// Adds (or with `None` removes) `host` in the user policy's network lists,
/// through the same validated, conflict-checked save as the rules editor.
fn set_policy_host(st: &Arc<UiState>, host: &str, effect: Option<Effect>) -> Result<bool> {
    let project = PathBuf::from(super::api::NO_PROJECT);
    let bytes = draft::read_policy(&st.paths, Scope::User, &project)?;
    let base = bytes.as_deref().map(agentacl_policy::set::sha256_hex);
    let yaml = match &bytes {
        Some(b) => String::from_utf8_lossy(b).into_owned(),
        None => super::api::seed_user_policy(),
    };
    let comments_lost = bytes.is_some() && yaml.lines().any(|l| l.trim_start().starts_with('#'));
    let mut doc = parse_doc(&yaml, Layer::User, "user").context("your policy file has a problem; fix it in Policies first")?;
    let key = netlive::host_key(host);
    doc.network.allow.retain(|r| r.pattern.to_ascii_lowercase() != key);
    doc.network.deny.retain(|r| r.pattern.to_ascii_lowercase() != key);
    let rule = |reason: &str| RawRule { kind: RuleKind::Host, pattern: key.clone(), except: vec![], id: None, reason: Some(reason.into()) };
    match effect {
        Some(Effect::Allow) => doc.network.allow.push(rule("Allowed in the AgentACL console")),
        Some(Effect::Deny) => doc.network.deny.push(rule("Blocked in the AgentACL console")),
        _ => {}
    }
    // A network change can't affect project read access, so no confirmation is needed.
    match draft::save(&st.paths, "claude-code", &project, Scope::User, &to_yaml(&doc), base.as_deref(), true) {
        Ok(_) => {}
        Err(draft::SaveError::Invalid(e)) => return Err(e.context("the policy change was refused")),
        Err(draft::SaveError::Conflict(_)) => bail!("your policy file changed while saving; try again"),
        Err(draft::SaveError::NeedsConfirm(what)) => bail!("saving needs confirmation ({what}); make this change in Policies"),
    }
    Ok(comments_lost)
}

fn apply_site_rule(st: &Arc<UiState>, host: &str, effect: Option<Effect>) -> Result<Value> {
    if !netlive::is_named_host(host) {
        bail!("{host:?} is not a site name (IP addresses and localhost are managed with address rules in Policies)");
    }
    let before = policy_hosts(st).ok();
    let comments_lost = set_policy_host(st, host, effect)?;
    netlive::set_rule(&state_dir(st), host, effect)?;
    reconcile_live(st, before.as_ref())?;
    let verb = match effect {
        Some(Effect::Allow) => "network.allowed",
        Some(_) => "network.blocked",
        None => "network.rule_removed",
    };
    st.store.lock().unwrap().record_ui(&st.ctx, verb, &netlive::host_key(host), "site rule changed in the console")?;
    Ok(json!({ "ok": true, "comments_lost": comments_lost }))
}

/// Evaluates `host` for `agent` with the user's own exact rule for it turned
/// into an allow: true if nothing else (wildcards, built-ins, providers)
/// would still block it.
fn without_own_block(st: &Arc<UiState>, host: &str, agent: &str, port: u16) -> bool {
    let project = PathBuf::from(super::api::NO_PROJECT);
    let Ok(Some(bytes)) = draft::read_policy(&st.paths, Scope::User, &project) else { return true };
    let Ok(mut doc) = parse_doc(&String::from_utf8_lossy(&bytes), Layer::User, "user") else { return false };
    doc.network.deny.retain(|r| r.pattern.to_ascii_lowercase() != host);
    doc.network.allow.push(RawRule { kind: RuleKind::Host, pattern: host.into(), except: vec![], id: None, reason: None });
    let Ok(c) = draft::check(&st.paths, agent, &project, Scope::User, Some(&to_yaml(&doc))) else { return false };
    use agentacl_policy::PolicyEngine;
    let subject = agentacl_policy::Subject { agent_id: agent.into(), project: super::api::NO_PROJECT.into(), ..Default::default() };
    c.policy.evaluate(&agentacl_policy::Request { subject, action: agentacl_policy::Action::NetConnect, resource: agentacl_policy::Resource::Host { host: host.into(), port } }).effect == Effect::Allow
}

/// After any user-policy save: drop live rules the policy no longer has, so
/// removing a rule from the file removes it for running sessions too.
/// `before` is the policy's host lists before the save: allows removed since
/// are revoked for sessions that loaded them (unless another rule still allows
/// the host). An unreadable policy leaves the live file alone.
pub fn reconcile_live(st: &Arc<UiState>, before: Option<&HostSets>) -> Result<()> {
    let Ok((allow, deny)) = policy_hosts(st) else { return Ok(()) };
    netlive::reconcile(&state_dir(st), &allow, &deny)?;
    if let Some((was_allowed, _)) = before {
        let mut ev = SiteEval::new(st);
        let gone: Vec<String> = was_allowed.difference(&allow).filter(|h| netlive::is_named_host(h)).filter(|h| ev.eval(h, &[], 443)["effect"] != "allow").cloned().collect();
        netlive::revoke(&state_dir(st), &gone)?;
    }
    Ok(())
}

// ---- sites ------------------------------------------------------------------------

pub fn network(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let (days, since) = since_days(q);
    let rows = st.store.lock().unwrap().network_activity(&since)?;
    let live = netlive::read_live(&state_dir(st));
    let (p_allow, p_deny) = policy_hosts(st).unwrap_or_default();
    let mut by_host: BTreeMap<String, Value> = BTreeMap::new();
    for r in rows {
        let resource = r["resource"].as_str().unwrap_or_default();
        let host = host_of(resource);
        let port = resource.rsplit_once(':').map(|(_, p)| p.to_string()).unwrap_or_default();
        let e = by_host.entry(host.clone()).or_insert_with(|| json!({ "host": host, "display": term_safe(&host), "ports": [], "allowed": 0, "blocked": 0, "first_seen": r["first_seen"], "last_seen": r["last_seen"], "agents": [], "projects": [], "last": r["last"] }));
        e["allowed"] = json!(e["allowed"].as_i64().unwrap_or(0) + r["allowed"].as_i64().unwrap_or(0));
        e["blocked"] = json!(e["blocked"].as_i64().unwrap_or(0) + r["blocked"].as_i64().unwrap_or(0));
        if r["first_seen"].as_str() < e["first_seen"].as_str() {
            e["first_seen"] = r["first_seen"].clone();
        }
        if r["last_seen"].as_str() > e["last_seen"].as_str() {
            e["last_seen"] = r["last_seen"].clone();
            e["last"] = r["last"].clone();
        }
        for (k, vals) in [("ports", vec![Value::String(port)]), ("agents", r["agents"].as_array().cloned().unwrap_or_default()), ("projects", r["projects"].as_array().cloned().unwrap_or_default())] {
            let mut set: BTreeSet<String> = e[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
            set.extend(vals.into_iter().filter_map(|v| v.as_str().map(str::to_string)));
            e[k] = json!(set);
        }
    }
    // Sites with a rule but no traffic yet.
    for h in p_allow.iter().chain(p_deny.iter()).chain(live.rules.iter().map(|r| &r.host)) {
        if !h.contains('*') {
            by_host.entry(h.clone()).or_insert_with(
                || json!({ "host": h, "display": term_safe(h), "ports": [], "allowed": 0, "blocked": 0, "first_seen": null, "last_seen": null, "agents": [], "projects": [], "last": null }),
            );
        }
    }
    let mut ev = SiteEval::new(st);
    let sites: Vec<Value> = by_host
        .into_values()
        .map(|mut v| {
            let h = v["host"].as_str().unwrap_or_default().to_string();
            let agents: Vec<String> = v["agents"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
            let ports: Vec<u16> = v["ports"].as_array().into_iter().flatten().filter_map(|x| x.as_str()?.parse().ok()).collect();
            let port = if ports.is_empty() || ports.contains(&443) { 443 } else { *ports.iter().min().unwrap_or(&443) };
            v["effective"] = ev.eval(&h, &agents, port);
            v["category"] = category_json(&h);
            v["policy_rule"] = json!(if p_deny.contains(&h) {
                "block"
            } else if p_allow.contains(&h) {
                "allow"
            } else {
                ""
            });
            v["console_rule"] = json!(live.rules.iter().find(|r| r.host == h).map(|r| if r.effect == Effect::Allow { "allow" } else { "block" }).unwrap_or(""));
            v["manageable"] = json!(netlive::is_named_host(&h));
            v
        })
        .collect();
    let wildcards: Vec<Value> = p_allow
        .iter()
        .filter(|h| h.contains('*'))
        .map(|h| json!({ "pattern": h, "effect": "allow" }))
        .chain(p_deny.iter().filter(|h| h.contains('*')).map(|h| json!({ "pattern": h, "effect": "block" })))
        .collect();
    Ok((200, json!({ "days": days, "mode": live.mode, "sites": sites, "patterns": wildcards })))
}

pub fn network_rule(st: &Arc<UiState>, body: &Value) -> Reply {
    let host = body["host"].as_str().context("host required")?;
    let effect = match body["effect"].as_str() {
        Some("allow") => Some(Effect::Allow),
        Some("block") => Some(Effect::Deny),
        Some("none") => None,
        _ => bail!("effect must be allow, block or none"),
    };
    Ok((200, apply_site_rule(st, host, effect)?))
}

pub fn network_mode(st: &Arc<UiState>, body: &Value) -> Reply {
    let mode = match body["mode"].as_str() {
        Some("ask") => Mode::Ask,
        Some("block") => Mode::Block,
        _ => bail!("mode must be ask or block"),
    };
    netlive::set_mode(&state_dir(st), mode)?;
    st.store.lock().unwrap().record_ui(&st.ctx, "network.mode", if mode == Mode::Ask { "ask" } else { "block" }, "unknown-site mode changed in the console")?;
    Ok((200, json!({ "ok": true, "mode": mode })))
}

// ---- live approvals -------------------------------------------------------------------

pub fn approvals(st: &Arc<UiState>) -> Reply {
    let sd = state_dir(st);
    netlive::prune(&sd);
    let list: Vec<Value> = netlive::pending(&sd)
        .into_iter()
        .map(|a| {
            let name = agentacl_core::agents::provider(&a.agent).map(|p| p.display_name().to_string()).unwrap_or(a.agent.clone());
            json!({
                "id": a.id, "session": a.session, "agent": a.agent, "agent_name": name, "project": a.project,
                "host": a.host, "display": term_safe(&a.host), "port": a.port, "created": a.created, "expires": a.expires,
                "category": category_json(&a.host),
            })
        })
        .collect();
    let requests_new = requests_new(st)?;
    Ok((200, json!({ "approvals": list, "requests_new": requests_new, "mode": netlive::read_live(&sd).mode })))
}

pub fn approval_answer(st: &Arc<UiState>, body: &Value) -> Reply {
    let id = body["id"].as_str().context("id required")?;
    let ans = match body["answer"].as_str() {
        Some("once") => Answer::Once,
        Some("session") => Answer::Session,
        Some("always") => Answer::Always,
        Some("block") => Answer::Block,
        Some("block-always") => Answer::BlockAlways,
        _ => bail!("answer must be once, session, always, block or block-always"),
    };
    // Save the durable rule first, so a failure is reported before the agent proceeds.
    let mut saved = Value::Null;
    if matches!(ans, Answer::Always | Answer::BlockAlways) {
        let a = netlive::pending(&state_dir(st)).into_iter().find(|a| a.id == id).context("this request is no longer waiting (it may have timed out)")?;
        saved = apply_site_rule(st, &a.host, Some(if ans == Answer::Always { Effect::Allow } else { Effect::Deny }))?;
    }
    let a = match netlive::answer(&state_dir(st), id, ans) {
        Ok(a) => a,
        // The rule is saved; only the waiting connection timed out meanwhile.
        Err(e) if !saved.is_null() => return Ok((200, json!({ "ok": true, "saved": saved, "note": format!("Rule saved. {e}") }))),
        Err(e) => return Err(e),
    };
    st.store.lock().unwrap().record_ui(&st.ctx, "network.answered", &a.host, &format!("{ans:?} for session {}", a.session))?;
    Ok((200, json!({ "ok": true, "saved": saved })))
}

// ---- requests inbox ---------------------------------------------------------------------

fn format_since(days: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    agentacl_core::audit::format_rfc3339(now - days * 86_400, 0)
}

fn read_dismissed(st: &Arc<UiState>) -> BTreeMap<String, String> {
    fsafe::open_dir(&state_dir(st)).ok().and_then(|d| fsafe::read_regular(&d, DISMISSED_FILE).ok().flatten()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// One request per area, not per nested folder: at most three levels below
/// the home folder (e.g. ~/Library/Caches/com.apple.python), or three below `/`.
fn folder_group(dir: &str, home: &str) -> String {
    let (base, rest) = match dir.strip_prefix(home).filter(|_| !home.is_empty()) {
        Some(r) => (home.to_string(), r.to_string()),
        None => (String::new(), dir.to_string()),
    };
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).take(3).collect();
    if parts.is_empty() {
        return if base.is_empty() { "/".into() } else { base };
    }
    format!("{base}/{}", parts.join("/"))
}

fn parent_dir(p: &str) -> String {
    Path::new(p).parent().map(|d| d.to_string_lossy().into_owned()).filter(|d| !d.is_empty()).unwrap_or_else(|| "/".into())
}

/// Blocked actions grouped into requests a human can decide on.
/// New (undismissed) requests in the last 24 h, recomputed at most every 30 s:
/// the console polls approvals every 2 s.
static NEW_CACHE: std::sync::Mutex<Option<(std::time::Instant, usize)>> = std::sync::Mutex::new(None);

fn requests_new(st: &Arc<UiState>) -> Result<usize> {
    if let Some((t, n)) = *NEW_CACHE.lock().unwrap() {
        if t.elapsed() < std::time::Duration::from_secs(30) {
            return Ok(n);
        }
    }
    let n = inbox_groups(st, &format_since(1))?.into_iter().filter(|g| !g["dismissed"].as_bool().unwrap_or(false)).count();
    *NEW_CACHE.lock().unwrap() = Some((std::time::Instant::now(), n));
    Ok(n)
}

fn inbox_groups(st: &Arc<UiState>, since: &str) -> Result<Vec<Value>> {
    let rows = st.store.lock().unwrap().blocked_groups(since, 5000)?;
    let dismissed = read_dismissed(st);
    let home = agentacl_core::identity::human().map(|h| h.home.to_string_lossy().into_owned()).unwrap_or_default();
    let mut groups: BTreeMap<String, Value> = BTreeMap::new();
    for r in rows {
        let action = r["action"].as_str().unwrap_or_default().to_string();
        let resource = r["resource"].as_str().unwrap_or_default().to_string();
        let policy = r["policy"].as_str().unwrap_or_default().to_string();
        let rule = r["rule_id"].as_str().unwrap_or_default().to_string();
        let (key, kind, target) = if action == "network.connect" {
            let h = host_of(&resource);
            (format!("net:{h}"), "network", h)
        } else if action.starts_with("filesystem.") {
            if policy == "protect-secrets" {
                (format!("secret:{rule}"), "secret", rule.clone())
            } else if matches!(policy.as_str(), "exec-persistence" | "agentacl-self") || policy.starts_with("provider:") {
                // A provider policy only denies the agent's own settings (protected-config).
                let d = folder_group(&parent_dir(&resource), &home);
                (format!("locked:{policy}:{d}"), "locked", d)
            } else {
                let d = folder_group(&parent_dir(&resource), &home);
                (format!("fs:{d}"), "file", d)
            }
        } else if action == "process.exec" {
            (format!("exec:{resource}"), "program", resource.clone())
        } else {
            (format!("other:{action}:{resource}"), "other", resource.clone())
        };
        let g = groups.entry(key.clone()).or_insert_with(|| {
            json!({
                "key": key, "kind": kind, "target": target, "display": term_safe(&target), "actions": [], "samples": [],
                "count": 0, "first_seen": r["first_seen"], "last_seen": r["last_seen"], "agents": [], "projects": [],
                "policy": policy, "rule_id": rule, "reason": term_safe(r["reason"].as_str().unwrap_or_default()),
            })
        });
        g["count"] = json!(g["count"].as_i64().unwrap_or(0) + r["count"].as_i64().unwrap_or(0));
        if r["first_seen"].as_str() < g["first_seen"].as_str() {
            g["first_seen"] = r["first_seen"].clone();
        }
        if r["last_seen"].as_str() > g["last_seen"].as_str() {
            g["last_seen"] = r["last_seen"].clone();
        }
        let mut add = |k: &str, vals: Vec<String>| {
            let mut set: BTreeSet<String> = g[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
            set.extend(vals);
            g[k] = json!(set);
        };
        add("actions", vec![action.clone()]);
        add("agents", r["agents"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect());
        add("projects", r["projects"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect());
        if let Some(s) = g["samples"].as_array_mut() {
            if s.len() < 5 {
                s.push(json!(term_safe(&resource)));
            }
        }
    }
    let mut out: Vec<Value> = groups
        .into_values()
        .map(|mut g| {
            let key = g["key"].as_str().unwrap_or_default().to_string();
            // Dismissed stays dismissed until it happens again.
            let d = dismissed.get(&key).is_some_and(|at| g["last_seen"].as_str().is_some_and(|l| l <= at.as_str()));
            g["dismissed"] = json!(d);
            if g["kind"] == "network" {
                let h = g["target"].as_str().unwrap_or_default().to_string();
                g["category"] = category_json(&h);
                g["manageable"] = json!(netlive::is_named_host(&h));
            }
            g
        })
        .collect();
    out.sort_by(|a, b| b["last_seen"].as_str().cmp(&a["last_seen"].as_str()));
    Ok(out)
}

/// The inbox, one page at a time. `kind`: all | network | file (with
/// protected settings) | secret | program. Counts per kind cover every page.
pub fn requests(st: &Arc<UiState>, q: &HashMap<String, String>) -> Reply {
    let (days, since) = since_days(q);
    let all = inbox_groups(st, &since)?;
    let show_dismissed = q.get("dismissed").is_some_and(|v| v == "1");
    let dismissed_count = all.iter().filter(|g| g["dismissed"].as_bool().unwrap_or(false)).count();
    let visible: Vec<Value> = all.into_iter().filter(|g| show_dismissed || !g["dismissed"].as_bool().unwrap_or(false)).collect();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for g in &visible {
        let k = match g["kind"].as_str().unwrap_or("other") {
            "locked" => "file",
            k @ ("network" | "file" | "secret" | "program") => k,
            _ => "other",
        };
        *counts.entry(k).or_default() += 1;
    }
    let kind = q.get("kind").map(String::as_str).unwrap_or("all");
    let matches = |g: &Value| match kind {
        "all" => true,
        "file" => matches!(g["kind"].as_str(), Some("file" | "locked")),
        k => g["kind"].as_str() == Some(k),
    };
    let filtered: Vec<Value> = visible.iter().filter(|g| matches(g)).cloned().collect();
    let size = q.get("size").and_then(|v| v.parse::<usize>().ok()).unwrap_or(25).clamp(1, 200);
    let total = filtered.len();
    let pages = total.div_ceil(size).max(1);
    let page = q.get("page").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1).clamp(1, pages);
    // Evaluate (compile policy per agent) only for the rows on this page.
    let mut ev = SiteEval::new(st);
    let rows: Vec<Value> = filtered
        .into_iter()
        .skip((page - 1) * size)
        .take(size)
        .map(|mut g| {
            if g["kind"] == "network" {
                let h = g["target"].as_str().unwrap_or_default().to_string();
                let agents: Vec<String> = g["agents"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
                g["effective"] = ev.eval(&h, &agents, 443);
            }
            g
        })
        .collect();
    Ok((
        200,
        json!({
            "days": days, "requests": rows, "dismissed": dismissed_count,
            "total": total, "page": page, "size": size, "pages": pages,
            "all": visible.len(), "counts": counts,
            // Keys of every matching row, for "Dismiss all" across pages.
            "keys": visible.iter().filter(|g| matches(g) && !g["dismissed"].as_bool().unwrap_or(false)).map(|g| g["key"].clone()).collect::<Vec<_>>(),
        }),
    ))
}

pub fn request_dismiss(st: &Arc<UiState>, body: &Value) -> Reply {
    // One key, or many ("Dismiss all shown").
    let keys: Vec<String> = match (body["key"].as_str(), body["keys"].as_array()) {
        (Some(k), _) => vec![k.to_string()],
        (None, Some(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => bail!("key required"),
    };
    if keys.len() > 5000 || keys.iter().any(|k| k.len() > 2048 || k.chars().any(char::is_control)) {
        bail!("invalid key");
    }
    let _g = DISMISSED_LOCK.lock().unwrap();
    *NEW_CACHE.lock().unwrap() = None;
    let mut d = read_dismissed(st);
    let now = agentacl_core::audit::now_rfc3339();
    for key in keys {
        if body["undo"].as_bool().unwrap_or(false) {
            d.remove(&key);
        } else {
            d.insert(key, now.clone());
        }
    }
    let dir = fsafe::open_dir(&state_dir(st))?;
    fsafe::write_atomic(&dir, DISMISSED_FILE, serde_json::to_string(&d)?.as_bytes())?;
    Ok((200, json!({ "ok": true })))
}

/// Overview charts: allowed/blocked per hour, top sites, blocks by kind.
pub fn stats_extra(st: &Arc<UiState>, now_secs: i64, since: &str) -> Result<Value> {
    let store = st.store.lock().unwrap();
    let hourly: Vec<Value> = store.hourly_split(now_secs)?.into_iter().map(|(a, b)| json!({ "allowed": a, "blocked": b })).collect();
    let net = store.network_activity(since)?;
    let breakdown = store.blocked_breakdown(since)?;
    drop(store);
    let mut hosts: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for r in &net {
        let e = hosts.entry(host_of(r["resource"].as_str().unwrap_or_default())).or_default();
        e.0 += r["allowed"].as_i64().unwrap_or(0);
        e.1 += r["blocked"].as_i64().unwrap_or(0);
    }
    let top = |f: fn(&(i64, i64)) -> i64| -> Vec<Value> {
        let mut v: Vec<(&String, &(i64, i64))> = hosts.iter().filter(|(_, c)| f(c) > 0).collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(f(c)));
        v.into_iter().take(8).map(|(h, c)| json!({ "host": term_safe(h), "count": f(c), "category": category_json(h) })).collect()
    };
    let mut kinds: BTreeMap<&str, i64> = BTreeMap::new();
    for b in &breakdown {
        let (action, policy, rule) = (b["action"].as_str().unwrap_or_default(), b["policy"].as_str().unwrap_or_default(), b["rule_id"].as_str().unwrap_or_default());
        let k = if action == "network.connect" {
            "Network"
        } else if policy == "protect-secrets" {
            "Secrets"
        } else if matches!(policy, "exec-persistence" | "agentacl-self") || policy.starts_with("provider:") || rule == "protected-config" {
            "Protected settings"
        } else if action == "process.exec" {
            "Programs"
        } else if policy == "seatbelt-baseline" {
            "macOS sandbox baseline"
        } else {
            "Files outside the project"
        };
        *kinds.entry(k).or_default() += b["count"].as_i64().unwrap_or(0);
    }
    Ok(json!({
        "hourly": hourly,
        "top_blocked_sites": top(|c| c.1),
        "top_allowed_sites": top(|c| c.0),
        "blocked_by_kind": kinds.into_iter().map(|(k, v)| json!({ "kind": k, "count": v })).collect::<Vec<_>>(),
        "sites_total": hosts.len(),
        "sites_blocked": hosts.values().filter(|c| c.1 > 0).count(),
    }))
}
