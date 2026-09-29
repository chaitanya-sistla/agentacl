//! Files and access map (ui.md §4.5): names and kinds only, never contents;
//! per-entry decisions under the draft; rule text generated server-side with
//! the symlink and representability restrictions.

use agentfence_core::draft::Scope;
use agentfence_core::escape::term_safe;
use agentfence_policy::pathpat::PatKind;
use agentfence_policy::set::{Matcher, PolicySet};
use agentfence_policy::{Action, Decision, Effect, PolicyEngine, Request, Resource, Subject, WriteOp};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// macOS may prompt for these; list only on explicit request.
const TCC_DIRS: &[&str] = &["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library/Mobile Documents"];
const MAX_PAGE: usize = 200;

pub fn tcc_protected(path: &Path, home: &Path) -> bool {
    TCC_DIRS.iter().any(|d| path.starts_with(home.join(d))) || path.starts_with("/Volumes")
}

pub struct Ctx<'a> {
    pub set: &'a PolicySet,
    pub agent: &'a str,
    pub project: &'a Path,
    pub home: &'a Path,
    pub scope: Scope,
}

impl Ctx<'_> {
    fn subject(&self) -> Subject {
        Subject { agent_id: self.agent.into(), project: self.project.to_string_lossy().into(), ..Default::default() }
    }
    fn decide(&self, action: Action, path: &str) -> Decision {
        self.set.evaluate(&Request { subject: self.subject(), action, resource: Resource::Path(path.into()) })
    }
    /// Distinct rules that target something inside `dir` (so parts of the
    /// folder are treated differently from the folder itself): (allows, denies).
    /// Rules that apply everywhere (e.g. `/**/.env`) are not counted.
    fn inner_rules(&self, dir: &str) -> (usize, usize) {
        let dir = dir.trim_end_matches('/');
        let prefix = format!("{dir}/");
        let mut allow = std::collections::BTreeSet::new();
        let mut deny = std::collections::BTreeSet::new();
        for r in self.set.rules_for(self.agent, &self.project.to_string_lossy()) {
            let Matcher::Path(p) = &r.matcher else { continue };
            let (loc, glob) = match p.kind() {
                PatKind::Literal(l) | PatKind::Subpath(l) => (l.as_str(), false),
                PatKind::Glob => (p.anchor(), true),
            };
            if loc == "/" {
                continue;
            }
            if loc.starts_with(&prefix) || (glob && loc == dir) {
                let key = format!("{}/{}", r.policy, r.id);
                if r.effect == Effect::Allow { allow.insert(key); } else { deny.insert(key); }
            }
        }
        (allow.len(), deny.len())
    }
}

fn dec_json(d: &Decision) -> Value {
    json!({ "effect": d.effect, "policy": d.policy, "rule_id": d.rule_id, "reason": term_safe(&d.reason) })
}

/// full | read-only | blocked | ask
fn status(read: &Decision, write: &Decision) -> &'static str {
    match (read.effect, write.effect) {
        (Effect::Deny, _) => "blocked",
        (Effect::Ask, _) | (_, Effect::Ask) => "ask",
        (Effect::Allow, Effect::Allow) => "full",
        (Effect::Allow, Effect::Deny) => "read-only",
    }
}

/// A path can be written as a literal pattern only without glob/variable/quote chars.
fn representable(p: &str) -> bool {
    !(p.contains(['*', '?', '"', '\\']) || p.contains("${") || p.chars().any(char::is_control))
}

/// Has any component (including the leaf) of `p` a symlink?
pub fn has_symlink_component(p: &Path) -> bool {
    let mut cur = PathBuf::from("/");
    for c in p.components().skip(1) {
        cur.push(c);
        if std::fs::symlink_metadata(&cur).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Rule text for an action, or why it isn't offered.
fn rule_for(ctx: &Ctx, path: &Path, is_dir: bool, allow: bool) -> Result<String, String> {
    let s = path.to_string_lossy().into_owned();
    if !representable(&s) {
        return Err("this name contains characters (*, ?, ${, quotes, backslashes or control characters) that can't be written as a literal rule".into());
    }
    if allow && ctx.scope == Scope::Project {
        return Err("project policies can only restrict".into());
    }
    let base = match ctx.scope {
        Scope::Project => match path.strip_prefix(ctx.project) {
            Ok(rel) if rel.as_os_str().is_empty() => "${PROJECT}".to_string(),
            Ok(rel) => format!("${{PROJECT}}/{}", rel.display()),
            Err(_) => s.clone(),
        },
        Scope::User => match path.strip_prefix(ctx.home) {
            Ok(rel) if rel.as_os_str().is_empty() => "${HOME}".to_string(),
            Ok(rel) => format!("${{HOME}}/{}", rel.display()),
            Err(_) => s.clone(),
        },
    };
    Ok(if is_dir { format!("{base}/**") } else { base })
}

/// One file-system node with decisions, status and rule actions.
pub fn node(ctx: &Ctx, path: &Path, label: Option<&str>, parent_has_link: bool) -> Value {
    let meta = std::fs::symlink_metadata(path).ok();
    let is_link = meta.as_ref().is_some_and(|m| m.file_type().is_symlink());
    let resolved = if is_link { std::fs::canonicalize(path).ok() } else { Some(path.to_path_buf()) };
    let target = resolved.clone().unwrap_or_else(|| path.to_path_buf());
    let is_dir = target.is_dir();
    let ts = target.to_string_lossy().into_owned();
    let read = ctx.decide(Action::FsRead, &ts);
    let write = ctx.decide(Action::FsWrite(WriteOp::Write), &ts);
    let linky = is_link || parent_has_link;
    let mut actions = serde_json::Map::new();
    for (key, allow, section) in [("allow_read", true, "filesystem.allow_read"), ("allow_write", true, "filesystem.allow_write"), ("deny_read", false, "filesystem.deny_read"), ("deny_write", false, "filesystem.deny_write")] {
        let r = if allow && linky {
            Err("allow isn't offered on symlinks or paths through a symlink: the link could be retargeted".to_string())
        } else {
            // Deny on a symlink targets the resolved path (what the kernel checks).
            rule_for(ctx, &target, is_dir, allow)
        };
        actions.insert(key.into(), match r {
            Ok(rule) => json!({ "section": section, "rule": rule, "display": term_safe(&rule) }),
            Err(why) => json!({ "unavailable": why }),
        });
    }
    let name = label.map(str::to_string).unwrap_or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string_lossy().into_owned()));
    let (inner_allow, inner_deny) = if is_dir { ctx.inner_rules(&ts) } else { (0, 0) };
    let mut st = status(&read, &write);
    // A folder that is itself blocked but has allowed paths inside.
    if st == "blocked" && inner_allow > 0 {
        st = "partial";
    }
    let builtin = |d: &Decision| matches!(d.policy.as_str(), "protect-secrets" | "exec-persistence" | "agentfence-self");
    json!({
        "id": path,
        "path": path,
        "name": name,
        "display": term_safe(&name),
        "kind": if is_link { "symlink" } else if is_dir { "dir" } else if meta.is_some() { "file" } else { "missing" },
        "link_target": if is_link { resolved.as_ref().map(|r| term_safe(&r.to_string_lossy())) } else { None },
        "is_dir": is_dir,
        "expandable": is_dir && !is_link,
        "read": dec_json(&read),
        "write": dec_json(&write),
        "status": st,
        "inner_allow": inner_allow,
        "inner_deny": inner_deny,
        "inner_rules": inner_allow + inner_deny,
        "builtin_lock": builtin(&read) || builtin(&write),
        "tcc": tcc_protected(&target, ctx.home),
        "actions": actions,
    })
}

/// Children of `dir`, one page at a time (dirs first, then files).
pub fn children(ctx: &Ctx, dir: &Path, offset: usize, limit: usize, force: bool) -> anyhow::Result<Value> {
    let dir = std::fs::canonicalize(dir)?;
    if !dir.is_dir() {
        anyhow::bail!("{} is not a directory", dir.display());
    }
    if tcc_protected(&dir, ctx.home) && !force {
        return Ok(json!({ "path": dir, "display": term_safe(&dir.to_string_lossy()), "parent": dir.parent(), "needs_force": true, "total": 0, "entries": [] }));
    }
    let mut names: Vec<(String, bool)> = std::fs::read_dir(&dir)?
        .flatten()
        .filter_map(|e| e.file_type().ok().map(|t| (e.file_name().to_string_lossy().into_owned(), t.is_dir())))
        .collect();
    names.sort_by(|a, b| (!a.1, a.0.to_lowercase()).cmp(&(!b.1, b.0.to_lowercase())));
    let total = names.len();
    let parent_has_link = has_symlink_component(&dir);
    let limit = limit.clamp(1, MAX_PAGE);
    let entries: Vec<Value> = names.iter().skip(offset).take(limit).map(|(n, _)| node(ctx, &dir.join(n), None, parent_has_link)).collect();
    Ok(json!({
        "path": dir,
        "display": term_safe(&dir.to_string_lossy()),
        "parent": dir.parent(),
        "tcc_protected": tcc_protected(&dir, ctx.home),
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": entries,
    }))
}

/// Top of the access map: the project, home, protected secrets that exist on
/// this Mac, and the read-only system areas.
pub fn map_roots(ctx: &Ctx) -> Value {
    let mut secrets: Vec<PathBuf> = vec![];
    for r in ctx.set.rules_for(ctx.agent, &ctx.project.to_string_lossy()) {
        if r.effect != Effect::Deny || r.policy != "protect-secrets" {
            continue;
        }
        if let Matcher::Path(p) = &r.matcher {
            if let PatKind::Literal(l) | PatKind::Subpath(l) = p.kind() {
                let pb = PathBuf::from(l);
                if pb.exists() && !secrets.contains(&pb) {
                    secrets.push(pb);
                }
            }
        }
    }
    // Secret files directly in the project (e.g. .env).
    if let Ok(rd) = std::fs::read_dir(ctx.project) {
        for e in rd.flatten().take(500) {
            let p = e.path();
            let s = p.to_string_lossy().into_owned();
            if e.file_type().map(|t| t.is_file()).unwrap_or(false) && ctx.decide(Action::FsRead, &s).policy == "protect-secrets" {
                secrets.push(p);
            }
        }
    }
    secrets.sort();
    let group = |id: &str, name: &str, desc: &str, kids: Vec<Value>| json!({ "id": id, "name": name, "display": name, "kind": "group", "description": desc, "expandable": false, "children": kids });
    json!({
        "roots": [
            group("group:project", "This project", "Where the agent works", vec![node(ctx, ctx.project, None, false)]),
            group("group:home", "Your home folder", "Everything else you own — blocked unless a rule allows it", vec![node(ctx, ctx.home, Some("~ (home)"), false)]),
            group("group:secrets", "Protected secrets", "Credentials AgentFence always shields", secrets.iter().map(|p| {
                let label = if let Ok(r) = p.strip_prefix(ctx.project) {
                    format!("{}/{}", ctx.project.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), r.display())
                } else if let Ok(r) = p.strip_prefix(ctx.home) {
                    format!("~/{}", r.display())
                } else {
                    p.to_string_lossy().into_owned()
                };
                node(ctx, p, Some(&label), false)
            }).collect()),
            group("group:system", "System", "OS and developer tools agents need to run", ["/System", "/usr", "/opt/homebrew", "/Applications"].iter().map(Path::new).filter(|p| p.exists()).map(|p| node(ctx, p, None, false)).collect()),
        ]
    })
}
