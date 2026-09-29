//! Files view (ui.md §4.5): names and kinds only, never contents; per-entry
//! decisions under the draft; rule text generated server-side with the
//! symlink and representability restrictions.

use agentfence_core::draft::Scope;
use agentfence_core::escape::term_safe;
use agentfence_policy::set::PolicySet;
use agentfence_policy::{Action, Decision, PolicyEngine, Request, Resource, Subject, WriteOp};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 2000;
/// macOS may prompt for these; list only on explicit request.
const TCC_DIRS: &[&str] = &["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library/Mobile Documents"];

pub fn tcc_protected(path: &Path, home: &Path) -> bool {
    TCC_DIRS.iter().any(|d| path.starts_with(home.join(d))) || path.starts_with("/Volumes")
}

fn decide(set: &PolicySet, subject: &Subject, action: Action, path: &str) -> Decision {
    set.evaluate(&Request { subject: subject.clone(), action, resource: Resource::Path(path.into()) })
}

fn dec_json(d: &Decision) -> Value {
    json!({ "effect": d.effect, "policy": d.policy, "rule_id": d.rule_id, "reason": term_safe(&d.reason) })
}

/// A path can be written as a literal pattern only without glob/variable/quote chars.
fn representable(p: &str) -> bool {
    !(p.contains(['*', '?', '"', '\\']) || p.contains("${") || p.chars().any(char::is_control))
}

/// Has any component (including the leaf) of `p` a symlink?
fn has_symlink_component(p: &Path) -> bool {
    let mut cur = PathBuf::from("/");
    for c in p.components().skip(1) {
        cur.push(c);
        if std::fs::symlink_metadata(&cur).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Rule text for an action, or `None` (with a reason) if not offered.
fn rule_for(path: &Path, is_dir: bool, scope: Scope, project: &Path, home: &Path, allow: bool) -> Result<String, String> {
    let s = path.to_string_lossy().into_owned();
    if !representable(&s) {
        return Err("this name contains characters (*, ?, ${, quotes, backslashes or control characters) that can't be written as a literal rule".into());
    }
    if allow && scope == Scope::Project {
        return Err("project policies can only restrict".into());
    }
    let base = match scope {
        Scope::Project => match path.strip_prefix(project) {
            Ok(rel) if rel.as_os_str().is_empty() => "${PROJECT}".to_string(),
            Ok(rel) => format!("${{PROJECT}}/{}", rel.display()),
            Err(_) => s.clone(),
        },
        Scope::User => match path.strip_prefix(home) {
            Ok(rel) if rel.as_os_str().is_empty() => "${HOME}".to_string(),
            Ok(rel) => format!("${{HOME}}/{}", rel.display()),
            Err(_) => s.clone(),
        },
    };
    Ok(if is_dir { format!("{base}/**") } else { base })
}

pub fn list(set: &PolicySet, agent: &str, project: &Path, home: &Path, scope: Scope, dir: &Path, force: bool) -> anyhow::Result<Value> {
    let dir = std::fs::canonicalize(dir)?;
    if !dir.is_dir() {
        anyhow::bail!("{} is not a directory", dir.display());
    }
    if tcc_protected(&dir, home) && !force {
        return Ok(json!({ "path": dir, "display": term_safe(&dir.to_string_lossy()), "needs_force": true, "entries": [] }));
    }
    let subject = Subject { agent_id: agent.into(), project: project.to_string_lossy().into(), ..Default::default() };
    let mut names: Vec<(String, std::fs::FileType)> = std::fs::read_dir(&dir)?
        .flatten()
        .filter_map(|e| e.file_type().ok().map(|t| (e.file_name().to_string_lossy().into_owned(), t)))
        .collect();
    names.sort_by(|a, b| (!a.1.is_dir(), a.0.to_lowercase()).cmp(&(!b.1.is_dir(), b.0.to_lowercase())));
    let truncated = names.len() > MAX_ENTRIES;
    names.truncate(MAX_ENTRIES);
    let parent_has_link = has_symlink_component(&dir);
    let mut entries = vec![];
    for (name, ft) in names {
        let p = dir.join(&name);
        let is_link = ft.is_symlink();
        let resolved = if is_link { std::fs::canonicalize(&p).ok() } else { Some(p.clone()) };
        let target = resolved.clone().unwrap_or_else(|| p.clone());
        let is_dir = target.is_dir();
        let ts = target.to_string_lossy().into_owned();
        let read = decide(set, &subject, Action::FsRead, &ts);
        let write = decide(set, &subject, Action::FsWrite(WriteOp::Write), &ts);
        let child = is_dir.then(|| {
            let c = format!("{ts}/x");
            json!({ "read": dec_json(&decide(set, &subject, Action::FsRead, &c)), "write": dec_json(&decide(set, &subject, Action::FsWrite(WriteOp::Write), &c)) })
        });
        let linky = is_link || parent_has_link;
        let mut actions = serde_json::Map::new();
        for (key, allow, section) in [("allow_read", true, "filesystem.allow_read"), ("allow_write", true, "filesystem.allow_write"), ("deny_read", false, "filesystem.deny_read"), ("deny_write", false, "filesystem.deny_write")] {
            let r = if allow && linky {
                Err("allow actions are not offered on symlinks or paths through a symlink: the link could be retargeted".to_string())
            } else {
                // Deny on a symlink targets the resolved path (what the kernel checks).
                rule_for(&target, is_dir, scope, project, home, allow)
            };
            actions.insert(key.into(), match r {
                Ok(rule) => json!({ "section": section, "rule": rule, "display": term_safe(&rule) }),
                Err(why) => json!({ "unavailable": why }),
            });
        }
        entries.push(json!({
            "name": name,
            "display": term_safe(&name),
            "path": p,
            "kind": if is_link { "symlink" } else if ft.is_dir() { "dir" } else if ft.is_file() { "file" } else { "other" },
            "link_target": if is_link { resolved.as_ref().map(|r| term_safe(&r.to_string_lossy())) } else { None },
            "is_dir": is_dir,
            "read": dec_json(&read),
            "write": dec_json(&write),
            "child": child,
            "builtin_lock": read.policy == "protect-secrets" || write.policy == "protect-secrets" || write.policy == "exec-persistence" || write.policy == "agentfence-self",
            "actions": actions,
        }));
    }
    Ok(json!({
        "path": dir,
        "display": term_safe(&dir.to_string_lossy()),
        "parent": dir.parent(),
        "tcc_protected": tcc_protected(&dir, home),
        "truncated": truncated,
        "entries": entries,
    }))
}
