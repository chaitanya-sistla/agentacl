//! Access granted from the console, per agent and per place
//! (docs/design/access-requests.md §1).
//!
//! Each grant scope is one ordinary policy document in
//! `${AGENTACL_CONFIG}/access/`, whose `match:` says which sessions it applies
//! to. The file name is a function of the scope (the agent id is hashed into
//! it), and a file whose name doesn't match its own `match:` is refused, so a
//! session can tell exactly which files concern it (restart hints).
//! Access documents hold only allow rules (`allow_read`, `allow_write`,
//! `network.allow` for plain host names), with no `except`, for at most one
//! literal agent id and one project.

use crate::config::Paths;
use crate::fsafe;
use agentacl_policy::emit::to_yaml;
use agentacl_policy::raw::{parse_doc, RawDoc, RawMatch, RawRule, RuleKind};
use agentacl_policy::set::{sha256_hex, PolicySource};
use agentacl_policy::Layer;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Who and where a grant applies to. `None` means every agent / everywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub agent: Option<String>,
    pub project: Option<PathBuf>,
}

/// What a grant opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    Read,
    Write,
    Site,
}

pub fn dir(paths: &Paths) -> PathBuf {
    paths.config_dir.join("access")
}

fn safe(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect()
}

fn project_tag(p: &Path) -> String {
    sha256_hex(p.to_string_lossy().as_bytes())[..12].to_string()
}

/// An agent id usable in an access scope: a literal id, never a pattern.
pub fn valid_agent(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
}

/// `all.yaml`, `all@<p>.yaml`, `agent-<name>-<h>.yaml` or
/// `agent-<name>-<h>@<p>.yaml`; `<h>` hashes the exact agent id, so two ids
/// never share a file.
pub fn file_name(scope: &Scope) -> String {
    let who = scope.agent.as_deref().map(|a| format!("agent-{}-{}", safe(a), &sha256_hex(a.as_bytes())[..8])).unwrap_or_else(|| "all".into());
    match &scope.project {
        Some(p) => format!("{who}@{}.yaml", project_tag(p)),
        None => format!("{who}.yaml"),
    }
}

/// The access files that can apply to `agent` in `project`, whether or not
/// they exist yet (a new one appearing must mark the session stale).
pub fn applicable(paths: &Paths, agent: &str, project: &Path) -> Vec<PathBuf> {
    let d = dir(paths);
    [
        Scope { agent: None, project: None },
        Scope { agent: None, project: Some(project.into()) },
        Scope { agent: Some(agent.into()), project: None },
        Scope { agent: Some(agent.into()), project: Some(project.into()) },
    ]
    .iter()
    .map(|s| d.join(file_name(s)))
    .collect()
}

/// An empty document for `scope`.
pub fn new_doc(scope: &Scope) -> Result<RawDoc> {
    if let Some(a) = &scope.agent {
        if !valid_agent(a) {
            bail!("unsupported agent id {a:?}");
        }
    }
    if let Some(p) = &scope.project {
        let s = p.to_string_lossy();
        if !s.starts_with('/') || s.contains(['*', '?', '$', '\n']) {
            bail!("unsupported project path {s:?}");
        }
    }
    let m = RawMatch { agents: scope.agent.iter().cloned().collect(), projects: scope.project.iter().map(|p| p.to_string_lossy().into_owned()).collect() };
    let mut d = parse_doc("version: v1\n", Layer::User, "access")?;
    d.name = format!("access:{}", file_name(scope).trim_end_matches(".yaml"));
    d.match_ = (!m.agents.is_empty() || !m.projects.is_empty()).then_some(m);
    Ok(d)
}

/// The scope an access document applies to.
pub fn scope_of(d: &RawDoc) -> Scope {
    let m = d.match_.clone().unwrap_or_default();
    Scope { agent: m.agents.first().cloned(), project: m.projects.first().map(PathBuf::from) }
}

/// Refuses anything but plain allow rules in an access document.
pub fn check_doc(d: &RawDoc, name: &str) -> Result<()> {
    let bad = |what: &str| bail!("access file {name}: {what} is not allowed in an access file");
    let m = d.match_.clone().unwrap_or_default();
    if m.agents.len() > 1 || m.projects.len() > 1 {
        return bad("more than one agent or project in `match`");
    }
    if m.agents.iter().any(|a| !valid_agent(a)) {
        return bad("an agent pattern (only a literal agent id)");
    }
    if m.projects.iter().any(|p| !p.starts_with('/') || p.contains(['*', '?', '$'])) {
        return bad("a project pattern (only a literal absolute path)");
    }
    if !d.filesystem.deny_read.is_empty() || !d.filesystem.deny_write.is_empty() || !d.network.deny.is_empty() {
        return bad("a deny rule");
    }
    let rules = d.filesystem.allow_read.iter().chain(&d.filesystem.allow_write).chain(&d.network.allow);
    if rules.clone().any(|r| !r.except.is_empty()) {
        return bad("`except`");
    }
    if d.network.allow.iter().any(|r| !crate::netlive::is_named_host(&r.pattern) || crate::netlive::host_key(&r.pattern) != r.pattern) {
        return bad("a site that isn't a plain, lowercase host name");
    }
    if d.defaults.filesystem.is_some() || d.defaults.network.is_some() || d.defaults.process.is_some() {
        return bad("`defaults`");
    }
    if d.builtin.as_ref().is_some_and(|b| !b.disable.is_empty()) {
        return bad("`builtin.disable`");
    }
    if !d.process.allow.is_empty() || !d.process.deny.is_empty() || !d.process.require_approval.is_empty() {
        return bad("a `process` rule");
    }
    if !d.network.listen.is_empty() {
        return bad("`network.listen`");
    }
    Ok(())
}

/// Every access document, as policy sources (User layer), sorted by name.
pub fn sources(paths: &Paths) -> Result<Vec<PolicySource>> {
    Ok(list(paths)?.into_iter().map(|(name, yaml, _)| PolicySource { layer: Layer::User, name: format!("access:{}", name.trim_end_matches(".yaml")), yaml }).collect())
}

/// `(file name, yaml, parsed)` of every valid access document. Invalid ones
/// are left out (see [`scan`]): a stray file costs only its own grants.
pub fn list(paths: &Paths) -> Result<Vec<(String, String, RawDoc)>> {
    Ok(scan(paths)?.0)
}

/// Valid access documents, and `(file name, why)` for the ones that aren't.
#[allow(clippy::type_complexity)]
pub fn scan(paths: &Paths) -> Result<(Vec<(String, String, RawDoc)>, Vec<(String, String)>)> {
    let d = dir(paths);
    let rd = match std::fs::read_dir(&d) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((vec![], vec![])),
        Err(e) => return Err(e).with_context(|| format!("reading {}", d.display())),
    };
    let mut names: Vec<String> = rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n.ends_with(".yaml") && !n.starts_with('.')).collect();
    names.sort();
    // fsafe refuses symlinked components; a symlinked ~/.config is fine.
    let fd = fsafe::open_dir(&crate::supervisor::canon_or(&d))?;
    let (mut ok, mut broken) = (vec![], vec![]);
    for n in names {
        let one = || -> Result<Option<(String, RawDoc)>> {
            let Some(bytes) = fsafe::read_regular(&fd, &n)? else { return Ok(None) };
            let text = String::from_utf8(bytes).context("not UTF-8")?;
            let mut doc = parse_doc(&text, Layer::User, &n)?;
            check_doc(&doc, &n)?;
            let want = file_name(&scope_of(&doc));
            if n != want {
                bail!("access file {n}: its `match` belongs in {want}");
            }
            // The policy name comes from the file name, so console
            // revocations (keyed by it) always match whatever the file says.
            doc.name = format!("access:{}", n.trim_end_matches(".yaml"));
            Ok(Some((to_yaml(&doc), doc)))
        };
        match one() {
            Ok(Some((yaml, doc))) => ok.push((n, yaml, doc)),
            Ok(None) => broken.push((n, "not a regular file".into())),
            Err(e) => broken.push((n, format!("{e:#}"))),
        }
    }
    Ok((ok, broken))
}

/// The access document for `scope` with one more rule, as YAML (not written).
/// Returns `None` if the rule is already there.
pub fn with_rule(paths: &Paths, scope: &Scope, grant: Grant, pattern: &str) -> Result<Option<(String, String)>> {
    with_rules(paths, scope, grant, &[pattern.to_string()])
}

/// As [`with_rule`], for several patterns at once; `None` if all are there.
pub fn with_rules(paths: &Paths, scope: &Scope, grant: Grant, patterns: &[String]) -> Result<Option<(String, String)>> {
    let name = file_name(scope);
    let (docs, broken) = scan(paths)?;
    if let Some((_, why)) = broken.iter().find(|(n, _)| *n == name) {
        bail!("{name} has a problem ({why}); remove it on the Agents page first");
    }
    let mut doc = match docs.into_iter().find(|(n, _, _)| *n == name) {
        Some((_, _, d)) if scope_of(&d) == *scope => d,
        Some(_) => bail!("{name} belongs to another scope"),
        None => new_doc(scope)?,
    };
    let kind = if grant == Grant::Site { RuleKind::Host } else { RuleKind::Path };
    let mut changed = false;
    for pattern in patterns {
        let list = match grant {
            Grant::Read => &mut doc.filesystem.allow_read,
            Grant::Write => &mut doc.filesystem.allow_write,
            Grant::Site => &mut doc.network.allow,
        };
        if !list.iter().any(|r| r.pattern == *pattern) {
            list.push(RawRule { kind: kind.clone(), pattern: pattern.clone(), except: vec![], id: None, reason: None });
            changed = true;
        }
        // Reading is implied by writing.
        if grant == Grant::Write && !doc.filesystem.allow_read.iter().any(|r| r.pattern == *pattern) {
            doc.filesystem.allow_read.push(RawRule { kind: RuleKind::Path, pattern: pattern.clone(), except: vec![], id: None, reason: None });
            changed = true;
        }
    }
    Ok(changed.then(|| (name, to_yaml(&doc))))
}

/// The access document `name` without the rule `pattern` in `section`
/// (`allow_read`, `allow_write` or `network.allow`), as YAML; `None` when the
/// document ends up empty (delete it).
pub fn without_rule(paths: &Paths, name: &str, section: &str, pattern: &str) -> Result<Option<String>> {
    let (_, _, mut doc) = list(paths)?.into_iter().find(|(n, _, _)| n == name).context("no such access file")?;
    let list = match section {
        "allow_read" => &mut doc.filesystem.allow_read,
        "allow_write" => &mut doc.filesystem.allow_write,
        "network.allow" => &mut doc.network.allow,
        o => bail!("unknown section {o:?}"),
    };
    let before = list.len();
    list.retain(|r| r.pattern != pattern);
    if list.len() == before {
        bail!("that rule is not in {name}");
    }
    let f = &doc.filesystem;
    let empty = f.allow_read.is_empty() && f.allow_write.is_empty() && f.deny_read.is_empty() && f.deny_write.is_empty() && doc.network.allow.is_empty() && doc.network.deny.is_empty();
    Ok((!empty).then(|| to_yaml(&doc)))
}

/// Writes (or with `None`, removes) access file `name`.
pub fn store(paths: &Paths, name: &str, yaml: Option<&str>) -> Result<()> {
    if name.contains('/') || !name.ends_with(".yaml") || name.starts_with('.') {
        bail!("bad access file name {name:?}");
    }
    crate::config::ensure_private_dir(&paths.config_dir)?;
    let parent = fsafe::open_dir(&crate::supervisor::canon_or(&paths.config_dir))?;
    let d = fsafe::ensure_subdir(&parent, "access")?;
    match yaml {
        Some(y) => fsafe::write_atomic(&d, name, y.as_bytes()),
        None => match std::fs::remove_file(crate::supervisor::canon_or(&dir(paths)).join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySet};
    use agentacl_policy::{Action, Effect, PolicyEngine, Request, Resource, Subject};

    fn paths(t: &Path) -> Paths {
        let t = std::fs::canonicalize(t).unwrap();
        Paths::with_dirs(t.join("home"), t.join("state"), t.join("config"))
    }

    fn set(p: &Paths) -> PolicySet {
        let mut src = builtin_sources(true);
        src.extend(sources(p).unwrap());
        let vars = agentacl_policy::expand::Vars {
            home: "/Users/u".into(),
            project: "/Users/u/src/a".into(),
            tmpdir: "/tmp/x".into(),
            agent_state: None,
            agentacl_state: "/s".into(),
            agentacl_config: "/c".into(),
        };
        PolicySet::load(src, &vars, &LoadOptions::default()).unwrap()
    }

    fn read(set: &PolicySet, agent: &str, project: &str, path: &str) -> Effect {
        set.evaluate(&Request { subject: Subject { agent_id: agent.into(), project: project.into(), ..Default::default() }, action: Action::FsRead, resource: Resource::Path(path.into()) }).effect
    }

    #[test]
    fn grants_apply_to_their_agent_and_project_only() {
        let t = tempfile::tempdir().unwrap();
        let p = paths(t.path());
        let claude_a = Scope { agent: Some("claude-code".into()), project: Some("/Users/u/src/a".into()) };
        let (n, y) = with_rule(&p, &claude_a, Grant::Read, "/Users/u/o2/**").unwrap().unwrap();
        store(&p, &n, Some(&y)).unwrap();
        let codex = Scope { agent: Some("codex".into()), project: None };
        let (n, y) = with_rule(&p, &codex, Grant::Write, "/Users/u/shared/**").unwrap().unwrap();
        store(&p, &n, Some(&y)).unwrap();
        assert!(with_rule(&p, &codex, Grant::Write, "/Users/u/shared/**").unwrap().is_none(), "duplicates are not added");

        let s = set(&p);
        assert_eq!(read(&s, "claude-code", "/Users/u/src/a", "/Users/u/o2/x.txt"), Effect::Allow);
        assert_ne!(read(&s, "codex", "/Users/u/src/a", "/Users/u/o2/x.txt"), Effect::Allow, "another agent");
        assert_ne!(read(&s, "claude-code", "/Users/u/src/b", "/Users/u/o2/x.txt"), Effect::Allow, "another project");
        assert_eq!(read(&s, "codex", "/Users/u/src/b", "/Users/u/shared/f"), Effect::Allow, "write implies read, every project");
        // Built-in protections still win.
        let (n, y) = with_rule(&p, &Scope::default(), Grant::Read, "/Users/u/.ssh/**").unwrap().unwrap();
        store(&p, &n, Some(&y)).unwrap();
        assert_eq!(read(&set(&p), "claude-code", "/Users/u/src/a", "/Users/u/.ssh/id_ed25519"), Effect::Deny);

        let names: Vec<String> = applicable(&p, "claude-code", Path::new("/Users/u/src/a")).iter().map(|f| f.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert!(names.contains(&file_name(&claude_a)) && names.contains(&"all.yaml".to_string()) && !names.contains(&"codex.yaml".to_string()), "{names:?}");

        // Removing a write keeps the implied read (the console removes both).
        let name = file_name(&codex);
        assert!(without_rule(&p, &name, "allow_write", "/Users/u/shared/**").unwrap().is_some(), "the implied read remains");
    }

    #[test]
    fn access_files_hold_rules_only() {
        let t = tempfile::tempdir().unwrap();
        let p = paths(t.path());
        let refused = |yaml: &str, why: &str| {
            store(&p, "all.yaml", Some(yaml)).unwrap();
            let (ok, broken) = scan(&p).unwrap();
            assert!(ok.is_empty() && broken.len() == 1, "{why}: {yaml}");
            assert!(broken[0].1.contains(why), "{why}: {}", broken[0].1);
            assert!(sources(&p).unwrap().is_empty(), "left out, not fatal");
        };
        refused("version: v1\nmatch: {agents: [\"custom:*\"]}\n", "agent pattern");
        refused("version: v1\nmatch: {agents: [codex]}\n", "belongs in");
        refused("version: v1\nnetwork:\n  allow: [\"*.example.com\"]\n", "host name");
        for bad in [
            "version: v1\nfilesystem:\n  deny_read: [\"/x\"]\n",
            "version: v1\nfilesystem:\n  allow_read: [{path: \"/x/**\", except: [\"**/y\"]}]\n",
            "version: v1\ndefaults: {filesystem: allow}\n",
            "version: v1\nbuiltin: {disable: [keys]}\n",
            "version: v1\nprocess:\n  deny: [\"x *\"]\n",
            "version: v1\nnetwork:\n  listen: [\"localhost:80\"]\n",
        ] {
            store(&p, "all.yaml", Some(bad)).unwrap();
            assert_eq!(scan(&p).unwrap().1.len(), 1, "{bad}");
        }
        assert!(store(&p, "../x.yaml", Some("version: v1\n")).is_err());
        assert!(new_doc(&Scope { agent: None, project: Some("/a/*".into()) }).is_err());
    }
}

#[cfg(test)]
mod naming {
    use super::*;

    #[test]
    fn site_grants_need_no_restart() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let p = Paths::with_dirs(root.join("home"), root.join("state"), root.join("config"));
        let scope = Scope { agent: Some("claude-code".into()), project: None };
        let f = dir(&p).join(file_name(&scope));
        let sha = || crate::supervisor::input_sha(&p, &f);
        let add = |g: Grant, pat: &str| {
            let (n, y) = with_rule(&p, &scope, g, pat).unwrap().unwrap();
            store(&p, &n, Some(&y)).unwrap();
        };
        add(Grant::Site, "pypi.org");
        assert_eq!(sha(), None, "sites only: as if there were no file");
        add(Grant::Read, "/Users/u/o2/**");
        let with_file = sha();
        assert!(with_file.is_some());
        add(Grant::Site, "npmjs.org");
        assert_eq!(sha(), with_file, "another site changes nothing that needs a restart");
    }

    #[test]
    fn agent_ids_never_share_a_file() {
        let f = |a: &str| file_name(&Scope { agent: Some(a.into()), project: None });
        assert_ne!(f("all"), "all.yaml", "an agent named all is not every agent");
        assert_ne!(f("custom:x"), f("custom_x"));
        assert!(new_doc(&Scope { agent: Some("custom:*".into()), project: None }).is_err());
    }
}
