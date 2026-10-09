//! Validating and saving policy drafts (used by the local UI; ui.md §4.3).
//! A draft goes through exactly the sources, trust, provider grants and
//! compiler that `agentacl run` uses, without creating a session.

use crate::config::Paths;
use crate::enforce::{rule_views, CompileInput, RuleView, SeatbeltBackend};
use crate::{agents, fsafe, identity, supervisor, trust};
use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, GeneratedDoc, LoadOptions, PolicySet, PolicySource};
use agentacl_policy::{Action, Effect, Layer, PolicyEngine, Request, Resource, Subject};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Project,
}

pub fn policy_file(paths: &Paths, scope: Scope, project: &Path) -> PathBuf {
    match scope {
        Scope::User => paths.user_policy.clone(),
        Scope::Project => project.join(".agentacl/policy.yaml"),
    }
}

/// Current bytes of the scope's policy file, read symlink-safely.
pub fn read_policy(paths: &Paths, scope: Scope, project: &Path) -> Result<Option<Vec<u8>>> {
    match scope {
        Scope::User => {
            let dir = supervisor::canon_or(&paths.config_dir);
            if !dir.exists() {
                return Ok(None);
            }
            fsafe::read_regular(&fsafe::open_dir(&dir)?, "policy.yaml")
        }
        Scope::Project => {
            let proj = fsafe::open_dir(project)?;
            let dir = match std::fs::symlink_metadata(project.join(".agentacl")) {
                Ok(m) if m.file_type().is_symlink() => bail!("{}/.agentacl is a symlink; refusing", project.display()),
                Ok(m) if m.is_dir() => fsafe::ensure_subdir(&proj, ".agentacl")?,
                Ok(_) => bail!("{}/.agentacl is not a directory", project.display()),
                Err(_) => return Ok(None),
            };
            fsafe::read_regular(&dir, "policy.yaml")
        }
    }
}

pub struct DraftCheck {
    pub policy: PolicySet,
    pub rules: Vec<RuleView>,
    pub warnings: Vec<String>,
    /// The project would become unreadable for this agent (policy-model §3).
    pub project_unreadable: bool,
}

fn vars(paths: &Paths, project: &Path) -> Result<Vars> {
    let human = identity::human()?;
    Ok(Vars {
        home: human.home.to_string_lossy().into(),
        project: project.to_string_lossy().into(),
        tmpdir: supervisor::darwin_user_temp_dir()?.join("agentacl/<session>/tmp").to_string_lossy().into(),
        agent_state: None,
        agentacl_state: supervisor::canon_or(&paths.state_dir).to_string_lossy().into(),
        agentacl_config: supervisor::canon_or(&paths.config_dir).to_string_lossy().into(),
    })
}

/// Sources as `run` builds them, with `draft` (YAML) substituted for the
/// scope's file. `draft = None` uses what is on disk.
pub fn sources(paths: &Paths, scope: Scope, project: &Path, draft: Option<&str>) -> Result<Vec<PolicySource>> {
    let user = match (scope, draft) {
        (Scope::User, Some(y)) => Some(y.to_string()),
        _ => read_policy(paths, Scope::User, project)?.map(|b| String::from_utf8_lossy(&b).into_owned()),
    };
    let proj = match (scope, draft) {
        (Scope::Project, Some(y)) => Some(y.to_string()),
        _ => read_policy(paths, Scope::Project, project)?.map(|b| String::from_utf8_lossy(&b).into_owned()),
    };
    let mut src = builtin_sources(user.is_none());
    // Company rules, as `run` loads them: a draft is checked against them.
    src.extend(paths.managed.org_source()?);
    if let Some(y) = user {
        src.push(PolicySource { layer: Layer::User, name: "user".into(), yaml: y });
    }
    src.extend(crate::access::sources(paths)?);
    if let Some(y) = proj {
        src.push(PolicySource { layer: Layer::Project, name: "project".into(), yaml: y });
    }
    Ok(src)
}

pub fn check(paths: &Paths, agent_id: &str, project: &Path, scope: Scope, draft: Option<&str>) -> Result<DraftCheck> {
    check_sources(paths, agent_id, project, sources(paths, scope, project, draft)?)
}

/// As [`check`], with access document `name` replaced by `yaml` (or removed).
pub fn check_access(paths: &Paths, agent_id: &str, project: &Path, name: &str, yaml: Option<&str>) -> Result<DraftCheck> {
    let source = format!("access:{}", name.trim_end_matches(".yaml"));
    let mut src = sources(paths, Scope::User, project, None)?;
    src.retain(|s| s.name != source);
    if let Some(y) = yaml {
        let doc = agentacl_policy::raw::parse_doc(y, Layer::User, name)?;
        crate::access::check_doc(&doc, name)?;
        src.push(PolicySource { layer: Layer::User, name: source, yaml: y.to_string() });
    }
    check_sources(paths, agent_id, project, src)
}

/// As [`check`] on disk, without the console's access files: what the policy
/// files alone decide.
pub fn check_policy_files(paths: &Paths, agent_id: &str, project: &Path) -> Result<DraftCheck> {
    let mut src = sources(paths, Scope::User, project, None)?;
    src.retain(|s| !s.name.starts_with("access:"));
    check_sources(paths, agent_id, project, src)
}

fn check_sources(paths: &Paths, agent_id: &str, project: &Path, src: Vec<PolicySource>) -> Result<DraftCheck> {
    let mut reqs = agents::provider(agent_id).map(|p| p.runtime_requirements()).unwrap_or_default();
    reqs.resolve_keychain(agents::env_set);
    let mut lopts = LoadOptions { trusted_project_sha256: trust::hashes_for(paths, project)?, generated: vec![] };
    if agents::provider(agent_id).is_some() {
        lopts.generated.push(GeneratedDoc {
            name: format!("provider:{agent_id}"),
            allow_read: reqs.read.clone(),
            allow_write: reqs.write.clone(),
            deny_write: reqs.protected_configs.clone(),
            net_allow: reqs.hosts.clone(),
            reason: format!("{agent_id} runtime requirement"),
        });
    }
    let policy = PolicySet::load(src, &vars(paths, project)?, &lopts)?;
    let proj_s = project.to_string_lossy().into_owned();
    // Same compiler as `run` (catches compile-only errors).
    crate::enforce::sbpl::compile_profile(
        &policy,
        &CompileInput { agent_id, project: &proj_s, mach_services: &reqs.mach_services, socket_allows: &reqs.unix_sockets, session_tag: "draft", ..Default::default() },
    )?;
    let rules = rule_views(&SeatbeltBackend, &policy, agent_id, &proj_s);
    let warnings = warnings(&policy, agent_id, &proj_s);
    let subject = Subject { agent_id: agent_id.into(), project: proj_s.clone(), ..Default::default() };
    let probe = format!("{proj_s}/.agentacl-read-probe");
    let project_unreadable = policy.evaluate(&Request { subject, action: Action::FsRead, resource: Resource::Path(probe) }).effect != Effect::Allow;
    Ok(DraftCheck { policy, rules, warnings, project_unreadable })
}

pub fn warnings(set: &PolicySet, agent: &str, proj: &str) -> Vec<String> {
    use agentacl_policy::pathpat::PatKind;
    use agentacl_policy::set::Matcher;
    let mut w = vec![];
    let defaults = set.effective_defaults(agent, proj);
    if defaults.process == Effect::Ask {
        w.push("defaults.process: ask cannot be enforced by the seatbelt backend; unmatched execs are observed only".into());
    }
    let rules = set.rules_for(agent, proj);
    for al in rules.iter().filter(|r| r.effect == Effect::Allow) {
        if let Matcher::Path(ap) = &al.matcher {
            let probe = match ap.kind() {
                PatKind::Subpath(s) | PatKind::Literal(s) => s.clone(),
                _ => continue,
            };
            if let Some(dn) = rules.iter().find(|r| r.effect == Effect::Deny && r.section == al.section && r.matches_path(&probe) && r.layer != Layer::Builtin) {
                w.push(format!("explicit deny {} ({}) shadows allow {} ({}): the allow has no effect there", dn.written, dn.id, al.written, al.id));
            } else if al.layer != Layer::Builtin {
                // A user/project allow whose whole target a built-in protection
                // denies has no effect (explicit deny wins).
                if let Some(dn) = rules.iter().find(|r| r.effect == Effect::Deny && r.section == al.section && r.layer == Layer::Builtin && r.matches_path(&probe)) {
                    let fix = if dn.policy == "protect-secrets" {
                        format!("to allow it, switch off the built-in \"{}\" group (builtin.disable)", dn.id)
                    } else {
                        "this protection can't be switched off".to_string()
                    };
                    w.push(format!("{} allow {} has no effect: built-in protection {} ({}) blocks it and a block always wins; {fix}", al.section.as_str(), al.written, dn.policy, dn.id));
                }
            }
        }
        if let Matcher::Net(n) = &al.matcher {
            if n.is_addr() && n.port().is_none() && n.matches_addr("127.0.0.1".parse().unwrap(), 1) {
                w.push(format!("network allow {:?} opens every loopback port to the agent (dev servers, databases); name specific ports instead", al.written));
            }
        }
    }
    let disabled = set.disabled_groups(agent, proj);
    if !disabled.is_empty() {
        w.push(format!("built-in secret protection disabled for: {}", disabled.join(", ")));
    }
    w
}

/// Saves `yaml` as the scope's policy after full validation (ui.md §4.3).
/// Returns the new sha256.
pub fn save(paths: &Paths, agent_id: &str, project: &Path, scope: Scope, yaml: &str, base_sha256: Option<&str>, confirm_unreadable: bool) -> Result<String, SaveError> {
    if scope == Scope::Project {
        if let Some(cur) = read_policy(paths, scope, project).map_err(SaveError::Invalid)? {
            let sha = agentacl_policy::set::sha256_hex(&cur);
            if trust::hashes_for(paths, project).map_err(SaveError::Invalid)?.contains(&sha) {
                return Err(SaveError::Invalid(anyhow::anyhow!("this project policy is trusted; edit it in a text editor and re-trust it with `agentacl policy trust`")));
            }
        }
    }
    let c = check(paths, agent_id, project, scope, Some(yaml)).map_err(SaveError::Invalid)?;
    if c.project_unreadable && !confirm_unreadable {
        return Err(SaveError::NeedsConfirm("project-unreadable".into()));
    }
    let dir = match scope {
        Scope::User => {
            crate::config::ensure_private_dir(&paths.config_dir).map_err(SaveError::Invalid)?;
            fsafe::open_dir(&supervisor::canon_or(&paths.config_dir)).map_err(SaveError::Invalid)?
        }
        Scope::Project => {
            let p = fsafe::open_dir(project).map_err(SaveError::Invalid)?;
            fsafe::ensure_subdir(&p, ".agentacl").map_err(SaveError::Invalid)?
        }
    };
    fsafe::replace_checked(&dir, "policy.yaml", yaml.as_bytes(), base_sha256).map_err(|e| match e.downcast::<fsafe::ConflictError>() {
        Ok(c) => SaveError::Conflict(c.current_sha),
        Err(e) => SaveError::Invalid(e),
    })
}

#[derive(Debug)]
pub enum SaveError {
    Invalid(anyhow::Error),
    NeedsConfirm(String),
    Conflict(Option<String>),
}
