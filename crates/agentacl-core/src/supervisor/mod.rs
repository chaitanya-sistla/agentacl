//! `agentacl run`: identify → load policy → create session → prepare the
//! Seatbelt profile → spawn on a pty → observe → finalize (architecture §5).
//!
//! Fail-closed: any error before spawn means the agent is not started.

pub mod env;
pub mod integrity;
pub mod pty;

use crate::agents::{self, RuntimeReqs};
use crate::audit::*;
use crate::config::{ensure_private_dir, Paths};
use crate::enforce::{rule_views, CompileInput, EnforcementBackend, LaunchPlan, RuleView, SeatbeltBackend};
use crate::identity::{self, AgentIdentity, Human};
use crate::observe::sandbox_log::{self, KernelDenial, LogLine, SandboxLogObserver};
use crate::proc::{self, ProcessTree, TreeChange};
use crate::session::{new_session_id, PolicyRef, Session};
use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, GeneratedDoc, LoadOptions, PolicySet, PolicySource};
use agentacl_policy::{Action, Decision, Effect, Layer, PolicyEngine, Request, Resource, Subject};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub argv: Vec<String>,
    pub project: Option<PathBuf>,
    pub policy_file: Option<PathBuf>,
    pub agent_id: Option<String>,
    pub accept_hardlinks: Vec<PathBuf>,
    pub keep_env: Vec<String>,
    pub cwd: Option<PathBuf>,
}

/// Everything decided before launch (also used by `--dry-run` and `policy check`).
pub struct Prepared {
    pub session: Session,
    pub policy: Arc<PolicySet>,
    pub reqs: RuntimeReqs,
    pub rules: Vec<RuleView>,
    pub agent_argv: Vec<String>,
    pub extra_denies: Vec<String>,
    pub exec_deny_literals: Vec<String>,
    pub socket_denies: Vec<String>,
    pub watch: Vec<PathBuf>,
    session_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub session_id: String,
    pub exit_code: i32,
    /// (action, resource, policy/rule, count): explicit policy rules first, then by count.
    pub denied: Vec<(String, String, String, u32)>,
    /// Denials by explicit policy rules vs. by the sandbox baseline / default deny.
    pub denied_by_policy: u32,
    pub denied_by_baseline: u32,
    /// The session ended because `agentacl restart` asked for a relaunch.
    pub restarted: bool,
    /// A policy file changed while the session ran (its sandbox is stale).
    pub policy_changed: bool,
    pub agent_argv0: String,
    pub resume_args: Vec<String>,
    pub observed: Vec<(String, String, String)>,
    pub integrity_changes: Vec<PathBuf>,
    pub stripped_env: Vec<String>,
    pub warnings: Vec<String>,
}

/// `DARWIN_USER_TEMP_DIR`, realpath'd (`/private/var/folders/.../T`).
pub fn darwin_user_temp_dir() -> Result<PathBuf> {
    let mut buf = vec![0u8; 1024];
    // SAFETY: confstr writes at most buf.len() bytes including the NUL.
    let n = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len()) };
    if n == 0 || n > buf.len() {
        bail!("confstr(_CS_DARWIN_USER_TEMP_DIR) failed");
    }
    buf.truncate(n - 1);
    let p = PathBuf::from(String::from_utf8(buf)?);
    Ok(std::fs::canonicalize(&p)?)
}

pub fn canon_or(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Identify the agent binary for `argv[0]`.
pub fn identify_agent(argv0: &str, agent_id: Option<&str>) -> Result<(PathBuf, AgentIdentity)> {
    let path = agents::path_lookup(argv0).with_context(|| format!("command not found: {argv0}"))?;
    let resolved = std::fs::canonicalize(&path)?;
    let sha = proc::sha256_file(&resolved).ok();
    let found = agents::identify_binary(&resolved);
    let ident = match (found, agent_id) {
        (Some((i, sig)), None) => AgentIdentity {
            id: i.id,
            display_name: i.display_name,
            version: i.m.version,
            binary: resolved.to_string_lossy().into(),
            binary_sha256: sha,
            team_id: sig.as_ref().and_then(|s| s.team_id.clone()),
            signing_id: sig.and_then(|s| s.signing_id),
            confidence: Some(i.m.confidence),
        },
        (found, forced) => {
            let base = resolved.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| argv0.into());
            let id = forced.map(str::to_string).unwrap_or_else(|| format!("custom:{base}"));
            let sig = proc::code_signature(&resolved);
            AgentIdentity {
                display_name: found.map(|(i, _)| i.display_name).unwrap_or_else(|| id.clone()),
                id,
                version: None,
                binary: resolved.to_string_lossy().into(),
                binary_sha256: sha,
                team_id: sig.as_ref().and_then(|s| s.team_id.clone()),
                signing_id: sig.and_then(|s| s.signing_id),
                confidence: None,
            }
        }
    };
    Ok((resolved, ident))
}

pub fn policy_sources(paths: &Paths, policy_file: Option<&Path>, project: &Path) -> Result<Vec<PolicySource>> {
    let user_path = policy_file.map(Path::to_path_buf).unwrap_or_else(|| paths.user_policy.clone());
    let user = match std::fs::read_to_string(&user_path) {
        Ok(y) => Some(PolicySource { layer: Layer::User, name: "user".into(), yaml: y }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && policy_file.is_none() => None,
        Err(e) => return Err(e).with_context(|| format!("reading policy {}", user_path.display())),
    };
    let mut src = builtin_sources(user.is_none());
    src.extend(user);
    // Grants made from the console; each document's `match:` scopes it. A
    // broken file is left out (only its grants are lost) and reported.
    let (docs, broken) = crate::access::scan(paths)?;
    for (n, why) in broken {
        eprintln!("agentacl: ignoring access file {n}: {why} (remove it in the console's Agents page)");
    }
    src.extend(docs.into_iter().map(|(name, yaml, _)| PolicySource { layer: Layer::User, name: format!("access:{}", name.trim_end_matches(".yaml")), yaml }));
    let proj = project.join(".agentacl/policy.yaml");
    match std::fs::read_to_string(&proj) {
        Ok(y) => src.push(PolicySource { layer: Layer::Project, name: "project".into(), yaml: y }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", proj.display())),
    }
    Ok(src)
}

fn provider_doc(id: &str, reqs: &RuntimeReqs) -> GeneratedDoc {
    GeneratedDoc {
        name: format!("provider:{id}"),
        allow_read: reqs.read.clone(),
        allow_write: reqs.write.clone(),
        deny_write: reqs.protected_configs.clone(),
        net_allow: reqs.hosts.clone(),
        reason: format!("{id} runtime requirement"),
    }
}

/// Loads the effective policy for `policy check` (same layering as `run`,
/// minus per-session grants).
pub fn load_policy_for_check(paths: &Paths, agent_id: &str, project: &Path, policy_file: Option<&Path>) -> Result<(PolicySet, RuntimeReqs)> {
    let home = identity::human()?.home;
    load_policy_with(paths, agent_id, project, policy_file, &home, agents::env_set, None)
}

/// Claude Code's settings files, whose hook scripts an agent must not edit.
pub fn claude_settings(home: &Path, project: &Path) -> Vec<PathBuf> {
    vec![home.join(".claude/settings.json"), home.join(".claude/settings.local.json"), project.join(".claude/settings.json"), project.join(".claude/settings.local.json")]
}

/// As [`load_policy_for_check`], for a given home folder and environment.
/// `tmpdir` is the agent's temp folder (`${TMPDIR}`); by default a session's.
/// With a `tmpdir` (an agent AgentACL didn't launch, enforced by Endpoint
/// Security) the protections `agentacl run` adds per session that don't
/// depend on the launch are added too: hook scripts can't be written.
pub fn load_policy_with(
    paths: &Paths,
    agent_id: &str,
    project: &Path,
    policy_file: Option<&Path>,
    home: &Path,
    has_env: impl Fn(&str) -> bool,
    tmpdir: Option<&Path>,
) -> Result<(PolicySet, RuntimeReqs)> {
    let mut reqs = agents::provider(agent_id).map(|p| p.runtime_requirements()).unwrap_or_default();
    reqs.resolve_keychain(has_env);
    let tmp = match tmpdir {
        Some(t) => t.to_path_buf(),
        None => darwin_user_temp_dir()?.join("agentacl").join("<session>"),
    };
    let vars = Vars {
        home: home.to_string_lossy().into(),
        project: project.to_string_lossy().into(),
        tmpdir: tmp.to_string_lossy().into(),
        agent_state: None,
        agentacl_state: canon_or(&paths.state_dir).to_string_lossy().into(),
        agentacl_config: canon_or(&paths.config_dir).to_string_lossy().into(),
    };
    let mut lopts = LoadOptions { trusted_project_sha256: crate::trust::hashes_for(paths, project)?, generated: vec![] };
    if agents::provider(agent_id).is_some() {
        lopts.generated.push(provider_doc(agent_id, &reqs));
    }
    if tmpdir.is_some() {
        let deny_write = integrity::claude_hook_scripts(&claude_settings(home, project));
        lopts.generated.push(GeneratedDoc { name: "session".into(), reason: "AgentACL session requirement".into(), deny_write, ..Default::default() });
    }
    let set = PolicySet::load(policy_sources(paths, policy_file, project)?, &vars, &lopts)?;
    Ok((set, reqs))
}

pub fn prepare(paths: &Paths, opts: &RunOptions) -> Result<Prepared> {
    let Some(argv0) = opts.argv.first() else { bail!("no command given") };
    let human: Human = identity::human()?;
    let machine = proc::machine_id().unwrap_or_else(|_| "mch_unknown".into());
    let cwd = match &opts.cwd {
        Some(c) => c.clone(),
        None => std::env::current_dir()?,
    };
    let project = identity::resolve_project(&cwd, opts.project.as_deref(), &human.home)?;
    if let Some(loc) = crate::exposure::project_opens_drive(&human.home, &project) {
        eprintln!("agentacl: warning: this project includes {loc}; a project is always open to the agent, so the cloud-drives protection doesn't apply inside it. Start from a project folder within the drive instead.");
    }
    let (binary, agent) = identify_agent(argv0, opts.agent_id.as_deref())?;
    let provider = agents::provider(&agent.id);
    let mut reqs = provider.as_ref().map(|p| p.runtime_requirements()).unwrap_or_default();
    reqs.resolve_keychain(agents::env_set);

    ensure_private_dir(&paths.state_dir)?;
    ensure_private_dir(&paths.config_dir)?;
    let session_id = new_session_id();
    let temp_root = darwin_user_temp_dir()?.join("agentacl");
    ensure_private_dir(&temp_root)?;
    let session_dir = temp_root.join(&session_id);
    let tmpdir = session_dir.join("tmp");
    ensure_private_dir(&tmpdir)?;

    let vars = Vars {
        home: human.home.to_string_lossy().into(),
        project: project.to_string_lossy().into(),
        tmpdir: tmpdir.to_string_lossy().into(),
        agent_state: None,
        agentacl_state: canon_or(&paths.state_dir).to_string_lossy().into(),
        agentacl_config: canon_or(&paths.config_dir).to_string_lossy().into(),
    };

    // Per-session generated grants and protections.
    let mut session_doc = GeneratedDoc { name: "session".into(), reason: "AgentACL session requirement".into(), ..Default::default() };
    // Read access to the agent's own install directory — but never to a
    // directory as broad as `/`, $HOME or an ancestor of $HOME.
    match binary.parent() {
        Some(dir) if dir != Path::new("/") && !human.home.starts_with(dir) => session_doc.allow_read.push(format!("{}/**", dir.display())),
        _ => session_doc.allow_read.push(binary.to_string_lossy().into_owned()),
    }
    session_doc.deny_write.extend(integrity::claude_hook_scripts(&claude_settings(&human.home, &project)));
    if let Some(pf) = &opts.policy_file {
        session_doc.deny_write.push(canon_or(pf).to_string_lossy().into());
    }

    let mut lopts = LoadOptions { trusted_project_sha256: crate::trust::hashes_for(paths, &project)?, generated: vec![] };
    if provider.is_some() {
        lopts.generated.push(provider_doc(&agent.id, &reqs));
    }
    lopts.generated.push(session_doc);
    let sources = policy_sources(paths, opts.policy_file.as_deref(), &project)?;
    let policy = Arc::new(PolicySet::load(sources, &vars, &lopts)?);
    let proj_s = project.to_string_lossy().into_owned();

    let backend = SeatbeltBackend;
    backend.available().map_err(anyhow::Error::msg)?;
    let rules = rule_views(&backend, &policy, &agent.id, &proj_s);

    let extra_denies = integrity::hardlink_check(&policy, &agent.id, &project, &opts.accept_hardlinks)?;

    // PATH-resolved executables for executable-only process denies.
    let mut exec_deny_literals = Vec::new();
    for r in policy.rules_for(&agent.id, &proj_s) {
        if let agentacl_policy::set::Matcher::Cmd(c) = &r.matcher {
            if r.effect != Effect::Allow && c.is_executable_only() {
                if let Some(name) = c.exe_basename() {
                    if let Some(p) = agents::path_lookup(name) {
                        exec_deny_literals.push(canon_or(&p).to_string_lossy().into());
                    }
                }
            }
        }
    }
    let socket_denies = credential_sockets(std::env::var("SSH_AUTH_SOCK").ok().map(PathBuf::from), Path::new("/var/run/docker.sock"), &human.home);

    let mut agent_argv = vec![binary.to_string_lossy().into_owned()];
    agent_argv.extend(reqs.launch_args.iter().cloned());
    agent_argv.extend(opts.argv[1..].iter().cloned());

    let disabled = policy.disabled_groups(&agent.id, &proj_s);
    let policy_name = if opts.policy_file.is_some() || paths.user_policy.exists() { "user" } else { "default" };
    let inputs = policy_inputs(paths, opts, &project, &agent.id);
    let session = Session {
        session_id,
        human,
        machine,
        agent,
        pid: None,
        // SAFETY: getpid has no memory effects.
        parent_pid: unsafe { libc::getpid() },
        project: project.clone(),
        tmpdir,
        policy: PolicyRef { name: policy_name.into(), sha256: policy.sha256.clone(), disabled_builtin_groups: disabled },
        backend: backend.name().into(),
        started_at: now_rfc3339(),
        agentacl_version: Some(env!("CARGO_PKG_VERSION").into()),
        features: vec!["restart".into(), "ui-port-deny".into(), "network-live".into()],
        policy_sources: inputs.into_iter().map(|p| crate::session::PolicyInput { sha256: input_sha(paths, &p), path: p }).collect(),
    };
    let watch = integrity::watch_list(&project, &session.human.home);
    let p = Prepared { session, policy, reqs, rules, agent_argv, extra_denies, exec_deny_literals, socket_denies, watch, session_dir };
    // Compile once now so every compiler-only error (e.g. `defaults.process:
    // deny`, a listen entry without a port) surfaces before anything launches.
    if let Err(e) = crate::enforce::sbpl::compile_profile(&p.policy, &p.compile_input(0, None)) {
        p.cleanup();
        return Err(e);
    }
    Ok(p)
}

impl Prepared {
    pub fn compile_input<'a>(&'a self, proxy_port: u16, pty_slave: Option<&'a str>) -> CompileInput<'a> {
        CompileInput {
            agent_id: &self.session.agent.id,
            project: self.session.project.to_str().unwrap_or_default(),
            proxy_port,
            mach_services: &self.reqs.mach_services,
            exec_deny_literals: &self.exec_deny_literals,
            socket_denies: &self.socket_denies,
            socket_allows: &self.reqs.unix_sockets,
            extra_denies: &self.extra_denies,
            pty_slave,
            session_tag: &self.session.session_id,
        }
    }

    pub fn profile_path(&self) -> PathBuf {
        self.session_dir.join("profile.sb")
    }

    /// Writes the profile without launching (for --dry-run).
    pub fn dry_run(&self) -> Result<LaunchPlan> {
        SeatbeltBackend.prepare(&self.policy, &self.compile_input(0, None), self.profile_path(), &self.agent_argv)
    }

    pub fn subject(&self) -> Subject {
        Subject {
            human: self.session.human.user.clone(),
            machine: self.session.machine.clone(),
            agent_id: self.session.agent.id.clone(),
            agent_version: self.session.agent.version.clone(),
            team_id: self.session.agent.team_id.clone(),
            session: self.session.session_id.clone(),
            project: self.session.project.to_string_lossy().into(),
            delegation_chain: vec![],
        }
    }

    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.session_dir);
    }
}

/// Shared state for observer threads.
struct Live {
    store: Mutex<Store>,
    ctx: EventContext,
    policy: Arc<PolicySet>,
    subject: Subject,
    tree: Mutex<Option<ProcessTree>>,
    dup_index: Mutex<HashMap<(i32, String, String), String>>,
    sentinel: String,
    sentinel_seen: AtomicBool,
    warnings: Mutex<Vec<String>>,
    /// State dir (notifications), agent display name and the human's home.
    state_dir: PathBuf,
    agent_name: String,
    home: String,
    /// Refusals already passed to the notifier (a burst of the same denial
    /// takes the shared lock once).
    refused_seen: Mutex<HashSet<String>>,
}

impl Live {
    /// Counts a refusal the human can act on into the notification digest.
    fn note_refused(&self, e: &crate::audit::Event) {
        if !matches!(e.decision, Some(Effect::Deny))
            || !crate::notify::actionable(&e.action, &e.resource, e.policy.as_deref().unwrap_or_default(), e.rule_id.as_deref().unwrap_or_default(), &self.home)
        {
            return;
        }
        let key = format!("{}|{}", e.action, e.resource);
        {
            let mut seen = self.refused_seen.lock().unwrap();
            if seen.len() >= 10_000 || !seen.insert(key.clone()) {
                return;
            }
        }
        let _ = crate::notify::on_refused(&self.state_dir, &self.agent_name, &key, crate::notify::now());
    }

    fn warn(&self, msg: String) {
        if let Ok(s) = self.store.lock() {
            let _ = s.record_lifecycle(&self.ctx, LifecycleEvent { kind: LifecycleKind::BackendWarning, pid: None, detail: msg.clone() });
        }
        self.warnings.lock().unwrap().push(msg);
    }

    /// Chain for a kernel-reported pid, adopting it via ppid ancestry if the
    /// poller has not seen it yet. None = not part of this session.
    fn chain_for(&self, pid: i32) -> Option<Vec<String>> {
        let mut guard = self.tree.lock().unwrap();
        let tree = guard.as_mut()?;
        if !tree.contains_pid(pid) {
            let anc = proc::resolve_ancestry(pid);
            let idx = anc.iter().position(|f| tree.contains_pid(f.pid))?;
            for i in (0..idx).rev() {
                let parent = anc[i + 1].pid;
                tree.adopt(anc[i].clone(), parent);
            }
        }
        tree.chain(pid)
    }

    /// The decision a kernel denial represents, from the rule tag the kernel
    /// reported (`af:<session>|<policy>|<rule>`).
    fn attribute(&self, d: &KernelDenial, policy: &str, rule: &str) -> Decision {
        if let Some(r) = self.policy.rules_for(&self.subject.agent_id, &self.subject.project).into_iter().find(|r| r.policy == policy && r.id == rule) {
            return Decision { effect: r.effect, policy: r.policy.clone(), rule_id: r.id.clone(), reason: r.reason.clone(), trace: vec![] };
        }
        let op = d.op();
        let reason = match (policy, rule) {
            ("builtin", "mach-service") => "IPC to this system service is not permitted: it could act outside the sandbox".to_string(),
            ("builtin", "credential-socket") => "Credential sockets (ssh-agent, docker) are protected".to_string(),
            ("builtin", "never-allow") => format!("`{op}` is never permitted to supervised agents"),
            ("builtin", "hardlink") => "Hard link to a protected file".to_string(),
            _ => match op {
                "mach-lookup" => "IPC to this system service is not permitted by the sandbox baseline".to_string(),
                "network-outbound" => "Direct network connections are blocked; traffic must use the AgentACL proxy".to_string(),
                "network-bind" | "network-inbound" => "Listening is denied unless network.listen names the loopback port".to_string(),
                o if o.starts_with("process-exec") => "Execution denied by the sandbox (setuid binaries cannot run in a session)".to_string(),
                o if o.starts_with("file-") => "No rule allows this path (default deny)".to_string(),
                o => format!("`{o}` is not permitted by the sandbox baseline"),
            },
        };
        Decision { effect: Effect::Deny, policy: policy.to_string(), rule_id: rule.to_string(), reason, trace: vec![] }
    }

    fn on_line(&self, line: LogLine) {
        match line {
            LogLine::Denial(d) => {
                if d.target() == self.sentinel {
                    self.sentinel_seen.store(true, Ordering::SeqCst);
                    return;
                }
                // Only denials stamped with this session's tag are ours.
                let Some(tag) = d.tag().filter(|t| t.session == self.subject.session).cloned() else { return };
                let chain = self.chain_for(d.pid()).unwrap_or_else(|| vec![self.subject.agent_id.clone(), "…".into(), d.proc_name().to_string()]);
                let decision = self.attribute(&d, &tag.policy, &tag.rule);
                let key = (d.pid(), d.op().to_string(), d.target().to_string());
                let ev = EnforcedEvent::from_kernel(&d, chain, decision, 1);
                if let Ok(s) = self.store.lock() {
                    if let Ok(e) = s.record_enforced(&self.ctx, ev) {
                        self.note_refused(&e);
                        self.dup_index.lock().unwrap().insert(key, e.id);
                    }
                }
            }
            LogLine::Duplicate { n, of } => {
                if of.tag().map(|t| t.session != self.subject.session).unwrap_or(true) {
                    return;
                }
                let key = (of.pid(), of.op().to_string(), of.target().to_string());
                if let Some(id) = self.dup_index.lock().unwrap().get(&key) {
                    if let Ok(s) = self.store.lock() {
                        let _ = s.bump_count(id, n);
                    }
                }
            }
            LogLine::Unparsed(msg) => {
                if msg.contains(&self.subject.session) {
                    self.warn(format!("unparsed sandbox report: {}", crate::escape::term_safe(&msg)));
                }
            }
            LogLine::Ignored => {}
        }
    }

    fn on_tree_change(&self, change: TreeChange) {
        let f = match change {
            TreeChange::New(f) | TreeChange::Exec(f) => f,
        };
        let Some(exe) = f.exe.clone() else { return };
        // For `#!` scripts the kernel reports the interpreter; the command the
        // agent ran is the script (argv[1]). Evaluate both; most restrictive wins.
        let mut candidates = vec![(exe.clone(), f.argv.clone())];
        if let Some(script) = script_target(&exe, &f.argv) {
            candidates.push((script, f.argv[1..].to_vec()));
        }
        let decision = candidates
            .into_iter()
            .map(|(exe, argv)| self.policy.evaluate(&Request { subject: self.subject.clone(), action: Action::Exec, resource: Resource::Exec { exe, argv } }))
            .max_by_key(|d| d.effect.restrictiveness())
            .expect("at least one candidate");
        if decision.effect == Effect::Allow {
            return;
        }
        // Executable-level rules are enforced by the kernel (and reported by the
        // sandbox log); only rules Seatbelt cannot express are recorded here.
        let enforced_in_kernel = self
            .policy
            .rules_for(&self.subject.agent_id, &self.subject.project)
            .iter()
            .find(|r| r.id == decision.rule_id && r.policy == decision.policy)
            .map(|r| crate::enforce::classify_seatbelt(r) != crate::enforce::Enforceability::Observed)
            .unwrap_or(false);
        if enforced_in_kernel {
            return;
        }
        let chain = self.tree.lock().unwrap().as_ref().and_then(|t| t.chain(f.pid)).unwrap_or_default();
        let resource = crate::escape::term_safe(&f.argv.join(" "));
        let obs = ObservedEvent { pid: Some(f.pid), delegation_chain: chain, action: "process.exec".into(), resource, decision };
        if let Ok(s) = self.store.lock() {
            let _ = s.record_observed(&self.ctx, obs);
        }
    }
}

/// Denials by the sandbox's default deny or baseline, as opposed to an explicit policy rule.
pub fn is_baseline(policy: Option<&str>, rule: Option<&str>) -> bool {
    matches!(policy, Some("seatbelt-baseline") | Some("fallback")) || matches!(rule, Some("default"))
}

/// If `exe` is a script interpreter running a script file, the script path.
fn script_target(exe: &str, argv: &[String]) -> Option<String> {
    const INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "env", "python", "python3", "perl", "ruby", "node", "bun", "deno"];
    let base = exe.rsplit('/').next().unwrap_or(exe);
    let is_interp = INTERPRETERS.contains(&base) || base.starts_with("python3.");
    let arg = argv.get(1)?;
    (is_interp && arg.starts_with('/') && Path::new(arg).is_file()).then(|| arg.clone())
}

fn wait_for(flag: &AtomicBool, timeout: Duration, mut retry: impl FnMut()) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        retry();
        let step = Instant::now() + Duration::from_millis(400);
        while Instant::now() < step {
            if flag.load(Ordering::SeqCst) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    flag.load(Ordering::SeqCst)
}

fn kill_all(pids: &[i32], me: i32) {
    for sig in [libc::SIGTERM, libc::SIGKILL] {
        for p in pids {
            if *p > 1 && *p != me {
                // SAFETY: kill has no memory effects.
                unsafe { libc::kill(*p, sig) };
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

static TERM_REQUESTED: AtomicBool = AtomicBool::new(false);
static RESTART_REQUESTED: AtomicBool = AtomicBool::new(false);
extern "C" fn on_term(_: libc::c_int) {
    TERM_REQUESTED.store(true, Ordering::SeqCst);
}
extern "C" fn on_restart(_: libc::c_int) {
    RESTART_REQUESTED.store(true, Ordering::SeqCst);
}

/// Asks the supervisor with `pid` to relaunch its agent (see [`run`]).
/// The live supervisor pid of `s`, refusing a pid that was reused: the
/// process must be an `agentacl` binary that started no later than the
/// session did (a reused pid belongs to a process started afterwards).
pub fn verified_supervisor(s: &crate::audit::SessionRecord) -> Result<i32> {
    if s.backend == "endpoint-security" {
        bail!("{} is enforced system-wide by Endpoint Security; it has no AgentACL supervisor to stop or restart (stop the agent itself)", s.session_id);
    }
    let f = crate::proc::facts(s.supervisor_pid).ok_or_else(|| anyhow::anyhow!("the supervisor of {} is not running", s.session_id))?;
    let exe = f.exe.unwrap_or_default();
    if !exe.ends_with("/agentacl") {
        bail!("pid {} is no longer an agentacl supervisor ({exe})", s.supervisor_pid);
    }
    let started = crate::audit::parse_ts(&s.started_at).ok_or_else(|| anyhow::anyhow!("session {} has an unreadable start time", s.session_id))?;
    if (f.start_time_us / 1_000_000) as i64 > started + 5 {
        bail!("pid {} started after session {}; it is not that session's supervisor", s.supervisor_pid, s.session_id);
    }
    Ok(s.supervisor_pid)
}

/// Asks a supervisor to stop its agent (SIGTERM, forwarded to the agent's
/// process group; the supervisor then records the session end).
pub fn request_stop(pid: i32) -> Result<()> {
    // SAFETY: kill has no memory effects.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        bail!("could not signal supervisor {pid}: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Unix sockets that hand out credentials or root-equivalent access (the
/// ssh-agent, Docker), resolved to the real paths the kernel checks. Only the
/// ones that exist are returned.
pub fn credential_sockets(ssh_auth_sock: Option<PathBuf>, system_docker: &Path, home: &Path) -> Vec<String> {
    [ssh_auth_sock, Some(system_docker.to_path_buf()), Some(home.join(".docker/run/docker.sock"))]
        .into_iter()
        .flatten()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

pub fn request_restart(pid: i32) -> Result<()> {
    // SAFETY: kill has no memory effects.
    if unsafe { libc::kill(pid, libc::SIGUSR1) } != 0 {
        bail!("could not signal supervisor {pid}: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// The policy files a session was built from; a change means the running
/// session's (fixed) sandbox no longer matches the policy on disk.
fn policy_inputs(paths: &Paths, opts: &RunOptions, project: &Path, agent: &str) -> Vec<PathBuf> {
    let mut v = vec![
        canon_or(&opts.policy_file.clone().unwrap_or_else(|| paths.user_policy.clone())),
        project.join(".agentacl/policy.yaml"),
        // Only this project's trust entries, not the whole trust file.
        PathBuf::from(format!("{}#{}", paths.trust_file.display(), project.display())),
    ];
    // The console's access files that can apply to this agent here.
    v.extend(crate::access::applicable(paths, agent, project));
    v
}

/// Current fingerprint of a policy input: file bytes, or (for the virtual
/// `config.yaml#<project>` input) that project's trust entries.
pub fn input_sha(paths: &Paths, input: &Path) -> Option<String> {
    let s = input.to_string_lossy();
    match s.split_once('#') {
        Some((_, project)) => crate::trust::fingerprint(paths, Path::new(project)),
        // Sites in an access file reach running agents live (scoped console
        // rules), so only its file rules need a restart.
        None if input.parent() == Some(crate::access::dir(paths).as_path()) => {
            let bytes = std::fs::read(input).ok()?;
            match agentacl_policy::raw::parse_doc(&String::from_utf8_lossy(&bytes), agentacl_policy::Layer::User, "access") {
                Ok(mut d) => {
                    d.network = Default::default();
                    // Only sites: the same as no file.
                    let f = &d.filesystem;
                    if f.allow_read.is_empty() && f.allow_write.is_empty() && f.deny_read.is_empty() && f.deny_write.is_empty() {
                        return None;
                    }
                    Some(agentacl_policy::set::sha256_hex(agentacl_policy::emit::to_yaml(&d).as_bytes()))
                }
                Err(_) => Some(agentacl_policy::set::sha256_hex(&bytes)),
            }
        }
        None => std::fs::read(input).ok().map(|b| agentacl_policy::set::sha256_hex(&b)),
    }
}

fn input_hashes(paths: &Paths, inputs: &[PathBuf]) -> Vec<Option<String>> {
    inputs.iter().map(|i| input_sha(paths, i)).collect()
}

/// Runs the agent. `agentacl restart` (SIGUSR1 to this supervisor) stops the
/// agent and relaunches it under freshly loaded policy, adding the provider's
/// resume arguments (e.g. `claude --continue`) so the conversation carries on.
/// Each launch is its own session; `on_session_end` is called after each.
pub fn run(paths: &Paths, mut opts: RunOptions, mut on_session_end: impl FnMut(&Summary)) -> Result<i32> {
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe {
        let h = on_restart as extern "C" fn(libc::c_int) as *const () as libc::sighandler_t;
        libc::signal(libc::SIGUSR1, h);
    }
    RESTART_REQUESTED.store(false, Ordering::SeqCst);
    let mut prepared = prepare(paths, &opts)?;
    loop {
        // The relaunch is prepared (and validated) while the agent still runs;
        // the agent is stopped only if this succeeds (ui.md §4.7).
        let mut next_opts = opts.clone();
        for a in &prepared.reqs.resume_args {
            if !next_opts.argv.iter().skip(1).any(|x| x == a) {
                next_opts.argv.push(a.clone());
            }
        }
        let mut try_next = || prepare(paths, &next_opts);
        let result = run_prepared(paths, &opts, &prepared, &mut try_next);
        prepared.cleanup();
        let (summary, next) = result?;
        on_session_end(&summary);
        match next {
            Some(n) => {
                prepared = n;
                opts = next_opts;
            }
            None => return Ok(summary.exit_code),
        }
    }
}

fn run_prepared(paths: &Paths, opts: &RunOptions, p: &Prepared, try_next: &mut dyn FnMut() -> Result<Prepared>) -> Result<(Summary, Option<Prepared>)> {
    let s = &p.session;
    let ctx = EventContext {
        human: s.human.user.clone(),
        machine: s.machine.clone(),
        agent: s.agent.id.clone(),
        agent_version: s.agent.version.clone(),
        session: s.session_id.clone(),
        backend: s.backend.clone(),
    };
    let store = Store::open(&paths.db_path)?;
    let before: BTreeMap<PathBuf, Option<String>> = integrity::snapshot_hashes(&p.watch);
    let policy_files = policy_inputs(paths, opts, &s.project, &s.agent.id);
    let policy_before = input_hashes(paths, &policy_files);

    // Sentinel for knowing the log stream is live / drained (must exist to be reported).
    let sentinel = p.session_dir.join("sentinel");
    std::fs::write(&sentinel, b"agentacl")?;
    let sentinel_s = canon_or(&sentinel).to_string_lossy().into_owned();

    let live = Arc::new(Live {
        store: Mutex::new(store),
        ctx: ctx.clone(),
        policy: p.policy.clone(),
        subject: p.subject(),
        tree: Mutex::new(None),
        dup_index: Mutex::new(HashMap::new()),
        sentinel: sentinel_s,
        sentinel_seen: AtomicBool::new(false),
        warnings: Mutex::new(vec![]),
        state_dir: canon_or(&paths.state_dir),
        agent_name: s.agent.display_name.clone(),
        home: s.human.home.to_string_lossy().into_owned(),
        refused_seen: Mutex::new(HashSet::new()),
    });

    // Proxy.
    // Policy decisions, adjusted live by the console (blocks, approvals).
    let decider = Arc::new(crate::netlive::LiveNetDecider::new(
        crate::netproxy::PolicyNetDecider { policy: p.policy.clone(), subject: p.subject() },
        canon_or(&paths.state_dir),
        s.session_id.clone(),
        s.agent.id.clone(),
        s.agent.display_name.clone(),
        s.project.to_string_lossy().into_owned(),
        s.started_at.clone(),
    ));
    let live_p = live.clone();
    let guard = Arc::new(crate::netproxy::UiPortGuard { state_dir: canon_or(&paths.state_dir) });
    let proxy = crate::netproxy::NetProxy::start_guarded(
        decider,
        Arc::new(move |e: EnforcedEvent| {
            let recorded = live_p.store.lock().ok().and_then(|st| st.record_enforced(&live_p.ctx, e).ok());
            if let Some(e) = recorded {
                live_p.note_refused(&e);
            }
        }),
        Some(guard),
    )?;

    // Profile + launch plan.
    let mut pty = pty::Pty::open()?;
    let plan = SeatbeltBackend.prepare(&p.policy, &p.compile_input(proxy.port, Some(&pty.slave_path)), p.profile_path(), &p.agent_argv)?;

    // Log observer, confirmed live before the agent starts.
    let live_o = live.clone();
    let observer = SandboxLogObserver::start(move |l| live_o.on_line(l))?;
    if !wait_for(&live.sentinel_seen, Duration::from_secs(4), || {
        let _ = sandbox_log::trigger_sentinel(&sentinel);
    }) {
        live.warn("sandbox log stream did not confirm it is live; early denials may be missing from the audit log (enforcement is unaffected)".into());
    }

    // Environment.
    let env = env::build(std::env::vars(), &p.reqs.env_passthrough, &opts.keep_env, proxy.port, &s.tmpdir.to_string_lossy(), &s.session_id);

    // Session record + start event.
    {
        let st = live.store.lock().unwrap();
        st.insert_session(&SessionRecord {
            session_id: s.session_id.clone(),
            identity_json: serde_json::to_string(s)?,
            agent: s.agent.id.clone(),
            project: s.project.to_string_lossy().into(),
            policy_name: s.policy.name.clone(),
            policy_sha256: s.policy.sha256.clone(),
            backend: s.backend.clone(),
            supervisor_pid: s.parent_pid,
            agent_pid: None,
            started_at: s.started_at.clone(),
            ended_at: None,
            exit_code: None,
        })?;
        st.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::SessionStart, pid: Some(s.parent_pid), detail: s.agent.binary.clone() })?;
        let inputs: Vec<String> = s.policy_sources.iter().map(|i| format!("{}={}", i.path.display(), i.sha256.as_deref().unwrap_or("absent"))).collect();
        st.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::PolicyInputs, pid: None, detail: inputs.join(" ") })?;
    }

    // Spawn.
    let cwd = opts.cwd.clone().map(Ok).unwrap_or_else(std::env::current_dir)?;
    let mut cmd = std::process::Command::new(&plan.program);
    cmd.args(&plan.args).env_clear().envs(env.vars.iter().map(|(k, v)| (k, v))).env("PWD", &cwd).current_dir(&cwd);
    pty.attach(&mut cmd)?;
    let raw = pty::RawGuard::enter();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            drop(raw);
            observer.stop();
            proxy.stop();
            return Err(e).context("spawning the sandboxed agent");
        }
    };
    let agent_pid = child.id() as i32;
    let relay = pty::Relay::start(&pty)?;
    // Only the agent holds the slave now, so the relay sees EOF when it exits.
    pty.close_slave();
    {
        let root = proc::facts(agent_pid).unwrap_or(proc::ProcessFacts { pid: agent_pid, ppid: s.parent_pid, pgid: agent_pid, uid: 0, start_time_us: 0, exe: None, argv: vec![], name: String::new() });
        *live.tree.lock().unwrap() = Some(ProcessTree::new(root, s.agent.id.clone()));
        let _ = live.store.lock().unwrap().set_agent_pid(&s.session_id, agent_pid);
    }

    // Poller.
    let stop = Arc::new(AtomicBool::new(false));
    let (live_t, stop_t) = (live.clone(), stop.clone());
    let poller = std::thread::spawn(move || {
        let mut next_flush = Instant::now();
        while !stop_t.load(Ordering::SeqCst) {
            if Instant::now() >= next_flush {
                next_flush = Instant::now() + Duration::from_secs(5);
                if let Ok(Some(text)) = crate::notify::flush(&live_t.state_dir, crate::notify::now()) {
                    crate::notify::send(&text);
                }
            }
            let snap = proc::snapshot();
            let changes = live_t.tree.lock().unwrap().as_mut().map(|t| t.refresh(&snap)).unwrap_or_default();
            for c in changes {
                live_t.on_tree_change(c);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    // Forward termination requests to the agent's session.
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe {
        let h = on_term as extern "C" fn(libc::c_int) as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGHUP, h);
    }
    let mut next: Option<Prepared> = None;
    let mut stop_deadline: Option<Instant> = None;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        let mut stop = TERM_REQUESTED.swap(false, Ordering::SeqCst);
        if RESTART_REQUESTED.swap(false, Ordering::SeqCst) && next.is_none() && stop_deadline.is_none() {
            match try_next() {
                Ok(n) => {
                    next = Some(n);
                    stop = true;
                }
                Err(e) => {
                    let msg = format!("restart refused, the agent keeps running under its current policy: {e:#}");
                    if let Ok(st) = live.store.lock() {
                        let _ = st.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::RestartRefused, pid: None, detail: crate::escape::term_safe(&msg) });
                    }
                    live.warnings.lock().unwrap().push(msg);
                }
            }
        }
        if stop {
            // SAFETY: signal the agent's process group (it is a session leader).
            unsafe { libc::kill(-agent_pid, libc::SIGTERM) };
            stop_deadline.get_or_insert(Instant::now() + Duration::from_secs(5));
        }
        if stop_deadline.is_some_and(|d| Instant::now() > d) {
            // SAFETY: as above; the agent ignored SIGTERM.
            unsafe { libc::kill(-agent_pid, libc::SIGKILL) };
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    use std::os::unix::process::ExitStatusExt;
    let exit_code = status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0));

    // Clean up descendants (T20): the agent's session, plus anything tracked.
    let me = std::process::id() as i32;
    let mut leftovers = proc::session_members(agent_pid);
    if let Some(t) = live.tree.lock().unwrap().as_mut() {
        t.refresh(&proc::snapshot());
        leftovers.extend(t.live_members());
    }
    leftovers.retain(|p| *p != agent_pid);
    leftovers.sort();
    leftovers.dedup();
    if !leftovers.is_empty() {
        kill_all(&leftovers, me);
    }
    drop(raw);
    relay.finish(Duration::from_millis(500));
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();

    // Drain the log stream: wait for a fresh sentinel report.
    live.sentinel_seen.store(false, Ordering::SeqCst);
    if !wait_for(&live.sentinel_seen, Duration::from_secs(3), || {
        let _ = sandbox_log::trigger_sentinel(&sentinel);
    }) {
        live.warn("sandbox log stream did not drain within 3s; late denials may be missing from the audit log".into());
    }
    observer.stop();
    proxy.stop();

    let policy_changed = policy_before != input_hashes(paths, &policy_files);
    let after = integrity::snapshot_hashes(&p.watch);
    let integrity_changes = integrity::changed(&before, &after);
    let st = live.store.lock().unwrap();
    let ended = now_rfc3339();
    st.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::SessionEnd, pid: Some(agent_pid), detail: format!("exit {exit_code}") })?;
    st.end_session(&s.session_id, &ended, Some(exit_code))?;
    if !env.stripped.is_empty() {
        let _ =
            st.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::BackendWarning, pid: None, detail: format!("environment variables withheld from the agent: {}", env.stripped.join(", ")) });
    }

    let events = st.events(&EventQuery { session: Some(s.session_id.clone()), limit: Some(100_000), ..Default::default() })?;
    let mut denied: BTreeMap<(String, String, String), u32> = BTreeMap::new();
    let mut observed = Vec::new();
    let (mut by_policy, mut by_baseline) = (0u32, 0u32);
    for (_, e) in &events {
        match (e.enforcement, e.decision) {
            (Some(Enforcement::Enforced), Some(Effect::Deny | Effect::Ask)) => {
                let baseline = is_baseline(e.policy.as_deref(), e.rule_id.as_deref());
                if baseline {
                    by_baseline += e.count;
                } else {
                    by_policy += e.count;
                }
                let rule = format!("{}/{}", e.policy.clone().unwrap_or_default(), e.rule_id.clone().unwrap_or_default());
                *denied.entry((e.action.clone(), e.resource.clone(), rule)).or_default() += e.count;
            }
            (Some(Enforcement::Observed), Some(Effect::Deny | Effect::Ask)) => {
                observed.push((e.action.clone(), e.resource.clone(), e.rule_id.clone().unwrap_or_default()));
            }
            _ => {}
        }
    }
    let warnings = live.warnings.lock().unwrap().clone();
    let restarted = next.is_some();
    let mut denied: Vec<(String, String, String, u32)> = denied.into_iter().map(|((a, r, id), n)| (a, r, id, n)).collect();
    denied.sort_by_key(|(_, _, rule, n)| {
        let (p, r) = rule.split_once('/').unwrap_or((rule, ""));
        (is_baseline(Some(p), Some(r)), std::cmp::Reverse(*n))
    });
    Ok((
        Summary {
            session_id: s.session_id.clone(),
            exit_code,
            denied,
            denied_by_policy: by_policy,
            denied_by_baseline: by_baseline,
            restarted,
            policy_changed,
            agent_argv0: opts.argv.first().cloned().unwrap_or_default(),
            resume_args: p.reqs.resume_args.clone(),
            observed,
            integrity_changes,
            stripped_env: env.stripped,
            warnings,
        },
        next,
    ))
}
