//! Decisions for every process on the Mac (docs/design/endpoint-security.md).
//!
//! - Processes that aren't part of an agent session are always allowed, and
//!   nothing is recorded for them.
//! - For an agent's processes, file, exec and socket requests are evaluated
//!   with the policy `agentacl run` loads for that agent and project (see
//!   the design doc for the differences). Exec rules see the arguments.
//!   Setuid programs are refused, and so are the programs that would start
//!   a process outside the session (launchd, Apple Events, `open`).
//! - Agents can't signal or take control of AgentACL's own processes, or
//!   take control of processes outside their session.
//! - The policy provider reloads when rules change, so a grant made in the
//!   console applies to the agent's next attempt, without a restart.
//! - Nothing is cached in the kernel (see [`Verdict`]).
//!
//! The engine never waits: every answer is computed from memory, within the
//! ES deadline. `ask` rules are refused and recorded as requests.

use crate::model::{Msg, Op, Proc, ProcKey, Verdict};
use crate::tracker::{project_for, Change, Session, Tracker};
use agentacl_core::enforce::seatbelt::SANDBOX_EXEC;
use agentacl_core::es_journal::{EsRecord, Kind};
use agentacl_policy::set::PolicySet;
use agentacl_policy::{Action, Decision, Effect, PolicyEngine, Request, Resource, Subject, WriteOp};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The policy for an agent in a project, as `agentacl run` would load it.
pub trait PolicyProvider {
    fn policy(&mut self, agent: &str, project: &Path) -> Arc<PolicySet>;
}

/// The user the daemon serves.
#[derive(Debug, Clone)]
pub struct Config {
    pub home: PathBuf,
    /// The user's temp folder (an unsupervised agent's `${TMPDIR}`).
    pub tmpdir: PathBuf,
    /// Only this user's agents get sessions (`None`: any user, for tests).
    pub uid: Option<u32>,
    pub own_pid: i32,
}

pub struct Engine<P: PolicyProvider> {
    tracker: Tracker,
    provider: P,
    config: Config,
    /// AgentACL's own processes (the daemon, supervisors, the console).
    protected: HashSet<ProcKey>,
    /// `sandbox-exec` started by AgentACL, about to exec a supervised agent.
    launching: HashSet<ProcKey>,
    /// Records for the journal, drained by the daemon.
    pub out: Vec<EsRecord>,
    now: Box<dyn Fn() -> String + Send>,
}

/// A process already running when the daemon starts.
#[derive(Debug, Clone)]
pub struct Running {
    pub proc: Proc,
    pub cwd: Option<String>,
    /// The agent it is (id, display name), if any.
    pub agent: Option<(String, String)>,
}

/// Unix sockets that hand out credentials or root-equivalent access
/// (threat model T6), wherever they are.
fn credential_socket(path: &str) -> bool {
    path.ends_with("docker.sock")
        || path.contains("/podman/")
        || path.ends_with("agent.sock")
        || path.contains("ssh-agent")
        || (path.starts_with("/private/tmp/com.apple.launchd.") && path.ends_with("/Listeners"))
        || path.contains("/S.gpg-agent")
        || path.ends_with("/usbmuxd") // iPhones and iPads attached to the Mac
}

fn is_agentacl(exe: &str) -> bool {
    matches!(Path::new(exe).file_name().and_then(|n| n.to_str()), Some("agentacl" | "agentacl-esd"))
}

/// Programs that start a process outside the agent's session: by launchd
/// (`launchctl submit`, `at`, `crontab`), by Apple Events (`osascript`
/// telling Terminal to run a script) or by LaunchServices (`open -a`).
/// Matched by name and by signing id, so a renamed copy is refused too.
/// `open` with only web addresses (signing in) is allowed.
fn launches_outside(target: &Proc, argv: &[String]) -> bool {
    let name = Path::new(&target.exe).file_name().and_then(|n| n.to_str()).unwrap_or("");
    let by = |names: &[&str], ids: &[&str]| names.contains(&name) || ids.contains(&target.signing_id.as_str());
    if by(&["launchctl", "osascript", "at", "batch", "crontab"], &["com.apple.xpc.launchctl", "com.apple.osascript", "com.apple.atrm", "com.apple.batch", "com.apple.crontab"]) {
        return true;
    }
    by(&["open"], &["com.apple.open"]) && !(argv.len() > 1 && argv[1..].iter().all(|a| a.starts_with("https://") || a.starts_with("http://")))
}

fn builtin(rule: &str, reason: &str) -> Decision {
    Decision { effect: Effect::Deny, policy: "builtin".into(), rule_id: rule.into(), reason: reason.into(), trace: vec![] }
}

impl<P: PolicyProvider> Engine<P> {
    pub fn new(provider: P, config: Config) -> Self {
        Engine { tracker: Tracker::default(), provider, config, protected: HashSet::new(), launching: HashSet::new(), out: vec![], now: Box::new(agentacl_core::audit::now_rfc3339) }
    }

    #[cfg(test)]
    pub fn with_clock(mut self, f: impl Fn() -> String + Send + 'static) -> Self {
        self.now = Box::new(f);
        self
    }

    pub fn sessions(&self) -> usize {
        self.tracker.session_count()
    }

    fn record(&mut self, s: &Session, kind: Kind, p: &Proc, action: &str, resource: &str, d: Option<Decision>) {
        let chain = vec![s.agent_name.clone(), Path::new(&p.exe).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()];
        self.out.push(EsRecord {
            ts: (self.now)(),
            kind,
            session: s.id.clone(),
            agent: s.agent_id.clone(),
            agent_name: s.agent_name.clone(),
            project: s.project.to_string_lossy().into_owned(),
            pid: p.key.map(|k| k.pid),
            chain,
            action: action.into(),
            resource: resource.into(),
            decision: d,
        });
    }

    fn change(&mut self, c: Option<Change>, p: &Proc) {
        match c {
            Some(Change::Started(s)) => self.record(&s, Kind::SessionStart, p, "", "", None),
            Some(Change::Ended(s)) => self.record(&s, Kind::SessionEnd, p, "", "", None),
            None => {}
        }
    }

    fn evaluate(&mut self, s: &Session, action: Action, resource: Resource) -> Decision {
        let set = self.provider.policy(&s.agent_id, &s.project);
        let subject = Subject { agent_id: s.agent_id.clone(), project: s.project.to_string_lossy().into(), session: s.id.clone(), ..Default::default() };
        set.evaluate(&Request { subject, action, resource })
    }

    /// Every check must allow; the first refusal is recorded and returned.
    /// An unknown path (ES couldn't give it, or truncated it) is refused:
    /// as a path it would match nothing, or the wrong thing. A read is
    /// allowed where a write is, unless a rule denies the read (as Seatbelt
    /// grants `file-read*` with `file-write*`).
    fn check(&mut self, s: &Session, p: &Proc, checks: Vec<(Action, String)>) -> Verdict {
        for (action, path) in checks {
            if path.is_empty() {
                return self.deny(s, p, action.event_name(), "(unknown path)", builtin("unknown-path", "Endpoint Security didn't give the full path; refused for an agent"));
            }
            let mut d = self.evaluate(s, action, Resource::Path(path.clone()));
            if action == Action::FsRead && d.effect != Effect::Allow && d.rule_id == "default" {
                let w = self.evaluate(s, Action::FsWrite(WriteOp::Write), Resource::Path(path.clone()));
                if w.effect == Effect::Allow {
                    d = w;
                }
            }
            if d.effect != Effect::Allow {
                self.record(s, Kind::Denied, p, action.event_name(), &path, Some(d));
                return Verdict::DENY;
            }
        }
        Verdict::ALLOW
    }

    fn deny(&mut self, s: &Session, p: &Proc, action: &str, resource: &str, d: Decision) -> Verdict {
        self.record(s, Kind::Denied, p, action, resource, Some(d));
        Verdict::DENY
    }

    /// Sessions for agents that were already running when the daemon
    /// started (best effort: ES only reports what happens from now on).
    /// Agents under an `agentacl` supervisor are left to it.
    pub fn adopt_running(&mut self, procs: &[Running]) {
        let by_pid: HashMap<i32, &Running> = procs.iter().filter_map(|r| r.proc.key.map(|k| (k.pid, r))).collect();
        let ancestors = |r: &Running| {
            let mut out = vec![];
            let mut cur = r.proc.ppid;
            while cur > 1 && out.len() < 64 {
                let Some(a) = by_pid.get(&cur) else { break };
                out.push(*a);
                cur = a.proc.ppid;
            }
            out
        };
        for r in procs {
            if r.proc.key.is_none() || is_agentacl(&r.proc.exe) {
                self.protected.insert(r.proc.key());
                continue;
            }
            let Some((agent_id, agent_name)) = r.agent.clone() else { continue };
            if self.config.uid.is_some_and(|u| u != r.proc.uid) {
                continue;
            }
            // The outermost agent is the session; a supervised one is skipped.
            if ancestors(r).iter().any(|a| is_agentacl(&a.proc.exe) || a.agent.is_some()) {
                continue;
            }
            let root = r.proc.key();
            let mut keys = vec![root];
            let mut frontier = vec![root.pid];
            while let Some(pid) = frontier.pop() {
                for c in procs.iter().filter(|c| c.proc.ppid == pid) {
                    if let Some(k) = c.proc.key {
                        if !keys.contains(&k) {
                            keys.push(k);
                            frontier.push(k.pid);
                        }
                    }
                }
            }
            let s = Session { id: agentacl_core::session::new_session_id(), agent_id, agent_name, project: project_for(r.cwd.as_deref(), &self.config.home), root };
            let c = self.tracker.insert(s, &keys);
            self.change(Some(c), &r.proc);
        }
    }

    pub fn decide(&mut self, m: &Msg) -> Verdict {
        let p = &m.proc;
        match &m.op {
            Op::Fork { child } => {
                self.tracker.on_fork(p, child);
                if self.protected.contains(&p.key()) {
                    if let Some(k) = child.key {
                        self.protected.insert(k);
                    }
                }
                Verdict::ALLOW
            }
            Op::Exit => {
                self.protected.remove(&p.key());
                self.launching.remove(&p.key());
                let c = self.tracker.on_exit(p);
                self.change(c, p);
                Verdict::ALLOW
            }
            Op::Exec { target, .. } if !m.auth => {
                self.tracker.on_exec_done(p, target);
                Verdict::ALLOW
            }
            Op::Exec { target, argv, cwd, setuid } => {
                // Protection follows the image, not the pid: a child AgentACL
                // forks stops being AgentACL once it execs something else.
                // (Before its exec the child is still `agentacl`, which covers
                // a fork notification that arrives late.)
                // Keyed by audit token, so a reused pid inherits nothing.
                let from_agentacl = self.protected.remove(&p.key()) || is_agentacl(&p.exe);
                let supervised = self.launching.remove(&p.key());
                if is_agentacl(&target.exe) {
                    self.protected.insert(target.key());
                } else if from_agentacl && target.exe == SANDBOX_EXEC {
                    self.launching.insert(target.key());
                }
                let Some(s) = self.tracker.member(p) else {
                    // `agentacl run` (agentacl → sandbox-exec → agent): Seatbelt
                    // and its supervisor enforce that session, and wait on
                    // `ask` rules that this engine would refuse at once.
                    if supervised || self.config.uid.is_some_and(|u| u != target.uid) {
                        return Verdict::ALLOW;
                    }
                    let c = self.tracker.start(target, argv, cwd.as_deref(), &self.config.home);
                    self.change(c, target);
                    return Verdict::ALLOW;
                };
                let cmd = argv.join(" ");
                let shown = if cmd.is_empty() { target.exe.clone() } else { cmd };
                if target.exe.is_empty() {
                    return self.deny(&s, p, "process.exec", &shown, builtin("unknown-path", "Endpoint Security didn't give the program's full path; refused for an agent"));
                }
                if *setuid {
                    return self.deny(&s, p, "process.exec", &shown, builtin("setuid", "setuid programs can't run in an agent session"));
                }
                if launches_outside(target, argv) {
                    return self.deny(&s, p, "process.exec", &shown, builtin("launch-outside", "would start a process outside the agent's session (launchd, Apple Events, open)"));
                }
                let d = self.evaluate(&s, Action::Exec, Resource::Exec { exe: target.exe.clone(), argv: argv.clone() });
                if d.effect != Effect::Allow {
                    return self.deny(&s, p, "process.exec", &shown, d);
                }
                self.tracker.add_image(target, &s.id);
                Verdict::ALLOW
            }
            Op::Signal { target, signal } => {
                let Some(s) = self.tracker.member(p) else { return Verdict::ALLOW };
                if self.protected.contains(&target.key()) || target.key().pid == self.config.own_pid || is_agentacl(&target.exe) {
                    let d = Decision { effect: Effect::Deny, policy: "agentacl-self".into(), rule_id: "agentacl-self".into(), reason: "agents can't signal AgentACL".into(), trace: vec![] };
                    return self.deny(&s, p, "process.signal", &format!("{} (signal {signal})", target.exe), d);
                }
                Verdict::ALLOW
            }
            Op::GetTask { target } => {
                let Some(s) = self.tracker.member(p) else { return Verdict::ALLOW };
                if self.tracker.session_of(target.key).is_some_and(|t| t.id == s.id) {
                    return Verdict::ALLOW; // a debugger on the agent's own processes
                }
                self.deny(&s, p, "process.control", &target.exe, builtin("task-for-pid", "agents can't take control of processes outside their session"))
            }
            Op::UnixConnect { path } => {
                let Some(s) = self.tracker.member(p) else { return Verdict::ALLOW };
                // Seatbelt refuses unix sockets unless allowed; here, sockets
                // of the system, the temp folders and the project are allowed,
                // except credential ones; outside the system's, only if the
                // policy lets the agent read the socket's path.
                let tmp = self.config.tmpdir.to_string_lossy().into_owned();
                let under = |root: &str| !root.is_empty() && path.starts_with(&format!("{}/", root.trim_end_matches('/')));
                let place = under("/private/var/run") || under("/private/tmp") || under(&tmp) || under(&s.project.to_string_lossy());
                if credential_socket(path) || !place {
                    return self.deny(
                        &s,
                        p,
                        "network.connect",
                        path,
                        builtin("credential-socket", "Unix sockets outside the system, temp and project folders, and credential sockets (ssh-agent, Docker, gpg-agent), are refused"),
                    );
                }
                if under("/private/var/run") {
                    return Verdict::ALLOW; // system services (name resolution, logging)
                }
                self.check(&s, p, vec![(Action::FsRead, path.clone())])
            }
            op => {
                let Some(s) = self.tracker.member(p) else { return Verdict::ALLOW };
                let w = |o: WriteOp| Action::FsWrite(o);
                let checks: Vec<(Action, String)> = match op {
                    Op::Open { path, read, write } => {
                        let mut c = vec![];
                        if *read || !*write {
                            c.push((Action::FsRead, path.clone()));
                        }
                        if *write {
                            c.push((w(WriteOp::Write), path.clone()));
                        }
                        c
                    }
                    Op::Create { path } => vec![(w(WriteOp::Create), path.clone())],
                    Op::Truncate { path } => vec![(w(WriteOp::Write), path.clone())],
                    Op::Unlink { path } => vec![(w(WriteOp::Unlink), path.clone())],
                    Op::Meta { path } => vec![(w(WriteOp::Meta), path.clone())],
                    Op::Exchange { a, b } => vec![(w(WriteOp::Write), a.clone()), (w(WriteOp::Write), b.clone())],
                    Op::Rename { source, destination } => vec![(w(WriteOp::Rename), source.clone()), (w(WriteOp::Create), destination.clone())],
                    Op::Link { source, destination } => vec![(w(WriteOp::Link), source.clone()), (w(WriteOp::Create), destination.clone())],
                    Op::Clone { source, destination } | Op::CopyFile { source, destination } => vec![(Action::FsRead, source.clone()), (w(WriteOp::Create), destination.clone())],
                    _ => vec![],
                };
                self.check(&s, p, checks)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcKey;
    use agentacl_policy::expand::Vars;
    use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySource};
    use agentacl_policy::Layer;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Built-ins plus a user policy that can change (to test live reload).
    struct TestPolicy {
        home: String,
        user: Rc<RefCell<String>>,
        loads: Rc<RefCell<usize>>,
    }

    impl PolicyProvider for TestPolicy {
        fn policy(&mut self, agent: &str, project: &Path) -> Arc<PolicySet> {
            *self.loads.borrow_mut() += 1;
            let mut src = builtin_sources(true);
            src.push(PolicySource { layer: Layer::User, name: "user".into(), yaml: self.user.borrow().clone() });
            let vars = Vars {
                home: self.home.clone(),
                project: project.to_string_lossy().into(),
                tmpdir: "/private/tmp/agentacl-es-test".into(),
                agent_state: None,
                agentacl_state: format!("{}/Library/Application Support/AgentACL", self.home),
                agentacl_config: format!("{}/.config/agentacl", self.home),
            };
            let _ = agent;
            Arc::new(PolicySet::load(src, &vars, &LoadOptions::default()).unwrap())
        }
    }

    const CLAUDE_TEAM: &str = "Q6L2SF6YDW";

    fn proc(pid: i32, version: i32, exe: &str) -> Proc {
        Proc { key: Some(ProcKey { pid, version }), parent: None, ppid: 1, uid: 501, exe: exe.into(), signing_id: String::new(), team_id: String::new(), platform_binary: true }
    }

    fn claude(pid: i32) -> Proc {
        Proc {
            key: Some(ProcKey { pid, version: 1 }),
            parent: None,
            ppid: 1,
            uid: 501,
            exe: "/Users/u/.local/share/claude/versions/2.1.280".into(),
            signing_id: "com.anthropic.claude-code".into(),
            team_id: CLAUDE_TEAM.into(),
            platform_binary: false,
        }
    }

    struct T {
        e: Engine<TestPolicy>,
        user: Rc<RefCell<String>>,
        loads: Rc<RefCell<usize>>,
        project: String,
    }

    /// A Mac with a home, a project (a git repo, so it resolves) and an engine.
    fn setup() -> (tempfile::TempDir, T) {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        let project = home.join("src/app");
        std::fs::create_dir_all(&project).unwrap();
        assert!(std::process::Command::new("/usr/bin/git").arg("-C").arg(&project).args(["init", "-q"]).status().unwrap().success());
        let user = Rc::new(RefCell::new("version: v1\n".to_string()));
        let loads = Rc::new(RefCell::new(0));
        let p = TestPolicy { home: home.to_string_lossy().into(), user: user.clone(), loads: loads.clone() };
        let config = Config { home: home.clone(), tmpdir: root.join("tmp"), uid: Some(501), own_pid: 99 };
        let e = Engine::new(p, config).with_clock(|| "2026-10-09T10:00:00.000Z".into());
        (t, T { e, user, loads, project: project.to_string_lossy().into() })
    }

    impl T {
        fn home(&self) -> String {
            self.e.config.home.to_string_lossy().into_owned()
        }
        /// `shell` (pid 10) execs Claude in the project.
        fn start_claude(&mut self) -> Proc {
            let shell = proc(10, 1, "/bin/zsh");
            let c = claude(10);
            let v = self.e.decide(&Msg { proc: shell, op: Op::Exec { target: c.clone(), argv: vec!["claude".into()], cwd: Some(self.project.clone()), setuid: false }, auth: true });
            assert_eq!(v, Verdict::ALLOW);
            c
        }
        fn open(&mut self, p: &Proc, path: &str, write: bool) -> Verdict {
            self.e.decide(&Msg { proc: p.clone(), op: Op::Open { path: path.into(), read: true, write }, auth: true })
        }
        /// `parent` forks a child (pid) and the child execs `exe` with `argv`.
        fn spawn(&mut self, parent: &Proc, pid: i32, exe: &str, argv: &[&str]) -> (Proc, Verdict) {
            let child = proc(pid, 1, &parent.exe);
            self.e.decide(&Msg { proc: parent.clone(), op: Op::Fork { child: child.clone() }, auth: false });
            let target = proc(pid, 2, exe);
            let exec = Op::Exec { target: target.clone(), argv: argv.iter().map(|s| s.to_string()).collect(), cwd: Some(self.project.clone()), setuid: false };
            let v = self.e.decide(&Msg { proc: child.clone(), op: exec.clone(), auth: true });
            if v.allow {
                self.e.decide(&Msg { proc: child, op: exec, auth: false }); // it happened
            }
            (target, v)
        }
    }

    #[test]
    fn identifies_agents_by_signature_and_starts_a_session() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        assert_eq!(t.e.sessions(), 1);
        let start = &t.e.out[0];
        assert_eq!((start.kind.clone(), start.agent.as_str(), start.project.as_str()), (Kind::SessionStart, "claude-code", t.project.as_str()));
        // The same binary with no signature and an unknown path isn't an agent.
        let mut fake = claude(20);
        fake.team_id.clear();
        fake.signing_id.clear();
        fake.exe = "/usr/local/bin/not-an-agent".into();
        t.e.decide(&Msg { proc: proc(20, 1, "/bin/zsh"), op: Op::Exec { target: fake, argv: vec![], cwd: None, setuid: false }, auth: true });
        assert_eq!(t.e.sessions(), 1);
        let _ = c;
    }

    #[test]
    fn protects_the_agent_and_every_descendant_but_not_others() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let secret = format!("{}/.aws/credentials", t.home());
        assert_eq!(t.open(&c, &secret, false), Verdict::DENY, "the agent itself");
        let (bash, v) = t.spawn(&c, 11, "/bin/bash", &["bash", "-c", "cat ~/.aws/credentials"]);
        assert_eq!(v, Verdict::ALLOW);
        let (cat, _) = t.spawn(&bash, 12, "/bin/cat", &["cat", &secret]);
        assert_eq!(t.open(&cat, &secret, false), Verdict::DENY, "a grandchild");
        let project_file = format!("{}/README.md", t.project);
        assert_eq!(t.open(&cat, &project_file, true), Verdict::ALLOW, "the project stays open");
        // The human's own cat, outside any session, is untouched and unrecorded.
        let before = t.e.out.len();
        assert_eq!(t.open(&proc(500, 1, "/bin/cat"), &secret, false), Verdict::ALLOW);
        assert_eq!(t.e.out.len(), before);
        let d = t.e.out.iter().rev().find(|r| r.kind == Kind::Denied).unwrap();
        assert_eq!((d.action.as_str(), d.decision.as_ref().unwrap().rule_id.as_str()), ("filesystem.read", "aws"));
        assert_eq!(d.chain, vec!["Claude Code".to_string(), "cat".to_string()]);
    }

    #[test]
    fn a_child_seen_before_its_fork_is_adopted_through_its_parent() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let mut early = proc(13, 1, "/bin/cat");
        early.parent = c.key;
        assert_eq!(t.open(&early, &format!("{}/.ssh/id_ed25519", t.home()), false), Verdict::DENY);
    }

    #[test]
    fn argument_rules_and_setuid_are_enforced() {
        let (_t, mut t) = setup();
        *t.user.borrow_mut() = "version: v1\nprocess:\n  deny: [\"git push *\"]\n".into();
        let c = t.start_claude();
        let (_, v) = t.spawn(&c, 30, "/usr/bin/git", &["git", "push", "origin", "main"]);
        assert_eq!(v, Verdict::DENY, "git push is blocked, not just observed");
        let (_, v) = t.spawn(&c, 31, "/usr/bin/git", &["git", "status"]);
        assert_eq!(v, Verdict::ALLOW);
        let child = proc(32, 1, &c.exe);
        t.e.decide(&Msg { proc: c.clone(), op: Op::Fork { child: child.clone() }, auth: false });
        let sudo = proc(32, 2, "/usr/local/bin/sudo-copy");
        let v = t.e.decide(&Msg { proc: child, op: Op::Exec { target: sudo, argv: vec!["sudo".into(), "true".into()], cwd: None, setuid: true }, auth: true });
        assert_eq!(v, Verdict::DENY, "setuid, platform binary or not");
    }

    #[test]
    fn renames_links_and_deletes_of_protected_files_are_refused() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let secret = format!("{}/.aws/credentials", t.home());
        let out = format!("{}/leak.txt", t.project);
        for op in [
            Op::Rename { source: secret.clone(), destination: out.clone() },
            Op::Link { source: secret.clone(), destination: out.clone() },
            Op::Clone { source: secret.clone(), destination: out.clone() },
            Op::Unlink { path: secret.clone() },
            Op::Truncate { path: secret.clone() },
            Op::Create { path: format!("{}/.git/hooks/pre-commit", t.project) },
        ] {
            assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: op.clone(), auth: true }), Verdict::DENY, "{op:?}");
        }
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Rename { source: format!("{}/a", t.project), destination: format!("{}/b", t.project) }, auth: true }), Verdict::ALLOW);
    }

    #[test]
    fn agents_cannot_signal_agentacl_or_reach_credential_sockets() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let esd = proc(99, 1, "/Library/PrivilegedHelperTools/agentacl-esd");
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Signal { target: esd.clone(), signal: 9 }, auth: true }), Verdict::DENY);
        // A supervisor started later is protected too.
        let sup = proc(200, 2, "/opt/homebrew/bin/agentacl");
        t.e.decide(&Msg { proc: proc(200, 1, "/bin/zsh"), op: Op::Exec { target: sup.clone(), argv: vec![], cwd: None, setuid: false }, auth: true });
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Signal { target: sup, signal: 15 }, auth: true }), Verdict::DENY);
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Signal { target: proc(300, 1, "/bin/sleep"), signal: 15 }, auth: true }), Verdict::ALLOW);
        // The human can still stop AgentACL.
        assert_eq!(t.e.decide(&Msg { proc: proc(400, 1, "/bin/kill"), op: Op::Signal { target: esd, signal: 15 }, auth: true }), Verdict::ALLOW);
        let sock = format!("{}/.docker/run/docker.sock", t.home());
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::UnixConnect { path: sock }, auth: true }), Verdict::DENY);
        assert_eq!(t.e.decide(&Msg { proc: c, op: Op::UnixConnect { path: "/private/var/run/mDNSResponder".into() }, auth: true }), Verdict::ALLOW);
    }

    #[test]
    fn a_rule_change_applies_to_the_next_attempt() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let notes = format!("{}/notes/plan.md", t.home());
        assert_eq!(t.open(&c, &notes, false), Verdict::DENY, "outside the project: denied by default");
        *t.user.borrow_mut() = format!("version: v1\nfilesystem:\n  allow_read: [\"{notes}\"]\n");
        assert_eq!(t.open(&c, &notes, false), Verdict::ALLOW, "granted: no restart needed");
        assert!(*t.loads.borrow() >= 2);
    }

    #[test]
    fn sessions_end_when_the_last_process_exits() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let (child, _) = t.spawn(&c, 40, "/bin/sleep", &["sleep", "1"]);
        t.e.decide(&Msg { proc: c, op: Op::Exit, auth: false });
        assert_eq!(t.e.sessions(), 1, "a child still runs");
        t.e.decide(&Msg { proc: child, op: Op::Exit, auth: false });
        assert_eq!(t.e.sessions(), 0);
        assert_eq!(t.e.out.last().unwrap().kind, Kind::SessionEnd);
    }

    #[test]
    fn an_agent_started_inside_another_stays_in_its_session() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let mut codex = claude(50);
        codex.key = Some(ProcKey { pid: 50, version: 2 });
        codex.exe = "/opt/homebrew/bin/codex".into();
        let child = proc(50, 1, &c.exe);
        t.e.decide(&Msg { proc: c.clone(), op: Op::Fork { child: child.clone() }, auth: false });
        t.e.decide(&Msg { proc: child, op: Op::Exec { target: codex, argv: vec!["codex".into()], cwd: None, setuid: false }, auth: true });
        assert_eq!(t.e.sessions(), 1, "no second session: the chain stays under Claude");
    }
    #[test]
    fn agentacl_run_sessions_are_left_to_seatbelt_and_protection_ends_at_exec() {
        let (_t, mut t) = setup();
        // `agentacl run claude`: agentacl → fork → sandbox-exec → claude.
        let shell = proc(10, 1, "/bin/zsh");
        let (sup, _) = t.spawn(&shell, 30, "/opt/homebrew/bin/agentacl", &["agentacl", "run", "claude"]);
        let (sbx, _) = t.spawn(&sup, 31, SANDBOX_EXEC, &["sandbox-exec", "-f", "p.sb", "claude"]);
        let c = claude(31);
        let c = Proc { key: Some(ProcKey { pid: 31, version: 3 }), ..c };
        let v = t.e.decide(&Msg { proc: sbx, op: Op::Exec { target: c.clone(), argv: vec!["claude".into()], cwd: Some(t.project.clone()), setuid: false }, auth: true });
        assert_eq!(v, Verdict::ALLOW);
        assert_eq!(t.e.sessions(), 0, "the supervisor's session, not a second one");
        // The agent isn't AgentACL: its own children can be stopped.
        assert!(!t.e.protected.iter().any(|k| k.pid == 31));
        // A plain `claude` still gets a session, and can signal its children.
        let c = t.start_claude();
        let (child, _) = t.spawn(&c, 40, "/usr/bin/make", &["make"]);
        let v = t.e.decide(&Msg { proc: c, op: Op::Signal { target: child, signal: 15 }, auth: true });
        assert_eq!(v, Verdict::ALLOW);
        // sandbox-exec run by anything else isn't a supervised launch.
        let other = proc(11, 1, "/bin/zsh");
        let (sbx, _) = t.spawn(&other, 50, SANDBOX_EXEC, &["sandbox-exec", "claude"]);
        let c2 = Proc { key: Some(ProcKey { pid: 50, version: 3 }), ..claude(50) };
        t.e.decide(&Msg { proc: sbx, op: Op::Exec { target: c2, argv: vec!["claude".into()], cwd: Some(t.project.clone()), setuid: false }, auth: true });
        assert_eq!(t.e.sessions(), 2);
    }
    #[test]
    fn programs_that_start_processes_outside_the_session_are_refused() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        for (pid, exe, argv) in [
            (60, "/usr/bin/osascript", vec!["osascript", "-e", "tell app \"Terminal\" to do script \"cat ~/.ssh/id_ed25519\""]),
            (61, "/bin/launchctl", vec!["launchctl", "submit", "-l", "x", "--", "sh", "-c", "id"]),
            (62, "/usr/bin/open", vec!["open", "-a", "Terminal", "x.command"]),
            (63, "/usr/bin/crontab", vec!["crontab", "evil"]),
        ] {
            assert_eq!(t.spawn(&c, pid, exe, &argv).1, Verdict::DENY, "{exe}");
        }
        // A renamed copy is still osascript by its signature.
        let child = proc(64, 1, &c.exe);
        t.e.decide(&Msg { proc: c.clone(), op: Op::Fork { child: child.clone() }, auth: false });
        let copy = Proc { signing_id: "com.apple.osascript".into(), ..proc(64, 2, &format!("{}/x", t.project)) };
        assert_eq!(t.e.decide(&Msg { proc: child, op: Op::Exec { target: copy, argv: vec!["x".into()], cwd: None, setuid: false }, auth: true }), Verdict::DENY);
        // Opening a web page (signing in) is fine.
        assert_eq!(t.spawn(&c, 65, "/usr/bin/open", &["open", "https://claude.ai/oauth"]).1, Verdict::ALLOW);
        let d = t.e.out.iter().find(|r| r.kind == Kind::Denied).unwrap();
        assert_eq!(d.decision.as_ref().unwrap().rule_id, "launch-outside");
    }

    #[test]
    fn task_ports_metadata_and_unix_sockets() {
        let (_t, mut t) = setup();
        let c = t.start_claude();
        let (own, _) = t.spawn(&c, 70, "/usr/bin/make", &["make"]);
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::GetTask { target: own }, auth: true }), Verdict::ALLOW, "its own processes");
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::GetTask { target: proc(700, 1, "/Applications/Terminal.app/x") }, auth: true }), Verdict::DENY);
        let secret = format!("{}/.aws/credentials", t.home());
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Meta { path: secret.clone() }, auth: true }), Verdict::DENY, "chmod/chflags of a protected file");
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Meta { path: format!("{}/a.sh", t.project) }, auth: true }), Verdict::ALLOW);
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Exchange { a: format!("{}/a", t.project), b: secret.clone() }, auth: true }), Verdict::DENY);
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::CopyFile { source: secret, destination: format!("{}/k", t.project) }, auth: true }), Verdict::DENY);
        let (home, project) = (t.home(), t.project.clone());
        let sock = |t: &mut T, path: String| t.e.decide(&Msg { proc: c.clone(), op: Op::UnixConnect { path }, auth: true });
        assert_eq!(sock(&mut t, format!("{home}/.orbstack/run/docker.sock")), Verdict::DENY);
        assert_eq!(sock(&mut t, format!("{home}/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock")), Verdict::DENY);
        let tmp = t.e.config.tmpdir.to_string_lossy().into_owned();
        assert_eq!(sock(&mut t, format!("{tmp}/podman/podman-machine-default-api.sock")), Verdict::DENY);
        assert_eq!(sock(&mut t, format!("{project}/.devserver.sock")), Verdict::ALLOW, "the project's own sockets");
        assert_eq!(sock(&mut t, "/private/var/run/mDNSResponder".into()), Verdict::ALLOW, "name resolution");
    }

    #[test]
    fn only_the_configured_users_agents_get_sessions() {
        let (_t, mut t) = setup();
        let c = Proc { uid: 0, ..claude(80) };
        t.e.decide(&Msg { proc: proc(80, 0, "/bin/zsh"), op: Op::Exec { target: c, argv: vec!["claude".into()], cwd: None, setuid: false }, auth: true });
        assert_eq!(t.e.sessions(), 0, "sudo claude: another user's home and rules");
    }

    #[test]
    fn membership_survives_refused_execs_late_forks_and_exited_parents() {
        let (_t, mut t) = setup();
        *t.user.borrow_mut() = "version: v1\nprocess:\n  deny: [\"git push *\"]\n".into();
        let c = t.start_claude();
        let secret = format!("{}/.ssh/id_ed25519", t.home());
        // A refused exec leaves the process as it was: still enforced.
        let (_, v) = t.spawn(&c, 90, "/usr/bin/git", &["git", "push"]);
        assert_eq!(v, Verdict::DENY);
        assert_eq!(t.open(&proc(90, 1, &c.exe), &secret, false), Verdict::DENY);
        // An exec that happened retires the old token.
        let (img, _) = t.spawn(&c, 91, "/bin/sh", &["sh"]);
        t.e.decide(&Msg { proc: proc(91, 1, &c.exe), op: Op::Exec { target: img.clone(), argv: vec![], cwd: None, setuid: false }, auth: false });
        t.e.decide(&Msg { proc: img.clone(), op: Op::Exit, auth: false });
        assert!(t.e.tracker.session_of(Some(ProcKey { pid: 91, version: 1 })).is_none());
        // A child seen after its parent exited (double fork) is adopted.
        let (mid, _) = t.spawn(&c, 92, "/bin/sh", &["sh"]);
        t.e.decide(&Msg { proc: mid.clone(), op: Op::Exit, auth: false });
        let orphan = Proc { parent: mid.key, ppid: 1, ..proc(93, 1, "/bin/cat") };
        assert_eq!(t.open(&orphan, &secret, false), Verdict::DENY);
        // A child whose parent exec'd before the child was seen is adopted.
        let (sh, _) = t.spawn(&c, 95, "/bin/sh", &["sh"]);
        let early = Proc { parent: Some(ProcKey { pid: 95, version: 1 }), ..proc(96, 1, "/bin/cat") };
        assert_eq!(sh.key, Some(ProcKey { pid: 95, version: 2 }));
        assert_eq!(t.open(&early, &secret, false), Verdict::DENY);
        // A fork notification for a child that already exited doesn't revive it.
        let gone = proc(94, 1, &c.exe);
        t.e.decide(&Msg { proc: c.clone(), op: Op::Fork { child: gone.clone() }, auth: false });
        t.e.decide(&Msg { proc: gone.clone(), op: Op::Exit, auth: false });
        t.e.decide(&Msg { proc: c.clone(), op: Op::Fork { child: gone.clone() }, auth: false });
        assert!(t.e.tracker.session_of(gone.key).is_none());
    }

    #[test]
    fn agents_running_before_the_daemon_are_adopted() {
        let (_t, mut t) = setup();
        let claude_id = Some(("claude-code".to_string(), "Claude Code".to_string()));
        let r = |pid: i32, ppid: i32, exe: &str, agent: Option<(String, String)>| Running { proc: Proc { ppid, ..proc(pid, 1, exe) }, cwd: Some(t.project.clone()), agent };
        let procs = vec![
            r(100, 1, "/bin/zsh", None),
            r(101, 100, "/Users/u/.local/bin/claude", claude_id.clone()),
            r(102, 101, "/bin/bash", None),
            r(103, 102, "/bin/cat", None),
            // Under `agentacl run`: left to its supervisor.
            r(110, 100, "/opt/homebrew/bin/agentacl", None),
            r(111, 110, "/usr/bin/sandbox-exec", None),
            r(112, 111, "/Users/u/.local/bin/claude", claude_id.clone()),
            // Another user's agent.
            Running { proc: Proc { uid: 0, ppid: 1, ..proc(120, 1, "/Users/u/.local/bin/claude") }, cwd: None, agent: claude_id },
        ];
        t.e.adopt_running(&procs);
        assert_eq!(t.e.sessions(), 1);
        let secret = format!("{}/.aws/credentials", t.home());
        assert_eq!(t.open(&proc(103, 1, "/bin/cat"), &secret, false), Verdict::DENY, "a descendant of the running agent");
        assert_eq!(t.open(&proc(112, 1, "/Users/u/.local/bin/claude"), &secret, false), Verdict::ALLOW, "Seatbelt's, not ours");
        assert!(t.e.protected.iter().any(|k| k.pid == 110), "a running agentacl is protected");
    }

    #[test]
    fn unknown_paths_are_refused_and_writable_paths_are_readable() {
        let (_t, mut t) = setup();
        *t.user.borrow_mut() = format!("version: v1\nfilesystem:\n  allow_write: [\"{}/out/**\"]\n  deny_read: [\"{}/out/secret\"]\n", t.home(), t.home());
        let c = t.start_claude();
        assert_eq!(t.open(&c, "", false), Verdict::DENY, "a truncated path");
        assert_eq!(t.e.decide(&Msg { proc: c.clone(), op: Op::Rename { source: format!("{}/a", t.project), destination: String::new() }, auth: true }), Verdict::DENY);
        let out = format!("{}/out/log.txt", t.home());
        assert_eq!(t.open(&c, &out, false), Verdict::ALLOW, "writable, so readable");
        assert_eq!(t.open(&c, &format!("{}/out/secret", t.home()), false), Verdict::DENY, "a read-deny rule still wins");
        for dev in ["/dev/null", "/dev/tty"] {
            assert_eq!(t.open(&c, dev, true), Verdict::ALLOW, "{dev} read-write (every shell)");
        }
        assert_eq!(t.open(&c, "/private/tmp/agentacl-es-test/x", true), Verdict::ALLOW, "the temp folder");
    }
}
