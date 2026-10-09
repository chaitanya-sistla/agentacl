//! Policies for the daemon, loaded as `agentacl run` loads them, and
//! reloaded when they change: a grant made in the console (an access file)
//! applies to the agent's next attempt, with no restart.
//!
//! The daemon's ES handler never reads a file: [`AsyncPolicy`] answers from
//! memory and has a loader thread, acting as the user, read and reload.

use crate::engine::PolicyProvider;
use agentacl_core::config::Paths;
use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySet};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often the rule files are checked for changes, at most.
const RECHECK: Duration = Duration::from_secs(1);
/// Larger rule files are refused (a link to `/dev/zero` must not exhaust
/// the daemon's memory).
const MAX_FILE: u64 = 1024 * 1024;
/// How long the handler waits for a policy it has never loaded, before
/// answering with the built-in protections.
const FIRST_LOAD: Duration = Duration::from_millis(250);
/// Load errors kept for `--check`.
const MAX_ERRORS: usize = 100;

struct Entry {
    set: Arc<PolicySet>,
    fingerprint: u64,
    checked: Instant,
}

pub struct FsPolicy {
    paths: Paths,
    home: PathBuf,
    /// The user's temp folder (`getconf DARWIN_USER_TEMP_DIR`): an
    /// unsupervised agent's `${TMPDIR}`.
    tmpdir: PathBuf,
    cache: HashMap<(String, PathBuf), Entry>,
    /// Reported when a policy fails to load (the built-ins still apply).
    pub errors: Vec<String>,
}

impl FsPolicy {
    pub fn new(paths: Paths, home: PathBuf, tmpdir: PathBuf) -> Self {
        FsPolicy { paths, home, tmpdir, cache: HashMap::new(), errors: vec![] }
    }

    /// Every file that can change a policy.
    fn inputs(&self, project: &Path) -> Vec<PathBuf> {
        let mut files = vec![self.paths.user_policy.clone(), self.paths.trust_file.clone(), project.join(".agentacl/policy.yaml")];
        // Their hook scripts are protected.
        files.extend(agentacl_core::supervisor::claude_settings(&self.home, project));
        if let Ok(rd) = std::fs::read_dir(agentacl_core::access::dir(&self.paths)) {
            let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            names.sort();
            files.extend(names);
        }
        files
    }

    /// Refuses inputs that aren't small regular files (a FIFO would block
    /// the loader, `/dev/zero` would exhaust memory).
    fn precheck(&self, project: &Path) -> anyhow::Result<()> {
        for f in self.inputs(project) {
            match std::fs::metadata(&f) {
                Ok(m) if !m.is_file() => anyhow::bail!("{} is not a regular file", f.display()),
                Ok(m) if m.len() > MAX_FILE => anyhow::bail!("{} is larger than {MAX_FILE} bytes", f.display()),
                _ => {}
            }
        }
        Ok(())
    }

    fn error(&mut self, e: String) {
        eprintln!("agentacl-esd: {e}");
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(e);
        }
    }

    /// Size and modification time of every file that can change a policy.
    fn fingerprint(&self, project: &Path) -> u64 {
        let mut h = DefaultHasher::new();
        for f in self.inputs(project) {
            f.hash(&mut h);
            if let Ok(m) = std::fs::metadata(&f) {
                m.len().hash(&mut h);
                m.modified().ok().hash(&mut h);
            }
        }
        h.finish()
    }

    fn load(&mut self, agent: &str, project: &Path) -> Arc<PolicySet> {
        // The daemon can't see an unsupervised agent's environment, so an
        // agent that keeps its login in the keychain (Claude Code's /login)
        // gets the keychain files it opens itself, as under `agentacl run`
        // without a token. Its requests to securityd aren't file opens; ES
        // can't narrow those (threat model T9).
        let loaded = self.precheck(project).and_then(|()| agentacl_core::supervisor::load_policy_with(&self.paths, agent, project, None, &self.home, |_| false, Some(&self.tmpdir)));
        match loaded {
            Ok((set, _)) => Arc::new(set),
            Err(e) => {
                self.error(format!("policy for {agent} in {}: {e:#}; using the built-in protections only", project.display()));
                Arc::new(self.builtins_only(project))
            }
        }
    }

    /// Fails closed: the built-in protections and the default policy.
    fn builtins_only(&self, project: &Path) -> PolicySet {
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let vars = Vars { home: s(&self.home), project: s(project), tmpdir: s(&self.tmpdir), agent_state: None, agentacl_state: s(&self.paths.state_dir), agentacl_config: s(&self.paths.config_dir) };
        PolicySet::load(builtin_sources(true), &vars, &LoadOptions::default()).expect("built-in policies load")
    }
}

impl PolicyProvider for FsPolicy {
    fn policy(&mut self, agent: &str, project: &Path) -> Arc<PolicySet> {
        let key = (agent.to_string(), project.to_path_buf());
        if let Some(e) = self.cache.get(&key) {
            if e.checked.elapsed() < RECHECK {
                return e.set.clone();
            }
        }
        self.reload(agent, project)
    }
}

impl FsPolicy {
    /// The policy, reloaded if its files changed since it was last loaded.
    pub fn reload(&mut self, agent: &str, project: &Path) -> Arc<PolicySet> {
        let key = (agent.to_string(), project.to_path_buf());
        let fp = self.fingerprint(project);
        if let Some(e) = self.cache.get_mut(&key) {
            e.checked = Instant::now();
            if e.fingerprint == fp {
                return e.set.clone();
            }
        }
        let set = self.load(agent, project);
        self.cache.insert(key, Entry { set: set.clone(), fingerprint: fp, checked: Instant::now() });
        set
    }
}

type Key = (String, PathBuf);

#[derive(Default)]
struct Shared {
    /// The current set, whether it is only the built-ins (not loaded yet),
    /// and when a reload was last asked for.
    sets: HashMap<Key, (Arc<PolicySet>, bool, Instant)>,
    pending: std::collections::HashSet<Key>,
}

/// The daemon's provider: answers from memory; a loader thread (acting as
/// the user) loads policies the first time and reloads them at most
/// once a second. If the loader is stuck, the last policy keeps applying.
pub struct AsyncPolicy {
    shared: Arc<(std::sync::Mutex<Shared>, std::sync::Condvar)>,
    tx: std::sync::mpsc::Sender<Key>,
    fallback: Box<dyn Fn(&Path) -> PolicySet + Send>,
}

impl AsyncPolicy {
    /// Starts the loader thread, as `uid`/`gid`.
    pub fn spawn(mut fs: FsPolicy, uid: u32, gid: u32) -> anyhow::Result<AsyncPolicy> {
        let shared: Arc<(std::sync::Mutex<Shared>, std::sync::Condvar)> = Arc::default();
        let (tx, rx) = std::sync::mpsc::channel::<Key>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (paths, home, tmpdir) = (fs.paths.clone(), fs.home.clone(), fs.tmpdir.clone());
        let s = shared.clone();
        std::thread::spawn(move || {
            let _ = ready_tx.send(crate::creds::become_user(uid, gid));
            for (agent, project) in rx {
                let set = fs.reload(&agent, &project);
                let (m, cv) = &*s;
                let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
                let key = (agent, project);
                g.pending.remove(&key);
                g.sets.insert(key, (set, false, Instant::now()));
                cv.notify_all();
            }
        });
        ready_rx.recv()??;
        let builtins = FsPolicy::new(paths, home, tmpdir);
        Ok(AsyncPolicy { shared, tx, fallback: Box::new(move |p| builtins.builtins_only(p)) })
    }
}

impl PolicyProvider for AsyncPolicy {
    fn policy(&mut self, agent: &str, project: &Path) -> Arc<PolicySet> {
        let key = (agent.to_string(), project.to_path_buf());
        let (m, cv) = &*self.shared;
        let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
        let ask = |g: &mut Shared, tx: &std::sync::mpsc::Sender<Key>| {
            if g.pending.insert(key.clone()) {
                let _ = tx.send(key.clone());
            }
        };
        if let Some((set, builtins_only, asked)) = g.sets.get(&key).cloned() {
            if builtins_only || asked.elapsed() >= RECHECK {
                ask(&mut g, &self.tx);
                if let Some(e) = g.sets.get_mut(&key) {
                    e.2 = Instant::now();
                }
            }
            return set;
        }
        ask(&mut g, &self.tx);
        let (mut g, _) = cv.wait_timeout_while(g, FIRST_LOAD, |g| !g.sets.contains_key(&key)).unwrap_or_else(|p| p.into_inner());
        if let Some((set, ..)) = g.sets.get(&key) {
            return set.clone();
        }
        // Not loaded in time (the loader may be stuck on a file): the
        // built-in protections, until it is.
        let set = Arc::new((self.fallback)(project));
        g.sets.insert(key, (set.clone(), true, Instant::now()));
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentacl_policy::{Action, Effect, PolicyEngine, Request, Resource, Subject};

    #[test]
    fn reloads_after_a_rule_change_and_fails_closed_on_a_broken_policy() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        let project = home.join("src/app");
        std::fs::create_dir_all(&project).unwrap();
        let paths = Paths::with_dirs(home.clone(), root.join("state"), root.join("config"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let mut p = FsPolicy::new(paths.clone(), home.clone(), root.join("tmp"));
        let notes = home.join("notes/plan.md").to_string_lossy().into_owned();
        let read = |set: &PolicySet| {
            set.evaluate(&Request {
                subject: Subject { agent_id: "claude-code".into(), project: project.to_string_lossy().into(), ..Default::default() },
                action: Action::FsRead,
                resource: Resource::Path(notes.clone()),
            })
            .effect
        };
        assert_ne!(read(&p.policy("claude-code", &project)), Effect::Allow);
        std::fs::write(&paths.user_policy, format!("version: v1\nfilesystem:\n  allow_read: [\"{notes}\"]\n")).unwrap();
        std::thread::sleep(RECHECK + Duration::from_millis(50));
        assert_eq!(read(&p.policy("claude-code", &project)), Effect::Allow, "picked up without a restart");
        std::fs::write(&paths.user_policy, "version: v1\nnot valid: [\n").unwrap();
        std::thread::sleep(RECHECK + Duration::from_millis(50));
        let set = p.policy("claude-code", &project);
        assert_ne!(read(&set), Effect::Allow, "a broken policy falls back to the built-ins");
        assert_eq!(p.errors.len(), 1);
        let ssh = home.join(".ssh/id_ed25519").to_string_lossy().into_owned();
        let d = set.evaluate(&Request {
            subject: Subject { agent_id: "claude-code".into(), project: project.to_string_lossy().into(), ..Default::default() },
            action: Action::FsRead,
            resource: Resource::Path(ssh),
        });
        assert_eq!(d.effect, Effect::Deny, "built-ins still apply");
        // A FIFO in place of a rule file is refused, not read.
        std::fs::remove_file(&paths.user_policy).unwrap();
        let fifo = std::ffi::CString::new(paths.user_policy.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        std::thread::sleep(RECHECK + Duration::from_millis(50));
        let _ = p.policy("claude-code", &project);
        assert!(p.errors.last().unwrap().contains("not a regular file"), "{:?}", p.errors);
    }

    #[test]
    fn the_async_provider_answers_from_memory_and_reloads_in_the_background() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        let project = home.join("src/app");
        std::fs::create_dir_all(&project).unwrap();
        let paths = Paths::with_dirs(home.clone(), root.join("state"), root.join("config"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let mut p = AsyncPolicy::spawn(FsPolicy::new(paths.clone(), home.clone(), root.join("tmp")), uid, gid).unwrap();
        let notes = home.join("notes/plan.md").to_string_lossy().into_owned();
        let read = |set: &PolicySet| {
            set.evaluate(&Request {
                subject: Subject { agent_id: "claude-code".into(), project: project.to_string_lossy().into(), ..Default::default() },
                action: Action::FsRead,
                resource: Resource::Path(notes.clone()),
            })
            .effect
        };
        assert_ne!(read(&p.policy("claude-code", &project)), Effect::Allow);
        std::fs::write(&paths.user_policy, format!("version: v1\nfilesystem:\n  allow_read: [\"{notes}\"]\n")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while read(&p.policy("claude-code", &project)) != Effect::Allow {
            assert!(Instant::now() < deadline, "the grant was never picked up");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
