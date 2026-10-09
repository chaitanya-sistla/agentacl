//! `agentacl-esd`: the Endpoint Security daemon (docs/design/endpoint-security.md).
//!
//! Runs as root (a LaunchDaemon), watches every process on the Mac, and
//! enforces AgentACL's rules for every agent however it was started.
//!
//! ```text
//! agentacl-esd [--config PATH]   run (root, ES entitlement, Full Disk Access)
//! agentacl-esd --check           validate the config and policies, no ES
//! ```

use agentacl_core::config::Paths;
use agentacl_core::es_journal::{EsRecord, Kind};
use agentacl_es::adapter;
use agentacl_es::engine::{Config as EngineConfig, Engine, Running};
use agentacl_es::journal;
use agentacl_es::model::{Proc, ProcKey};
use agentacl_es::provider::{AsyncPolicy, FsPolicy};
use agentacl_es::tracker::NO_PROJECT;
use anyhow::{bail, Context, Result};
use endpoint_sec::AuditToken;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

const DEFAULT_CONFIG: &str = "/Library/Application Support/AgentACL/esd.json";

/// Written by the installer (as the user, then moved into a root-owned
/// folder), so agents running as the user can't change it.
#[derive(Debug, Deserialize)]
struct Config {
    user: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
    /// `getconf DARWIN_USER_TEMP_DIR` for the user.
    tmpdir: PathBuf,
}

fn load_config(path: &Path) -> Result<Config> {
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    use std::os::unix::fs::MetadataExt;
    if meta.file_type().is_symlink() {
        bail!("{} is a symlink", path.display());
    }
    // Root-owned and not writable by anyone else, or anyone could re-point it.
    if unsafe { libc::geteuid() } == 0 && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
        bail!("{} must be owned by root and not group- or world-writable", path.display());
    }
    let c: Config = serde_json::from_slice(&std::fs::read(path)?).with_context(|| format!("parsing {}", path.display()))?;
    if !c.home.is_absolute() || !c.tmpdir.is_absolute() {
        bail!("home and tmpdir must be absolute paths");
    }
    // As ES reports them (`/private/var/...`, no links).
    let canon = |p: &Path| std::fs::canonicalize(p).with_context(|| format!("{} must exist", p.display()));
    Ok(Config { home: canon(&c.home)?, tmpdir: canon(&c.tmpdir)?, ..c })
}

fn paths_for(c: &Config) -> Paths {
    Paths::with_dirs(c.home.clone(), c.home.join("Library/Application Support/AgentACL"), c.home.join(".config/agentacl"))
}

fn check(c: &Config) -> Result<()> {
    use agentacl_es::engine::PolicyProvider;
    let paths = paths_for(c);
    let mut p = FsPolicy::new(paths.clone(), c.home.clone(), c.tmpdir.clone());
    for agent in agentacl_core::agents::registry() {
        p.policy(agent.id(), Path::new(NO_PROJECT));
    }
    if !p.errors.is_empty() {
        bail!("{}", p.errors.join("\n"));
    }
    println!("agentacl-esd: config OK for {} (uid {}); policies load for every agent", c.user, c.uid);
    Ok(())
}

/// Every process running now, for sessions of agents started before the
/// daemon. Runs `codesign` on candidates, so call it without the engine lock.
fn running() -> Vec<Running> {
    let snap = agentacl_core::proc::snapshot();
    let agents: HashMap<i32, (String, String)> = agentacl_core::agents::running_agents(&snap).into_iter().map(|a| (a.pid, (a.id, a.display_name))).collect();
    snap.iter()
        .filter_map(|f| {
            let t = AuditToken::from_pid(f.pid).ok()?;
            let proc = Proc { key: Some(ProcKey { pid: t.pid(), version: t.pidversion() }), ppid: f.ppid, uid: f.uid, exe: f.exe.clone().unwrap_or_default(), ..Default::default() };
            let agent = agents.get(&f.pid).cloned();
            let cwd = agent.as_ref().and_then(|_| agentacl_core::proc::cwd(f.pid));
            Some(Running { proc, cwd, agent })
        })
        .collect()
}

/// Tells the ES crate which macOS this is, so it uses the current message
/// API (retain, not the deprecated copy).
fn set_runtime_version() {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    let name = c"kern.osproductversion";
    // SAFETY: sysctlbyname writes at most `len` bytes into `buf`.
    let ok = unsafe { libc::sysctlbyname(name.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } == 0;
    let v = if ok { String::from_utf8_lossy(&buf[..len.saturating_sub(1)]).into_owned() } else { String::new() };
    let mut n = v.split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    let (major, minor, patch) = (n.next().unwrap_or(0), n.next().unwrap_or(0), n.next().unwrap_or(0));
    if major >= 11 {
        endpoint_sec::version::set_runtime_version(major, minor, patch);
    }
}

fn run(c: Config) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("agentacl-esd must run as root (it is a LaunchDaemon)");
    }
    let paths = paths_for(&c);
    let (tx, rx) = std::sync::mpsc::channel();
    let _writer = journal::spawn(paths.state_dir.clone(), c.uid, c.gid, rx)?;
    // Sessions from before a restart are gone from memory: they end here.
    let _ = tx.send(EsRecord {
        ts: agentacl_core::audit::now_rfc3339(),
        kind: Kind::DaemonStart,
        session: String::new(),
        agent: String::new(),
        agent_name: String::new(),
        project: String::new(),
        pid: Some(std::process::id() as i32),
        chain: vec![],
        action: String::new(),
        resource: String::new(),
        decision: None,
    });
    // The handler must never read a file a process chose.
    agentacl_core::agents::identify_without_file_reads();
    set_runtime_version();
    let config = EngineConfig { home: c.home.clone(), tmpdir: c.tmpdir.clone(), uid: Some(c.uid), own_pid: std::process::id() as i32 };
    let policies = AsyncPolicy::spawn(FsPolicy::new(paths, c.home.clone(), c.tmpdir.clone()), c.uid, c.gid)?;
    let engine = Arc::new(Mutex::new(Engine::new(policies, config)));
    let handler = std::panic::AssertUnwindSafe((engine.clone(), Mutex::new(tx.clone())));
    let mut client = endpoint_sec::Client::new(move |client, msg| {
        let (engine, tx) = &*handler;
        let tx = tx.lock().unwrap_or_else(|p| p.into_inner()).clone();
        adapter::handle(client, msg, engine, &tx);
    })
    .map_err(|e| {
        use endpoint_sec::sys::NewClientError as E;
        let hint = match e {
            E::NotEntitled => "the binary lacks the com.apple.developer.endpoint-security.client entitlement (production: Apple-provisioned; development: a Mac with SIP and AMFI off, see docs/design/endpoint-security.md)",
            E::NotPermitted => "Full Disk Access isn't granted to agentacl-esd (System Settings → Privacy & Security → Full Disk Access)",
            E::NotPrivileged => "not running as root",
            E::TooManyClients => "too many Endpoint Security clients are running",
            _ => "Endpoint Security refused the client",
        };
        anyhow::anyhow!("{hint} ({e:?})")
    })?;
    // The daemon's own file reads (policies) must not wait on itself: ES
    // delivers this client's messages one at a time.
    let me = AuditToken::from_pid(std::process::id() as i32).map_err(|e| anyhow::anyhow!("own audit token: {e}"))?;
    client.mute_process(&me).map_err(|e| anyhow::anyhow!("muting itself: {e:?}"))?;
    client.subscribe(adapter::EVENTS).map_err(|e| anyhow::anyhow!("subscribing: {e:?}"))?;
    // Agents already running (best effort; ES reports only what happens next).
    let procs = running();
    {
        let mut e = engine.lock().unwrap_or_else(|p| p.into_inner());
        e.adopt_running(&procs);
        for r in e.out.drain(..) {
            let _ = tx.send(r);
        }
    }
    eprintln!("agentacl-esd: watching every process for {} (pid {})", c.user, std::process::id());
    loop {
        std::thread::park();
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let config = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let result = load_config(&config).and_then(|c| if args.iter().any(|a| a == "--check") { check(&c) } else { run(c) });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agentacl-esd: {e:#}");
            ExitCode::FAILURE
        }
    }
}
