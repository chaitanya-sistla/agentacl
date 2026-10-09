//! The fleet service on a Mac (docs/design/fleet.md): enrollment, reports
//! to the server, and company rules from it. Runs as root
//! (`agentacl fleet run`, LaunchDaemon `ai.agentacl.fleet`).

pub mod collect;
pub mod http;

use crate::managed::Managed;
use agentacl_fleet::{EnrollRequest, EnrollResponse, MachineStatus, PolicyResponse, Report, ReportResponse};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Discovery of installed agents runs `codesign`: not every cycle.
const DISCOVER_EVERY: i64 = 600;
/// Report requests per cycle (each up to [`REPORT_BYTES`]).
const MAX_REQUESTS: usize = 10;
const REPORT_BYTES: usize = 4 * 1024 * 1024;
/// One user's share of a report request.
const USER_BYTES: usize = 1024 * 1024;

/// `fleet.json` (root, 0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    pub server: String,
    pub device_id: String,
    pub device_key: String,
    #[serde(default)]
    pub proxy: Option<String>,
}

/// `fleet-state.json` (root, 0600).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetState {
    /// Per user: (audit log id, last row id the server acknowledged).
    pub cursors: HashMap<String, (String, i64)>,
    pub policy_version: Option<u64>,
    pub policy_error: Option<String>,
    pub last_discover: i64,
    pub last_report: Option<i64>,
    pub last_error: Option<String>,
    /// Events the server didn't keep (over the device's daily quota).
    #[serde(default)]
    pub dropped: u64,
}

/// How a Mac was told to enroll, before it is: a file the package installs
/// (`enroll.json`), or a configuration profile (managed preferences).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollSource {
    pub server: String,
    pub token: String,
    #[serde(default)]
    pub proxy: Option<String>,
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    std::io::Write::write_all(&mut f, bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// The machine-wide folders, created root-owned 0755 if missing.
fn ensure_dirs(m: &Managed) -> Result<()> {
    for d in [m.root.clone(), m.root.join("managed"), m.root.join("tmp")] {
        if !d.exists() {
            std::fs::DirBuilder::new().recursive(true).mode(0o755).create(&d).with_context(|| format!("creating {}", d.display()))?;
        }
    }
    std::fs::set_permissions(m.root.join("tmp"), std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

impl Managed {
    pub fn fleet_state(&self) -> PathBuf {
        self.root.join("fleet-state.json")
    }
    /// Written by a package built for an organization; removed once used.
    pub fn enroll_file(&self) -> PathBuf {
        self.root.join("enroll.json")
    }
    pub fn read_config(&self) -> Result<Option<FleetConfig>> {
        match std::fs::read(self.fleet_config()) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b).context("reading fleet.json")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading fleet.json"),
        }
    }
    pub fn read_state(&self) -> FleetState {
        std::fs::read(self.fleet_state()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    pub fn write_state(&self, s: &FleetState) -> Result<()> {
        write_private(&self.fleet_state(), &serde_json::to_vec_pretty(s)?, 0o600)
    }

    /// Checks a company policy the way every load on this Mac will use it
    /// (company-rules format, full load, Seatbelt profile), then writes it
    /// atomically. A version older than the one in force is refused.
    pub fn apply_policy(&self, p: &PolicyResponse, current: Option<u64>) -> Result<()> {
        if current.is_some_and(|c| p.version < c) {
            bail!(
                "refusing company policy v{} older than v{} in force (a server restored from a backup: publish the policy again until its version passes v{}, or re-enroll the Mac)",
                p.version,
                current.unwrap_or(0),
                current.unwrap_or(0)
            );
        }
        // Versions go up one at a time: a huge jump would lock the Mac out
        // of every later policy.
        if p.version > current.unwrap_or(0) + 100_000 {
            bail!("refusing company policy v{}: too far ahead of v{} in force", p.version, current.unwrap_or(0));
        }
        let yaml = if p.yaml.trim().is_empty() { "version: v1\n".to_string() } else { p.yaml.clone() };
        agentacl_fleet::validate_company_policy(&yaml).map_err(|e| anyhow::anyhow!("company policy v{}: {e}", p.version))?;
        compiles(&yaml).with_context(|| format!("company policy v{}", p.version))?;
        ensure_dirs(self)?;
        write_private(&self.policy(), yaml.as_bytes(), 0o644)
    }
}

/// The company policy compiles into a Seatbelt profile, with the built-ins.
fn compiles(yaml: &str) -> Result<()> {
    use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySet, PolicySource};
    let vars = agentacl_policy::expand::Vars {
        home: "/Users/example".into(),
        project: "/Users/example/src/project".into(),
        tmpdir: "/private/var/folders/xx/agentacl/session/tmp".into(),
        agent_state: None,
        agentacl_state: "/Users/example/Library/Application Support/AgentACL".into(),
        agentacl_config: "/Users/example/.config/agentacl".into(),
    };
    let mut src = builtin_sources(true);
    src.push(PolicySource { layer: agentacl_policy::Layer::Org, name: "company policy".into(), yaml: yaml.into() });
    let set = PolicySet::load(src, &vars, &LoadOptions::default())?;
    let input = crate::enforce::sbpl::CompileInput { agent_id: "claude-code", project: "/Users/example/src/project", proxy_port: 1, session_tag: "check", ..Default::default() };
    crate::enforce::sbpl::compile_profile(&set, &input)?;
    Ok(())
}

/// Where this Mac was told to enroll: `enroll.json` from the package, else
/// a configuration profile's managed preferences.
pub fn enroll_source(m: &Managed) -> Option<EnrollSource> {
    if let Ok(b) = std::fs::read(m.enroll_file()) {
        if let Ok(s) = serde_json::from_slice::<EnrollSource>(&b) {
            return Some(s);
        }
    }
    let plist = Path::new("/Library/Managed Preferences/ai.agentacl.fleet.plist");
    let out = std::process::Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-"]).arg(plist).output().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    Some(EnrollSource { server: v["ServerURL"].as_str()?.into(), token: v["EnrollmentToken"].as_str()?.into(), proxy: v["Proxy"].as_str().map(str::to_string) })
}

fn http(m: &Managed, server: &str, proxy: Option<String>) -> http::Http {
    http::Http { server: server.trim_end_matches('/').to_string(), proxy, tmp: m.root.join("tmp") }
}

/// Enrolls this Mac. The company policy is written before `fleet.json`, so
/// an enrolled Mac always has company rules.
pub fn enroll(m: &Managed, src: &EnrollSource) -> Result<FleetConfig> {
    http::check_url(&src.server)?;
    if let Some(p) = &src.proxy {
        http::check_proxy(p)?;
    }
    ensure_dirs(m)?;
    let body = serde_json::to_vec(&EnrollRequest { token: src.token.trim().to_string(), machine: collect::identity() })?;
    let (code, out) = http(m, &src.server, src.proxy.clone()).request("POST", agentacl_fleet::ENROLL, None, Some(&body))?;
    if code != 200 {
        bail!("the server refused the enrollment ({code}): {}", server_error(&out));
    }
    let e: EnrollResponse = serde_json::from_slice(&out).context("the server's enrollment answer")?;
    m.apply_policy(&e.policy, None)?;
    let mut state = m.read_state();
    state.policy_version = Some(e.policy.version);
    state.policy_error = None;
    m.write_state(&state)?;
    let cfg = FleetConfig { server: src.server.trim_end_matches('/').to_string(), device_id: e.device_id, device_key: e.device_key, proxy: src.proxy.clone() };
    write_private(&m.fleet_config(), &serde_json::to_vec_pretty(&cfg)?, 0o600)?;
    let _ = std::fs::remove_file(m.enroll_file());
    Ok(cfg)
}

fn server_error(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or_else(|| String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned())
}

/// One reporting cycle: collect, report (in requests of at most 4 MiB),
/// and apply a newer company policy.
pub fn cycle(m: &Managed, cfg: &FleetConfig, exe: &Path) -> Result<()> {
    let client = http(m, &cfg.server, cfg.proxy.clone());
    let mut state = m.read_state();
    let now = crate::notify::now();
    let discover = now - state.last_discover >= DISCOVER_EVERY;
    let snap = crate::proc::snapshot();
    let machine = MachineStatus { identity: collect::identity(), enforcement: collect::enforcement(&snap, m), policy_version: state.policy_version, policy_error: state.policy_error.clone() };
    let running = collect::running(&snap);
    let mut server_policy = None;
    // A test folder (`--root`): the collector reads the test's data folders
    // too, never the real ones.
    let test_env: Vec<(String, String)> =
        if m.root != Path::new(crate::managed::ROOT) { ["AGENTACL_HOME", "AGENTACL_CONFIG_DIR"].iter().filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v))).collect() } else { vec![] };
    for round in 0..MAX_REQUESTS {
        let mut users = vec![];
        let mut more = false;
        let me = unsafe { libc::getuid() };
        let root = unsafe { libc::geteuid() } == 0;
        for (name, uid, gid, home) in collect::users().into_iter().filter(|u| root || u.1 == me) {
            let (log_id, after) = state.cursors.get(&name).cloned().map(|(l, r)| (Some(l), r)).unwrap_or((None, 0));
            let req = collect::UserRequest { log_id, after_rowid: after, discover: discover && round == 0 };
            let mut u = match collect::spawn_collector(exe, &name, uid, gid, &home, &req, &test_env) {
                Ok(u) => u,
                Err(e) => agentacl_fleet::UserReport { user: name.clone(), uid, error: Some(format!("{e:#}")), ..Default::default() },
            };
            more |= u.events.len() >= agentacl_fleet::MAX_EVENTS;
            if round > 0 {
                u.installed = None;
            }
            // Each user gets a fair share of the request.
            let before = u.events.len();
            collect::fit_user(&mut u, USER_BYTES);
            more |= u.events.len() < before;
            users.push(u);
        }
        let mut report = Report { machine: machine.clone(), running: running.clone(), users };
        // Keep each request under the size limit: shrink the largest user.
        while serde_json::to_vec(&report)?.len() > REPORT_BYTES {
            let sizes: Vec<usize> = report.users.iter().map(|u| serde_json::to_vec(u).map(|b| b.len()).unwrap_or(0)).collect();
            let Some((i, &size)) = sizes.iter().enumerate().max_by_key(|(_, s)| **s) else { break };
            if size < 1024 {
                break;
            }
            collect::fit_user(&mut report.users[i], size / 2);
            more = true;
        }
        let (code, out) = client.request("POST", agentacl_fleet::REPORT, Some(&cfg.device_key), Some(&serde_json::to_vec(&report)?))?;
        if code == 401 {
            bail!("the server doesn't accept this Mac's key (revoked?); company rules in force stay");
        }
        if code == 429 {
            break; // the server's limit: the rest goes with the next cycle
        }
        if code != 200 {
            bail!("report refused ({code}): {}", server_error(&out));
        }
        let resp: ReportResponse = serde_json::from_slice(&out).context("the server's report answer")?;
        server_policy = Some(resp.policy_version);
        state.dropped += resp.dropped;
        // Acknowledged: advance each user's cursor.
        for u in &report.users {
            if let (Some(log), Some(last)) = (&u.log_id, u.events.last()) {
                state.cursors.insert(u.user.clone(), (log.clone(), last.rowid));
            } else if let Some(log) = &u.log_id {
                state
                    .cursors
                    .entry(u.user.clone())
                    .and_modify(|c| {
                        if c.0 != *log {
                            *c = (log.clone(), 0)
                        }
                    })
                    .or_insert((log.clone(), 0));
            }
        }
        if discover && round == 0 {
            state.last_discover = now;
        }
        state.last_report = Some(now);
        m.write_state(&state)?;
        if !more {
            break;
        }
    }
    if server_policy.is_some_and(|v| Some(v) != state.policy_version) {
        let (code, out) = client.request("GET", agentacl_fleet::POLICY, Some(&cfg.device_key), None)?;
        if code == 200 {
            let p: PolicyResponse = serde_json::from_slice(&out).context("the server's policy")?;
            match m.apply_policy(&p, state.policy_version) {
                Ok(()) => {
                    state.policy_version = Some(p.version);
                    state.policy_error = None;
                }
                Err(e) => state.policy_error = Some(format!("{e:#}")),
            }
            m.write_state(&state)?;
        }
    }
    Ok(())
}

/// A cycle for an enrolled Mac; a token left by a reinstalled package is
/// no longer needed.
fn cycle_enrolled(m: &Managed, cfg: &FleetConfig, exe: &Path) -> Result<()> {
    let _ = std::fs::remove_file(m.enroll_file());
    cycle(m, cfg, exe)
}

/// The LaunchDaemon's loop: enroll if told to and not yet enrolled, then a
/// cycle every minute (every 10 minutes after errors).
pub fn run(m: &Managed, exe: &Path) -> ! {
    crate::agents::identify_without_file_reads();
    loop {
        let wait = match m.read_config() {
            Ok(Some(cfg)) => match cycle_enrolled(m, &cfg, exe) {
                Ok(()) => {
                    let mut s = m.read_state();
                    s.last_error = None;
                    let _ = m.write_state(&s);
                    60
                }
                Err(e) => {
                    eprintln!("agentacl fleet: {e:#}");
                    let mut s = m.read_state();
                    s.last_error = Some(format!("{e:#}"));
                    let _ = m.write_state(&s);
                    if format!("{e:#}").contains("revoked") {
                        600
                    } else {
                        120
                    }
                }
            },
            Ok(None) => match enroll_source(m) {
                Some(src) => match enroll(m, &src) {
                    Ok(cfg) => {
                        eprintln!("agentacl fleet: enrolled as {} with {}", cfg.device_id, cfg.server);
                        0
                    }
                    Err(e) => {
                        eprintln!("agentacl fleet: enrolling: {e:#}");
                        300
                    }
                },
                None => 600,
            },
            Err(e) => {
                eprintln!("agentacl fleet: {e:#}");
                600
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(wait));
    }
}

#[cfg(test)]
mod tests;
