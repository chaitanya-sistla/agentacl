//! What a Mac reports (docs/design/fleet.md). The root service reads only
//! the process table; each user's files are read by a separate process
//! running as that user ([`collect_user`]), which prints JSON.

use agentacl_fleet::{Enforcement, EventInfo, InstalledAgent, MachineIdentity, RunningAgent, SessionInfo, UserReport};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A per-user collector that takes longer is killed (and reported).
const USER_TIMEOUT: Duration = Duration::from_secs(90);
/// Its output is read up to this size.
const USER_MAX_OUTPUT: u64 = 6 * 1024 * 1024;
/// Command lines and paths are cut at this length before they leave the Mac.
const MAX_RESOURCE: usize = 1024;

fn sysctl_string(name: &str) -> Option<String> {
    let c = CString::new(name).ok()?;
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    // SAFETY: sysctlbyname writes at most `len` bytes into `buf`.
    let ok = unsafe { libc::sysctlbyname(c.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } == 0;
    ok.then(|| String::from_utf8_lossy(&buf[..len.saturating_sub(1)]).into_owned())
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes a NUL-terminated name into `buf`.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return "unknown".into();
    }
    CStr::from_bytes_until_nul(&buf).map(|c| c.to_string_lossy().into_owned()).unwrap_or_else(|_| "unknown".into())
}

fn serial() -> Option<String> {
    let out = Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("\"IOPlatformSerialNumber\""))?;
    let v = line.split('=').nth(1)?.trim().trim_matches('"').to_string();
    (!v.is_empty()).then_some(v)
}

pub fn identity() -> MachineIdentity {
    MachineIdentity {
        machine_id: crate::proc::machine_id().unwrap_or_else(|_| "mch_unknown".into()),
        hostname: hostname(),
        serial: serial(),
        os_version: sysctl_string("kern.osproductversion").unwrap_or_default(),
        agentacl_version: env!("CARGO_PKG_VERSION").into(),
    }
}

fn exe_name(f: &crate::proc::ProcessFacts) -> &str {
    f.exe.as_deref().map(|e| e.rsplit('/').next().unwrap_or(e)).unwrap_or(&f.name)
}

/// Endpoint Security, from root processes at their installed paths only (a
/// user's process with the same name doesn't count), and the user it serves.
pub fn enforcement(snap: &[crate::proc::ProcessFacts], managed: &crate::managed::Managed) -> Enforcement {
    let root_at = |pred: &dyn Fn(&str) -> bool| snap.iter().any(|f| f.uid == 0 && f.exe.as_deref().is_some_and(pred));
    let es_daemon = root_at(&|e| e == "/Library/PrivilegedHelperTools/agentacl-esd");
    let es_extension = root_at(&|e| e.starts_with("/Library/SystemExtensions/") && e.ends_with("/ai.agentacl.app.esd"));
    let es_user = (es_daemon || es_extension)
        .then(|| std::fs::read(managed.root.join("esd.json")).ok())
        .flatten()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["user"].as_str().map(str::to_string));
    Enforcement { es_daemon, es_extension, es_user }
}

fn user_name(uid: u32) -> String {
    // SAFETY: getpwuid returns static storage or null; copied at once.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return uid.to_string();
        }
        CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
    }
}

/// Agent processes, from the process table only: identified by their path
/// (no file is read, no program run: a user can't stall the root service).
/// Requires [`crate::agents::identify_without_file_reads`] in this process.
pub fn running(snap: &[crate::proc::ProcessFacts]) -> Vec<RunningAgent> {
    let by_pid: std::collections::HashMap<i32, &crate::proc::ProcessFacts> = snap.iter().map(|f| (f.pid, f)).collect();
    let mut out = vec![];
    for f in snap {
        let Some(i) = crate::agents::identify(f, None) else { continue };
        // Only the outermost agent process of a tree (not its helpers).
        let mut up = f.ppid;
        let mut supervisor = None;
        let mut nested = false;
        for _ in 0..64 {
            let Some(p) = by_pid.get(&up) else { break };
            if crate::agents::identify(p, None).is_some() {
                nested = true;
                break;
            }
            if exe_name(p) == "agentacl" && supervisor.is_none() {
                supervisor = p.exe.clone();
            }
            if p.ppid <= 1 {
                break;
            }
            up = p.ppid;
        }
        if nested {
            continue;
        }
        out.push(RunningAgent { pid: f.pid, user: user_name(f.uid), agent: i.id, agent_name: i.display_name, exe: f.exe.clone().unwrap_or_default(), supervisor });
    }
    out
}

/// Accounts to report: uid ≥ 501 with an existing home folder.
pub fn users() -> Vec<(String, u32, u32, PathBuf)> {
    let mut out = vec![];
    // SAFETY: getpwent iterates static storage; each entry is copied before
    // the next call, and the iteration is closed with endpwent.
    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() {
                break;
            }
            let uid = (*pw).pw_uid;
            let name = CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
            let home = PathBuf::from(CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned());
            if (501..65_534).contains(&uid) && !name.starts_with('_') && home.is_dir() {
                out.push((name, uid, (*pw).pw_gid, home));
            }
        }
        libc::endpwent();
    }
    out.sort();
    out.dedup_by(|a, b| a.1 == b.1);
    out
}

/// What the root service asks a per-user collector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserRequest {
    pub log_id: Option<String>,
    pub after_rowid: i64,
    pub discover: bool,
}

/// Replaces values that look like secrets in a command line, and cuts it:
/// values of `--token`, `--password`, `--secret`, `-u user:pass`,
/// `Authorization:` headers, `*KEY=`/`*TOKEN=` style assignments, and words
/// that look like well-known API keys.
pub fn redact(s: &str) -> String {
    const MARKERS: [&str; 6] = ["token", "password", "passwd", "secret", "apikey", "api-key"];
    const PREFIXES: [&str; 9] = ["sk-", "ghp_", "gho_", "ghs_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "AKIA"];
    let mut out: Vec<String> = vec![];
    let mut hide_next = false;
    for word in s.split(' ') {
        if hide_next {
            out.push("[redacted]".into());
            // `Authorization: Bearer <token>`: the scheme, then its value.
            hide_next = matches!(word.trim_matches(['"', '\'']).to_ascii_lowercase().as_str(), "bearer" | "basic" | "token");
            continue;
        }
        let bare = word.trim_matches(['"', '\'']);
        let lower = bare.to_ascii_lowercase();
        if PREFIXES.iter().any(|p| bare.starts_with(p) && bare.len() > p.len() + 8) {
            out.push("[redacted]".into());
            continue;
        }
        let secretish = MARKERS.iter().any(|m| lower.contains(m)) || lower.contains("_key") || lower.ends_with("key");
        match bare.split_once('=') {
            Some((k, _)) if secretish && MARKERS.iter().chain(&["key"]).any(|m| k.to_ascii_lowercase().contains(m)) => out.push(format!("{k}=[redacted]")),
            None if (secretish && bare.starts_with('-')) || matches!(lower.as_str(), "-u" | "--user" | "authorization:" | "bearer" | "basic" | "token") => {
                out.push(word.into());
                hide_next = true;
            }
            _ => out.push(word.into()),
        }
    }
    let joined = out.join(" ");
    match joined.char_indices().nth(MAX_RESOURCE) {
        Some((i, _)) => format!("{}…", &joined[..i]),
        None => joined,
    }
}

/// Runs in the per-user process (as the user): reads the user's AgentACL
/// data and returns what to report. Never creates an audit log.
pub fn collect_user(req: &UserRequest) -> UserReport {
    match crate::config::Paths::from_env() {
        Ok(p) => collect_user_at(&p, req),
        Err(e) => UserReport { error: Some(format!("{e:#}")), ..Default::default() },
    }
}

/// [`collect_user`] for given locations.
pub fn collect_user_at(paths: &crate::config::Paths, req: &UserRequest) -> UserReport {
    let mut r = UserReport { user: user_name(unsafe { libc::getuid() }), uid: unsafe { libc::getuid() }, ..Default::default() };
    if req.discover {
        let (found, _) = crate::agents::discover(&paths.home);
        r.installed = Some(found.into_iter().map(|d| InstalledAgent { agent: d.id, agent_name: d.display_name, path: d.path, version: d.version }).collect());
    }
    if !paths.db_path.is_file() {
        return r; // no AgentACL sessions yet; none is created
    }
    let store = match crate::audit::Store::open(&paths.db_path) {
        Ok(s) => s,
        Err(e) => {
            r.error = Some(format!("{e:#}"));
            return r;
        }
    };
    let _ = crate::es_journal::ingest(paths, &store);
    let managed = paths.managed.policy();
    let week_ago = crate::audit::format_rfc3339(crate::notify::now() - 7 * 86_400, 0);
    for s in store.recent_sessions(&week_ago, 200).unwrap_or_default() {
        let ident: Option<crate::session::Session> = serde_json::from_str(&s.identity_json).ok();
        let company_rules = ident.as_ref().is_some_and(|i| i.policy_sources.iter().any(|p| p.path == managed && p.sha256.is_some()));
        r.sessions.push(SessionInfo {
            session_id: s.session_id,
            agent: s.agent,
            project: s.project,
            backend: s.backend,
            started_at: s.started_at,
            ended_at: s.ended_at,
            agentacl_version: ident.and_then(|i| i.agentacl_version),
            company_rules,
        });
    }
    let log_id = match store.log_id() {
        Ok(l) => l,
        Err(e) => {
            r.error = Some(format!("{e:#}"));
            return r;
        }
    };
    // A different log than the cursor's: start from its beginning.
    let after = if req.log_id.as_deref() == Some(log_id.as_str()) { req.after_rowid } else { 0 };
    let mut bytes = 0;
    for (rowid, e) in store.events_after(after, agentacl_fleet::MAX_EVENTS).unwrap_or_default() {
        let ev = EventInfo {
            rowid,
            ts: e.timestamp,
            session: e.session,
            agent: e.agent,
            kind: if e.enforcement.is_some() { "enforced".into() } else { "observed".into() },
            source: serde_json::to_value(e.source).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
            action: e.action,
            resource: redact(&e.resource),
            decision: e.decision.map(|d| d.as_str().to_string()),
            policy: e.policy,
            rule_id: e.rule_id,
            reason: e.reason.map(|r| redact(&r)),
        };
        bytes += ev.resource.len() + ev.action.len() + 200;
        r.events.push(ev);
        if bytes > 3 * 1024 * 1024 {
            break;
        }
    }
    r.log_id = Some(log_id);
    r
}

/// Caps what one user's report may take, so one user can't crowd out the
/// others (or make the whole report too large): lists are cut, and events
/// dropped from the end until it fits in `limit` bytes (the cursor then
/// stops at the last event kept).
pub fn fit_user(u: &mut UserReport, limit: usize) {
    if let Some(i) = &mut u.installed {
        i.truncate(100);
    }
    u.sessions.truncate(500);
    if let Some(e) = &mut u.error {
        if let Some((i, _)) = e.char_indices().nth(2048) {
            e.truncate(i);
        }
    }
    while serde_json::to_vec(u).map(|b| b.len()).unwrap_or(usize::MAX) > limit {
        if !u.events.is_empty() {
            let keep = u.events.len() / 2;
            u.events.truncate(keep);
        } else if !u.sessions.is_empty() || u.installed.is_some() {
            u.sessions.clear();
            u.installed = None;
            u.error = Some("this user's AgentACL data is too large to report".into());
        } else {
            break;
        }
    }
}

/// Collects `user`'s report in a child process running as that user: its
/// primary group as the only group, its gid and uid, set before exec, an empty environment but HOME,
/// USER, LOGNAME and a PATH with the usual install folders, in the user's
/// home. Killed after 90 seconds.
pub fn spawn_collector(exe: &Path, name: &str, uid: u32, gid: u32, home: &Path, req: &UserRequest, test_env: &[(String, String)]) -> Result<UserReport> {
    let h = home.to_string_lossy();
    let path = format!("{h}/.local/bin:{h}/.npm-global/bin:{h}/.bun/bin:{h}/.volta/bin:{h}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    let mut cmd = Command::new(exe);
    cmd.args(["fleet", "collect-user"]).env_clear().env("HOME", home).env("USER", name).env("LOGNAME", name).env("PATH", path).current_dir(home);
    cmd.envs(test_env.iter().cloned());
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    // As root, become the user; otherwise (tests) only the caller's own data.
    let root = unsafe { libc::geteuid() } == 0;
    if !root && uid != unsafe { libc::getuid() } {
        bail!("collecting another user's data needs root");
    }
    // Only the user's primary group: the collector reads the user's own
    // files and needs no other (and nothing is looked up after the fork).
    let groups: [libc::gid_t; 1] = [gid];
    // SAFETY: the closure makes only async-signal-safe calls, on data
    // prepared before the fork.
    unsafe {
        cmd.pre_exec(move || {
            // Its own process group: a timeout kills everything it started.
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if !root {
                return Ok(());
            }
            if libc::setgroups(groups.len() as libc::c_int, groups.as_ptr()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Never back to root.
            if libc::setuid(0) == 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().with_context(|| format!("collecting {name}'s data"))?;
    child.stdin.take().context("stdin")?.write_all(&serde_json::to_vec(req)?)?;
    let mut stdout = child.stdout.take().context("stdout")?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.by_ref().take(USER_MAX_OUTPUT + 1).read_to_end(&mut out);
        out
    });
    let start = Instant::now();
    let pgid = child.id() as libc::pid_t;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() > USER_TIMEOUT {
            // SAFETY: signals the collector's own process group.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
            let _ = child.wait();
            bail!("collecting {name}'s data took longer than {} s", USER_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Anything it left running keeps the pipe open: end the group, and don't
    // wait for the reader forever.
    // SAFETY: as above.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !reader.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !reader.is_finished() {
        bail!("{name}'s collector left its output open");
    }
    let out = reader.join().map_err(|_| anyhow::anyhow!("reading {name}'s data"))?;
    if out.len() as u64 > USER_MAX_OUTPUT {
        bail!("{name}'s data is too large");
    }
    let mut r: UserReport = serde_json::from_slice(&out).with_context(|| format!("reading {name}'s data"))?;
    // The process said who it was; the root service knows.
    r.user = name.to_string();
    r.uid = uid;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_in_command_lines_are_replaced() {
        assert_eq!(redact("curl -H x --token abc123 https://x"), "curl -H x --token [redacted] https://x");
        assert_eq!(redact("deploy --password=hunter2 --env prod"), "deploy --password=[redacted] --env prod");
        assert_eq!(redact("env AWS_SECRET_ACCESS_KEY=AKIAx OPENAI_API_KEY=sk-1 node x"), "env AWS_SECRET_ACCESS_KEY=[redacted] OPENAI_API_KEY=[redacted] node x");
        assert_eq!(redact("cat /Users/a/.ssh/id_ed25519"), "cat /Users/a/.ssh/id_ed25519");
        assert_eq!(redact("curl -u alice:hunter2 https://x"), "curl -u [redacted] https://x");
        assert_eq!(redact("curl -H \"Authorization: Bearer abc.def\" https://x"), "curl -H \"Authorization: [redacted] [redacted] https://x");
        assert_eq!(redact("echo sk-ant-api03-abcdefghijk ghp_1234567890abcdef"), "echo [redacted] [redacted]");
        assert_eq!(redact(&"x".repeat(2000)).chars().count(), MAX_RESOURCE + 1);
    }

    #[test]
    fn one_user_cant_crowd_out_the_report() {
        let ev = |i: i64| EventInfo { rowid: i, resource: "x".repeat(900), ..Default::default() };
        let mut u = UserReport { events: (1..=1000).map(ev).collect(), sessions: vec![SessionInfo::default(); 900], ..Default::default() };
        fit_user(&mut u, 200_000);
        assert!(serde_json::to_vec(&u).unwrap().len() <= 200_000);
        assert!(u.sessions.len() <= 500 && !u.events.is_empty() && u.events[0].rowid == 1, "oldest events kept");
        let mut huge = UserReport { sessions: vec![SessionInfo { project: "p".repeat(10_000), ..Default::default() }; 400], ..Default::default() };
        fit_user(&mut huge, 100_000);
        assert!(huge.sessions.is_empty() && huge.error.is_some());
    }

    #[test]
    fn endpoint_security_counts_only_as_root_at_its_path() {
        let f = |uid: u32, exe: &str| crate::proc::ProcessFacts { pid: 1, ppid: 1, pgid: 0, uid, start_time_us: 0, exe: Some(exe.into()), argv: vec![], name: String::new() };
        let m = crate::managed::Managed { root: "/nonexistent".into(), owner: 0 };
        let fake = [f(501, "/Users/u/agentacl-esd"), f(501, "/Library/PrivilegedHelperTools/agentacl-esd")];
        assert_eq!(enforcement(&fake, &m), Enforcement::default(), "a user's look-alike doesn't count");
        let real = [f(0, "/Library/PrivilegedHelperTools/agentacl-esd")];
        assert!(enforcement(&real, &m).es_daemon);
        let ext = [f(0, "/Library/SystemExtensions/ABC/ai.agentacl.app.esd.systemextension/Contents/MacOS/ai.agentacl.app.esd")];
        assert!(enforcement(&ext, &m).es_extension);
    }

    #[test]
    fn this_machine_and_its_users() {
        let id = identity();
        assert!(id.machine_id.starts_with("mch_") && !id.os_version.is_empty() && !id.hostname.is_empty());
        let me = unsafe { libc::getuid() };
        if me >= 501 {
            assert!(users().iter().any(|u| u.1 == me), "the test user is listed");
        }
        assert!(!users().iter().any(|u| u.1 < 501 || u.0.starts_with('_')));
    }

    #[test]
    fn collects_a_users_data_without_creating_a_log() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let paths = crate::config::Paths::with_dirs(root.join("home"), root.join("state"), root.join("config"));
        let r = collect_user_at(&paths, &UserRequest::default());
        assert!(r.error.is_none() && r.log_id.is_none() && r.sessions.is_empty());
        assert!(!paths.db_path.exists(), "no log created");
        let store = crate::audit::Store::open(&paths.db_path).unwrap();
        let ctx = crate::audit::EventContext { agent: "claude-code".into(), session: "agt_1".into(), backend: "seatbelt".into(), ..Default::default() };
        for i in 0..3 {
            store.record_ui(&ctx, "filesystem.read", &format!("/x/{i} --token sekrit"), "test").unwrap();
        }
        let r = collect_user_at(&paths, &UserRequest::default());
        let log = r.log_id.clone().unwrap();
        assert_eq!(r.events.len(), 3);
        assert!(r.events[0].resource.ends_with("--token [redacted]"), "{}", r.events[0].resource);
        let next = collect_user_at(&paths, &UserRequest { log_id: Some(log.clone()), after_rowid: r.events[1].rowid, discover: false });
        assert_eq!(next.events.len(), 1, "after the cursor");
        let other = collect_user_at(&paths, &UserRequest { log_id: Some("log_other".into()), after_rowid: 1_000_000, discover: false });
        assert_eq!(other.events.len(), 3, "another log: from the start");
    }
}
