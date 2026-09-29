use super::*;
use agentfence_policy::expand::Vars;
use agentfence_policy::set::{builtin_sources, LoadOptions, PolicySource};
use agentfence_policy::Layer;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A fake home + project on disk, with fake secrets.
pub struct Fixture {
    _dir: tempfile::TempDir,
    pub root: PathBuf,
    pub home: PathBuf,
    pub project: PathBuf,
    pub tmp: PathBuf,
    pub state: PathBuf,
    pub config: PathBuf,
}

impl Fixture {
    pub fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let project = home.join("src/proj");
        let tmp = root.join("sessiontmp");
        let state = home.join("Library/Application Support/AgentFence");
        let config = home.join(".config/agentfence");
        for d in [&project, &tmp, &state, &config, &home.join(".ssh"), &home.join(".aws"), &home.join("Library/LaunchAgents")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let w = |p: PathBuf, s: &str| std::fs::write(p, s).unwrap();
        w(project.join("README"), "hello readme\n");
        w(project.join(".env"), "SECRET=env-canary\n");
        w(project.join(".env.production"), "SECRET=prod-canary\n");
        w(project.join(".env.example"), "SECRET=\n");
        w(home.join(".ssh/id_ed25519"), "ssh-canary\n");
        w(home.join(".aws/credentials"), "aws-canary\n");
        w(home.join(".gitconfig"), "[user]\n\tname = Test\n\temail = t@example.com\n");
        w(config.join("policy.yaml"), "version: v1\n");
        assert!(Command::new("/usr/bin/git").arg("-C").arg(&project).args(["init", "-q"]).env("HOME", &home).status().unwrap().success());
        Fixture { _dir: dir, root, home, project, tmp, state, config }
    }

    pub fn vars(&self) -> Vars {
        Vars {
            home: self.home.to_string_lossy().into(),
            project: self.project.to_string_lossy().into(),
            tmpdir: self.tmp.to_string_lossy().into(),
            agent_state: None,
            agentfence_state: self.state.to_string_lossy().into(),
            agentfence_config: self.config.to_string_lossy().into(),
        }
    }

    pub fn policy(&self, user_yaml: Option<&str>) -> PolicySet {
        let mut src = builtin_sources(user_yaml.is_none());
        if let Some(y) = user_yaml {
            src.push(PolicySource { layer: Layer::User, name: "user".into(), yaml: y.into() });
        }
        PolicySet::load(src, &self.vars(), &LoadOptions::default()).unwrap()
    }

    pub fn profile(&self, policy: &PolicySet, input: CompileInput) -> PathBuf {
        let text = sbpl::compile_profile(policy, &CompileInput { agent_id: "custom:test", project: &self.project.to_string_lossy(), ..input }).unwrap();
        let p = self.root.join(format!("profile-{}.sb", ulid::Ulid::new()));
        std::fs::write(&p, text).unwrap();
        p
    }

    /// Runs `sh -c script` under the profile; returns (exit code, stdout+stderr).
    pub fn run(&self, profile: &Path, script: &str) -> (i32, String) {
        let out = Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(profile)
            .args(["/bin/sh", "-c", script])
            .current_dir(&self.project)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("TMPDIR", &self.tmp)
            .env("P", &self.project)
            .env("H", &self.home)
            .output()
            .unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.code().unwrap_or(-1), text)
    }
}

fn input() -> CompileInput<'static> {
    CompileInput { proxy_port: 18999, ..Default::default() }
}

// ---------------- pure compiler tests ----------------

#[test]
fn profile_invariants() {
    let f = Fixture::new();
    let text = sbpl::compile_profile(&f.policy(None), &CompileInput { agent_id: "x", project: &f.project.to_string_lossy(), ..input() }).unwrap();
    assert!(text.contains("(deny default)"));
    let last_allow = text.rfind("(allow ").unwrap();
    let deny_block = text.find(";; ---- deny rules").unwrap();
    assert!(last_allow < deny_block, "an allow appears after the deny block");
    for op in baseline::NEVER_ALLOW {
        assert!(!text.contains(&format!("(allow {op}")), "{op}");
    }
    assert!(!text.contains("(allow network-bind"));
    assert!(!text.contains("(allow network-inbound"));
    assert!(text.contains("(remote ip \"localhost:18999\")"));
    // network is never opened beyond the proxy, even with defaults.network: allow
    let open = f.policy(Some("version: v1\ndefaults: {network: allow, filesystem: deny}\n"));
    let t2 = sbpl::compile_profile(&open, &CompileInput { agent_id: "x", project: &f.project.to_string_lossy(), ..input() }).unwrap();
    assert_eq!(t2.matches("(allow network-outbound").count(), 1);
    // builtins survive a user policy (invariant 5)
    for needle in [".ssh", "\\.[eE][nN][vV]", "AgentFence", "[gG][iI][tT]"] {
        assert!(t2.contains(needle), "{needle}");
    }
    for m in baseline::MACH_DENY {
        assert!(!text[..deny_block].contains(m), "{m} allowed");
    }
}

#[test]
fn hostile_paths_are_refused() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\nfilesystem:\n  allow_read: [\"/tmp/a\\\")(allow default)(\"]\n"));
    let err = sbpl::compile_profile(&pol, &CompileInput { agent_id: "x", project: &f.project.to_string_lossy(), ..input() }).unwrap_err();
    assert!(err.to_string().contains("refusing"), "{err}");
}

#[test]
fn process_default_deny_rejected() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\ndefaults: {process: deny}\n"));
    assert!(sbpl::compile_profile(&pol, &CompileInput { agent_id: "x", project: "/p", ..input() }).is_err());
}

#[test]
fn listen_rules() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\nnetwork:\n  listen: [\"localhost:18778\"]\n"));
    let t = sbpl::compile_profile(&pol, &CompileInput { agent_id: "x", project: "/p", ..input() }).unwrap();
    assert!(t.contains("(allow network-bind network-inbound (local ip \"localhost:18778\"))"));
    let bad = f.policy(Some("version: v1\nnetwork:\n  listen: [\"localhost\"]\n"));
    assert!(sbpl::compile_profile(&bad, &CompileInput { agent_id: "x", project: "/p", ..input() }).is_err());
}

#[test]
fn classification_matches_compilation() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\nprocess:\n  deny: [\"terra* *\", \"/opt/x/tool\", \"git push *\"]\nnetwork:\n  allow: [\"a.com\"]\n"));
    let views = rule_views(&SeatbeltBackend, &pol, "x", "/p");
    let get = |pat: &str| views.iter().find(|v| v.pattern == pat).unwrap().enforceability;
    assert_eq!(get("terra* *"), Enforceability::EnforcedCoarse);
    assert_eq!(get("/opt/x/tool"), Enforceability::EnforcedCoarse);
    assert_eq!(get("git push *"), Enforceability::Observed);
    assert_eq!(get("a.com"), Enforceability::Enforced);
    let t = sbpl::compile_profile(&pol, &CompileInput { agent_id: "x", project: "/p", ..input() }).unwrap();
    assert!(t.contains("(regex #\"/[tT][eE][rR][rR][aA][^/]*$\")"), "{t}");
    assert!(t.contains("(literal \"/opt/x/tool\")"));
    assert!(MacOSEndpointSecurityBackend.available().is_err());
}

// ---------------- real sandbox tests ----------------

fn secret_free(out: &str) {
    for c in ["env-canary", "prod-canary", "ssh-canary", "aws-canary"] {
        assert!(!out.contains(c), "leaked {c}: {out}");
    }
}

#[test]
fn sandbox_reads() {
    let f = Fixture::new();
    let p = f.profile(&f.policy(None), input());
    let (c, o) = f.run(&p, "cat README");
    assert_eq!((c, o.as_str()), (0, "hello readme\n"));
    let (c, o) = f.run(&p, "cat .env.example");
    assert_eq!(c, 0, "{o}");
    for cmd in ["cat .env", "cat .env.production", "cat $H/.ssh/id_ed25519", "cat $H/.aws/credentials", "ls $H/.ssh"] {
        let (c, o) = f.run(&p, cmd);
        assert_ne!(c, 0, "{cmd}: {o}");
        secret_free(&o);
    }
    // case variant and symlink
    let (c, o) = f.run(&p, "cat .ENV");
    assert_ne!(c, 0, "{o}");
    std::os::unix::fs::symlink(f.home.join(".ssh/id_ed25519"), f.project.join("link")).unwrap();
    let (c, o) = f.run(&p, "cat link");
    assert_ne!(c, 0);
    secret_free(&o);
}

#[test]
fn sandbox_location_protection() {
    let f = Fixture::new();
    // Home fully writable, to prove the location rules (not the default) stop these.
    let pol = f.policy(Some("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\n  allow_write: [\"${HOME}/**\"]\n"));
    let p = f.profile(&pol, input());
    let (c, o) = f.run(&p, "echo ok > $H/scratch && cat $H/scratch");
    assert_eq!((c, o.as_str()), (0, "ok\n"), "positive control");
    let (c, o) = f.run(&p, "mv .env.production leak.txt; cat leak.txt");
    assert_ne!(c, 0, "{o}");
    secret_free(&o);
    assert!(f.project.join(".env.production").exists());
    let (c, _) = f.run(&p, "mv $H/.aws $H/aws2");
    assert_ne!(c, 0);
    assert!(f.home.join(".aws/credentials").exists() && !f.home.join("aws2").exists());
    let (c, _) = f.run(&p, "ln .env hard");
    assert_ne!(c, 0);
    assert!(!f.project.join("hard").exists());
    // move the project out and back
    let (c, _) = f.run(&p, "mv $P $TMPDIR/moved");
    assert_ne!(c, 0);
    assert!(f.project.join("README").exists());
}

#[test]
fn sandbox_writes_and_exec_persistence() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\n  allow_write: [\"${PROJECT}/**\", \"${HOME}/**\"]\n"));
    let p = f.profile(&pol, input());
    let (c, o) = f.run(&p, "git status --short >/dev/null && echo fine");
    assert_eq!((c, o.trim()), (0, "fine"), "positive control: git runs");
    let cfg_before = std::fs::read_to_string(f.project.join(".git/config")).unwrap();
    for cmd in [
        "git config core.fsmonitor 'touch /tmp/pwn'",
        "printf x > .git/commondir",
        "printf x > .git/hooks/pre-commit",
        "mv .git g2",
        "printf x > .envrc",
        "printf x > .mcp.json",
        "mkdir -p .vscode && printf x > .vscode/tasks.json",
        "mkdir -p .claude && printf x > .claude/settings.json",
        "printf x >> $H/.zshrc",
        "printf x > $H/Library/LaunchAgents/x.plist",
        "printf x > $H/.gitconfig",
        "printf x > $H/.config/agentfence/policy.yaml",
        "mkdir -p '$H/Library/Application Support/AgentFence' && printf x > \"$H/Library/Application Support/AgentFence/x\"",
        "mkdir -p .agentfence && printf x > .agentfence/policy.yaml",
    ] {
        let (c, o) = f.run(&p, cmd);
        assert_ne!(c, 0, "{cmd} succeeded: {o}");
    }
    assert_eq!(std::fs::read_to_string(f.project.join(".git/config")).unwrap(), cfg_before);
    assert!(f.project.join(".git").is_dir());
    // git data writes still work
    let (c, o) = f.run(&p, "echo hi > a.txt && git add a.txt && git -c user.name=t -c user.email=t@e commit -qm x && echo committed");
    assert_eq!((c, o.trim()), (0, "committed"), "{o}");
}

#[test]
fn sandbox_network_and_listen() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\ndefaults: {filesystem: deny, network: allow}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\nnetwork:\n  listen: [\"localhost:18778\"]\n"));
    let p = f.profile(&pol, input());
    let (c, _) = f.run(&p, "curl -sS -m 3 https://example.com -o /dev/null");
    assert_ne!(c, 0, "direct egress must fail");
    let (c, _) = f.run(&p, "nc -l -w1 127.0.0.1 18777");
    assert_ne!(c, 0, "unlisted listen must fail");
    let (c, o) = f.run(&p, "nc -l 127.0.0.1 18778 & pid=$!; sleep 0.5; kill $pid 2>/dev/null && echo bound");
    assert_eq!(o.trim(), "bound", "listed listen port should bind (c={c})");
}

#[test]
fn sandbox_unix_socket_deny() {
    let f = Fixture::new();
    let sock = f.root.join("agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let s = sock.to_string_lossy().into_owned();
    let pol = f.policy(None);
    let socks = [s.clone()];
    let p = f.profile(&pol, CompileInput { socket_denies: &socks, ..input() });
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains(&format!("(path-literal \"{s}\")")));
    let (c, _) = f.run(&p, &format!("nc -U {s} </dev/null"));
    assert_ne!(c, 0);
    drop(listener);
}

#[test]
fn sandbox_exec_deny() {
    let f = Fixture::new();
    // a non-setuid copy of a harmless binary named like the denied tool
    let bin = f.project.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy("/bin/echo", bin.join("terraform")).unwrap();
    let pol = f.policy(Some("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\n  allow_write: [\"${PROJECT}/**\"]\nprocess:\n  deny: [\"terraform *\"]\n"));
    let p = f.profile(&pol, input());
    let (c, o) = f.run(&p, "/bin/echo control");
    assert_eq!((c, o.trim()), (0, "control"));
    let (c, o) = f.run(&p, "./bin/terraform hi");
    assert_ne!(c, 0, "{o}");
}

/// Writes a fixture + default-policy profile to $AF_DUMP_DIR for baseline capture.
#[test]
#[ignore = "tooling: AF_DUMP_DIR=... cargo test -p agentfence-core dump_profile -- --ignored"]
fn dump_profile() {
    let Some(dir) = std::env::var_os("AF_DUMP_DIR") else { return };
    let f = Fixture::new();
    let text = sbpl::compile_profile(&f.policy(None), &CompileInput { agent_id: "x", project: &f.project.to_string_lossy(), ..input() }).unwrap();
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("profile.sb"), text).unwrap();
    std::fs::write(dir.join("project"), f.project.to_string_lossy().as_bytes()).unwrap();
    // keep the fixture alive on disk
    let keep = f.root.clone();
    std::mem::forget(f);
    std::fs::write(dir.join("root"), keep.to_string_lossy().as_bytes()).unwrap();
}

fn build_helper(f: &Fixture, name: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/helpers/{name}.c"));
    let out = f.project.join(name);
    let st = Command::new("/usr/bin/cc").arg("-o").arg(&out).arg(&src).status().unwrap();
    assert!(st.success(), "cc {name}");
    out
}

#[test]
fn sandbox_mach_services() {
    let f = Fixture::new();
    let helper = build_helper(&f, "machlookup");
    let p = f.profile(&f.policy(None), input());
    let (c, o) = f.run(&p, &format!("{} com.apple.system.notification_center", helper.display()));
    assert_eq!(c, 0, "positive control: {o}");
    for svc in baseline::MACH_DENY.iter().chain(["com.apple.SecurityServer", "com.apple.dnssd.service"].iter()) {
        let (c, o) = f.run(&p, &format!("{} {svc}", helper.display()));
        assert_ne!(c, 0, "{svc} reachable: {o}");
    }
}

fn run_on_pty(program: &Path, args: &[&str], pty_hook: impl FnOnce(&str) -> Option<PathBuf>) -> String {
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty fills two fds; we own and close them.
    let r = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(r, 0);
    let slave_path = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(master)) }.to_string_lossy().into_owned();
    // No echo: otherwise the injected byte is echoed into an output queue nobody
    // drains, and the child blocks on exit.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        libc::tcgetattr(slave, &mut t);
        t.c_lflag &= !(libc::ECHO | libc::ICANON);
        libc::tcsetattr(slave, libc::TCSANOW, &t);
    }
    let profile = pty_hook(&slave_path);
    let stdin = unsafe { std::process::Stdio::from_raw_fd(slave) };
    let mut cmd = match &profile {
        Some(p) => {
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-f").arg(p).arg(program);
            c
        }
        None => Command::new(program),
    };
    cmd.args(args).stdin(stdin);
    // Make the pty the child's controlling terminal so TIOCSTI is otherwise legal.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    unsafe { libc::close(master) };
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn sandbox_blocks_tiocsti() {
    let f = Fixture::new();
    let helper = build_helper(&f, "tiocsti");
    // control: outside the sandbox the injection works
    assert_eq!(run_on_pty(&helper, &[], |_| None), "injected");
    let pol = f.policy(None);
    let got = run_on_pty(&helper, &[], |slave| Some(f.profile(&pol, CompileInput { pty_slave: Some(slave), ..input() })));
    assert_eq!(got, "Operation not permitted");
}
