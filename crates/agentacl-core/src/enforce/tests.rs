use super::*;
use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySource};
use agentacl_policy::Layer;
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
        let state = home.join("Library/Application Support/AgentACL");
        let config = home.join(".config/agentacl");
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
            agentacl_state: self.state.to_string_lossy().into(),
            agentacl_config: self.config.to_string_lossy().into(),
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
    CompileInput { proxy_port: 18999, session_tag: "agt_TEST", ..Default::default() }
}

// ---------------- pure compiler tests ----------------

#[test]
fn profile_invariants() {
    let f = Fixture::new();
    let text = sbpl::compile_profile(&f.policy(None), &CompileInput { agent_id: "x", project: &f.project.to_string_lossy(), ..input() }).unwrap();
    assert!(text.contains("(deny default"));
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
    assert_eq!(t2.matches("(allow network-outbound (remote ip").count(), 1);
    // builtins survive a user policy (invariant 5)
    for needle in [".ssh", "\\.[eE][nN][vV]", "AgentACL", "[gG][iI][tT]"] {
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
    assert!(t.contains("(with message \"af:agt_TEST|user|user/process.deny/0\")"), "{t}");
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
    // The default policy: the project is writable, the rest of home is not.
    let (c, o) = f.run(&p, "echo x > notes.txt && cat notes.txt");
    assert_eq!((c, o.as_str()), (0, "x\n"), "project stays writable");
    let (c, o) = f.run(&p, "echo x > $H/outside.txt");
    assert_ne!(c, 0, "write outside the project succeeded: {o}");
    assert!(!f.home.join("outside.txt").exists());
    // case variant and symlink
    let (c, o) = f.run(&p, "cat .ENV");
    assert_ne!(c, 0, "{o}");
    std::os::unix::fs::symlink(f.home.join(".ssh/id_ed25519"), f.project.join("link")).unwrap();
    let (c, o) = f.run(&p, "cat link");
    assert_ne!(c, 0);
    secret_free(&o);
}

/// One fake file per built-in secret group (and several paths per group):
/// every one must be unreadable and unwritable, and stay unchanged.
#[test]
fn sandbox_every_builtin_secret_group() {
    let f = Fixture::new();
    // (group, path relative to $H or $P); all contents are fake canaries.
    let files: &[(&str, &str)] = &[
        ("env-files", "$P/.env"),
        ("env-files", "$P/sub/.env.local"),
        ("env-files", "$P/.envrc"),
        ("ssh", "$H/.ssh/id_ed25519"),
        ("ssh", "$H/.ssh/config"),
        ("aws", "$H/.aws/credentials"),
        ("aws", "$H/.aws/sso/cache/token.json"),
        ("gcp", "$H/.config/gcloud/credentials.db"),
        ("azure", "$H/.azure/msal_token_cache.json"),
        ("kube", "$H/.kube/config"),
        ("kube", "$H/.kube/clusters/prod/config"),
        ("terraform", "$H/.terraform.d/credentials.tfrc.json"),
        ("terraform", "$P/infra/terraform.tfstate"),
        ("terraform", "$P/infra/terraform.tfvars"),
        ("git-creds", "$H/.git-credentials"),
        ("git-creds", "$H/.config/gh/hosts.yml"),
        ("package-creds", "$H/.npmrc"),
        ("package-creds", "$H/.pypirc"),
        ("package-creds", "$H/.netrc"),
        ("package-creds", "$H/.docker/config.json"),
        ("package-creds", "$H/.cargo/credentials.toml"),
        ("keys", "$P/certs/server.pem"),
        ("keys", "$P/deploy/id_rsa"),
        ("gpg", "$H/.gnupg/private-keys-v1.d/key.key"),
        ("browsers", "$H/Library/Application Support/Google/Chrome/Default/Cookies"),
        ("browsers", "$H/Library/Cookies/Cookies.binarycookies"),
        ("browsers", "$H/Library/Safari/History.db"),
    ];
    let real = |p: &str| PathBuf::from(p.replace("$H", &f.home.to_string_lossy()).replace("$P", &f.project.to_string_lossy()));
    for (group, p) in files {
        let path = real(p);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{group}-canary\n")).unwrap();
    }
    // Everything in home and the project is readable and writable, so only
    // the built-in secret rules can be what blocks these (not the default).
    let permissive = "version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_read: [\"${HOME}/**\", \"${PROJECT}/**\"]\n  allow_write: [\"${HOME}/**\", \"${PROJECT}/**\"]\n";
    let prof = f.profile(&f.policy(Some(permissive)), input());
    let (c, o) = f.run(&prof, "echo ok > \"$H/notes.txt\" && cat \"$H/notes.txt\" && cat README");
    assert_eq!((c, o.as_str()), (0, "ok\nhello readme\n"), "positive control: home and project are open");
    for (group, p) in files {
        let (c, o) = f.run(&prof, &format!("cat \"{p}\""));
        assert_ne!(c, 0, "{group}: read of {p} succeeded: {o}");
        assert!(!o.contains("canary"), "{group}: {p} leaked: {o}");
        let (c, o) = f.run(&prof, &format!("printf pwned >> \"{p}\""));
        assert_ne!(c, 0, "{group}: write to {p} succeeded: {o}");
        let (c, o) = f.run(&prof, &format!("rm -f \"{p}\""));
        assert!(c != 0 || real(p).exists(), "{group}: delete of {p} succeeded: {o}");
        assert_eq!(std::fs::read_to_string(real(p)).unwrap(), format!("{group}-canary\n"), "{group}: {p} changed");
    }
    // AgentACL's own state (audit log of every session) is unreadable, even
    // under a policy that opens all of home.
    std::fs::write(f.state.join("agentacl.db"), "audit-canary\n").unwrap();
    let (c, o) = f.run(&prof, "cat \"$H/Library/Application Support/AgentACL/agentacl.db\"");
    assert!(c != 0 && !o.contains("canary"), "state dir readable: {o}");
    // Every group is covered.
    let mut groups: Vec<&str> = files.iter().map(|(g, _)| *g).collect();
    groups.dedup();
    let mut want = agentacl_policy::set::protect_secrets_groups();
    want.dedup();
    for g in want {
        assert!(groups.contains(&g.as_str()), "no probe for built-in group {g}");
    }
}

/// The boundary holds through interpreters and nested delegation:
/// sh -> bash -> python3 -> file, and python3 -> subprocess -> file.
#[test]
fn sandbox_holds_through_python_and_nested_shells() {
    let f = Fixture::new();
    let prof = f.profile(&f.policy(None), input());
    let py = "/usr/bin/python3";
    // Positive control: Python runs in the sandbox and reads project files.
    let (c, o) = f.run(&prof, &format!("{py} -c \"print(open('README').read(), end='')\""));
    // (xcrun may warn on stderr that its cache stays closed; see sandbox_writes_and_exec_persistence.)
    assert!(c == 0 && o.lines().any(|l| l == "hello readme"), "positive control: python works in the sandbox: {c} {o}");
    // A tiny reader, so the nested chains below need no nested quoting.
    std::fs::write(f.project.join("read.py"), "import sys\nprint(open(sys.argv[1]).read())\n").unwrap();
    for script in [
        format!("{py} read.py $H/.aws/credentials"),
        format!("/bin/bash -c '/bin/sh -c \"{py} read.py .env\"'"),
        format!("{py} -c \"import subprocess; print(subprocess.run(['/bin/cat', '$H/.ssh/id_ed25519'], capture_output=True, text=True))\""),
        format!("{py} -c \"import os; os.system('/bin/sh -c \\\"/bin/cat $H/.aws/credentials\\\"')\""),
    ] {
        let (_, o) = f.run(&prof, &script);
        assert!(!o.contains("canary"), "secret leaked via: {script}\n{o}");
        assert!(o.contains("Operation not permitted") || o.contains("PermissionError"), "expected a kernel denial via: {script}\n{o}");
    }
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

/// A glob rule (`**/*.pem`) protects by name, so moving the directory that
/// holds a match to another writable place (the temp dirs) must not unprotect
/// it: the names are denied there too.
#[test]
fn sandbox_moved_directory_keeps_secret_names() {
    let f = Fixture::new();
    for (dir, file, text) in [("certs", "server.pem", "pem-canary"), ("infra", "terraform.tfvars", "tfvars-canary"), ("docs", "notes.txt", "notes-ok")] {
        std::fs::create_dir_all(f.project.join(dir)).unwrap();
        std::fs::write(f.project.join(dir).join(file), text).unwrap();
    }
    let shared = PathBuf::from(format!("/private/tmp/agentacl-test-{}", ulid::Ulid::new()));
    let p = f.profile(&f.policy(None), input());
    let (c, o) = f.run(&p, "mv docs $TMPDIR/d && cat $TMPDIR/d/notes.txt");
    assert_eq!((c, o.as_str()), (0, "notes-ok"), "positive control: moving an ordinary directory works");
    for script in [
        "mv certs $TMPDIR/c; cat $TMPDIR/c/server.pem".to_string(),
        "mv $TMPDIR/c/server.pem $TMPDIR/c/x.txt; cat $TMPDIR/c/x.txt".to_string(),
        format!("mv infra {}; cat {}/terraform.tfvars", shared.display(), shared.display()),
    ] {
        let (_, o) = f.run(&p, &script);
        assert!(!o.contains("canary"), "{script}: {o}");
        assert!(o.contains("Operation not permitted") || o.contains("No such file"), "{script}: {o}");
    }
    let _ = std::fs::remove_dir_all(&shared);
}

/// A grant made from the console for one agent opens the path for that agent
/// only, in the real kernel sandbox.
#[test]
fn sandbox_access_grant_is_per_agent() {
    use crate::access::{store, with_rule, Grant, Scope};
    let f = Fixture::new();
    std::fs::create_dir_all(f.home.join("o2/src")).unwrap();
    std::fs::write(f.home.join("o2/src/main.rs"), "o2-ok").unwrap();
    let paths = crate::config::Paths::with_dirs(f.home.clone(), f.state.clone(), f.config.clone());
    let o2 = format!("{}/o2/**", f.home.display());
    let (n, y) = with_rule(&paths, &Scope { agent: Some("claude-code".into()), project: None }, Grant::Read, &o2).unwrap().unwrap();
    store(&paths, &n, Some(&y)).unwrap();
    let mut src = builtin_sources(true);
    src.extend(crate::access::sources(&paths).unwrap());
    let pol = PolicySet::load(src, &f.vars(), &LoadOptions::default()).unwrap();
    let project = f.project.to_string_lossy().into_owned();
    let prof = |agent: &str| {
        let text = sbpl::compile_profile(&pol, &CompileInput { agent_id: agent, project: &project, ..input() }).unwrap();
        let p = f.root.join(format!("profile-{agent}.sb"));
        std::fs::write(&p, text).unwrap();
        p
    };
    let (c, o) = f.run(&prof("claude-code"), "cat $H/o2/src/main.rs");
    assert_eq!((c, o.as_str()), (0, "o2-ok"), "granted to Claude");
    let (c, o) = f.run(&prof("codex"), "cat $H/o2/src/main.rs");
    assert!(c != 0 && o.contains("Operation not permitted"), "not granted to Codex: {c} {o}");
}

/// Confused deputies: unsandboxed services that would act for the agent.
/// Services the sandbox can't reach (Apple Events, launch services, the
/// clipboard, Spotlight, the log stream) are proven by sandbox_mach_services,
/// another app's preferences by e2e::preferences_of_other_apps_are_refused.
/// Here: a launchd job, whose effect is visible.
#[test]
fn sandbox_refuses_confused_deputies() {
    let f = Fixture::new();
    let p = f.profile(&f.policy(None), input());
    let label = format!("com.agentacl.test.{}", ulid::Ulid::new().to_string().to_lowercase());
    let marker = f.root.join("deputy-marker");
    // Positive control: unsandboxed, the same submit runs a job.
    let control = f.root.join("control-marker");
    let control_label = format!("{label}.control");
    assert!(Command::new("/bin/launchctl").args(["submit", "-l", &control_label, "--", "/usr/bin/touch"]).arg(&control).status().unwrap().success());
    let t0 = std::time::Instant::now();
    while !control.exists() && t0.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = Command::new("/bin/launchctl").args(["remove", &control_label]).status();
    assert!(control.exists(), "positive control: launchd ran the unsandboxed job");
    let (_, o) = f.run(&p, &format!("/bin/launchctl submit -l {label} -- /usr/bin/touch {}; echo launchctl=$?", marker.display()));
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = Command::new("/bin/launchctl").args(["remove", &label]).status();
    assert!(o.contains("launchctl=") && !o.contains("launchctl=0"), "launchctl submit succeeded: {o}");
    assert!(!marker.exists(), "a launchd job ran outside the sandbox");
}

/// POSIX shared memory is one namespace per user: the agent must not reach
/// another process's segment by name, yet Python's own segments work.
#[test]
fn sandbox_shared_memory_is_scoped() {
    let f = Fixture::new();
    let p = f.profile(&f.policy(None), input());
    let name = format!("agentacl_t{}", std::process::id());
    let hold = format!("import time\nfrom multiprocessing import shared_memory as m\ns=m.SharedMemory(name='{name}',create=True,size=64)\ns.buf[:10]=b'SHM-CANARY'\nprint('up',flush=True)\ntime.sleep(8)\ns.close();s.unlink()\n");
    let mut holder = Command::new("/usr/bin/python3").args(["-W", "ignore", "-c", &hold]).stdout(std::process::Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(holder.stdout.take().unwrap()), &mut line).unwrap();
    assert_eq!(line.trim(), "up");
    let probe = format!(
        "/usr/bin/python3 -W ignore -c \"from multiprocessing import shared_memory as m\ntry:\n  s=m.SharedMemory(name='{name}'); print('read', bytes(s.buf[:10]).decode()); s.close()\nexcept Exception as e: print('refused', type(e).__name__)\nn=m.SharedMemory(create=True,size=16); n.buf[0]=1; print('own-ok'); n.close(); n.unlink()\""
    );
    // Sandboxed first: the unsandboxed control's Python unlinks the segment
    // when it exits (its resource tracker treats attached segments as its own).
    let (_, o) = f.run(&p, &probe);
    let control = Command::new("/bin/sh").args(["-c", &probe]).output().unwrap();
    let _ = holder.kill();
    let _ = holder.wait();
    assert!(String::from_utf8_lossy(&control.stdout).contains("read SHM-CANARY"), "positive control: readable outside the sandbox");
    assert!(o.contains("refused PermissionError") && !o.contains("SHM-CANARY"), "another process's segment reached: {o}");
    assert!(o.contains("own-ok"), "Python's own shared memory works: {o}");
}

#[test]
fn sandbox_writes_and_exec_persistence() {
    let f = Fixture::new();
    let pol = f.policy(Some("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\n  allow_write: [\"${PROJECT}/**\", \"${HOME}/**\"]\n"));
    let p = f.profile(&pol, input());
    let (c, o) = f.run(&p, "git status --short >/dev/null && echo fine");
    // xcrun may warn that it can't write its tool-location cache in the user
    // temp dir: that stays denied on purpose (a poisoned cache would redirect
    // tools for unsandboxed processes). git itself must succeed.
    assert!(c == 0 && o.lines().any(|l| l == "fine"), "positive control: git runs: {c} {o}");
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
        "printf x > $H/.config/agentacl/policy.yaml",
        "mkdir -p \"$H/Library/Application Support/AgentACL\" && printf x > \"$H/Library/Application Support/AgentACL/x\"",
        "mkdir -p .husky && printf x > .husky/pre-commit",
        "mkdir -p pkg/__pycache__ && printf x > pkg/__pycache__/mod.cpython-39.pyc",
        "mkdir -p $H/Library/Python/3.9/lib/python/site-packages && printf x > $H/Library/Python/3.9/lib/python/site-packages/evil.pth",
        "mkdir -p $H/.local/lib/python3.12/site-packages && printf x > $H/.local/lib/python3.12/site-packages/evil.pth",
        "mkdir -p $H/Library/Caches/com.apple.python/x && printf x > $H/Library/Caches/com.apple.python/x/mod.pyc",
        "mkdir -p .agentacl && printf x > .agentacl/policy.yaml",
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
    // A raw socket that ignores the proxy, to a listener that is reachable
    // outside the sandbox (no internet needed): refused by the kernel.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let ctl = Command::new("/usr/bin/nc").args(["-z", "-w", "2", "127.0.0.1", &port.to_string()]).status().unwrap();
    assert!(ctl.success(), "positive control: the listener is reachable unsandboxed");
    let (c, o) = f.run(&p, &format!("/usr/bin/nc -z -w 2 127.0.0.1 {port}"));
    assert_ne!(c, 0, "direct socket to a non-proxy port succeeded: {o}");
    drop(listener);
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
    // The socket is also allowed, so only the deny can refuse it (the
    // profile's default would refuse any unlisted socket anyway).
    let allowed = f.profile(&pol, CompileInput { socket_allows: &socks, ..input() });
    let (c, o) = f.run(&allowed, &format!("nc -w 1 -U {s} </dev/null"));
    assert_eq!(c, 0, "positive control: an allowed socket connects: {o}");
    let p = f.profile(&pol, CompileInput { socket_allows: &socks, socket_denies: &socks, ..input() });
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains(&format!("(path-literal \"{s}\")")));
    let (c, _) = f.run(&p, &format!("nc -w 1 -U {s} </dev/null"));
    assert_ne!(c, 0);
    drop(listener);
}

/// The real socket list the supervisor denies (ssh-agent via SSH_AUTH_SOCK,
/// the user's Docker socket), end to end through the compiled profile.
#[test]
fn credential_sockets_are_denied() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.home.join(".docker/run")).unwrap();
    let ssh = f.root.join("ssh-agent.sock");
    let docker = f.home.join(".docker/run/docker.sock");
    let _l1 = std::os::unix::net::UnixListener::bind(&ssh).unwrap();
    let _l2 = std::os::unix::net::UnixListener::bind(&docker).unwrap();
    let socks = crate::supervisor::credential_sockets(Some(ssh.clone()), Path::new("/nonexistent/docker.sock"), &f.home);
    assert_eq!(socks.len(), 2, "{socks:?}");
    // Also allowed, so only the deny can refuse them (see sandbox_unix_socket_deny).
    let allowed = f.profile(&f.policy(None), CompileInput { socket_allows: &socks, ..input() });
    let p = f.profile(&f.policy(None), CompileInput { socket_allows: &socks, socket_denies: &socks, ..input() });
    for s in [&ssh, &docker] {
        let (c, o) = f.run(&allowed, &format!("/usr/bin/nc -w 1 -U '{}' </dev/null", s.display()));
        assert_eq!(c, 0, "positive control: {} connects when only allowed: {o}", s.display());
        let (c, o) = f.run(&p, &format!("/usr/bin/nc -w 1 -U '{}' </dev/null", s.display()));
        assert_ne!(c, 0, "{} reachable from the sandbox: {o}", s.display());
    }
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
    // setuid binaries can't be executed under any profile. `sudo -n` outside a
    // sandbox fails too, but with a password message, not EPERM.
    for cmd in ["/usr/bin/sudo -n true", "/usr/bin/su -c true root </dev/null"] {
        let (c, o) = f.run(&p, cmd);
        assert!(c != 0 && o.contains("Operation not permitted"), "{cmd} under the sandbox: {c} {o}");
    }
}

/// Writes a fixture + default-policy profile to $AF_DUMP_DIR for baseline capture.
#[test]
#[ignore = "tooling: AF_DUMP_DIR=... cargo test -p agentacl-core dump_profile -- --ignored"]
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
        // Each exists outside the sandbox (a misspelled name can't pass vacuously).
        assert!(Command::new(&helper).arg(svc).status().unwrap().success(), "positive control: {svc} reachable unsandboxed");
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

#[test]
fn sandbox_cannot_read_other_processes_argv() {
    let f = Fixture::new();
    let helper = build_helper(&f, "procargs");
    // A process in another session, like the human's other terminals.
    use std::os::unix::process::CommandExt;
    let mut other = unsafe {
        Command::new("/bin/sleep")
            .arg("30")
            .pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()
            .unwrap()
    };
    // control: outside the sandbox the argv is readable
    let ctl = Command::new(&helper).arg(other.id().to_string()).output().unwrap();
    assert!(String::from_utf8_lossy(&ctl.stdout).contains("procargs2=READ"));
    let p = f.profile(&f.policy(None), input());
    let (_, o) = f.run(&p, &format!("{} {}", helper.display(), other.id()));
    other.kill().ok();
    other.wait().ok();
    assert!(o.contains("procargs2=denied"), "{o}");
    assert!(o.contains("proc_all=denied"), "{o}");
    assert!(o.contains("hw.ncpu=ok"), "{o}");
}
