use super::*;
use std::io::Write;
use std::net::TcpStream;

struct T {
    _d: tempfile::TempDir,
    st: Arc<UiState>,
    project: std::path::PathBuf,
}

fn setup() -> T {
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let project = root.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    assert!(std::process::Command::new("/usr/bin/git").arg("-C").arg(&project).args(["init", "-q"]).status().unwrap().success());
    std::fs::write(project.join("README"), "x").unwrap();
    let home = agentfence_core::config::user_home().unwrap();
    let paths = Paths::with_dirs(home, root.join("state"), root.join("config"));
    T { _d: d, st: start_for_test(paths).unwrap(), project }
}

/// Raw HTTP request; returns (status, json body).
fn req(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: Option<&str>) -> (u16, serde_json::Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut r = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        r.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    r.push_str("\r\n");
    if let Some(b) = body {
        r.push_str(b);
    }
    s.write_all(r.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status: u16 = out.split(' ').nth(1).unwrap().parse().unwrap();
    let (head, raw) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(raw) } else { raw.to_string() };
    let json = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    while let Some((len, rest)) = s.split_once("\r\n") {
        let n = usize::from_str_radix(len.trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.push_str(&rest[..n]);
        s = &rest[n + 2..];
    }
    out
}

impl T {
    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.st.port)
    }
    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.st.port)
    }
    fn login(&self) -> String {
        let code = self.st.mint_code().unwrap();
        let (s, v) = self.post_raw("/api/session", &format!("{{\"code\":\"{code}\"}}"), None);
        assert_eq!(s, 200, "{v}");
        v["token"].as_str().unwrap().to_string()
    }
    fn post_raw(&self, path: &str, body: &str, token: Option<&str>) -> (u16, serde_json::Value) {
        let (h, o) = (self.host(), self.origin());
        let auth = token.map(|t| format!("Bearer {t}"));
        let mut hs = vec![("Host", h.as_str()), ("Origin", o.as_str()), ("Content-Type", "application/json")];
        if let Some(a) = &auth {
            hs.push(("Authorization", a.as_str()));
        }
        req(self.st.port, "POST", path, &hs, Some(body))
    }
    fn post(&self, token: &str, path: &str, v: serde_json::Value) -> (u16, serde_json::Value) {
        self.post_raw(path, &v.to_string(), Some(token))
    }
    fn get(&self, token: &str, path: &str) -> (u16, serde_json::Value) {
        let h = self.host();
        let a = format!("Bearer {token}");
        req(self.st.port, "GET", path, &[("Host", h.as_str()), ("Authorization", a.as_str())], None)
    }
}

#[test]
fn credentials_and_request_shape() {
    let t = setup();
    let h = t.host();
    // no token / wrong token
    assert_eq!(req(t.st.port, "GET", "/api/overview", &[("Host", &h)], None).0, 401);
    assert_eq!(t.get("deadbeef", "/api/overview").0, 401);
    // bad host (DNS rebinding) and localhost alias refused
    assert_eq!(req(t.st.port, "GET", "/", &[("Host", "evil.com")], None).0, 421);
    assert_eq!(req(t.st.port, "GET", "/", &[("Host", &format!("localhost:{}", t.st.port))], None).0, 421);
    // OPTIONS
    assert_eq!(req(t.st.port, "OPTIONS", "/api/overview", &[("Host", &h)], None).0, 405);
    // POST origin / content-type
    let tok = t.login();
    let a = format!("Bearer {tok}");
    assert_eq!(req(t.st.port, "POST", "/api/evaluate", &[("Host", &h), ("Authorization", &a), ("Content-Type", "application/json"), ("Origin", "http://evil.com")], Some("{}")).0, 403);
    assert_eq!(req(t.st.port, "POST", "/api/evaluate", &[("Host", &h), ("Authorization", &a), ("Content-Type", "application/json")], Some("{}")).0, 403, "missing Origin");
    assert_eq!(req(t.st.port, "POST", "/api/evaluate", &[("Host", &h), ("Authorization", &a), ("Origin", &t.origin()), ("Content-Type", "text/plain")], Some("{}")).0, 415);
    // valid token works; static assets carry CSP
    assert_eq!(t.get(&tok, "/api/overview").0, 200);
    let mut s = TcpStream::connect(("127.0.0.1", t.st.port)).unwrap();
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.contains("Content-Security-Policy: default-src 'self'") && out.contains("frame-ancestors 'none'"));
    // a new login revokes the previous token
    let tok2 = t.login();
    assert_eq!(t.get(&tok, "/api/overview").0, 401);
    assert_eq!(t.get(&tok2, "/api/overview").0, 200);
}

#[test]
fn draft_validation_and_save() {
    let t = setup();
    let tok = t.login();
    let p = t.project.to_string_lossy().into_owned();
    // invalid draft: compiler-only error surfaces with CLI text
    let (_, v) = t.post(&tok, "/api/policy/preview", serde_json::json!({ "scope": "user", "project": p, "yaml": "version: v1\ndefaults: {process: deny}\n" }));
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().contains("defaults.process: deny"), "{v}");
    // project scope: allow keys refused
    let (_, v) = t.post(&tok, "/api/policy/preview", serde_json::json!({ "scope": "project", "project": p, "yaml": "version: v1\nfilesystem:\n  allow_read: [\"/**\"]\n" }));
    assert!(v["error"].as_str().unwrap().contains("restrict-only"), "{v}");
    // user policy that drops project access needs confirmation
    let bare = "version: v1\ndefaults: {filesystem: deny}\n";
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "user", "project": p, "yaml": bare, "base_sha256": null }));
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["needs_confirm"][0], "project-unreadable");
    // proper save creates the file; stale base conflicts; structured doc round-trips
    let good = "version: v1\ndefaults: {filesystem: deny, network: deny}\nfilesystem:\n  allow_read: [\"${PROJECT}/**\"]\n  allow_write: [\"${PROJECT}/**\"]\n";
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "user", "project": p, "yaml": good, "base_sha256": null }));
    assert_eq!(s, 200, "{v}");
    let sha = v["sha256"].as_str().unwrap().to_string();
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "user", "project": p, "yaml": good, "base_sha256": null }));
    assert_eq!((s, v["conflict"].as_bool()), (409, Some(true)));
    let (_, g) = t.get(&tok, &format!("/api/policy?scope=user&project={}", p));
    assert_eq!(g["sha256"], sha.as_str(), "{g}");
    let mut doc = g["doc"].clone();
    doc["filesystem"]["deny_read"] = serde_json::json!([{ "kind": "path", "pattern": "${PROJECT}/bumper.yaml", "except": [], "id": null, "reason": null }]);
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "user", "project": p, "doc": doc, "base_sha256": sha }));
    assert_eq!(s, 200, "{v}");
    let saved = std::fs::read_to_string(t.st.paths.config_dir.join("policy.yaml")).unwrap();
    assert!(saved.contains("bumper.yaml"));
    assert!(t.st.paths.config_dir.join("policy.yaml.bak").exists());
    // evaluate against the saved policy
    let (_, v) = t.post(&tok, "/api/evaluate", serde_json::json!({ "scope": "user", "project": p, "request": { "kind": "path", "path": format!("{p}/bumper.yaml"), "action": "read" } }));
    assert_eq!(v["effect"], "deny", "{v}");
    // the save is audited
    let (_, ev) = t.get(&tok, "/api/events?limit=50");
    assert!(ev["events"].as_array().unwrap().iter().any(|e| e["action"] == "policy.saved" && e["source"] == "ui"));
}

#[test]
fn trusted_and_symlinked_project_files_refused() {
    let t = setup();
    let tok = t.login();
    let p = t.project.to_string_lossy().into_owned();
    // symlinked .agentfence
    let elsewhere = t.project.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, t.project.join(".agentfence")).unwrap();
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "project", "project": p, "yaml": "version: v1\n", "base_sha256": null }));
    assert_ne!(s, 200, "{v}");
    assert!(!elsewhere.join("policy.yaml").exists());
    std::fs::remove_file(t.project.join(".agentfence")).unwrap();
    // trusted project file is read-only
    std::fs::create_dir_all(t.project.join(".agentfence")).unwrap();
    let y = "version: v1\n";
    std::fs::write(t.project.join(".agentfence/policy.yaml"), y).unwrap();
    let sha = agentfence_policy::set::sha256_hex(y.as_bytes());
    agentfence_core::trust::trust(&t.st.paths, &t.project, &sha).unwrap();
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "project", "project": p, "yaml": "version: v1\nfilesystem:\n  deny_read: [\"${PROJECT}/x\"]\n", "base_sha256": sha }));
    assert_eq!(s, 400);
    assert!(v["error"].as_str().unwrap().contains("trusted"), "{v}");
}

#[test]
fn code_is_single_use() {
    let t = setup();
    let code = t.st.mint_code().unwrap();
    assert_eq!(t.post_raw("/api/session", &format!("{{\"code\":\"{code}\"}}"), None).0, 200);
    // replay: 401 and the server shuts down all access (process exit is skipped in tests via the flag)
    let (s, _) = t.post_raw("/api/session", &format!("{{\"code\":\"{code}\"}}"), None);
    assert_eq!(s, 401);
    // all access revoked: even a fresh code can't bring back the old token
    assert!(t.st.auth.lock().unwrap().token.is_none());
}

#[test]
fn files_view_rules() {
    let t = setup();
    let tok = t.login();
    let p = t.project.to_string_lossy().into_owned();
    std::fs::create_dir_all(t.project.join("docs")).unwrap();
    std::fs::write(t.project.join("a*b.txt"), "x").unwrap();
    std::os::unix::fs::symlink(t.project.join("docs"), t.project.join("link")).unwrap();
    let (_, v) = t.post(&tok, "/api/fs/list", serde_json::json!({ "scope": "user", "project": p, "path": p }));
    let get = |n: &str| v["entries"].as_array().unwrap().iter().find(|e| e["name"] == n).cloned().unwrap();
    // user scope: absolute (or ${HOME}-relative) paths, never ${PROJECT}
    assert_eq!(get("docs")["actions"]["deny_read"]["rule"], format!("{p}/docs/**"));
    assert!(get("a*b.txt")["actions"]["deny_read"]["unavailable"].is_string());
    assert!(get("link")["actions"]["allow_read"]["unavailable"].is_string(), "no allow on symlinks");
    assert!(get("link")["actions"]["deny_read"]["rule"].as_str().unwrap().ends_with("/docs/**"), "deny on resolved path");
    let (_, v) = t.post(&tok, "/api/fs/list", serde_json::json!({ "scope": "project", "project": p, "path": p }));
    let docs = v["entries"].as_array().unwrap().iter().find(|e| e["name"] == "docs").cloned().unwrap();
    assert_eq!(docs["actions"]["deny_read"]["rule"], "${PROJECT}/docs/**");
    assert!(docs["actions"]["allow_read"]["unavailable"].is_string(), "project scope is restrict-only");
}
