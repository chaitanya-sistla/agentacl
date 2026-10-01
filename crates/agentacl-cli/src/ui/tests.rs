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
    let home = agentacl_core::config::user_home().unwrap();
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
    /// Redeems a code; returns the session token from the Set-Cookie header.
    fn login(&self) -> String {
        let code = self.st.mint_code().unwrap();
        let body = format!("{{\"code\":\"{code}\"}}");
        let mut s = TcpStream::connect(("127.0.0.1", self.st.port)).unwrap();
        let (h, o) = (self.host(), self.origin());
        s.write_all(
            format!("POST /api/session HTTP/1.1\r\nHost: {h}\r\nOrigin: {o}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes(),
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(!out.contains("\"token\""), "token must not reach page script");
        let prefix = format!("Set-Cookie: af_session_{}=", self.st.port);
        let line = out.lines().find(|l| l.starts_with(&prefix)).expect("session cookie");
        assert!(line.contains("HttpOnly") && line.contains("SameSite=Strict"));
        line[prefix.len()..].split(';').next().unwrap().to_string()
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
    // symlinked .agentacl
    let elsewhere = t.project.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, t.project.join(".agentacl")).unwrap();
    let (s, v) = t.post(&tok, "/api/policy/save", serde_json::json!({ "scope": "project", "project": p, "yaml": "version: v1\n", "base_sha256": null }));
    assert_ne!(s, 200, "{v}");
    assert!(!elsewhere.join("policy.yaml").exists());
    std::fs::remove_file(t.project.join(".agentacl")).unwrap();
    // trusted project file is read-only
    std::fs::create_dir_all(t.project.join(".agentacl")).unwrap();
    let y = "version: v1\n";
    std::fs::write(t.project.join(".agentacl/policy.yaml"), y).unwrap();
    let sha = agentacl_policy::set::sha256_hex(y.as_bytes());
    agentacl_core::trust::trust(&t.st.paths, &t.project, &sha).unwrap();
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

#[test]
fn cookie_session_needs_custom_header_and_assets_served() {
    let t = setup();
    let tok = t.login();
    let h = t.host();
    let cookie = format!("af_session_{}={tok}", t.st.port);
    // a cookie for another port's console doesn't count
    let other = format!("af_session={tok}");
    assert_eq!(req(t.st.port, "GET", "/api/status", &[("Host", &h), ("Cookie", &other), ("X-AgentACL", "1")], None).0, 401);
    // cookie alone (what a cross-site form/img could send) is refused
    assert_eq!(req(t.st.port, "GET", "/api/status", &[("Host", &h), ("Cookie", &cookie)], None).0, 401);
    // cookie + X-AgentACL (needs a CORS preflight cross-site, which we refuse)
    let (s, v) = req(t.st.port, "GET", "/api/status", &[("Host", &h), ("Cookie", &cookie), ("X-AgentACL", "1")], None);
    assert_eq!(s, 200);
    assert!(v["warnings"].is_array() && v["backend"]["name"] == "seatbelt");
    // a foreign Origin on a GET is refused too
    assert_eq!(req(t.st.port, "GET", "/api/status", &[("Host", &h), ("Cookie", &cookie), ("X-AgentACL", "1"), ("Origin", "http://evil.com")], None).0, 403);
    // the built console is embedded at fixed paths
    for p in ["/assets/app.js", "/assets/app.css"] {
        let mut s = TcpStream::connect(("127.0.0.1", t.st.port)).unwrap();
        s.write_all(format!("GET {p} HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{p}");
        assert!(out.contains("Content-Security-Policy"), "{p}");
    }
}

#[test]
fn fs_node_and_project_scope_guard() {
    let t = setup();
    let tok = t.login();
    let p = t.project.to_string_lossy().into_owned();
    std::fs::create_dir_all(t.project.join("docs")).unwrap();
    let (s, v) = t.post(&tok, "/api/fs/node", serde_json::json!({ "scope": "project", "project": p, "path": format!("{p}/docs") }));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["actions"]["deny_read"]["rule"], "${PROJECT}/docs/**");
    assert_eq!(t.post(&tok, "/api/fs/node", serde_json::json!({ "scope": "user", "project": p, "path": "relative" })).0, 400);
    // an unknown picker purpose is refused before anything runs
    assert_eq!(t.post(&tok, "/api/pick-folder", serde_json::json!({ "purpose": "rm" })).0, 400);
    // the machine-wide map works without a project
    let (s, v) = t.post(&tok, "/api/map", serde_json::json!({ "scope": "user", "project": "" }));
    assert_eq!(s, 200, "{v}");
    assert!(v["roots"].is_array());
}

#[test]
fn preview_reports_changes_per_agent_and_excepts() {
    let t = setup();
    let tok = t.login();
    let p = t.project.to_string_lossy().into_owned();
    let y = "version: v1\nfilesystem:\n  deny_read:\n    - path: \"${PROJECT}/data/**\"\n      except: [\"${PROJECT}/data/public/**\"]\n";
    let (s, v) = t.post(&tok, "/api/policy/preview", serde_json::json!({ "scope": "project", "project": p, "yaml": y }));
    assert_eq!(s, 200, "{v}");
    let added = v["effective_diff"]["added"].as_array().unwrap();
    let hit = added.iter().find(|a| a["key"].as_str().unwrap().contains("/data/**")).expect("deny listed");
    assert!(hit["key"].as_str().unwrap().contains(" except "), "{hit}");
    assert_eq!(hit["agents"], serde_json::json!([]), "applies to every agent");
    assert!(v["unreadable_projects"].is_array());
    assert!(v["current_sha256"].is_null());
}

#[test]
fn allow_under_builtin_protection_is_flagged() {
    let t = setup();
    let tok = t.login();
    let p = t.project.to_string_lossy().into_owned();
    let y = "version: v1\nfilesystem:\n  allow_read: [\"${PROJECT}/**\", \"${HOME}/Library/Cookies/**\"]\n  allow_write: [\"${PROJECT}/**\"]\n";
    let (s, v) = t.post(&tok, "/api/policy/preview", serde_json::json!({ "scope": "user", "project": p, "yaml": y }));
    assert_eq!(s, 200, "{v}");
    let w: Vec<String> = v["effective"]["warnings"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    assert!(w.iter().any(|x| x.contains("Library/Cookies") && x.contains("no effect") && x.contains("\"browsers\"")), "{w:?}");
    // the project allow is not flagged (no built-in covers the whole project)
    assert!(!w.iter().any(|x| x.contains("${PROJECT}/**") && x.contains("no effect")), "{w:?}");
}

fn deny(reason: &str, policy: &str, rule: &str) -> agentacl_policy::Decision {
    agentacl_policy::Decision { effect: agentacl_policy::Effect::Deny, policy: policy.into(), rule_id: rule.into(), reason: reason.into(), trace: vec![] }
}

#[test]
fn network_sites_rules_and_requests() {
    let t = setup();
    let tok = t.login();
    // Real proxy events (they can only be created by the proxy): two refused CONNECT requests.
    struct DenyAll;
    impl agentacl_core::netproxy::NetDecider for DenyAll {
        fn host(&self, _: &str, _: u16) -> agentacl_policy::Decision {
            deny("not allowed", "default", "default")
        }
        fn addr(&self, _: std::net::IpAddr, _: u16) -> agentacl_policy::Decision {
            deny("not allowed", "default", "default")
        }
    }
    let st2 = t.st.clone();
    let proxy = agentacl_core::netproxy::NetProxy::start(
        std::sync::Arc::new(DenyAll),
        std::sync::Arc::new(move |e| {
            let _ = st2.store.lock().unwrap().record_enforced(&st2.ctx, e);
        }),
    )
    .unwrap();
    for _ in 0..2 {
        let mut c = TcpStream::connect(("127.0.0.1", proxy.port)).unwrap();
        c.write_all(b"CONNECT http-intake.logs.us5.datadoghq.com:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    }
    proxy.stop();
    let (s, v) = t.get(&tok, "/api/network?days=7");
    assert_eq!(s, 200, "{v}");
    let site = |v: &serde_json::Value, h: &str| v["sites"].as_array().unwrap().iter().find(|x| x["host"] == h).cloned().unwrap();
    let dd = site(&v, "http-intake.logs.us5.datadoghq.com");
    assert_eq!(dd["blocked"], 2);
    assert_eq!(dd["category"]["id"], "telemetry");
    assert_eq!(v["mode"], "block");

    // Block: saved to the user policy and to the live file.
    let (s, r) = t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "http-intake.logs.us5.datadoghq.com", "effect": "block" }));
    assert_eq!(s, 200, "{r}");
    let yaml = std::fs::read_to_string(&t.st.paths.user_policy).unwrap();
    assert!(yaml.contains("http-intake.logs.us5.datadoghq.com"), "{yaml}");
    let live = agentacl_core::netlive::read_live(&agentacl_core::supervisor::canon_or(&t.st.paths.state_dir));
    assert!(live.rules.iter().any(|r| r.host == "http-intake.logs.us5.datadoghq.com" && r.effect == agentacl_policy::Effect::Deny));
    let (_, v) = t.get(&tok, "/api/network");
    assert_eq!(site(&v, "http-intake.logs.us5.datadoghq.com")["policy_rule"], "block");
    // IPs and junk are refused.
    assert_eq!(t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "169.254.169.254", "effect": "allow" })).0, 400);
    assert_eq!(t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "a\"b", "effect": "allow" })).0, 400);
    // Remove.
    assert_eq!(t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "http-intake.logs.us5.datadoghq.com", "effect": "none" })).0, 200);
    assert!(!std::fs::read_to_string(&t.st.paths.user_policy).unwrap().contains("datadoghq"));

    // Mode.
    assert_eq!(t.post(&tok, "/api/network/mode", serde_json::json!({ "mode": "ask" })).0, 200);
    assert_eq!(t.get(&tok, "/api/approvals").1["mode"], "ask");

    // Requests inbox groups by host, and dismissing hides it.
    let (_, v) = t.get(&tok, "/api/requests?days=7");
    let g = v["requests"].as_array().unwrap().iter().find(|g| g["key"] == "net:http-intake.logs.us5.datadoghq.com").cloned().unwrap();
    assert_eq!(g["count"], 2);
    assert_eq!(g["kind"], "network");
    assert_eq!(v["pages"], 1);
    assert_eq!(v["counts"]["network"], 1);
    assert_eq!(v["keys"].as_array().unwrap().len(), v["total"].as_u64().unwrap() as usize);
    // Paged and filtered on the server: an empty kind has no rows but the same counts.
    let (_, p) = t.get(&tok, "/api/requests?days=7&kind=program&page=1&size=10");
    assert_eq!(p["total"], 0);
    assert_eq!(p["counts"], v["counts"]);
    assert_eq!(p["size"], 10);
    assert_eq!(t.post(&tok, "/api/requests/dismiss", serde_json::json!({ "key": g["key"] })).0, 200);
    let (_, v) = t.get(&tok, "/api/requests?days=7");
    assert!(!v["requests"].as_array().unwrap().iter().any(|g| g["key"] == "net:http-intake.logs.us5.datadoghq.com"));
    assert_eq!(v["dismissed"], 1);
}

#[test]
fn approvals_answer_and_always_saves_a_rule() {
    let t = setup();
    let tok = t.login();
    let sd = agentacl_core::supervisor::canon_or(&t.st.paths.state_dir);
    let a = agentacl_core::netlive::Approval {
        id: agentacl_core::netlive::new_id(),
        session: "agt_x".into(),
        agent: "claude-code".into(),
        project: t.project.to_string_lossy().into(),
        host: "registry.npmjs.org".into(),
        port: 443,
        created: agentacl_core::audit::now_rfc3339(),
        expires: "2999-01-01T00:00:00.000Z".into(),
    };
    agentacl_core::netlive::request(&sd, &a).unwrap();
    let (_, v) = t.get(&tok, "/api/approvals");
    assert_eq!(v["approvals"][0]["host"], "registry.npmjs.org");
    assert_eq!(v["approvals"][0]["agent_name"], "Claude Code");
    assert_eq!(v["approvals"][0]["category"]["id"], "package-registry");
    assert_eq!(t.post(&tok, "/api/approvals/answer", serde_json::json!({ "id": a.id, "answer": "nope" })).0, 400);
    let (s, r) = t.post(&tok, "/api/approvals/answer", serde_json::json!({ "id": a.id, "answer": "always" }));
    assert_eq!(s, 200, "{r}");
    assert!(std::fs::read_to_string(&t.st.paths.user_policy).unwrap().contains("registry.npmjs.org"));
    assert!(t.get(&tok, "/api/approvals").1["approvals"].as_array().unwrap().is_empty());
    // A second answer finds nothing waiting.
    assert_eq!(t.post(&tok, "/api/approvals/answer", serde_json::json!({ "id": a.id, "answer": "always" })).0, 400);
}

#[test]
fn restart_status_reports_the_real_outcome() {
    use agentacl_core::audit::{EventContext, LifecycleEvent, LifecycleKind, SessionRecord, Store};
    let t = tempfile::tempdir().unwrap();
    let store = Store::open(&t.path().join("a.db")).unwrap();
    let rec = |id: &str, sup: i32, started: &str| SessionRecord {
        session_id: id.into(),
        identity_json: "{}".into(),
        agent: "claude-code".into(),
        project: "/p".into(),
        policy_name: "user".into(),
        policy_sha256: "x".into(),
        backend: "seatbelt".into(),
        supervisor_pid: sup,
        agent_pid: None,
        started_at: started.into(),
        ended_at: None,
        exit_code: None,
    };
    let since = "2026-01-01T00:00:10.000Z";
    let state = |old: &str, alive: bool| super::api::restart_state(&store, old, since, |_| alive).unwrap()["state"].as_str().unwrap().to_string();

    // Still running, nothing new yet.
    store.insert_session(&rec("agt_A", 100, "2026-01-01T00:00:00.000Z")).unwrap();
    assert_eq!(state("agt_A", true), "restarting");
    // Relaunched by the same supervisor: the new session is prepared (and
    // stamped) before the old one ends.
    store.end_session("agt_A", "2026-01-01T00:00:12.000Z", Some(0)).unwrap();
    assert_eq!(state("agt_A", true), "restarting", "ended, successor not registered yet");
    store.insert_session(&rec("agt_B", 100, "2026-01-01T00:00:11.000Z")).unwrap();
    let v = super::api::restart_state(&store, "agt_A", since, |_| true).unwrap();
    assert_eq!((v["state"].as_str(), v["session"].as_str()), (Some("restarted"), Some("agt_B")));

    // Refused: the agent keeps running and says why.
    store.insert_session(&rec("agt_C", 200, "2026-01-01T00:00:00.000Z")).unwrap();
    let ctx = EventContext { human: "u".into(), machine: "m".into(), agent: "claude-code".into(), agent_version: None, session: "agt_C".into(), backend: "seatbelt".into() };
    store.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::RestartRefused, pid: None, detail: "restart refused: bad rule".into() }).unwrap();
    // Many later events don't hide it.
    for _ in 0..600 {
        store.record_lifecycle(&ctx, LifecycleEvent { kind: LifecycleKind::BackendWarning, pid: None, detail: "noise".into() }).unwrap();
    }
    assert!(super::api::restart_state(&store, "agt_C", "", |_| true).is_err(), "the request time is required");
    let v = super::api::restart_state(&store, "agt_C", since, |_| true).unwrap();
    assert_eq!(v["state"], "refused");
    assert!(v["detail"].as_str().unwrap().contains("bad rule"));

    // Exited without coming back; a successor from an unrelated supervisor doesn't count.
    store.insert_session(&rec("agt_D", 300, "2026-01-01T00:00:00.000Z")).unwrap();
    store.end_session("agt_D", "2026-01-01T00:00:11.000Z", Some(1)).unwrap();
    store.insert_session(&rec("agt_E", 301, "2026-01-01T00:00:12.000Z")).unwrap();
    assert_eq!(state("agt_D", false), "exited");
}

#[test]
fn access_grants_scopes_and_removal() {
    let t = setup();
    let tok = t.login();
    let home = agentacl_core::config::user_home().unwrap();
    let sd = agentacl_core::supervisor::canon_or(&t.st.paths.state_dir);
    let proj = t.project.to_string_lossy().into_owned();
    let o2 = format!("{}/agentacl-test-o2", home.display());
    let grant = |v: serde_json::Value| t.post(&tok, "/api/access/allow", v);

    // A folder, for Claude, in this project.
    let (s, r) = grant(serde_json::json!({ "kind": "read", "target": o2, "dir": true, "agent": "claude-code", "project": proj, "for_agent": "claude-code" }));
    assert_eq!(s, 200, "{r}");
    let file = r["file"].as_str().unwrap().to_string();
    assert!(file.starts_with("agent-claude-code-") && file.contains('@') && t.st.paths.config_dir.join("access").join(&file).exists());
    let (_, l) = t.get(&tok, "/api/access?agent=claude-code");
    let entry = l["access"].as_array().unwrap().iter().find(|e| e["file"] == file.as_str()).unwrap().clone();
    assert_eq!(entry["project"], proj.as_str());
    assert_eq!(entry["rules"][0]["pattern"], format!("{o2}/**"));
    assert!(t.get(&tok, "/api/access?agent=codex").1["access"].as_array().unwrap().iter().all(|e| e["file"] != file.as_str()), "filtered by agent");

    // Built-in protections can't be allowed; one agent can't grant for another.
    let (s, r) = grant(serde_json::json!({ "kind": "read", "target": format!("{}/.ssh", home.display()), "dir": true, "agent": "claude-code", "for_agent": "claude-code" }));
    assert_eq!(s, 400, "{r}");
    assert!(r["error"].as_str().unwrap().contains("protect-secrets"), "{r}");
    assert_eq!(grant(serde_json::json!({ "kind": "read", "target": o2, "agent": "codex", "for_agent": "claude-code" })).0, 400);
    assert_eq!(grant(serde_json::json!({ "kind": "read", "target": "relative/path", "for_agent": "claude-code" })).0, 400);
    assert_eq!(grant(serde_json::json!({ "kind": "read", "target": format!("{o2}/*"), "for_agent": "claude-code" })).0, 400);
    let lower = home.display().to_string().to_lowercase();
    for broad in [
        home.display().to_string(),
        lower,
        format!("{}/.", home.display()),
        format!("/System/Volumes/Data{}", home.display()),
        "/Users".into(),
        "/Library".into(),
        "/private/var".into(),
        "/private/etc".into(),
        "/private/tmp".into(),
        "/".into(),
    ] {
        let (s, r) = grant(serde_json::json!({ "kind": "read", "target": broad, "dir": true, "for_agent": "claude-code" }));
        assert_eq!(s, 400, "{broad}: {r}");
    }

    // A site, for Claude everywhere: saved and live, scoped, removable.
    let (s, r) = grant(serde_json::json!({ "kind": "site", "target": "API.Example.com", "agent": "claude-code", "for_agent": "claude-code" }));
    assert_eq!(s, 200, "{r}");
    let live = agentacl_core::netlive::read_live(&sd);
    let rule = live.rules.iter().find(|r| r.host == "api.example.com").unwrap();
    assert_eq!((rule.agent.as_deref(), rule.project.as_deref()), (Some("claude-code"), None));
    let claude_file = agentacl_core::access::file_name(&agentacl_core::access::Scope { agent: Some("claude-code".into()), project: None });
    let claude_src = format!("access:{}", claude_file.trim_end_matches(".yaml"));
    assert_eq!(rule.source.as_deref(), Some(claude_src.as_str()));
    // The same site for every agent too; removing Claude's grant keeps that one working.
    assert_eq!(grant(serde_json::json!({ "kind": "site", "target": "api.example.com", "for_agent": "claude-code" })).0, 200);
    let (s, r) = t.post(&tok, "/api/access/remove", serde_json::json!({ "file": claude_file, "section": "network.allow", "pattern": "api.example.com" }));
    assert_eq!(s, 200, "{r}");
    let live = agentacl_core::netlive::read_live(&sd);
    assert!(!live.rules.iter().any(|r| r.host == "api.example.com" && r.source.as_deref() == Some(claude_src.as_str())));
    assert!(live.revoked.iter().any(|r| r.host == "api.example.com" && r.policy.as_deref() == Some(claude_src.as_str())));
    assert!(live.rules.iter().any(|r| r.host == "api.example.com" && r.source.as_deref() == Some("access:all") && r.effect == agentacl_policy::Effect::Allow), "the every-agent grant stays live");
    assert!(!t.st.paths.config_dir.join("access").join(&claude_file).exists(), "empty access file removed");
    // A hand edit that drops a site drops its live rule too.
    std::fs::remove_file(t.st.paths.config_dir.join("access/all.yaml")).unwrap();
    t.get(&tok, "/api/access");
    assert!(!agentacl_core::netlive::read_live(&sd).rules.iter().any(|r| r.source.as_deref() == Some("access:all")));

    // "Only in this project" is the exact folder the session uses, not its git root.
    let sub = t.project.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let (s, r) = grant(serde_json::json!({ "kind": "read", "target": o2, "dir": true, "agent": "claude-code", "project": sub.to_string_lossy(), "for_agent": "claude-code" }));
    assert_eq!(s, 200, "{r}");
    let (_, l) = t.get(&tok, "/api/access");
    assert!(l["access"].as_array().unwrap().iter().any(|e| e["file"] == r["file"] && e["project"] == sub.to_string_lossy().as_ref()), "{l}");
}

#[test]
fn waiting_requests_extend_and_scoped_always() {
    let t = setup();
    let tok = t.login();
    let sd = agentacl_core::supervisor::canon_or(&t.st.paths.state_dir);
    let a = agentacl_core::netlive::Approval {
        id: agentacl_core::netlive::new_id(),
        session: "agt_x".into(),
        agent: "claude-code".into(),
        project: t.project.to_string_lossy().into(),
        host: "pypi.org".into(),
        port: 443,
        created: agentacl_core::audit::now_rfc3339(),
        expires: "2999-01-01T00:00:00.000Z".into(),
    };
    agentacl_core::netlive::request(&sd, &a).unwrap();
    let (s, r) = t.post(&tok, "/api/approvals/extend", serde_json::json!({ "id": a.id }));
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["expires"], "2999-01-01T00:01:00.000Z");
    assert_eq!(t.post(&tok, "/api/network/wait", serde_json::json!({ "secs": 45 })).0, 400);
    assert_eq!(t.post(&tok, "/api/network/wait", serde_json::json!({ "secs": 120 })).0, 200);
    assert_eq!(agentacl_core::netlive::read_live(&sd).ask_timeout_secs, Some(120));

    // "Always, for this agent" goes to Claude's access file, not the policy file.
    let (s, r) = t.post(&tok, "/api/approvals/answer", serde_json::json!({ "id": a.id, "answer": "always", "agent_only": true }));
    assert_eq!(s, 200, "{r}");
    let f = agentacl_core::access::file_name(&agentacl_core::access::Scope { agent: Some("claude-code".into()), project: None });
    let y = std::fs::read_to_string(t.st.paths.config_dir.join("access").join(f)).unwrap();
    assert!(y.contains("pypi.org") && y.contains("claude-code"), "{y}");
    assert!(!std::fs::read_to_string(&t.st.paths.user_policy).unwrap_or_default().contains("pypi.org"));
}

#[test]
fn quiet_mode_settings() {
    let t = setup();
    let tok = t.login();
    let (_, v) = t.get(&tok, "/api/notify");
    assert_eq!((v["quiet"].as_bool(), v["wait_secs"].as_u64()), (Some(false), Some(30)));
    let (s, v) = t.post(&tok, "/api/notify", serde_json::json!({ "quiet": true, "minutes": 60 }));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["quiet"], false, "temporary, not permanent");
    assert!(v["quiet_until"].is_string());
    assert_eq!(t.post(&tok, "/api/notify", serde_json::json!({ "quiet": true, "minutes": 0 })).0, 400);
    let (_, v) = t.post(&tok, "/api/notify", serde_json::json!({ "quiet": true }));
    assert_eq!((v["quiet"].as_bool(), v["quiet_until"].is_null()), (Some(true), true));
    let (_, v) = t.post(&tok, "/api/notify", serde_json::json!({ "quiet": false }));
    assert_eq!(v["quiet"], false);
}

#[test]
fn access_edge_cases() {
    let t = setup();
    let tok = t.login();
    let sd = agentacl_core::supervisor::canon_or(&t.st.paths.state_dir);
    let grant = |v: serde_json::Value| t.post(&tok, "/api/access/allow", v);

    // Your own block is named as yours, not as a built-in protection.
    assert_eq!(t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "b.example.com", "effect": "block" })).0, 200);
    let (s, r) = grant(serde_json::json!({ "kind": "site", "target": "b.example.com", "agent": "claude-code", "for_agent": "claude-code" }));
    assert_eq!(s, 400);
    assert!(r["error"].as_str().unwrap().contains("your own rule"), "{r}");

    // A site removed from an access file by hand is revoked for running sessions.
    assert_eq!(grant(serde_json::json!({ "kind": "site", "target": "h.example.com", "for_agent": "claude-code" })).0, 200);
    std::fs::remove_file(t.st.paths.config_dir.join("access/all.yaml")).unwrap();
    t.get(&tok, "/api/access");
    let live = agentacl_core::netlive::read_live(&sd);
    assert!(!live.rules.iter().any(|r| r.host == "h.example.com"));
    assert!(live.revoked.iter().any(|r| r.host == "h.example.com" && r.policy.as_deref() == Some("access:all")));
    // …and one added by hand gets a live rule.
    std::fs::write(t.st.paths.config_dir.join("access/all.yaml"), "version: v1\nnetwork:\n  allow: [\"hand.example.com\"]\n").unwrap();
    t.get(&tok, "/api/access");
    assert!(agentacl_core::netlive::read_live(&sd).rules.iter().any(|r| r.host == "hand.example.com" && r.source.as_deref() == Some("access:all")));

    // Removing a site from the policy file revokes it for sessions that
    // loaded it, even though Claude also has its own grant (which stays live).
    assert_eq!(t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "p.example.com", "effect": "allow" })).0, 200);
    assert_eq!(grant(serde_json::json!({ "kind": "site", "target": "p.example.com", "agent": "claude-code", "for_agent": "claude-code" })).0, 200);
    assert_eq!(t.post(&tok, "/api/network/rule", serde_json::json!({ "host": "p.example.com", "effect": "none" })).0, 200);
    let live = agentacl_core::netlive::read_live(&sd);
    assert!(live.revoked.iter().any(|r| r.host == "p.example.com" && r.policy.is_none()), "{:?}", live.revoked);
    assert!(live.rules.iter().any(|r| r.host == "p.example.com" && r.agent.as_deref() == Some("claude-code")), "Claude's grant is re-added");

    // A stray file is listed as broken (not fatal) and can be removed.
    std::fs::write(t.st.paths.config_dir.join("access/all copy.yaml"), "version: v1\n").unwrap();
    let (s, l) = t.get(&tok, "/api/access");
    assert_eq!(s, 200, "{l}");
    assert_eq!(l["broken"][0]["file"], "all copy.yaml");
    assert!(l["access"].as_array().unwrap().iter().any(|e| e["file"] == "all.yaml"), "the valid files still load");
    assert_eq!(t.post(&tok, "/api/access/remove", serde_json::json!({ "file": "all.yaml", "broken": true })).0, 400, "only broken files");
    assert_eq!(t.post(&tok, "/api/access/remove", serde_json::json!({ "file": "all copy.yaml", "broken": true })).0, 200);
    assert!(!t.st.paths.config_dir.join("access/all copy.yaml").exists());
}

#[test]
fn exact_file_grants_by_default() {
    let t = setup();
    let tok = t.login();
    let home = agentacl_core::config::user_home().unwrap();
    let dir = format!("{}/agentacl-test-exact", home.display());
    let (a, b) = (format!("{dir}/a.txt"), format!("{dir}/b.txt"));
    let (s, r) = t.post(&tok, "/api/access/allow", serde_json::json!({ "kind": "read", "targets": [a, b], "agent": "claude-code", "for_agent": "claude-code" }));
    assert_eq!(s, 200, "{r}");
    let y = std::fs::read_to_string(t.st.paths.config_dir.join("access").join(r["file"].as_str().unwrap())).unwrap();
    assert!(y.contains(&a) && y.contains(&b) && !y.contains(&format!("{dir}/**")), "exactly the two files: {y}");
    // One protected path in the list refuses the whole grant (nothing saved).
    let before = std::fs::read_to_string(t.st.paths.config_dir.join("access").join(r["file"].as_str().unwrap())).unwrap();
    let c = format!("{dir}/c.txt");
    let (s, r2) =
        t.post(&tok, "/api/access/allow", serde_json::json!({ "kind": "read", "targets": [c, format!("{}/.ssh/id_ed25519", home.display())], "agent": "claude-code", "for_agent": "claude-code" }));
    assert_eq!(s, 400, "{r2}");
    assert_eq!(std::fs::read_to_string(t.st.paths.config_dir.join("access").join(r["file"].as_str().unwrap())).unwrap(), before);
    assert_eq!(t.post(&tok, "/api/access/allow", serde_json::json!({ "kind": "read", "targets": [], "for_agent": "claude-code" })).0, 400);
    assert_eq!(t.post(&tok, "/api/access/allow", serde_json::json!({ "kind": "read", "targets": [format!("{dir}/d.txt"), 123], "for_agent": "claude-code" })).0, 400, "non-strings refuse the grant");
    for bad in [format!("{dir}/x.txt "), format!(" {dir}/x.txt"), format!("{}/Library/Keychains/login.keychain-db", home.display()), format!("{}/library/keychains/x", home.display())] {
        let (s, r) = t.post(&tok, "/api/access/allow", serde_json::json!({ "kind": "read", "targets": [bad], "for_agent": "claude-code" }));
        assert_eq!(s, 400, "{bad:?}: {r}");
    }
}
