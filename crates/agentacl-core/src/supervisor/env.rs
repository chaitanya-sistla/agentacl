//! Child environment: strip inherited secrets (threat T21), route egress
//! through the proxy, and point TMPDIR at the session's private temp dir.

/// Names (case-insensitive; `*` wildcards) never passed to a supervised agent
/// unless the provider passes them through or the user asks with --keep-env.
pub const SECRET_ENV: &[&str] = &[
    "*_TOKEN",
    "*_TOKEN_*",
    "*_SECRET",
    "*_SECRET_*",
    "*_PASSWORD",
    "*_PASSWD",
    "*_API_KEY",
    "*_APIKEY",
    "*_ACCESS_KEY",
    "*_ACCESS_KEY_ID",
    "*_PRIVATE_KEY",
    "*_CREDENTIALS",
    "AWS_*",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "KUBECONFIG",
    "VAULT_*",
    "DOCKER_HOST",
];

/// Proxy-related variables we always replace.
const PROXY_VARS: &[&str] = &["http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

pub fn glob_match(pat: &str, name: &str) -> bool {
    let (p, n) = (pat.to_ascii_uppercase(), name.to_ascii_uppercase());
    fn go(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some(a), Some(b)) if a == b => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    go(p.as_bytes(), n.as_bytes())
}

pub struct ChildEnv {
    pub vars: Vec<(String, String)>,
    pub stripped: Vec<String>,
}

pub fn build(inherited: impl IntoIterator<Item = (String, String)>, passthrough: &[String], keep: &[String], proxy_port: u16, tmpdir: &str, session_id: &str) -> ChildEnv {
    let mut vars = Vec::new();
    let mut stripped = Vec::new();
    for (k, v) in inherited {
        if PROXY_VARS.contains(&k.as_str()) || k == "TMPDIR" || k.starts_with("AGENTACL_") {
            continue;
        }
        let secret = SECRET_ENV.iter().any(|p| glob_match(p, &k));
        let allowed = passthrough.iter().any(|p| glob_match(p, &k)) || keep.iter().any(|p| p.eq_ignore_ascii_case(&k));
        if secret && !allowed {
            stripped.push(k);
        } else {
            vars.push((k, v));
        }
    }
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    for k in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        vars.push((k.into(), proxy.clone()));
    }
    vars.push(("NO_PROXY".into(), String::new()));
    vars.push(("no_proxy".into(), String::new()));
    vars.push(("TMPDIR".into(), format!("{tmpdir}/")));
    // Python bytecode goes to the session's temp dir, always: the usual
    // caches (~/Library/Caches/com.apple.python, a project's __pycache__) are
    // write-denied because a planted .pyc runs later, unsandboxed, and an
    // inherited prefix could point somewhere the sandbox can write (/tmp)
    // that the human's own Python also uses.
    vars.retain(|(k, _)| k != "PYTHONPYCACHEPREFIX");
    vars.push(("PYTHONPYCACHEPREFIX".into(), format!("{tmpdir}/pycache")));
    vars.push(("AGENTACL_SESSION".into(), session_id.into()));
    stripped.sort();
    ChildEnv { vars, stripped }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob_match("*_TOKEN", "FOO_TOKEN"));
        assert!(glob_match("*_TOKEN", "foo_token"));
        assert!(!glob_match("*_TOKEN", "TOKENS"));
        assert!(glob_match("AWS_*", "AWS_PROFILE"));
        assert!(glob_match("CLAUDE_CODE_*", "CLAUDE_CODE_USE_BEDROCK"));
    }

    #[test]
    fn strips_secrets_keeps_passthrough() {
        let inherited = vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("FOO_TOKEN".into(), "x".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "x".into()),
            ("ANTHROPIC_API_KEY".into(), "k".into()),
            ("MY_API_KEY".into(), "k".into()),
            ("HTTPS_PROXY".into(), "http://evil".into()),
            ("SSH_AUTH_SOCK".into(), "/tmp/s".into()),
        ];
        let e = build(inherited, &["ANTHROPIC_API_KEY".into()], &["my_api_key".into()], 4242, "/t", "agt_1");
        let get = |k: &str| e.vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("PATH").as_deref(), Some("/bin"));
        assert_eq!(get("ANTHROPIC_API_KEY").as_deref(), Some("k"));
        assert_eq!(get("MY_API_KEY").as_deref(), Some("k"));
        assert_eq!(get("FOO_TOKEN"), None);
        assert_eq!(get("SSH_AUTH_SOCK"), None);
        assert_eq!(get("HTTPS_PROXY").as_deref(), Some("http://127.0.0.1:4242"));
        assert_eq!(get("TMPDIR").as_deref(), Some("/t/"));
        assert_eq!(get("PYTHONPYCACHEPREFIX").as_deref(), Some("/t/pycache"));
        let own = build(vec![("PYTHONPYCACHEPREFIX".to_string(), "/tmp/shared".to_string())], &[], &[], 1, "/t", "agt_1");
        assert_eq!(own.vars.iter().filter(|(k, _)| k == "PYTHONPYCACHEPREFIX").map(|(_, v)| v.as_str()).collect::<Vec<_>>(), vec!["/t/pycache"], "always the session's own cache");
        assert_eq!(e.stripped, vec!["AWS_SECRET_ACCESS_KEY", "FOO_TOKEN", "SSH_AUTH_SOCK"]);
    }
}
