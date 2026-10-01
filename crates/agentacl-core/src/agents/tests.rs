use super::*;

fn facts(exe: &str, argv: &[&str]) -> ProcessFacts {
    ProcessFacts { pid: 10, ppid: 1, pgid: 10, uid: 501, start_time_us: 1, exe: Some(exe.into()), argv: argv.iter().map(|s| s.to_string()).collect(), name: String::new() }
}
fn sig(team: &str, id: &str) -> CodeSignature {
    CodeSignature { team_id: Some(team.into()), signing_id: Some(id.into()), authority: vec![] }
}

#[test]
fn claude_native_signed_is_high() {
    let p = facts("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", &["claude"]);
    let i = identify(&p, Some(&sig("Q6L2SF6YDW", "com.anthropic.claude-code"))).unwrap();
    assert_eq!((i.id.as_str(), i.m.confidence), ("claude-code", Confidence::High));
}

#[test]
fn claude_desktop_app_is_not_claude_code() {
    let p = facts("/Applications/Claude.app/Contents/MacOS/Claude", &["Claude"]);
    assert!(identify(&p, Some(&sig("Q6L2SF6YDW", "com.anthropic.claudefordesktop"))).is_none());
}

#[test]
fn claude_unsigned_paths_are_medium_with_version() {
    let p = facts("/Users/u/.vscode/extensions/anthropic.claude-code-2.1.261-darwin-arm64/resources/native-binary/claude", &["claude"]);
    let i = identify(&p, None).unwrap();
    assert_eq!((i.id.as_str(), i.m.confidence, i.m.version.as_deref()), ("claude-code", Confidence::Medium, Some("2.1.261")));
    let v = facts("/Users/u/.local/share/claude/versions/2.1.2", &["claude"]);
    assert_eq!(identify(&v, None).unwrap().m.version.as_deref(), Some("2.1.2"));
    let node = facts("/opt/homebrew/bin/node", &["node", "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"]);
    assert_eq!(identify(&node, None).unwrap().id, "claude-code");
}

#[test]
fn names_alone_never_match() {
    assert!(identify(&facts("/usr/bin/vim", &["vim", "claude.txt"]), None).is_none());
    assert!(identify(&facts("/tmp/claude", &["claude"]), None).is_none());
    assert!(identify(&facts("/tmp/x/codex", &["codex"]), None).is_none());
    assert!(identify(&facts("/opt/homebrew/bin/node", &["node", "server.js"]), None).is_none());
    // a signature for a different team does not make a lookalike binary an agent
    assert!(identify(&facts("/tmp/claude", &["claude"]), Some(&sig("AAAAAAAAAA", "com.anthropic.claude-code"))).is_none());
}

#[test]
fn codex_app_binary_and_helpers() {
    let c = facts("/Applications/ChatGPT.app/Contents/Resources/codex", &["codex"]);
    let i = identify(&c, Some(&sig("2DC432GLL2", "codex"))).unwrap();
    assert_eq!((i.id.as_str(), i.m.confidence), ("codex", Confidence::High));
    let helper = facts("/Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/1/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service)", &["x"]);
    assert!(identify(&helper, Some(&sig("2DC432GLL2", "codex"))).is_none());
    let sparkle = facts("/Users/u/Library/Caches/com.openai.codex/org.sparkle-project.Sparkle/Launcher/X/Updater.app/Contents/MacOS/Updater", &["Updater"]);
    assert!(identify(&sparkle, None).is_none());
    let npm = facts("/opt/homebrew/bin/node", &["node", "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js"]);
    assert_eq!(identify(&npm, None).unwrap().id, "codex");
}

#[test]
fn node_based_agents() {
    let g = facts("/opt/homebrew/bin/node", &["node", "/opt/homebrew/lib/node_modules/@google/gemini-cli/dist/index.js"]);
    assert_eq!(identify(&g, None).unwrap().id, "gemini-cli");
    let c = facts("/usr/local/bin/node", &["node", "/usr/local/lib/node_modules/@github/copilot/index.js"]);
    assert_eq!(identify(&c, None).unwrap().id, "copilot-cli");
    let o = facts("/Users/u/.opencode/bin/opencode", &["opencode"]);
    assert_eq!(identify(&o, None).unwrap().id, "opencode");
}

#[test]
fn registry_ids_are_unique() {
    let mut ids: Vec<&str> = registry().iter().map(|p| p.id()).collect();
    ids.sort();
    let n = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), n);
    assert_eq!(n, 5);
}

#[test]
#[ignore = "live: requires Claude Code installed on PATH"]
fn live_discover_finds_claude() {
    let home = crate::config::user_home().unwrap();
    let (found, _) = discover(&home);
    let c = found.iter().find(|d| d.id == "claude-code").expect("claude found");
    assert_eq!(c.confidence, Confidence::High);
}

#[test]
fn keychain_only_without_a_login_in_the_environment() {
    let claude = || super::provider("claude-code").unwrap().runtime_requirements();
    let mut with_login = claude();
    assert!(with_login.resolve_keychain(|_| false), "no token: the keychain holds the login");
    assert!(with_login.mach_services.iter().any(|m| m == "com.apple.SecurityServer"));
    assert!(with_login.read.iter().any(|r| r.contains("Library/Keychains")));
    for var in ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX"] {
        let mut r = claude();
        assert!(!r.resolve_keychain(|v| v == var), "{var}: no keychain");
        assert!(!r.mach_services.iter().any(|m| m.contains("Security") || m.contains("securityd")), "{var}");
        assert!(!r.read.iter().any(|p| p.contains("Keychains")) && r.unix_sockets.is_empty(), "{var}");
    }
    // Other agents never get it.
    let mut codex = super::provider("codex").unwrap().runtime_requirements();
    assert!(!codex.resolve_keychain(|_| false));
}
