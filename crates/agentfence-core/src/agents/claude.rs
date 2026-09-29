use super::*;

pub struct Claude;

const TEAM_ID: &str = "Q6L2SF6YDW";
const SIGNING_IDS: &[&str] = &["com.anthropic.claude-code"];
const NPM_PKG: &str = "/@anthropic-ai/claude-code";
/// Path fragments of known native installs.
const NATIVE_DIRS: &[&str] = &[NPM_PKG, "/.local/share/claude/versions/", "/.claude/local/", "/anthropic.claude-code-"];

fn version_from_path(p: &str) -> Option<String> {
    if let Some(rest) = p.split("/.local/share/claude/versions/").nth(1) {
        return rest.split('/').next().map(str::to_string);
    }
    if let Some(rest) = p.split("/anthropic.claude-code-").nth(1) {
        // anthropic.claude-code-2.1.261-darwin-arm64/...
        let dir = rest.split('/').next()?;
        return dir.split('-').next().map(str::to_string);
    }
    npm_version(p, NPM_PKG)
}

impl AgentProvider for Claude {
    fn id(&self) -> &'static str {
        "claude-code"
    }
    fn display_name(&self) -> &'static str {
        "Claude Code"
    }
    fn commands(&self) -> &'static [&'static str] {
        &["claude"]
    }

    fn match_process(&self, p: &ProcessFacts, sig: Option<&CodeSignature>) -> Option<Match> {
        let exe = p.exe.as_deref()?;
        if let Some(ev) = sig_matches(sig, TEAM_ID, SIGNING_IDS) {
            return Some(Match { confidence: Confidence::High, evidence: vec![ev, Evidence::Executable { path: exe.into() }], version: version_from_path(exe) });
        }
        let name = basename(exe);
        let native = NATIVE_DIRS.iter().any(|d| exe.contains(d))
            && (matches!(name, "claude" | "claude.exe") || exe.contains("/.local/share/claude/versions/"));
        if native {
            return Some(Match { confidence: Confidence::Medium, evidence: vec![Evidence::Executable { path: exe.into() }], version: version_from_path(exe) });
        }
        let script = entry_script(p)?;
        script.contains(&format!("{NPM_PKG}/")).then(|| Match {
            confidence: Confidence::Medium,
            evidence: vec![Evidence::EntryScript { path: script.into() }],
            version: npm_version(script, NPM_PKG),
        })
    }

    fn install_candidates(&self, home: &Path) -> Vec<PathBuf> {
        let mut v = vec![home.join(".local/bin/claude"), home.join(".claude/local/claude"), PathBuf::from("/opt/homebrew/bin/claude"), PathBuf::from("/usr/local/bin/claude")];
        if let Ok(rd) = std::fs::read_dir(home.join(".local/share/claude/versions")) {
            v.extend(rd.flatten().map(|e| e.path()));
        }
        v
    }

    fn runtime_requirements(&self) -> RuntimeReqs {
        RuntimeReqs {
            // Claude Code keeps its OAuth login in the macOS keychain. Reading the
            // keychain files is required to log in; item access is still
            // mediated by securityd and each item's ACL (threat T9). Users who
            // prefer no keychain access can use ANTHROPIC_API_KEY instead.
            read: vec![
                "${HOME}/Library/Keychains/**".into(),
                "/Library/Keychains/**".into(),
                "/private/var/db/mds/messages/*/**".into(),
                "/private/var/run/systemkeychaincheck.done".into(),
            ],
            write: vec![
                "${HOME}/.claude/**".into(),
                "${HOME}/.claude.json".into(),
                "${HOME}/.claude.json.*".into(),
                "${HOME}/.local/share/claude/**".into(),
                "${HOME}/.local/state/claude/**".into(),
                "${HOME}/.cache/claude/**".into(),
                "${HOME}/Library/Caches/claude-cli-nodejs/**".into(),
            ],
            hosts: vec!["api.anthropic.com".into(), "statsig.anthropic.com".into(), "claude.ai".into(), "console.anthropic.com".into()],
            mach_services: vec!["com.apple.SecurityServer".into(), "com.apple.securityd.xpc".into()],
            unix_sockets: vec!["/private/var/run/systemkeychaincheck.socket".into()],
            env_passthrough: vec!["ANTHROPIC_API_KEY".into(), "ANTHROPIC_AUTH_TOKEN".into(), "CLAUDE_CODE_*".into()],
            protected_configs: vec![
                "${HOME}/.claude/settings.json".into(),
                "${HOME}/.claude/settings.local.json".into(),
                "${HOME}/.claude/plugins/**".into(),
                "${HOME}/.claude/hooks/**".into(),
                "${HOME}/.claude/agents/**".into(),
                "${HOME}/.claude/commands/**".into(),
                "${HOME}/.claude/skills/**".into(),
            ],
            launch_args: vec![],
            resume_args: vec!["--continue".into()],
        }
    }
}
