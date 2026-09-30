use super::*;

pub struct Codex;

const TEAM_ID: &str = "2DC432GLL2";
const SIGNING_IDS: &[&str] = &["codex"];
const NPM_PKG: &str = "/@openai/codex";
const NATIVE_DIRS: &[&str] = &[NPM_PKG, "/Applications/ChatGPT.app/Contents/Resources/", "/opt/homebrew/", "/usr/local/", "/.codex/"];
/// Helper processes of the ChatGPT/Codex app are not the agent.
const NOT_AGENT: &[&str] = &["Codex Framework.framework", "/Helpers/", "Sparkle", "crashpad"];

impl AgentProvider for Codex {
    fn id(&self) -> &'static str {
        "codex"
    }
    fn display_name(&self) -> &'static str {
        "Codex"
    }
    fn commands(&self) -> &'static [&'static str] {
        &["codex"]
    }

    fn match_process(&self, p: &ProcessFacts, sig: Option<&CodeSignature>) -> Option<Match> {
        let exe = p.exe.as_deref()?;
        if NOT_AGENT.iter().any(|n| exe.contains(n)) {
            return None;
        }
        if basename(exe) == "codex" {
            if let Some(ev) = sig_matches(sig, TEAM_ID, SIGNING_IDS) {
                return Some(Match { confidence: Confidence::High, evidence: vec![ev, Evidence::Executable { path: exe.into() }], version: npm_version(exe, NPM_PKG) });
            }
            if NATIVE_DIRS.iter().any(|d| exe.contains(d)) {
                return Some(Match { confidence: Confidence::Medium, evidence: vec![Evidence::Executable { path: exe.into() }], version: npm_version(exe, NPM_PKG) });
            }
        }
        let script = entry_script(p)?;
        script.contains(&format!("{NPM_PKG}/")).then(|| Match { confidence: Confidence::Medium, evidence: vec![Evidence::EntryScript { path: script.into() }], version: npm_version(script, NPM_PKG) })
    }

    fn install_candidates(&self, _home: &Path) -> Vec<PathBuf> {
        vec![PathBuf::from("/opt/homebrew/bin/codex"), PathBuf::from("/usr/local/bin/codex"), PathBuf::from("/Applications/ChatGPT.app/Contents/Resources/codex")]
    }

    fn runtime_requirements(&self) -> RuntimeReqs {
        RuntimeReqs {
            write: vec!["${HOME}/.codex/**".into()],
            hosts: vec!["api.openai.com".into(), "chatgpt.com".into(), "auth.openai.com".into()],
            env_passthrough: vec!["OPENAI_API_KEY".into(), "CODEX_*".into()],
            protected_configs: vec!["${HOME}/.codex/config.toml".into()],
            // Codex sandboxes its own commands with Seatbelt, which cannot nest
            // inside AgentACL's profile; AgentACL is the outer boundary.
            launch_args: vec!["--sandbox".into(), "danger-full-access".into()],
            ..Default::default()
        }
    }
}
