use super::*;

pub struct OpenCode;

const NPM_PKG: &str = "/opencode-ai";
const NATIVE_DIRS: &[&str] = &["/.opencode/bin/", "/opt/homebrew/", "/usr/local/", NPM_PKG];

impl AgentProvider for OpenCode {
    fn id(&self) -> &'static str {
        "opencode"
    }
    fn display_name(&self) -> &'static str {
        "OpenCode"
    }
    fn commands(&self) -> &'static [&'static str] {
        &["opencode"]
    }

    fn match_process(&self, p: &ProcessFacts, _sig: Option<&CodeSignature>) -> Option<Match> {
        let exe = p.exe.as_deref()?;
        if basename(exe) == "opencode" && NATIVE_DIRS.iter().any(|d| exe.contains(d)) {
            return Some(Match { confidence: Confidence::Medium, evidence: vec![Evidence::Executable { path: exe.into() }], version: npm_version(exe, NPM_PKG) });
        }
        let script = entry_script(p)?;
        script.contains(&format!("{NPM_PKG}/")).then(|| Match { confidence: Confidence::Medium, evidence: vec![Evidence::EntryScript { path: script.into() }], version: npm_version(script, NPM_PKG) })
    }

    fn install_candidates(&self, home: &Path) -> Vec<PathBuf> {
        vec![home.join(".opencode/bin/opencode"), PathBuf::from("/opt/homebrew/bin/opencode"), PathBuf::from("/usr/local/bin/opencode")]
    }

    fn runtime_requirements(&self) -> RuntimeReqs {
        RuntimeReqs {
            write: vec!["${HOME}/.config/opencode/**".into(), "${HOME}/.local/share/opencode/**".into(), "${HOME}/.local/state/opencode/**".into(), "${HOME}/.cache/opencode/**".into()],
            hosts: vec!["api.anthropic.com".into(), "api.openai.com".into(), "opencode.ai".into(), "models.dev".into()],
            protected_configs: vec!["${HOME}/.config/opencode/opencode.json".into(), "${HOME}/.config/opencode/plugin/**".into()],
            ..Default::default()
        }
    }
}
