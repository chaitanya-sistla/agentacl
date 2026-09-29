use super::*;

pub struct Gemini;

const NPM_PKG: &str = "/@google/gemini-cli";

impl AgentProvider for Gemini {
    fn id(&self) -> &'static str {
        "gemini-cli"
    }
    fn display_name(&self) -> &'static str {
        "Gemini CLI"
    }
    fn commands(&self) -> &'static [&'static str] {
        &["gemini"]
    }

    fn match_process(&self, p: &ProcessFacts, _sig: Option<&CodeSignature>) -> Option<Match> {
        let script = entry_script(p)?;
        script.contains(&format!("{NPM_PKG}/")).then(|| Match {
            confidence: Confidence::Medium,
            evidence: vec![Evidence::EntryScript { path: script.into() }],
            version: npm_version(script, NPM_PKG),
        })
    }

    fn install_candidates(&self, _home: &Path) -> Vec<PathBuf> {
        vec![PathBuf::from("/opt/homebrew/bin/gemini"), PathBuf::from("/usr/local/bin/gemini")]
    }

    fn runtime_requirements(&self) -> RuntimeReqs {
        RuntimeReqs {
            write: vec!["${HOME}/.gemini/**".into()],
            hosts: vec!["generativelanguage.googleapis.com".into(), "oauth2.googleapis.com".into(), "cloudcode-pa.googleapis.com".into()],
            env_passthrough: vec!["GEMINI_API_KEY".into(), "GOOGLE_API_KEY".into()],
            protected_configs: vec!["${HOME}/.gemini/settings.json".into()],
            ..Default::default()
        }
    }
}
