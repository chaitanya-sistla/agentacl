use super::*;

pub struct Copilot;

const NPM_PKG: &str = "/@github/copilot";

impl AgentProvider for Copilot {
    fn id(&self) -> &'static str {
        "copilot-cli"
    }
    fn display_name(&self) -> &'static str {
        "GitHub Copilot CLI"
    }
    fn commands(&self) -> &'static [&'static str] {
        &["copilot"]
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
        vec![PathBuf::from("/opt/homebrew/bin/copilot"), PathBuf::from("/usr/local/bin/copilot")]
    }

    fn runtime_requirements(&self) -> RuntimeReqs {
        RuntimeReqs {
            write: vec!["${HOME}/.copilot/**".into()],
            hosts: vec!["api.githubcopilot.com".into(), "api.github.com".into(), "github.com".into()],
            env_passthrough: vec!["COPILOT_*".into()],
            protected_configs: vec!["${HOME}/.copilot/config.json".into(), "${HOME}/.copilot/mcp-config.json".into()],
            ..Default::default()
        }
    }
}
