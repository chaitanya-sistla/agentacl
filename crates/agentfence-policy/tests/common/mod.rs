#![allow(dead_code)]
use agentfence_policy::expand::Vars;
use agentfence_policy::set::{builtin_sources, LoadOptions, PolicySet, PolicySource};
use agentfence_policy::Layer;

pub fn vars() -> Vars {
    Vars {
        home: "/u".into(),
        project: "/p".into(),
        tmpdir: "/private/var/folders/t/agentfence/s".into(),
        agent_state: None,
        agentfence_state: "/u/Library/Application Support/AgentFence".into(),
        agentfence_config: "/u/.config/agentfence".into(),
    }
}

pub fn user(yaml: &str) -> PolicySource {
    PolicySource { layer: Layer::User, name: "user".into(), yaml: yaml.into() }
}

pub fn project(yaml: &str) -> PolicySource {
    PolicySource { layer: Layer::Project, name: "project".into(), yaml: yaml.into() }
}

/// Builtins (+ default when no user doc) + extra sources.
pub fn load(extra: Vec<PolicySource>) -> PolicySet {
    try_load(extra, LoadOptions::default()).unwrap()
}

pub fn try_load(extra: Vec<PolicySource>, opts: LoadOptions) -> Result<PolicySet, agentfence_policy::PolicyError> {
    let has_user = extra.iter().any(|s| s.layer == Layer::User);
    let mut src = builtin_sources(!has_user);
    src.extend(extra);
    PolicySet::load(src, &vars(), &opts)
}
