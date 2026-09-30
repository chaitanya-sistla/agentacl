#![allow(dead_code)]
use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySet, PolicySource};
use agentacl_policy::Layer;

pub fn vars() -> Vars {
    Vars {
        home: "/u".into(),
        project: "/p".into(),
        tmpdir: "/private/var/folders/t/agentacl/s".into(),
        agent_state: None,
        agentacl_state: "/u/Library/Application Support/AgentACL".into(),
        agentacl_config: "/u/.config/agentacl".into(),
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

pub fn try_load(extra: Vec<PolicySource>, opts: LoadOptions) -> Result<PolicySet, agentacl_policy::PolicyError> {
    let has_user = extra.iter().any(|s| s.layer == Layer::User);
    let mut src = builtin_sources(!has_user);
    src.extend(extra);
    PolicySet::load(src, &vars(), &opts)
}
