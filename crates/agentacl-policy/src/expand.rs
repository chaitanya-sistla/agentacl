//! `${VAR}` expansion and lexical path canonicalization.

use crate::error::PolicyError;
use serde::{Deserialize, Serialize};

/// Values for policy variables. Callers pass canonical absolute paths
/// (realpath'd, `/private/...` form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vars {
    pub home: String,
    pub project: String,
    pub tmpdir: String,
    pub agent_state: Option<String>,
    /// AgentACL's own state and config dirs (write-denied in every profile).
    pub agentacl_state: String,
    pub agentacl_config: String,
}

/// An expanded pattern string. `var_root` is the value of a *leading*
/// variable, e.g. `/Users/u` for `${HOME}/.aws/credentials`; it bounds which
/// ancestor directories are protected against rename (policy-model §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    pub text: String,
    pub var_root: Option<String>,
}

pub fn expand(s: &str, vars: &Vars, source: &str) -> Result<Expanded, PolicyError> {
    let mut out = String::with_capacity(s.len());
    let mut var_root = None;
    let mut rest = s;
    let mut first = true;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| PolicyError::BadPattern { doc: source.into(), pattern: s.into(), msg: "unterminated ${".into() })?;
        let name = &after[..end];
        let value = match name {
            "HOME" => Some(vars.home.clone()),
            "PROJECT" => Some(vars.project.clone()),
            "TMPDIR" => Some(vars.tmpdir.clone()),
            "AGENT_STATE" => vars.agent_state.clone(),
            "AGENTACL_STATE" => Some(vars.agentacl_state.clone()),
            "AGENTACL_CONFIG" => Some(vars.agentacl_config.clone()),
            _ => None,
        }
        .ok_or_else(|| PolicyError::UnknownVariable { doc: source.into(), var: name.into() })?;
        let value = value.trim_end_matches('/').to_string();
        if first && start == 0 {
            var_root = Some(value.clone());
        }
        out.push_str(&value);
        rest = &after[end + 1..];
        first = false;
    }
    out.push_str(rest);
    Ok(Expanded { text: out, var_root })
}

/// Lexical canonicalization: maps the macOS `/tmp`, `/var`, `/etc` symlinks to
/// `/private/...`, collapses `//` and `/./`, and resolves `..` lexically.
/// Glob characters pass through untouched.
pub fn canonical_prefix_map(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if let Some(first) = parts.first().copied() {
        if matches!(first, "tmp" | "var" | "etc") {
            parts.insert(0, "private");
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        Vars {
            home: "/u".into(),
            project: "/p".into(),
            tmpdir: "/private/var/folders/t".into(),
            agent_state: None,
            agentacl_state: "/u/Library/Application Support/AgentACL".into(),
            agentacl_config: "/u/.config/agentacl".into(),
        }
    }

    #[test]
    fn expands_known_vars() {
        let e = expand("${HOME}/.ssh/**", &vars(), "t").unwrap();
        assert_eq!(e.text, "/u/.ssh/**");
        assert_eq!(e.var_root.as_deref(), Some("/u"));
        let e = expand("/x/${PROJECT}", &vars(), "t").unwrap();
        assert_eq!(e.var_root, None);
        assert_eq!(expand("$HOME/x", &vars(), "t").unwrap().text, "$HOME/x");
    }

    #[test]
    fn unknown_or_unset_var_is_error() {
        assert!(matches!(expand("${NOPE}/x", &vars(), "t"), Err(PolicyError::UnknownVariable { .. })));
        assert!(matches!(expand("${AGENT_STATE}/x", &vars(), "t"), Err(PolicyError::UnknownVariable { .. })));
    }

    #[test]
    fn canonical_prefixes() {
        assert_eq!(canonical_prefix_map("/tmp/a/../b"), "/private/tmp/b");
        assert_eq!(canonical_prefix_map("/var/folders/x"), "/private/var/folders/x");
        assert_eq!(canonical_prefix_map("/Users/u"), "/Users/u");
        assert_eq!(canonical_prefix_map("/a//b/./c/"), "/a/b/c");
        assert_eq!(canonical_prefix_map("/"), "/");
    }
}
