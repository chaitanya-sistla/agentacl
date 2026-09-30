//! Serde model of a `version: v1` policy document. Every struct uses
//! `deny_unknown_fields`, so every layer has a closed schema; project documents
//! are further restricted in [`parse_doc`].

use crate::error::PolicyError;
use crate::model::{Effect, Layer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Path,
    Command,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRule {
    pub kind: RuleKind,
    pub pattern: String,
    pub except: Vec<String>,
    pub id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RuleRepr {
    Plain(String),
    Full(RuleObject),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleObject {
    path: Option<String>,
    command: Option<String>,
    host: Option<String>,
    #[serde(default)]
    except: Vec<String>,
    id: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawMatch {
    #[serde(default)]
    pub agents: Vec<String>,
    #[serde(default)]
    pub projects: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    pub filesystem: Option<Effect>,
    pub network: Option<Effect>,
    pub process: Option<Effect>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsRepr {
    #[serde(default)]
    allow_read: Vec<RuleRepr>,
    #[serde(default)]
    allow_write: Vec<RuleRepr>,
    #[serde(default)]
    deny_read: Vec<RuleRepr>,
    #[serde(default)]
    deny_write: Vec<RuleRepr>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcRepr {
    #[serde(default)]
    allow: Vec<RuleRepr>,
    #[serde(default)]
    deny: Vec<RuleRepr>,
    #[serde(default)]
    require_approval: Vec<RuleRepr>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetRepr {
    #[serde(default)]
    allow: Vec<RuleRepr>,
    #[serde(default)]
    deny: Vec<RuleRepr>,
    #[serde(default)]
    listen: Vec<RuleRepr>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawBuiltin {
    #[serde(default)]
    pub disable: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocRepr {
    version: String,
    name: Option<String>,
    #[serde(rename = "match")]
    match_: Option<RawMatch>,
    #[serde(default)]
    defaults: RawDefaults,
    filesystem: Option<FsRepr>,
    process: Option<ProcRepr>,
    network: Option<NetRepr>,
    builtin: Option<RawBuiltin>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RawFs {
    pub allow_read: Vec<RawRule>,
    pub allow_write: Vec<RawRule>,
    pub deny_read: Vec<RawRule>,
    pub deny_write: Vec<RawRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RawProc {
    pub allow: Vec<RawRule>,
    pub deny: Vec<RawRule>,
    pub require_approval: Vec<RawRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RawNet {
    pub allow: Vec<RawRule>,
    pub deny: Vec<RawRule>,
    pub listen: Vec<RawRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawDoc {
    pub name: String,
    pub layer: Layer,
    pub match_: Option<RawMatch>,
    pub defaults: RawDefaults,
    pub filesystem: RawFs,
    pub process: RawProc,
    pub network: RawNet,
    pub builtin: Option<RawBuiltin>,
}

fn convert(source: &str, section: &str, want: RuleKind, items: Vec<RuleRepr>) -> Result<Vec<RawRule>, PolicyError> {
    let bad = |index: usize, msg: String| PolicyError::BadRule { doc: source.to_string(), section: section.to_string(), index, msg };
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.into_iter().enumerate() {
        let rule = match item {
            RuleRepr::Plain(p) => RawRule { kind: want.clone(), pattern: p, except: vec![], id: None, reason: None },
            RuleRepr::Full(o) => {
                let given: Vec<(RuleKind, String)> =
                    [o.path.map(|v| (RuleKind::Path, v)), o.command.map(|v| (RuleKind::Command, v)), o.host.map(|v| (RuleKind::Host, v))].into_iter().flatten().collect();
                if given.len() != 1 {
                    return Err(bad(i, "exactly one of `path`, `command`, `host` is required".into()));
                }
                let (kind, pattern) = given.into_iter().next().unwrap();
                if kind != want {
                    return Err(bad(i, format!("expected a {want:?} rule in this section").to_lowercase()));
                }
                if !o.except.is_empty() && kind != RuleKind::Path {
                    return Err(bad(i, "`except` is only supported on path rules".into()));
                }
                RawRule { kind, pattern, except: o.except, id: o.id, reason: o.reason }
            }
        };
        if rule.pattern.trim().is_empty() {
            return Err(bad(i, "empty pattern".into()));
        }
        out.push(rule);
    }
    Ok(out)
}

pub fn parse_doc(yaml: &str, layer: Layer, source_name: &str) -> Result<RawDoc, PolicyError> {
    let repr: DocRepr = serde_yaml_ng::from_str(yaml).map_err(|e| PolicyError::Yaml { doc: source_name.to_string(), msg: e.to_string() })?;
    if repr.version != "v1" {
        return Err(PolicyError::Version { doc: source_name.into(), found: repr.version });
    }
    let fs = repr.filesystem.unwrap_or_default();
    let pr = repr.process.unwrap_or_default();
    let nt = repr.network.unwrap_or_default();

    if layer == Layer::Project {
        // Closed, restrict-only schema for repository-supplied policy (policy-model §3).
        let forbidden = [
            (!fs.allow_read.is_empty(), "filesystem.allow_read"),
            (!fs.allow_write.is_empty(), "filesystem.allow_write"),
            (!pr.allow.is_empty(), "process.allow"),
            (!nt.allow.is_empty(), "network.allow"),
            (!nt.listen.is_empty(), "network.listen"),
            (repr.builtin.is_some(), "builtin"),
        ];
        if let Some((_, key)) = forbidden.iter().find(|(present, _)| *present) {
            return Err(PolicyError::ProjectForbidden { doc: source_name.into(), key: (*key).into() });
        }
    }

    let s = source_name;
    Ok(RawDoc {
        name: repr.name.unwrap_or_else(|| s.to_string()),
        layer,
        match_: repr.match_,
        defaults: repr.defaults,
        filesystem: RawFs {
            allow_read: convert(s, "filesystem.allow_read", RuleKind::Path, fs.allow_read)?,
            allow_write: convert(s, "filesystem.allow_write", RuleKind::Path, fs.allow_write)?,
            deny_read: convert(s, "filesystem.deny_read", RuleKind::Path, fs.deny_read)?,
            deny_write: convert(s, "filesystem.deny_write", RuleKind::Path, fs.deny_write)?,
        },
        process: RawProc {
            allow: convert(s, "process.allow", RuleKind::Command, pr.allow)?,
            deny: convert(s, "process.deny", RuleKind::Command, pr.deny)?,
            require_approval: convert(s, "process.require_approval", RuleKind::Command, pr.require_approval)?,
        },
        network: RawNet {
            allow: convert(s, "network.allow", RuleKind::Host, nt.allow)?,
            deny: convert(s, "network.deny", RuleKind::Host, nt.deny)?,
            listen: convert(s, "network.listen", RuleKind::Host, nt.listen)?,
        },
        builtin: repr.builtin,
    })
}
