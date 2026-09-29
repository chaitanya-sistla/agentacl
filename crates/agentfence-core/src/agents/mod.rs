//! Agent providers: how to recognize each AI coding agent and what it needs to
//! run. Adding an agent = one file implementing [`AgentProvider`] + one line in
//! [`registry`] + fixtures (architecture §3.2).
//!
//! Matching never relies on process names alone: evidence is the code
//! signature, the resolved executable path, or a Node/Bun entry script inside
//! the agent's package.

mod claude;
mod codex;
mod copilot;
mod gemini;
mod opencode;

use crate::proc::{code_signature, snapshot, CodeSignature, ProcessFacts};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Signature { team_id: String, signing_id: String },
    Executable { path: String },
    EntryScript { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub version: Option<String>,
}

/// What an agent needs to function, as policy (converted into a generated
/// `provider:<id>` policy document so evaluation and the profile agree).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeReqs {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub hosts: Vec<String>,
    pub mach_services: Vec<String>,
    /// Environment variables passed through despite the secret-env denylist.
    pub env_passthrough: Vec<String>,
    /// Hook/MCP/plugin configs: write-denied (threat T19).
    pub protected_configs: Vec<String>,
    /// Arguments inserted after argv[0], e.g. to switch off the agent's own
    /// inner sandbox, which cannot nest inside ours.
    pub launch_args: Vec<String>,
}

pub trait AgentProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn match_process(&self, p: &ProcessFacts, sig: Option<&CodeSignature>) -> Option<Match>;
    /// Known install locations (in addition to PATH lookup of `commands`).
    fn install_candidates(&self, home: &Path) -> Vec<PathBuf>;
    /// Command names to look up on PATH.
    fn commands(&self) -> &'static [&'static str];
    fn runtime_requirements(&self) -> RuntimeReqs;
}

pub fn registry() -> Vec<Box<dyn AgentProvider>> {
    vec![
        Box::new(claude::Claude),
        Box::new(codex::Codex),
        Box::new(gemini::Gemini),
        Box::new(copilot::Copilot),
        Box::new(opencode::OpenCode),
    ]
}

pub fn provider(id: &str) -> Option<Box<dyn AgentProvider>> {
    registry().into_iter().find(|p| p.id() == id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identified {
    pub id: String,
    pub display_name: String,
    #[serde(flatten)]
    pub m: Match,
}

/// Highest-confidence match across providers.
pub fn identify(p: &ProcessFacts, sig: Option<&CodeSignature>) -> Option<Identified> {
    registry()
        .into_iter()
        .filter_map(|prov| {
            prov.match_process(p, sig).map(|m| Identified { id: prov.id().into(), display_name: prov.display_name().into(), m })
        })
        .max_by_key(|i| i.m.confidence)
}

// ---- helpers shared by providers ----

pub(crate) fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// For Node/Bun-launched agents: the entry script (argv[1]) if the executable is an interpreter.
pub(crate) fn entry_script(p: &ProcessFacts) -> Option<&str> {
    let exe = p.exe.as_deref()?;
    matches!(basename(exe), "node" | "bun" | "nodejs").then(|| p.argv.get(1).map(String::as_str)).flatten()
}

pub(crate) fn sig_matches(sig: Option<&CodeSignature>, team: &str, signing_ids: &[&str]) -> Option<Evidence> {
    let s = sig?;
    let (t, id) = (s.team_id.as_deref()?, s.signing_id.as_deref()?);
    (t == team && signing_ids.contains(&id)).then(|| Evidence::Signature { team_id: t.into(), signing_id: id.into() })
}

/// Reads `version` from the nearest `package.json` at or above `start` inside a package named `pkg`.
pub(crate) fn npm_version(start: &str, pkg: &str) -> Option<String> {
    let idx = start.find(pkg)?;
    let root = &start[..idx + pkg.len()];
    let text = std::fs::read_to_string(Path::new(root).join("package.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

// ---- discovery ----

#[derive(Debug, Clone, Serialize)]
pub struct Discovered {
    pub id: String,
    pub display_name: String,
    pub path: String,
    pub resolved: String,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub signature: Option<CodeSignature>,
    pub sha256: Option<String>,
    pub running_pids: Vec<i32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunningAgent {
    pub id: String,
    pub display_name: String,
    pub pid: i32,
    pub ppid: i32,
    pub exe: Option<String>,
    pub version: Option<String>,
    pub confidence: Confidence,
}

pub fn path_lookup(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(cmd)).find(|p| p.is_file())
}

fn synthetic_facts(resolved: &Path) -> ProcessFacts {
    let s = resolved.to_string_lossy().into_owned();
    // A JS entry point (npm bin symlink) runs under node: model it as such.
    if s.ends_with(".js") || s.ends_with(".mjs") || s.ends_with(".cjs") {
        return ProcessFacts { pid: 0, ppid: 0, pgid: 0, uid: 0, start_time_us: 0, exe: Some("/usr/local/bin/node".into()), argv: vec!["node".into(), s], name: String::new() };
    }
    ProcessFacts { pid: 0, ppid: 0, pgid: 0, uid: 0, start_time_us: 0, exe: Some(s.clone()), argv: vec![s], name: String::new() }
}

/// Identifies an executable on disk (used by `discover` and `run`).
pub fn identify_binary(path: &Path) -> Option<(Identified, Option<CodeSignature>)> {
    let resolved = std::fs::canonicalize(path).ok()?;
    let sig = code_signature(&resolved);
    let facts = synthetic_facts(&resolved);
    identify(&facts, sig.as_ref()).map(|i| (i, sig))
}

pub fn running_agents(snap: &[ProcessFacts]) -> Vec<RunningAgent> {
    let me = std::process::id() as i32;
    snap.iter()
        .filter(|p| p.pid != me)
        .filter_map(|p| {
            // Cheap pre-filter before running codesign: only processes some provider matches without a signature,
            // or whose exe a provider could match by signature (claude/codex native binaries).
            let quick = identify(p, None);
            let sig = match (&quick, p.exe.as_deref()) {
                (Some(_), Some(exe)) => code_signature(Path::new(exe)),
                _ => None,
            };
            let i = identify(p, sig.as_ref()).or(quick)?;
            Some(RunningAgent { id: i.id, display_name: i.display_name, pid: p.pid, ppid: p.ppid, exe: p.exe.clone(), version: i.m.version, confidence: i.m.confidence })
        })
        .collect()
}

pub fn discover(home: &Path) -> (Vec<Discovered>, Vec<RunningAgent>) {
    let running = running_agents(&snapshot());
    let mut found: Vec<Discovered> = Vec::new();
    for prov in registry() {
        let mut cands: Vec<PathBuf> = prov.commands().iter().filter_map(|c| path_lookup(c)).collect();
        cands.extend(prov.install_candidates(home).into_iter().filter(|p| p.is_file()));
        for c in cands {
            let Ok(resolved) = std::fs::canonicalize(&c) else { continue };
            let rs = resolved.to_string_lossy().into_owned();
            if found.iter().any(|d| d.resolved == rs) {
                continue;
            }
            let sig = code_signature(&resolved);
            let facts = synthetic_facts(&resolved);
            let Some(m) = prov.match_process(&facts, sig.as_ref()) else { continue };
            let running_pids = running
                .iter()
                .filter(|r| r.id == prov.id() && (r.exe.as_deref() == Some(rs.as_str()) || r.version == m.version))
                .map(|r| r.pid)
                .collect();
            found.push(Discovered {
                id: prov.id().into(),
                display_name: prov.display_name().into(),
                path: c.to_string_lossy().into_owned(),
                resolved: rs,
                version: m.version.clone(),
                confidence: m.confidence,
                signature: sig,
                sha256: crate::proc::sha256_file(&resolved).ok(),
                running_pids,
            });
        }
    }
    (found, running)
}

#[cfg(test)]
mod tests;
