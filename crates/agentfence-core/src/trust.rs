//! Trust of project policies, bound to the project path + exact bytes
//! (policy-model §3, ui.md §4.6). Stored in `~/.config/agentfence/config.yaml`:
//!
//! ```yaml
//! trusted_project_policies:
//!   - { project: "/Users/u/src/app", sha256: "…" }
//! ```
//!
//! Legacy hash-only entries (bare strings) are ignored: they would trust the
//! same bytes in every repository.

use crate::config::Paths;
use crate::fsafe;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    pub project: String,
    pub sha256: String,
}

#[derive(Deserialize, Default)]
struct TrustFile {
    #[serde(default)]
    trusted_project_policies: Vec<serde_yaml_ng::Value>,
}

pub struct Trust {
    pub entries: Vec<TrustEntry>,
    /// Count of ignored legacy (hash-only) entries.
    pub legacy_ignored: usize,
    /// sha256 of the file bytes (None if absent), for conflict checks.
    pub file_sha: Option<String>,
}

fn config_dir_fd(paths: &Paths) -> Result<std::os::fd::OwnedFd> {
    let dir = crate::supervisor::canon_or(&paths.config_dir);
    fsafe::open_dir(&dir)
}

pub fn load(paths: &Paths) -> Result<Trust> {
    let bytes = match config_dir_fd(paths) {
        Ok(fd) => fsafe::read_regular(&fd, "config.yaml")?,
        Err(_) if !paths.config_dir.exists() => None,
        Err(e) => return Err(e),
    };
    let Some(bytes) = bytes else { return Ok(Trust { entries: vec![], legacy_ignored: 0, file_sha: None }) };
    let file_sha = Some(agentfence_policy::set::sha256_hex(&bytes));
    let tf: TrustFile = serde_yaml_ng::from_slice(&bytes).with_context(|| format!("parsing {}", paths.trust_file.display()))?;
    let mut entries = vec![];
    let mut legacy_ignored = 0;
    for v in tf.trusted_project_policies {
        match serde_yaml_ng::from_value::<TrustEntry>(v) {
            Ok(e) => entries.push(e),
            Err(_) => legacy_ignored += 1,
        }
    }
    Ok(Trust { entries, legacy_ignored, file_sha })
}

/// Hashes trusted for this (canonical) project.
pub fn hashes_for(paths: &Paths, project: &Path) -> Result<Vec<String>> {
    let p = project.to_string_lossy();
    Ok(load(paths)?.entries.into_iter().filter(|e| e.project == p).map(|e| e.sha256).collect())
}

/// Stable fingerprint of this project's trust entries (for stale detection).
pub fn fingerprint(paths: &Paths, project: &Path) -> Option<String> {
    let mut h = hashes_for(paths, project).ok()?;
    if h.is_empty() {
        return None;
    }
    h.sort();
    Some(agentfence_policy::set::sha256_hex(h.join(",").as_bytes()))
}

/// Trusts the project policy's current bytes, which must hash to `sha256`.
pub fn trust(paths: &Paths, project: &Path, sha256: &str) -> Result<()> {
    let proj_fd = fsafe::open_dir(project)?;
    let af = fsafe::ensure_subdir(&proj_fd, ".agentfence")?;
    let Some(bytes) = fsafe::read_regular(&af, "policy.yaml")? else { bail!("{} has no .agentfence/policy.yaml", project.display()) };
    let actual = agentfence_policy::set::sha256_hex(&bytes);
    if !actual.eq_ignore_ascii_case(sha256) {
        bail!("the project policy's current sha256 is {actual}, not {sha256}; review it again and pass the current hash");
    }
    let t = load(paths)?;
    let mut entries = t.entries.clone();
    let p = project.to_string_lossy().into_owned();
    if !entries.iter().any(|e| e.project == p && e.sha256 == actual) {
        entries.push(TrustEntry { project: p, sha256: actual });
    }
    let yaml = format!(
        "# Managed by `agentfence policy trust`. Entries bind a project path to exact policy bytes.\ntrusted_project_policies:\n{}",
        entries.iter().map(|e| format!("  - {{ project: {}, sha256: {} }}\n", serde_json::to_string(&e.project).unwrap(), serde_json::to_string(&e.sha256).unwrap())).collect::<String>()
    );
    crate::config::ensure_private_dir(&paths.config_dir)?;
    let dir = config_dir_fd(paths)?;
    fsafe::replace_checked(&dir, "config.yaml", yaml.as_bytes(), t.file_sha.as_deref())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_bound_trust_and_legacy_ignored() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let paths = Paths::with_dirs(root.clone(), root.join("state"), root.join("config"));
        let a = root.join("a");
        let b = root.join("b");
        for p in [&a, &b] {
            std::fs::create_dir_all(p.join(".agentfence")).unwrap();
            std::fs::write(p.join(".agentfence/policy.yaml"), "version: v1\n").unwrap();
        }
        let sha = agentfence_policy::set::sha256_hex(b"version: v1\n");
        assert!(trust(&paths, &a, "deadbeef").is_err(), "wrong sha refused");
        trust(&paths, &a, &sha).unwrap();
        assert_eq!(hashes_for(&paths, &a).unwrap(), vec![sha.clone()]);
        assert!(hashes_for(&paths, &b).unwrap().is_empty(), "same bytes elsewhere not trusted");
        // legacy entries ignored
        std::fs::write(paths.config_dir.join("config.yaml"), format!("trusted_project_policies:\n  - {sha}\n")).unwrap();
        let t = load(&paths).unwrap();
        assert_eq!((t.entries.len(), t.legacy_ignored), (0, 1));
    }
}
