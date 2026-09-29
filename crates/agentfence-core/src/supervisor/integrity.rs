//! Startup and end-of-session integrity checks:
//! - pre-existing hard links to protected files (threat T2)
//! - files a tool may later execute on the human's behalf (threat T19)
//! - scripts referenced by agent hook configs (write-denied)

use agentfence_policy::pathpat::PatKind;
use agentfence_policy::set::{Matcher, PolicySet, Section};
use agentfence_policy::Effect;
use anyhow::{bail, Result};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".venv", "venv", "__pycache__", ".next", "dist", "build"];
const MAX_WALK: usize = 200_000;

fn walk(root: &Path, out: &mut Vec<PathBuf>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if out.len() >= MAX_WALK {
                return;
            }
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                if !SKIP_DIRS.iter().any(|s| e.file_name() == *s) {
                    stack.push(p);
                }
            } else if ft.is_file() {
                out.push(p);
            }
        }
    }
}

/// Finds protected regular files with more than one link, and every name of
/// them inside the project. Returns extra deny literals (the other names) for
/// accepted links; errs if any link is not accepted.
pub fn hardlink_check(policy: &PolicySet, agent_id: &str, project: &Path, accepted: &[PathBuf]) -> Result<Vec<String>> {
    let proj = project.to_string_lossy().into_owned();
    let denies: Vec<_> = policy
        .rules_for(agent_id, &proj)
        .into_iter()
        .filter(|r| r.effect == Effect::Deny && r.section == Section::FsRead)
        .collect();
    let is_protected = |p: &str| denies.iter().any(|r| r.matches_path(p));

    // Candidates: concrete protected literals + every protected file in the project.
    let mut candidates: Vec<PathBuf> = denies
        .iter()
        .filter_map(|r| match &r.matcher {
            Matcher::Path(p) => match p.kind() {
                PatKind::Literal(l) => Some(PathBuf::from(l)),
                _ => None,
            },
            _ => None,
        })
        .collect();
    let mut files = Vec::new();
    walk(project, &mut files);
    let mut by_inode: HashMap<(u64, u64), Vec<PathBuf>> = HashMap::new();
    for f in &files {
        if let Ok(m) = std::fs::symlink_metadata(f) {
            by_inode.entry((m.dev(), m.ino())).or_default().push(f.clone());
        }
        if is_protected(&f.to_string_lossy()) {
            candidates.push(f.clone());
        }
    }
    let accepted: Vec<PathBuf> = accepted.iter().map(|a| std::fs::canonicalize(a).unwrap_or_else(|_| a.clone())).collect();
    let mut extra = Vec::new();
    let mut problems = Vec::new();
    for c in candidates {
        let Ok(m) = std::fs::symlink_metadata(&c) else { continue };
        if !m.file_type().is_file() || m.nlink() <= 1 {
            continue;
        }
        let names: Vec<PathBuf> = by_inode.get(&(m.dev(), m.ino())).cloned().unwrap_or_default();
        let others: Vec<&PathBuf> = names.iter().filter(|n| **n != c).collect();
        let unaccepted: Vec<&&PathBuf> = others.iter().filter(|o| !accepted.contains(o)).collect();
        if !unaccepted.is_empty() || (others.is_empty() && !accepted.contains(&c)) {
            let listed = if others.is_empty() {
                "(other names are outside the project)".to_string()
            } else {
                others.iter().map(|o| o.display().to_string()).collect::<Vec<_>>().join(", ")
            };
            problems.push(format!("{} has {} hard links: {listed}", c.display(), m.nlink()));
        }
        for o in others {
            extra.push(o.to_string_lossy().into_owned());
        }
    }
    if !problems.is_empty() {
        bail!(
            "protected files have extra hard links, which the sandbox cannot see through:\n  {}\nRemove the links, or pass --accept-hardlink <path> for each to launch anyway (the listed names will be denied too).",
            problems.join("\n  ")
        );
    }
    extra.sort();
    extra.dedup();
    Ok(extra)
}

/// Files that must stay writable but that tools execute later (T19).
pub fn watch_list(project: &Path, home: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "package.json", "Makefile", "makefile", "GNUmakefile", "justfile", "Justfile", "Taskfile.yml", "Cargo.toml", "build.rs",
        "pyproject.toml", "setup.py", "setup.cfg", "tox.ini", "noxfile.py", "Rakefile", "Gemfile", "build.gradle", "build.gradle.kts",
        "pom.xml", "CMakeLists.txt", "Dockerfile", "docker-compose.yml", "compose.yaml", ".pre-commit-config.yaml", ".tool-versions",
        ".nvmrc", "go.mod",
    ]
    .iter()
    .map(|f| project.join(f))
    .collect();
    v.push(home.join(".claude.json"));
    v
}

pub fn snapshot_hashes(paths: &[PathBuf]) -> BTreeMap<PathBuf, Option<String>> {
    paths.iter().map(|p| (p.clone(), crate::proc::sha256_file(p).ok())).collect()
}

pub fn changed(before: &BTreeMap<PathBuf, Option<String>>, after: &BTreeMap<PathBuf, Option<String>>) -> Vec<PathBuf> {
    after.iter().filter(|(p, h)| before.get(*p) != Some(h)).map(|(p, _)| p.clone()).collect()
}

/// Absolute paths mentioned in hook commands of Claude Code settings files
/// (`hooks.<Event>[].hooks[].command`). They run outside any agent sandbox
/// when the human later uses the agent unsupervised, so they are write-denied.
pub fn claude_hook_scripts(settings_files: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for f in settings_files {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let Some(hooks) = v.get("hooks").and_then(|h| h.as_object()) else { continue };
        for groups in hooks.values().filter_map(|g| g.as_array()) {
            for g in groups {
                for h in g.get("hooks").and_then(|h| h.as_array()).into_iter().flatten() {
                    if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                        for tok in cmd.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ';' || c == '&' || c == '|') {
                            let tok = tok.trim();
                            if tok.starts_with('/') && tok.len() > 1 && !tok.contains('$') {
                                out.push(tok.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_script_parsing() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("settings.json");
        std::fs::write(&f, r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 /Users/u/.claude/hooks/check.py --x"}]}],"Stop":[{"hooks":[{"type":"command","command":"$HOME/x.sh && /opt/tools/notify"}]}]}}"#).unwrap();
        assert_eq!(claude_hook_scripts(&[f]), vec!["/Users/u/.claude/hooks/check.py", "/opt/tools/notify"]);
    }

    #[test]
    fn change_detection() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("package.json");
        let b = d.path().join("Makefile");
        std::fs::write(&a, "{}").unwrap();
        let before = snapshot_hashes(&[a.clone(), b.clone()]);
        std::fs::write(&a, "{\"scripts\":{}}").unwrap();
        std::fs::write(&b, "all:").unwrap();
        let after = snapshot_hashes(&[a.clone(), b.clone()]);
        assert_eq!(changed(&before, &after), vec![b, a]); // BTreeMap order
    }
}
