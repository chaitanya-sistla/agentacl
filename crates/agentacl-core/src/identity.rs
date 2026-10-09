//! Principals: the human, the machine, the agent, and the project it acts on
//! (architecture §4).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Human {
    pub user: String,
    pub uid: u32,
    pub home: PathBuf,
}

pub fn human() -> Result<Human> {
    let (user, home) = crate::config::passwd_entry()?;
    // SAFETY: getuid has no memory effects.
    let uid = unsafe { libc::getuid() };
    Ok(Human { user, uid, home: std::fs::canonicalize(&home).unwrap_or(home) })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: String,
    pub display_name: String,
    pub version: Option<String>,
    pub binary: String,
    pub binary_sha256: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub confidence: Option<crate::agents::Confidence>,
}

/// Project root: `--project`, else the git toplevel of `cwd`, else `cwd`.
/// Refuses `/`, `$HOME`, and any ancestor of `$HOME` (granting write there
/// would grant write to all of `$HOME`).
pub fn resolve_project(cwd: &Path, override_: Option<&Path>, home: &Path) -> Result<PathBuf> {
    let candidate = match override_ {
        Some(p) => p.to_path_buf(),
        None => git_toplevel(cwd).unwrap_or_else(|| cwd.to_path_buf()),
    };
    let project = std::fs::canonicalize(&candidate).with_context(|| format!("project {} does not exist", candidate.display()))?;
    if !project.is_dir() {
        bail!("project {} is not a directory", project.display());
    }
    let home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    if project == Path::new("/") || home.starts_with(&project) {
        bail!("refusing to use {} as the project: it is {} your home directory; run from inside a project or pass --project", project.display(), if project == home { "" } else { "an ancestor of" });
    }
    for c in project.to_string_lossy().chars() {
        // `*` and `?` would act as wildcards in `${PROJECT}` rules (an
        // exception for the project would cover its siblings).
        if c == '"' || c == '\\' || c == '*' || c == '?' || c.is_control() {
            bail!("project path contains a character AgentACL cannot safely express in a sandbox profile: {c:?}");
        }
    }
    Ok(project)
}

/// The repository `cwd` is in, found by walking up to a `.git` entry,
/// without running git (the Endpoint Security daemon can't wait on a child
/// process, and git as root refuses a user's repository).
pub fn repo_root(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors().find(|d| std::fs::symlink_metadata(d.join(".git")).is_ok()).map(Path::to_path_buf)
}

fn git_toplevel(cwd: &Path) -> Option<PathBuf> {
    let out = Command::new("/usr/bin/git").arg("-C").arg(cwd).args(["rev-parse", "--show-toplevel"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| PathBuf::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_resolution() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        let repo = home.join("src/repo");
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        assert!(Command::new("/usr/bin/git").arg("-C").arg(&repo).arg("init").arg("-q").status().unwrap().success());
        assert_eq!(resolve_project(&repo.join("sub"), None, &home).unwrap(), repo);
        assert_eq!(repo_root(&repo.join("sub")), Some(repo.clone()));
        // non-git dir → cwd
        let plain = home.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(resolve_project(&plain, None, &home).unwrap(), plain);
        // home and its ancestors refused
        assert!(resolve_project(&home, None, &home).is_err());
        assert!(resolve_project(&root, None, &home).is_err());
        assert!(resolve_project(Path::new("/"), None, &home).is_err());
        // override
        assert_eq!(resolve_project(&plain, Some(&repo), &home).unwrap(), repo);
    }

    #[test]
    fn hostile_project_name_refused() {
        let d = tempfile::tempdir().unwrap();
        let bad = d.path().join("p\")(allow default)(");
        std::fs::create_dir_all(&bad).unwrap();
        let err = resolve_project(&bad, None, Path::new("/nonexistent-home")).unwrap_err();
        assert!(err.to_string().contains("cannot safely express"), "{err}");
    }
}
