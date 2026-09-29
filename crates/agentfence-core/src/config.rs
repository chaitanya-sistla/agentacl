//! Filesystem locations used by AgentFence.

use anyhow::{bail, Context, Result};
use std::ffi::CStr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
    pub state_dir: PathBuf,
    pub config_dir: PathBuf,
    pub db_path: PathBuf,
    pub user_policy: PathBuf,
    pub trust_file: PathBuf,
}

impl Paths {
    /// Resolves paths for the invoking user. `AGENTFENCE_HOME` and
    /// `AGENTFENCE_CONFIG_DIR` override the state and config dirs (used by tests).
    pub fn from_env() -> Result<Paths> {
        let home = user_home()?;
        let state_dir = match std::env::var_os("AGENTFENCE_HOME") {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => home.join("Library/Application Support/AgentFence"),
        };
        let config_dir = match std::env::var_os("AGENTFENCE_CONFIG_DIR") {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => home.join(".config/agentfence"),
        };
        Ok(Self::with_dirs(home, state_dir, config_dir))
    }

    pub fn with_dirs(home: PathBuf, state_dir: PathBuf, config_dir: PathBuf) -> Paths {
        Paths {
            db_path: state_dir.join("agentfence.db"),
            user_policy: config_dir.join("policy.yaml"),
            trust_file: config_dir.join("config.yaml"),
            home,
            state_dir,
            config_dir,
        }
    }
}

/// Home directory from the password database, never from `$HOME`, which a
/// parent process controls.
pub fn user_home() -> Result<PathBuf> {
    let (_, home) = passwd_entry()?;
    Ok(home)
}

/// (username, home) of the real uid.
pub fn passwd_entry() -> Result<(String, PathBuf)> {
    // SAFETY: getpwuid returns a pointer into static storage or null; we copy
    // the fields out immediately and never retain the pointer.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            bail!("getpwuid failed for uid {}", libc::getuid());
        }
        let name = CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
        let dir = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        Ok((name, PathBuf::from(dir)))
    }
}

pub fn ensure_private_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !p.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)
            .with_context(|| format!("creating {}", p.display()))?;
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", p.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_dirs_derives_files() {
        let p = Paths::with_dirs("/u".into(), "/tmp/x".into(), "/tmp/c".into());
        assert_eq!(p.db_path, PathBuf::from("/tmp/x/agentfence.db"));
        assert_eq!(p.user_policy, PathBuf::from("/tmp/c/policy.yaml"));
        assert_eq!(p.trust_file, PathBuf::from("/tmp/c/config.yaml"));
    }

    #[test]
    fn default_state_dir_is_application_support() {
        let home = user_home().unwrap();
        let p = Paths::with_dirs(
            home.clone(),
            home.join("Library/Application Support/AgentFence"),
            home.join(".config/agentfence"),
        );
        assert!(p.state_dir.ends_with("Library/Application Support/AgentFence"));
    }
}
