//! Company rules from the fleet server (docs/design/fleet.md): a root-owned
//! policy document the fleet service writes, loaded by every policy load on
//! the Mac as the `org` layer (explicit denies only).

use agentacl_policy::set::PolicySource;
use agentacl_policy::Layer;
use anyhow::{bail, Context, Result};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Where the package installs AgentACL, root-owned.
pub const ROOT: &str = "/Library/Application Support/AgentACL";
/// Company rules files are small; a larger one is refused.
const MAX_BYTES: u64 = 1024 * 1024;

/// The machine-wide AgentACL folders.
#[derive(Debug, Clone)]
pub struct Managed {
    pub root: PathBuf,
    /// The owner every path must have (root; the test user in tests).
    pub owner: u32,
}

impl Default for Managed {
    fn default() -> Self {
        Managed { root: PathBuf::from(ROOT), owner: 0 }
    }
}

impl Managed {
    pub fn policy(&self) -> PathBuf {
        self.root.join("managed/policy.yaml")
    }
    /// Present once the Mac is enrolled with a fleet server.
    pub fn fleet_config(&self) -> PathBuf {
        self.root.join("fleet.json")
    }

    /// Owned by `owner`, not writable by group or others, not a link.
    fn check(&self, p: &Path) -> Result<()> {
        let m = std::fs::symlink_metadata(p).with_context(|| format!("company rules: {}", p.display()))?;
        if m.file_type().is_symlink() {
            bail!("company rules: {} is a symbolic link", p.display());
        }
        if m.uid() != self.owner || m.mode() & 0o022 != 0 {
            bail!("company rules: {} must be owned by root and not writable by group or others", p.display());
        }
        Ok(())
    }

    /// The company rules, if this Mac has any. An error (rather than none)
    /// when they exist but could have been planted or changed by a user, or
    /// when the Mac is enrolled and they are missing: a policy load must
    /// then fail, not go on without them.
    pub fn org_source(&self) -> Result<Option<PolicySource>> {
        let file = self.policy();
        if std::fs::symlink_metadata(&file).is_err() {
            if std::fs::symlink_metadata(self.fleet_config()).is_ok() {
                bail!("company rules: this Mac is enrolled with a fleet server but {} is missing; wait for the fleet service to fetch them, or ask your administrator", file.display());
            }
            return Ok(None);
        }
        for p in [self.root.as_path(), &self.root.join("managed"), &file] {
            self.check(p)?;
        }
        let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&file).with_context(|| format!("company rules: {}", file.display()))?;
        if f.metadata()?.len() > MAX_BYTES {
            bail!("company rules: {} is larger than {MAX_BYTES} bytes", file.display());
        }
        let mut yaml = String::new();
        f.by_ref().take(MAX_BYTES + 1).read_to_string(&mut yaml).with_context(|| format!("company rules: {}", file.display()))?;
        Ok(Some(PolicySource { layer: Layer::Org, name: file.to_string_lossy().into_owned(), yaml }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, Managed) {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap().join("AgentACL");
        std::fs::create_dir_all(root.join("managed")).unwrap();
        for d in [&root, &root.join("managed")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let owner = unsafe { libc::getuid() };
        (t, Managed { root, owner })
    }

    #[test]
    fn loads_only_untampered_company_rules() {
        let (_t, m) = setup();
        assert!(m.org_source().unwrap().is_none(), "not enrolled, no rules: none");
        std::fs::write(m.fleet_config(), "{}").unwrap();
        assert!(m.org_source().unwrap_err().to_string().contains("missing"), "enrolled: must have them");
        std::fs::write(m.policy(), "version: v1\nfilesystem:\n  deny_read: [\"/x/**\"]\n").unwrap();
        std::fs::set_permissions(m.policy(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let src = m.org_source().unwrap().unwrap();
        assert_eq!(src.layer, Layer::Org);
        // Writable by others: could have been changed by anyone.
        std::fs::set_permissions(m.policy(), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(m.org_source().is_err());
        std::fs::set_permissions(m.policy(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(m.root.join("managed"), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(m.org_source().is_err(), "a writable folder");
        std::fs::set_permissions(m.root.join("managed"), std::fs::Permissions::from_mode(0o755)).unwrap();
        // Another owner (here: root is expected, the test user owns it).
        let other = Managed { owner: m.owner + 1, ..m.clone() };
        assert!(other.org_source().is_err());
        // A link in place of the file.
        std::fs::rename(m.policy(), m.root.join("real.yaml")).unwrap();
        std::os::unix::fs::symlink(m.root.join("real.yaml"), m.policy()).unwrap();
        assert!(m.org_source().unwrap_err().to_string().contains("symbolic link"));
    }
}
