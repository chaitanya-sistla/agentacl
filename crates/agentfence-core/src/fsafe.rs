//! Symlink-safe file replacement for security-relevant files (policy, trust
//! config, backups). A supervised agent may control directories other than
//! its own project, so every path component is opened with `O_NOFOLLOW` from
//! `/`, the leaf must be a regular single-link file, and writes go through an
//! exclusive random temp file + `fsync` + `renameat` inside the same dirfd
//! (ui.md §4.3.5).

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path};

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).context("path contains NUL")
}

fn openat_dir(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: openat with a valid dirfd and NUL-terminated name.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) {
            bail!("refusing to follow a symlink or non-directory at component {name:?}");
        }
        return Err(e).with_context(|| format!("opening directory component {name:?}"));
    }
    // SAFETY: fd is a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens `dir` (absolute, canonical) one component at a time without
/// following symlinks.
pub fn open_dir(dir: &Path) -> Result<OwnedFd> {
    if !dir.is_absolute() {
        bail!("{} is not absolute", dir.display());
    }
    let root = cstr("/")?;
    // SAFETY: opening "/" as a directory.
    let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fresh descriptor.
    let mut cur = unsafe { OwnedFd::from_raw_fd(fd) };
    for comp in dir.components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(n) => cur = openat_dir(&cur, &n.to_string_lossy())?,
            other => bail!("unexpected path component {other:?} in {}", dir.display()),
        }
    }
    Ok(cur)
}

/// `mkdirat` (0700) if missing, then open without following symlinks.
pub fn ensure_subdir(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: mkdirat with a valid dirfd; EEXIST is fine.
    let r = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e).with_context(|| format!("creating {name}"));
        }
    }
    openat_dir(parent, name)
}

fn fstat(fd: i32) -> Result<libc::stat> {
    // SAFETY: fstat into a zeroed struct.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(st)
    }
}

/// Reads `name` in `dir`: `None` if absent. Refuses symlinks, FIFOs and
/// hard-linked files.
pub fn read_regular(dir: &OwnedFd, name: &str) -> Result<Option<Vec<u8>>> {
    let c = cstr(name)?;
    // SAFETY: openat with NOFOLLOW|NONBLOCK (a FIFO cannot hang us).
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => bail!("refusing to read {name}: it is a symlink"),
            _ => Err(e).with_context(|| format!("opening {name}")),
        };
    }
    // SAFETY: fresh descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = fstat(owned.as_raw_fd())?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        bail!("refusing to read {name}: not a regular file");
    }
    if st.st_nlink != 1 {
        bail!("refusing to use {name}: it has {} hard links", st.st_nlink);
    }
    let mut f = std::fs::File::from(owned);
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(Some(buf))
}

fn random_hex(n: usize) -> Result<String> {
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(hex::encode(b))
}

/// Atomically replaces `name` in `dir` with `bytes` (mode 0600).
pub fn write_atomic(dir: &OwnedFd, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = format!(".{name}.af-{}", random_hex(8)?);
    let ct = cstr(&tmp)?;
    let cn = cstr(name)?;
    // SAFETY: exclusive create; never follows or reuses an existing path.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), ct.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating temp file");
    }
    // SAFETY: fresh descriptor.
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let res = (|| -> Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?;
        // SAFETY: renameat within one dirfd; replaces the directory entry
        // `name` itself (a symlink there is replaced, not followed).
        if unsafe { libc::renameat(dir.as_raw_fd(), ct.as_ptr(), dir.as_raw_fd(), cn.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("renaming into place");
        }
        Ok(())
    })();
    if res.is_err() {
        // SAFETY: best-effort cleanup of our own temp entry.
        unsafe { libc::unlinkat(dir.as_raw_fd(), ct.as_ptr(), 0) };
    }
    res
}

/// Replaces `dir/name` after checking that its current bytes hash to
/// `expected` (`None` = must not exist), writing `name.bak` first.
/// Returns the new sha256.
pub fn replace_checked(dir: &OwnedFd, name: &str, bytes: &[u8], expected: Option<&str>) -> Result<String> {
    let current = read_regular(dir, name)?;
    let cur_sha = current.as_deref().map(agentfence_policy::set::sha256_hex);
    if cur_sha.as_deref() != expected {
        bail!(ConflictError { current_sha: cur_sha });
    }
    if let Some(old) = &current {
        write_atomic(dir, &format!("{name}.bak"), old)?;
    }
    write_atomic(dir, name, bytes)?;
    Ok(agentfence_policy::set::sha256_hex(bytes))
}

#[derive(Debug)]
pub struct ConflictError {
    pub current_sha: Option<String>,
}
impl std::fmt::Display for ConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the file changed on disk since it was loaded (now {})", self.current_sha.as_deref().unwrap_or("absent"))
    }
}
impl std::error::Error for ConflictError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(d.path()).unwrap();
        (d, r)
    }

    #[test]
    fn replace_and_backup() {
        let (_d, r) = root();
        let dir = open_dir(&r).unwrap();
        let sub = ensure_subdir(&dir, ".agentfence").unwrap();
        let s1 = replace_checked(&sub, "policy.yaml", b"one", None).unwrap();
        assert!(replace_checked(&sub, "policy.yaml", b"x", None).is_err(), "conflict when it exists");
        replace_checked(&sub, "policy.yaml", b"two", Some(&s1)).unwrap();
        assert_eq!(std::fs::read(r.join(".agentfence/policy.yaml")).unwrap(), b"two");
        assert_eq!(std::fs::read(r.join(".agentfence/policy.yaml.bak")).unwrap(), b"one");
    }

    #[test]
    fn refuses_symlinks_everywhere() {
        let (_d, r) = root();
        let victim = r.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        // symlinked .agentfence
        let p1 = r.join("p1");
        std::fs::create_dir(&p1).unwrap();
        std::os::unix::fs::symlink(&r, p1.join(".agentfence")).unwrap();
        assert!(ensure_subdir(&open_dir(&p1).unwrap(), ".agentfence").is_err());
        // symlinked ancestor
        std::os::unix::fs::symlink(&p1, r.join("link")).unwrap();
        assert!(open_dir(&r.join("link")).is_err());
        // planted .bak symlink is replaced, never followed
        let p2 = r.join("p2");
        std::fs::create_dir_all(p2.join(".agentfence")).unwrap();
        std::fs::write(p2.join(".agentfence/policy.yaml"), "old").unwrap();
        std::os::unix::fs::symlink(&victim, p2.join(".agentfence/policy.yaml.bak")).unwrap();
        let sub = ensure_subdir(&open_dir(&p2).unwrap(), ".agentfence").unwrap();
        let sha = agentfence_policy::set::sha256_hex(b"old");
        replace_checked(&sub, "policy.yaml", b"new", Some(&sha)).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        // symlinked policy file is refused
        let p3 = r.join("p3");
        std::fs::create_dir_all(p3.join(".agentfence")).unwrap();
        std::os::unix::fs::symlink(&victim, p3.join(".agentfence/policy.yaml")).unwrap();
        let sub = ensure_subdir(&open_dir(&p3).unwrap(), ".agentfence").unwrap();
        assert!(read_regular(&sub, "policy.yaml").is_err());
        // FIFO does not hang
        let fifo = r.join("fifo");
        let c = CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert!(read_regular(&open_dir(&r).unwrap(), "fifo").is_err());
    }
}
