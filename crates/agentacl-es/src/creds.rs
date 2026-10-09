//! Threads of the root daemon that touch the user's files act as the user,
//! and never wait on iCloud: a link or a placeholder the user (or an agent)
//! planted can then neither make root write elsewhere nor stall the daemon.

use anyhow::{bail, Result};

extern "C" {
    /// Sets the calling thread's user and group (`<unistd.h>`).
    fn pthread_setugid_np(uid: libc::uid_t, gid: libc::gid_t) -> libc::c_int;
    /// `<sys/resource.h>`.
    fn setiopolicy_np(iotype: libc::c_int, scope: libc::c_int, policy: libc::c_int) -> libc::c_int;
}

const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: libc::c_int = 3;
const IOPOL_SCOPE_THREAD: libc::c_int = 1;
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: libc::c_int = 1;

/// Makes the current thread act as `uid`/`gid` (when the daemon is root),
/// and fail rather than download a file that is only in iCloud.
pub fn become_user(uid: u32, gid: u32) -> Result<()> {
    // SAFETY: both change only this thread's state.
    unsafe {
        setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD, IOPOL_MATERIALIZE_DATALESS_FILES_OFF);
        if libc::geteuid() != 0 {
            return Ok(()); // tests, `--check`: already a user
        }
        if pthread_setugid_np(uid, gid) != 0 {
            bail!("acting as uid {uid}: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}
