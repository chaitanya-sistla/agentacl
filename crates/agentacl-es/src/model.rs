//! What the Endpoint Security adapter hands the engine: plain data, so the
//! engine is testable without the ES framework (docs/design/endpoint-security.md).

/// A process instance: pid plus the pid version from its audit token. The
/// version changes on every exec, so a pid can't be confused with a later
/// process that reuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey {
    pub pid: i32,
    pub version: i32,
}

/// Signed with the hardened runtime: no injected libraries (`DYLD_*`), no
/// debugger attached by its user.
pub const CS_RUNTIME: u32 = 0x10000;

#[derive(Debug, Clone, Default)]
pub struct Proc {
    pub key: Option<ProcKey>,
    /// The parent's audit token (ES message version ≥ 4), when known.
    pub parent: Option<ProcKey>,
    pub ppid: i32,
    /// Real user id (from the audit token).
    pub uid: u32,
    pub exe: String,
    pub signing_id: String,
    pub team_id: String,
    pub platform_binary: bool,
    /// Code-signing flags (`CS_*`, `<kern/cs_blobs.h>`).
    pub cs_flags: u32,
}

impl Proc {
    pub fn key(&self) -> ProcKey {
        self.key.unwrap_or(ProcKey { pid: -1, version: -1 })
    }
}

#[derive(Debug, Clone)]
pub enum Op {
    /// `target` is the process image after the exec (same pid).
    /// As an AUTH event, the request; as a NOTIFY, the exec happened.
    Exec {
        target: Proc,
        argv: Vec<String>,
        cwd: Option<String>,
        /// The new image is setuid or setgid.
        setuid: bool,
    },
    Fork {
        child: Proc,
    },
    Exit,
    Open {
        path: String,
        read: bool,
        write: bool,
    },
    Create {
        path: String,
    },
    Rename {
        source: String,
        destination: String,
    },
    Unlink {
        path: String,
    },
    Link {
        source: String,
        destination: String,
    },
    Truncate {
        path: String,
    },
    Clone {
        source: String,
        destination: String,
    },
    /// Mode, owner, flags, extended attributes, ACL or times of a file.
    Meta {
        path: String,
    },
    /// `exchangedata`: two files swap contents.
    Exchange {
        a: String,
        b: String,
    },
    CopyFile {
        source: String,
        destination: String,
    },
    Signal {
        target: Proc,
        signal: i32,
    },
    /// `task_for_pid`: control of another process.
    GetTask {
        target: Proc,
    },
    UnixConnect {
        path: String,
    },
}

#[derive(Debug, Clone)]
pub struct Msg {
    pub proc: Proc,
    pub op: Op,
    /// An AUTH event (needs an answer) rather than a NOTIFY.
    pub auth: bool,
}

/// The engine's answer. `cache` is always false today: ES caches by file, not
/// by who asks, so a cached allow for one process would apply to an agent
/// later (docs/macos-enforcement.md §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allow: bool,
    pub cache: bool,
}

impl Verdict {
    pub const ALLOW: Verdict = Verdict { allow: true, cache: false };
    pub const DENY: Verdict = Verdict { allow: false, cache: false };
}
