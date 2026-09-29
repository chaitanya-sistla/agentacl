//! Non-file operations every process needs, and the Mach-service policy
//! (macos-enforcement §2.2). This is data: refine it with
//! scripts/capture-baseline.sh, never by adding NEVER_ALLOW items.

/// Operations the compiler must never allow (policy-model §5.1). `network-bind`
/// and `network-inbound` are allowed only scoped to `network.listen` loopback
/// ports; the compiler checks that separately.
pub const NEVER_ALLOW: &[&str] = &["hid-control", "lsopen", "appleevent-send", "job-creation"];

/// Unconditional runtime operations. `(target same-sandbox)` keeps signals and
/// process inspection inside the agent's own sandbox (threat T5).
pub const RUNTIME_OPS: &[&str] = &[
    "(allow process-fork)",
    "(allow signal (target same-sandbox))",
    "(allow process-info* (target same-sandbox))",
    "(allow sysctl-read)",
    "(allow ipc-posix-shm*)",
    "(allow ipc-posix-sem)",
    "(allow pseudo-tty)",
    "(allow user-preference-read)",
    "(allow iokit-open (iokit-user-client-class \"RootDomainUserClient\"))",
    "(allow file-read-metadata (literal \"/\"))",
];

/// Mach services allowed for every agent (macos-enforcement §2.2).
pub const MACH_ALLOW: &[&str] = &[
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.bsd.dirhelper",
    "com.apple.system.notification_center",
    "com.apple.logd",
    "com.apple.system.logger",
    "com.apple.trustd",
    "com.apple.trustd.agent",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
    "com.apple.coreservices.quarantine-resolver",
    "com.apple.diagnosticd",
    "com.apple.analyticsd",
    "com.apple.FSEvents",
    "com.apple.system.opendirectoryd.api",
    "com.apple.SystemConfiguration.configd",
];

/// Services explicitly denied even if something above would allow them:
/// they let a sandboxed process make an unsandboxed one act (T6, T7, T9).
pub const MACH_DENY: &[&str] = &[
    "com.apple.coreservices.launchservicesd",
    "com.apple.coreservices.appleevents",
    "com.apple.pasteboard.1",
    "com.apple.metadata.mds",
    "com.apple.metadata.mds.legacy",
    "com.apple.nsurlsessiond",
];
