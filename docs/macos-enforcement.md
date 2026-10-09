# macOS Enforcement

Status: design, iteration 1. Tested on macOS 26.5.1 (Apple Silicon).

This document answers three questions:

1. What can AgentACL **strongly enforce** in the MVP, without special
   entitlements?
2. What **requires Endpoint Security** (ES)?
3. What is **observation only**?

Where a claim was checked empirically on this machine, it's marked **[verified]**.
Where it comes from Apple documentation or headers and still needs to be checked
during implementation, it's marked **[to verify]**.

## 1. The `EnforcementBackend` boundary

```rust
pub trait EnforcementBackend {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    fn prepare(&self, session: &Session, policy: &CompiledPolicy) -> Result<LaunchPlan>;
    fn observe(&self, session: &Session, sink: &dyn EventSink) -> Result<ObserverHandle>;
}
```

| Backend | Iteration 1 | Mechanism |
|---|---|---|
| `SeatbeltBackend` | **Implemented** | Kernel sandbox (Sandbox.kext, a MAC policy) applied via `sandbox-exec` to the agent and every descendant |
| `MacOSEndpointSecurityBackend` | Stub: `capabilities()` returns none, and `status` reports "unavailable: requires com.apple.developer.endpoint-security.client" | ES system extension (Swift) linking `agentacl-policy` |
| `OpenShellBackend`, `LinuxBackend` | Not started, and no code in iteration 1 | n/a |

`status` and every event name the backend that produced the decision.

## 2. MVP mechanism: Seatbelt (`sandbox-exec`)

`agentacl run` compiles the effective policy into an SBPL (Sandbox Profile
Language) profile and launches the agent with `/usr/bin/sandbox-exec -f
<profile> -- <agent>`. The sandbox is attached to the process **in the kernel**
and is inherited by every child across `fork`/`exec`. It keeps working if the
AgentACL supervisor dies. The same mechanism underlies the built-in
sandboxing in Claude Code and Codex on macOS.

### 2.1 What we verified on this machine

| Probe | Result |
|---|---|
| `deny file-read*` (regex `/\.env$`), then `cat .env` | EPERM **[verified]** |
| Same rule, `cat .ENV` (case variant, case-insensitive APFS) | EPERM **[verified]** |
| Symlink in project → denied file, then `cat` the link | EPERM (checked on the resolved path) **[verified]** |
| Hard link from project → denied file | `ln` itself fails with EPERM **[verified]** |
| Rename the **parent dir** of a denied subpath, then read via the new path | **Bypass: the read succeeded.** Fixed by also denying `file-write-unlink` on the protected directory literal, which made the rename fail with EPERM **[verified]** |
| `require-all` + `require-not` to carve `.env.example` out of a `.env.*` deny | Works **[verified]** |
| `deny network-outbound` + `allow (remote ip "localhost:*")`, `curl https://example.com` | Fails, and DNS resolution fails too, because the mDNSResponder socket counts as outbound **[verified]** |
| `deny process-exec (literal "/usr/bin/sudo")` | EPERM, but the probe is confounded: **any** sandbox forbids exec of setuid/setgid binaries (`forbidden-exec-sugid`, even under `(allow default)`), so `sudo`, `su` and `ps` never run in a session **[verified]**. The exec-deny mechanism itself needs a non-setuid probe binary in the E2E suite |
| `osascript -e 'do shell script "cat <denied>"'` | EPERM, because the child is sandboxed **[verified]** |
| `deny appleevent-send`, then `osascript` → Finder | **Not blocked.** Apple Events escape is an open item (§5, T7) **[verified]** |
| Nested `sandbox-exec` inside `sandbox-exec` | **Fails for any real outer profile** (`sandbox_apply: Operation not permitted`; with `(deny default)` the log shows `forbidden-sandbox-reinit`). It only works under a bare `(allow default)` **[verified]**. Consequence: agents that sandbox their own commands (Codex's default mode, Claude Code's sandbox setting) would have every shell command fail. Each provider must declare how to switch off the agent's inner sandbox when AgentACL is the outer one (flag, env or settings override), and an E2E test covers it **[to verify per agent]** |
| Hard link created **before** the session, then read inside it | **Readable: bypass** **[verified]**. Handled by the startup `st_nlink` check (threat model T2) |
| Unix-socket connect deny `(remote unix-socket (path-literal …))` | Works, including via symlink/hard link to the socket **[verified]** |
| `(with message "…")` on a deny, including `(deny default …)` | The message is appended to the kernel violation report; used for exact session/rule attribution **[verified]** |
| Background process started by the agent, still running after the agent exits | Keeps running, still sandboxed, no longer audited **[verified]**. Handled by process-group kill at session end (T20) |
| Kernel denials visible to an **unprivileged** `log stream --predicate 'sender == "Sandbox"'` | Yes: `Sandbox: cat(22304) deny(1) file-read-data /…/.env`, with pid, operation and path **[verified]** |

### 2.2 How the profile is built

```scheme
(version 1)
(deny default)                         ; ALWAYS. Category defaults of `allow` become explicit broad allows below
(allow <runtime-ops>)                  ; curated non-file ops: sysctl-read, ipc-posix-shm, signal (see T5),
                                       ; file-read-metadata on / and ancestors of allowed paths, and the mach-lookup allowlist below
(allow process-fork)
(allow file-read* <runtime baseline> <allow_read rules>)
(allow file-write* <allow_write rules>)
(allow process-exec …)                 ; per process defaults
(allow network-outbound (remote ip "localhost:<proxy-port>"))
;; ---- all deny rules come LAST: in SBPL the last matching rule wins, and that is how explicit-deny-wins is realized
(deny file-read* file-write* <deny_read/deny_write rules, with require-not for `except`>)
(deny file-write-unlink <ancestor literals of anchored secret paths>)
(deny file-write* <agentacl-self paths>)
(deny process-exec <resolved binaries for executable-only process deny/ask rules>)
(deny network-outbound (remote unix-socket (path-literal "<SSH_AUTH_SOCK>")))   ; verified syntax
;; network-bind / network-inbound: never allowed except loopback ports from network.listen
```

Why `(deny default)` even when a category default is `allow`? Because it keeps
every operation class the policy language doesn't model — Mach services, Apple
Events, IOKit — closed unless we list it. That allowlist is also the main MVP lever
against T7 escapes (threat model). A category default of `allow` becomes, e.g.,
`(allow file-read*)` or `(allow process-exec)` placed before the deny block.

**Mach-service allowlist.** This list is a security boundary as real as the file
rules: Mach services are how a sandboxed process asks an *unsandboxed* daemon
to act (T6, T7, T9). The initial policy:

| Mach service | Decision | Why |
|---|---|---|
| `com.apple.system.opendirectoryd.membership`, `com.apple.bsd.dirhelper`, `com.apple.system.notification_center`, `com.apple.logd`, `com.apple.trustd*` (TLS verification), `com.apple.system.logger` | allow | Needed by shells, git and TLS clients (seen as denials in the review probes) |
| `com.apple.SecurityServer` (keychain) | allow **only** for Claude Code without a token in the environment | Claude Code's `/login` lives in the keychain. Without a token, the provider also grants read of `~/Library/Keychains/**`, `/Library/Keychains/**`, `/private/var/db/mds/messages/*/**`, and connect to `/private/var/run/systemkeychaincheck.socket`; without these, `/login` fails (verified). This is a confused deputy: the session can run the credential helpers items trust (`git-credential-osxkeychain` returns git's saved GitHub tokens without asking; verified, T9), read the encrypted login keychain database, and raise keychain prompts. With `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_USE_BEDROCK` or `CLAUDE_CODE_USE_VERTEX` set in the environment `agentacl run` starts from, none of this is granted |
| `com.apple.diagnosticd` | **deny** | Streams the unified log of every process into the sandbox (verified: other apps' messages arrived; T7) |
| `com.apple.coreservices.launchservicesd`, `com.apple.coreservices.appleevents` | **deny** | `open -a` and Apple Events launch or drive unsandboxed apps (T7) |
| `com.apple.pasteboard.1` | **deny** | Clipboard contents are often secrets |
| `com.apple.metadata.mds*` | **deny** | A Spotlight query can return contents of protected files |
| `com.apple.nsurlsessiond` | **deny** | Background downloads run outside the sandbox and the proxy |

Each **deny** row gets a probe in the E2E suite. A service that's absent from the
list is denied by `(deny default)`.

Glob→SBPL: `${X}/**` becomes `(subpath "X")`. A literal path becomes
`(literal …)`. Anything with `*`, `?` or an inner `**` becomes an anchored,
case-insensitive-safe `(regex …)`. The compiler is golden-tested, and every
deny rule is also run through the integration suite (architecture §9).

Relying on SBPL's "last match wins" ordering is fine, but only because the
compiler **always** emits every deny after every allow. A test asserts that
invariant on the generated profile.

### 2.3 Turning kernel denials into events

The supervisor runs `/usr/bin/log stream --style ndjson --predicate
'processIdentifier == 0 AND sender == "Sandbox"'`. The pid-0 clause matters:
without it, any process that loads an image named `Sandbox` can forge a denial
line (verified in review; threat model T15a). Only messages that **start with**
`Sandbox: ` are parsed. The same stream also carries `System Policy: …` lines
and `N duplicate report(s) for Sandbox: …` lines. The latter add N to the
denial count of the matching event and never create a new decision.

**Attribution comes from kernel-reported tags, not from process tracking**
(implemented; this supersedes the earlier re-evaluation design). Every deny in
the generated profile, including `(deny default)`, carries
`(with message "af:<session>|<policy>|<rule>")`. The kernel appends that
message to its violation report, on a new line after the path. We verified
this on macOS 26.5.

The supervisor accepts a denial only if its tag names *its own* session. The
tag's policy and rule give the event's `policy`/`rule_id`, and the rule's
reason is looked up in the loaded policy. So:

- A process that lives for milliseconds (e.g. `cat .env`) is still
  attributed. The tag is in the kernel's line, so the process doesn't have to
  be alive when we read it.
- Denials from other sessions or other sandboxed apps are ignored: wrong or
  missing tag.
- The agent can't alter the tags, because they're compiled into the profile
  before exec. It can't forge kernel lines either (pid-0 check).

The delegation chain is taken from the polled process tree when the pid is
known. Otherwise it's `["<agent>", "…", "<process name>"]`: an honest partial
chain.

Known gaps, all **observability** gaps and never enforcement gaps:

- The kernel rate-limits and deduplicates violation reports. The count of
  denials is therefore a **lower bound**. `N duplicate reports` lines are
  added to the matching event's `count`.
- The log format is not an API and could change in a macOS release. The parser
  is fixture-tested, and on a parse failure it emits a `backend_warning`
  event instead of dropping the denial silently.

### 2.4 Network

SBPL can filter by IP/port but not by hostname. So:

1. The sandbox denies all outbound traffic except `localhost:<proxy-port>`. This
   includes DNS, which [verified] fails under this rule.
2. The supervisor runs a CONNECT/HTTP proxy on that port, and the child gets
   `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`.
3. The proxy evaluates `network.connect {host, port}`, then either connects or
   answers `403` with an AgentACL reason header. Every decision is an
   `decision=allow|deny, enforcement=enforced` event.

A tool that ignores the proxy variables simply fails to connect, so the design
fails closed. This holds even when `defaults.network: allow`: the sandbox
still forces all egress through the proxy, and the proxy then allows every host
not explicitly denied. We accept that proxy-unaware tools break. The
alternative — opening raw egress — would make every `network.deny` rule
bypassable. The limits: host decisions rely on the CONNECT authority (no TLS
interception, and no SNI inspection in iteration 1). The proxy resolves
names itself and checks the resolved addresses, so loopback, link-local
(metadata) and private ranges stay unreachable **through the proxy** unless
allowed (policy-model §2.4). Direct connections to them are blocked by the sandbox. Agents that need local
MCP servers on other ports need an explicit `network.allow: ["localhost:PORT"]`.

### 2.5 Seatbelt risks we accept

- `sandbox-exec` and SBPL are **deprecated and undocumented**. Apple still ships
  them and uses them heavily, and major agent vendors rely on them. The
  mitigation is the `EnforcementBackend` boundary plus the ES backend.
- Profiles are all-or-nothing at launch and can't change mid-session, so a
  policy edit applies to the **next** session. `status` shows the policy hash
  in force.
- There's no "ask": approval-gated filesystem rules compile to deny
  (policy-model §6).
- Seatbelt can't see **argv**, so argument-level process rules are observed only.

## 3. What requires Endpoint Security

A first version of this backend is in `crates/agentacl-es` (the
`agentacl-esd` daemon), not yet run on a real Endpoint Security client. It
differs from the design below: it reads policies from disk and journals
decisions to a file rather than using XPC snapshots, and it doesn't enforce
network rules. See [design/endpoint-security.md](design/endpoint-security.md)
for what it does, what is tested, its known gaps and what has to be
verified.

ES is Apple's kernel-backed, user-space security API (`EndpointSecurity.framework`,
macOS 10.15+). A client subscribes to **AUTH** events, which the kernel holds
until the client allows or denies them, and to **NOTIFY** events, which are
informational.

### 3.1 Requirements

- **Entitlement:** `com.apple.developer.endpoint-security.client`. It's granted
  by Apple on request, and a provisioning profile that includes it is needed
  for distribution.
- Packaging: normally a **System Extension** inside an app in `/Applications`,
  activated with `OSSystemExtensionRequest`, then approved by the user in System
  Settings. A root LaunchDaemon ES client is also possible.
- Runs as **root**, and needs **Full Disk Access** granted in TCC for the client.
- Signed with Developer ID and notarized.
- **Development without the entitlement:** only on a dedicated test Mac or VM
  with SIP disabled and AMFI relaxed. That setup is never supported for users.
  **[to verify exact boot-args for the current macOS]**

Until the entitlement is granted, `MacOSEndpointSecurityBackend` returns
`Unavailable`. No code path pretends otherwise.

### 3.2 Events we'd use

| Need | ES events | Why Seatbelt can't |
|---|---|---|
| Exact delegation chain | `NOTIFY_FORK`, `NOTIFY_EXEC`, `NOTIFY_EXIT`; `es_process_t.{audit_token, ppid, original_ppid, responsible_audit_token}` | Seatbelt has no process events. The MVP polls |
| argv-aware exec authorization (`git push`, `terraform apply`) | `AUTH_EXEC` (argv via `es_exec_arg`) | SBPL can't see argv |
| Per-session filesystem decisions | `AUTH_OPEN`, `AUTH_READDIR`, `AUTH_READLINK`, `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_TRUNCATE`, `AUTH_CLONE`, `AUTH_EXCHANGEDATA`, `AUTH_COPYFILE`, `AUTH_SETEXTATTR`, `AUTH_DELETEEXTATTR`, `AUTH_SETMODE`, `AUTH_SETOWNER`, `AUTH_SETFLAGS`, `AUTH_SETACL`, `AUTH_SETATTRLIST`, `AUTH_UTIMES` | Seatbelt already does these, but its profile is fixed at launch |
| Unix-socket access (ssh-agent, docker.sock) | `AUTH_UIPC_CONNECT`, `AUTH_UIPC_BIND` | SBPL handles connect statically (verified); ES adds per-session decisions |
| Unsupervised agents (started outside `agentacl run`) | All of the above, system-wide, matched by signing identity | Seatbelt applies only to what we launch |
| Agent signing identity for every exec | `es_process_t.{team_id, signing_id, cdhash, is_platform_binary}` | We call `codesign` APIs ourselves, which is racy |
| Tamper protection (killing the supervisor, rewriting policy) | `AUTH_SIGNAL`, `AUTH_GET_TASK`, `AUTH_GET_TASK_READ`, `AUTH_PROC_SUSPEND_RESUME`, `AUTH_OPEN`/`AUTH_UNLINK` on our own files | Partial in SBPL |

**Network** is not ES. Host-level egress control past the MVP proxy
would use a NetworkExtension content filter (`NEFilterDataProvider`), which is a
separate entitlement and a separate project.

### 3.3 ES design constraints (they shape the architecture now)

1. **Deadlines.** Each AUTH message carries a deadline. A client that misses
   deadlines gets its message defaulted, and it can be **terminated by the
   kernel**. So:
   - Policy evaluation happens **in-process** in the extension (the Rust
     `agentacl-policy` staticlib), over a pre-compiled, pre-expanded policy.
     There's no IPC to the CLI and no disk I/O.
   - The engine never waits on a human (policy-model §6: deny, record a pending
     approval, then grant and retry).
2. **Caching.** `es_respond_auth_result(..., cache=true)` caches a result in the
   kernel, and the cache key is "generally the involved files" (`ESClient.h`),
   **not** our session or delegation chain. `AUTH_OPEN` is answered with
   `es_respond_flags_result`. Decisions that depend on who is asking
   (agent vs. non-agent `cat`) must be answered with `cache=false`. Caching is
   only safe for decisions that are the same for every process.
3. **Scope.** An AUTH subscription is system-wide, so non-agent processes must
   hit a fast path: an audit-token lookup in the in-memory agent set, then
   allow. Inverted process muting (macOS 13+) is tempting, but a newly forked
   agent child isn't in the muted set until we add it. That opens a window
   where its events would bypass us, so it's rejected. Path muting must use only
   the **target** mute types (`ES_MUTE_PATH_TYPE_TARGET_PREFIX` /
   `TARGET_LITERAL`). The plain `PREFIX`/`LITERAL` types mute by the
   *acting process's executable*, so muting `/bin` would silence the agent's
   own `/bin/cat`.
4. **Identity source of truth.** Under ES, session membership comes from
   `audit_token` lineage, never from an environment variable. `NOTIFY_FORK` is
   asynchronous, so a child's AUTH event can arrive **before** its fork
   notification. Membership is therefore evaluated per message: the acting
   process is a member if its `audit_token`, or its `parent_audit_token`
   (message version ≥ 4), is already in the set. If so, it's added right then.
   Whether this closes every race (e.g. a grandchild acting before the child
   has produced any event) is **[to verify]**. If it doesn't, AUTH events on
   *protected* resources from processes whose lineage is unknown are resolved
   by walking `ppid` ancestry via libproc before answering.

### 3.4 Process layout with ES

```
AgentACL.app (/Applications)
 └─ Contents/Library/SystemExtensions/ai.agentacl.es.systemextension   (Swift, root)
       links libagentacl_policy.a  (Rust, C ABI: af_policy_load / af_policy_evaluate / af_policy_free)
       ⇅ XPC (Mach service): policy snapshots in, decision events out
 agentacld (Rust, per-user LaunchAgent) — session registry, SQLite audit, approvals; the CLI talks to it
 (the ES extension is the only root component)
```

The extension keeps working, and fails closed on protected paths, if the Rust
daemon is down. It holds the last policy snapshot it received.

## 4. Enforceable vs. observational: the MVP matrix

| Control | MVP (Seatbelt + proxy) | With ES | Notes |
|---|---|---|---|
| Read-deny for secret files (.env, ~/.ssh, cloud creds…) | **Enforced** | Enforced | Covers symlink and case variants, hard-link creation, and rename-then-read (implied unlink/rename deny). Pre-existing hard links: `run` refuses to start for the ones it finds; others remain a residual (T2) |
| Write-deny outside project / to protected paths | **Enforced** | Enforced | |
| Filesystem default-deny + project allowlist | **Enforced** | Enforced | Needs the runtime baseline (policy-model §5.1) |
| Filesystem `ask` | **Enforced as deny** | Deny + approve/retry | No interactive approval in the MVP |
| Process deny, executable-level (`terraform *`) | **Enforced (coarse)** | Enforced | Matched by basename regex plus the PATH-resolved paths. A copied or renamed binary isn't covered in the MVP. ES matches by signing identity. Setuid binaries (`sudo`) can't run in a session at all |
| Inbound listeners (exfiltration via a local port) | **Enforced** (`network-bind`/`network-inbound` denied except `network.listen`) | Same | T8a |
| Process deny/ask with arguments (`git push *`) | **Observed only** | Enforced | MVP events are `enforcement=observed`, rendered as NOT BLOCKED |
| Network host allowlist | **Enforced** (proxy + sandbox egress lock) | Same (+ NE later) | No TLS interception |
| SSH-agent / Unix-socket use (docker.sock) | **Enforced** (env removed + `remote unix-socket` deny, verified) | Enforced (`AUTH_UIPC_CONNECT`) | |
| Session/rule attribution of kernel denials | **Exact** (kernel-reported profile tags) | Exact | Independent of process polling |
| Delegation chain in events | **Observed** (100 ms polling; intermediate hops of short-lived processes may show as `…`) | Exact | Enforcement never depends on it |
| Agent identity of the launched binary | **Verified at launch** (path, SHA-256, code signature) | Continuous per exec | |
| Agents **not** launched via `agentacl run` | **Observed only** (`discover`, `agents --all`) | Enforced | MVP can't restrict what it didn't launch |
| Escape via launchd / Apple Events / other apps | **Not enforced until probes pass** (Mach-service allowlist, T7) | Partial (`AUTH_EXEC` can refuse `osascript`/`open`/`launchctl` for agent-tree processes) | Open item |
| Delayed execution via files the human later runs (`.git/**`, hooks, rc files, agent configs) | **Enforced** for the `exec-persistence` paths, **pending per-vector E2E probes**; **observed** (session-end diff) for build files | Same | T19 |
| Read of protected file via a pre-existing hard link | **Fail-closed at startup** for concrete protected paths and files in `${PROJECT}`; **not covered** for glob matches elsewhere in `${HOME}` | Same | T2 |
| Audit completeness of denials | **Best-effort** (log stream, lower bound) | Complete for subscribed events | |

## 5. Rules for honest output

- `enforcement=enforced` is set only by the kernel-report path (§2.3) or the proxy (§2.4).
- The observation path (process-tree monitor) can only emit
  `enforcement=observed`. Its `deny`/`ask` decisions are rendered as
  `AGENTACL OBSERVED — NOT BLOCKED`. This is enforced in code: the
  `EventSink` constructor for observers can't set `enforced`.
- `agentacl status` always prints the backend and the enforceability summary,
  for example: `Enforced: filesystem, network, exec(binary)` and
  `Observed only: exec(arguments)`.
- If the Seatbelt profile fails to compile or apply, the agent isn't started
  and the exit code is non-zero. There's no fallback to an unconfined or
  observe-only mode in iteration 1.
