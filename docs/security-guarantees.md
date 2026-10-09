# Security guarantees

What AgentACL actually does, today (v0.4.0), and what it doesn't. This file
exists so that we can't overstate a claim by accident. If README, a blog post
or a launch message says something stronger than this table, the table wins,
and the other text is a bug.

**Statuses:**
- **ENFORCED**: blocked by the kernel sandbox or the network proxy, with an
  automated test that proves it.
- **PARTIALLY ENFORCED**: blocked, but with a known gap (see Notes).
- **OBSERVED**: detected and recorded, never blocked.
- **PLANNED**: not implemented.
- **NOT SUPPORTED**: not possible with the current design.

**Scope.** Everything marked ENFORCED applies only to agents started with
`agentacl run -- <agent>` (the *supervised runtime*), and to every process
they start. An agent started any other way is not restricted at all; see the
first row.

## Who is protected

| Capability | Status | Enforcement | Notes | Evidence |
|---|---|---|---|---|
| Agent started with `agentacl run`, and all its descendants | ENFORCED | macOS Seatbelt (kernel sandbox), inherited across fork/exec | Holds through shells, nested shells, Python and Python subprocesses | `sandbox_holds_through_python_and_nested_shells`, `enforce::tests::*`, `e2e::*` |
| Agent started outside AgentACL (plain `claude`, IDE, GUI) | OBSERVED | Process discovery | Reported as *not protected* by `discover`, `agents --all` and the console. **Not blocked** | `agents::tests`, manual |
| System-wide enforcement regardless of how the agent was launched | PLANNED | Endpoint Security (`agentacl-esd`) | Implemented and unit-tested, but **not yet run on a real Endpoint Security client**: that needs a development Mac (SIP and AMFI off) or Apple's `com.apple.developer.endpoint-security.client` entitlement. Stays PLANNED until it has run and been verified ([design](design/endpoint-security.md)) | `agentacl-es` engine tests (no ES) |

## Files

| Capability | Status | Enforcement | Notes | Evidence |
|---|---|---|---|---|
| Reading built-in secrets (`.env*`, `~/.ssh`, cloud credentials, kubeconfig, Terraform, git/package tokens, keys, GPG, browser profiles, synced cloud drives) | ENFORCED | Seatbelt | All 13 built-in groups are probed (37 fake files) under a policy that otherwise allows all of home, so the secret rules alone block them. Case variants and symlinks are covered. `.env.example` and similar are allowed | `sandbox_every_builtin_secret_group`, `sandbox_reads`, `e2e::secret_read_blocked_and_audited` |
| Writing or deleting protected files | ENFORCED | Seatbelt | Every built-in read-deny also denies write, unlink, rename and link. A `deny_read` in *your* policy denies reading, deleting, renaming and linking, but not overwriting: add the path to `deny_write` too | `sandbox_every_builtin_secret_group` (overwrite, delete), `sandbox_location_protection` (rename, link) |
| Moving a secret out from under its rule (rename a parent, hard link, move the project, move a folder that holds a key) | PARTIALLY ENFORCED | Seatbelt | Rename and unlink of the protected path's ancestors are denied. For name rules (`**/*.pem`, `**/terraform.tfvars`), a folder in between can still be moved, so the same names are also denied in every other writable place (the temp directories and your `allow_write` locations). Not covered: `defaults.filesystem: allow` or a writable `/`, where anything can be moved anywhere | `sandbox_location_protection`, `sandbox_moved_directory_keeps_secret_names` |
| Reading a protected file through a hard link that existed before the session | PARTIALLY ENFORCED | Startup check (fail closed) | `run` refuses to start if a concrete protected path or a protected file in the project has extra links (tested for a file in the project). Glob-matched files elsewhere in `$HOME` aren't scanned | `e2e::hardlinks_fail_closed` |
| Synced cloud drives (Google Drive, OneDrive, Dropbox, Box in `~/Library/CloudStorage`; iCloud Drive; legacy `~/Dropbox`, `~/Dropbox (…)`, `~/Google Drive`, `~/OneDrive`, `~/OneDrive - …`, `~/Box`, `~/Box Sync`, `/Volumes/GoogleDrive*`), and the drive apps' own data (Google Drive's file cache in `DriveFS`, `~/.dropbox`; Box's and OneDrive's app data at their usual locations, not verified on a real install) | PARTIALLY ENFORCED | Seatbelt (built-in `cloud-drives` group) | Read, write and delete denied even under a policy that opens all of home. A project that lives inside a drive stays usable; the rest of the drive stays protected. Not covered: iCloud's "Desktop & Documents" sync (those files stay in `~/Desktop` and `~/Documents`; `agentacl audit` flags it), a Dropbox moved to a custom location, and a project that *is* or *contains* a drive or its top level (such as Google Drive's `My Drive`): the project is always open, so `run` warns and `audit` reports it as High. Reaching a drive's *web API* is a network question: see `agentacl audit` | `sandbox_every_builtin_secret_group`, `sandbox_project_inside_a_cloud_drive` (under a policy that opens all of home) |
| Writes outside the project (default policy) | ENFORCED | Seatbelt | Project read/write, everything else denied unless a rule allows it | `sandbox_reads` (default policy) |
| Planting code that runs later outside the sandbox (git hooks and config, `.git` swap, `.husky`, `.envrc`, shell rc, LaunchAgents, agent and editor configs, Python bytecode caches and user site-packages) | PARTIALLY ENFORCED | Seatbelt | Writing each listed file in place is blocked (tested). Not covered: build files (`package.json`, `Makefile`), which must stay writable and are **OBSERVED** (flagged "REVIEW BEFORE RUNNING"); a git `core.hooksPath` set to some other project directory; a folder prepared in a temp directory (holding a `__pycache__` or a nested `.git`) and then moved into the project; a sourceless `.pyc` outside `__pycache__`; `.pth` files in a project virtualenv (the project and its dependencies are writable by design). Trade-off: deleting a folder that contains `__pycache__` or a nested `.git` fails inside the sandbox | `sandbox_writes_and_exec_persistence`, `e2e::build_file_changes_flagged` |
| Changing AgentACL's own policy, trust or audit log | ENFORCED | Seatbelt | Built-in `agentacl-self` can't be disabled | `sandbox_writes_and_exec_persistence` |
| Reading AgentACL's state (the audit log of every session, live network decisions) | ENFORCED | Seatbelt | Denied even under a policy that opens all of home | `sandbox_every_builtin_secret_group` |
| A file request waiting for your answer | NOT SUPPORTED | n/a | Seatbelt refuses a file at once and AgentACL learns of it afterwards, so a file request can't wait. It shows up as a request instead. Waiting on files needs Endpoint Security (planned) | none |
| Allowing a refused file or folder for one agent, in one project | ENFORCED | Seatbelt, after a restart | Saved as an access file with `match:` for that literal agent id and project folder; applies when the agent restarts (the conversation resumes), and so does removing it. Built-in protections, your home folder and top-level folders (under any of their names) can't be granted | `sandbox_access_grant_is_per_agent`, `access::tests`, `ui::tests::access_grants_scopes_and_removal` |
| Allowing a site for one agent, in one project | ENFORCED | Proxy (scoped live rule) and the access file | Applies to running agents at once; removing it revokes it for sessions that loaded it | `netlive::tests::scoped_rules_apply_to_their_agent_only` (agent and project scope), `ui::tests::access_grants_scopes_and_removal`, `ui::tests::access_edge_cases` |
| Allowing a protected file for one request ("allow once") | PLANNED | n/a | Needs Endpoint Security | none |

## Processes

| Capability | Status | Enforcement | Notes | Evidence |
|---|---|---|---|---|
| Blocking a program by name (`terraform *`) | PARTIALLY ENFORCED | Seatbelt `process-exec` | Matches the name and the resolved path. A copied or renamed binary is not matched | `sandbox_exec_deny` |
| Blocking by arguments (`git push *`, `terraform apply *`) | OBSERVED | Process-tree polling | Recorded as "OBSERVED, NOT BLOCKED". Seatbelt can't see arguments | `e2e::argument_rule_is_observed_not_blocked` |
| setuid binaries (`sudo`, `su`) | ENFORCED | Seatbelt (always) | Any Seatbelt profile forbids exec of setuid binaries | `sandbox_exec_deny` (`sudo`, `su`) |
| Reading other processes' command lines | ENFORCED | Seatbelt | | `sandbox_cannot_read_other_processes_argv` |
| Injecting keystrokes into your terminal (`TIOCSTI`) | ENFORCED | pty + Seatbelt | | `sandbox_blocks_tiocsti` |
| Secret environment variables (`*_TOKEN`, `AWS_*`, …) | ENFORCED | Supervisor strips them before launch | `--keep-env NAME` passes one through deliberately | `e2e::secret_env_is_withheld` |
| Background processes surviving the session | PARTIALLY ENFORCED | Supervisor kills the session's processes at exit | Survivors stay sandboxed but are no longer audited | `e2e::orphans_are_cleaned_up` |
| Delegation chain (which process started which) | OBSERVED | Process-tree polling (about 100 ms) | Very short-lived intermediate processes may appear as `…`. Enforcement never depends on it | `e2e::secret_read_blocked_and_audited` (chain on the event) |

## Network

| Capability | Status | Enforcement | Notes | Evidence |
|---|---|---|---|---|
| Egress that bypasses AgentACL (direct sockets, direct DNS) | ENFORCED | Seatbelt | The sandbox allows outbound traffic only to the local AgentACL proxy. Tools that ignore `HTTPS_PROXY` fail to connect (fail closed) | `sandbox_network_and_listen` (raw socket to a listener reachable outside the sandbox, with a positive control) |
| Host allow/deny (`network.allow`, `network.deny`) | ENFORCED | AgentACL proxy | Decided on the CONNECT/HTTP host **before** DNS. No TLS interception or SNI inspection. Data sent to an allowed host is not inspected (see below) | `e2e::network_default_deny_through_proxy`, `netproxy::tests` |
| Private, loopback and link-local addresses (e.g. cloud metadata `169.254.169.254`) | ENFORCED | Proxy (after resolution) | Refused unless an address rule names them, even when the host name is allowed | `netproxy::tests::reserved_range_blocked_even_when_host_allowed` |
| Blocking a site from the console, for agents already running | ENFORCED | Proxy live rules | Applies on the next connection. Established connections aren't cut | `netlive::tests` |
| Allowing a site from the console, for agents already running | ENFORCED | Proxy live rules | Only lifts a *default* denial, never an explicit or built-in block | `netlive::tests` |
| *Ask me*: approving an unknown site while the agent waits | ENFORCED | Proxy approvals (30 s by default, up to 5 min, "+1 min" at most 5 times; then blocked) | Per host and port, rate limited. The name isn't looked up in DNS before you answer | `netlive::tests` (answer; timeout, with the pending prompt observed for a name that doesn't resolve; rate limit), `ui::tests::approvals_*`, manual end-to-end |
| Listening on a local port (inbound exfiltration) | ENFORCED | Seatbelt | Only ports in `network.listen` | `sandbox_network_and_listen` |
| ssh-agent and Docker sockets | ENFORCED | Seatbelt + env stripping | `SSH_AUTH_SOCK`, `/var/run/docker.sock` and `~/.docker/run/docker.sock` when present | `credential_sockets_are_denied`, `sandbox_unix_socket_deny` (the socket is also allowed, so only the deny can refuse it; unlisted sockets are refused by default anyway), `supervisor::env` tests |
| Exfiltration through an allowed host (e.g. a gist on an allowed `github.com`) | NOT SUPPORTED | n/a | Allowed means allowed. Needs content inspection, which AgentACL doesn't do | none |

## Escapes and integrity

| Capability | Status | Enforcement | Notes | Evidence |
|---|---|---|---|---|
| Asking another, unsandboxed app or service to act (a confused deputy: Apple Events, `open -a`, launchd jobs, pasteboard, Spotlight, the unified log, background downloads) | PARTIALLY ENFORCED | Seatbelt Mach-service allowlist and operation rules | Their services are unreachable (tested, each with the lookup working outside the sandbox), including `diagnosticd`, which streamed every process's log messages into the sandbox before it was denied. A `launchctl submit` job never runs (tested, with an unsandboxed positive control). Not yet probed end to end: `osascript` → Terminal `do script` and `open -a` | `sandbox_mach_services`, `sandbox_refuses_confused_deputies` |
| Reading or writing another app's preferences through `cfprefsd` (which runs outside the sandbox) | ENFORCED | Seatbelt `user-preference-read` limited to the global domain | Verified as a hole before this fix: `defaults read` returned another app's values although its preference files were denied. The global domain stays readable: locale and units, and anything apps choose to store there. System-wide preferences in `/Library/Preferences` are readable as files (they're world-readable anyway) |
| Another process's POSIX shared memory (a same-user namespace) | ENFORCED | Seatbelt `ipc-posix-shm` limited to Python's own segment names (`psm_…`), plus read-only access to Apple's system state and the preferences service's coordination segment | Verified as a hole before this fix: an agent read, changed and unlinked a segment another process created. POSIX semaphores are still unscoped (they carry no data; an agent could interfere with one it can name) | `sandbox_shared_memory_is_scoped` | `e2e::preferences_of_other_apps_are_refused` (with the kernel's denial record) |
| Keychain items, for Claude Code logged in with `/login` | NOT SUPPORTED | n/a | Claude keeps that login in the keychain, so its session can reach `securityd` and read the keychain files. It can run the credential helpers other items trust: a credential saved by `git-credential-osxkeychain` is returned by `git credential` without asking (verified). It can read the encrypted login keychain database (offline cracking), and raise keychain prompts you might approve. Other agents get no keychain access | `scripts/probes/keychain-deputy.sh` (manual) |
| Keychain items, for Claude Code with a token in the environment `agentacl run` starts from (`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, Bedrock or Vertex), and for every other agent | ENFORCED | Seatbelt: no `securityd`; keychain files are denied by default and can't be granted from a request | The same probe returns nothing. A token set only in Claude's own settings isn't seen, so the keychain is still granted then. A rule you write yourself in a policy file could still open the encrypted keychain database | `agents::tests::keychain_only_without_a_login_in_the_environment`, `sandbox_mach_services`, `scripts/probes/keychain-deputy.sh` |
| Killing or tracing the supervisor | PARTIALLY ENFORCED | Kernel sandbox survives supervisor death | Enforcement continues; auditing stops | [threat-model.md](threat-model.md) T5 |
| An agent approving its own network requests | ENFORCED | Approvals live in the state directory, which agents can't write | | `sandbox_writes_and_exec_persistence` (state dir), `netlive::tests` |
| The console being driven by a web page or an agent | ENFORCED | Localhost only, one-time link, HttpOnly per-port cookie plus a custom header, strict Host/Origin/CSP; the proxy refuses the console's port | | `ui::tests::*`, `netproxy::tests::ui_port_is_always_refused` |
| Audit completeness | PARTIALLY ENFORCED | Kernel violation reports + proxy | Kernel reports are rate-limited, so denial counts are a lower bound. Enforcement is unaffected | [macos-enforcement.md](macos-enforcement.md) §2.3 |

## Checking your own setup

`agentacl audit` (and the console's Agents page) reports what an agent
would reach on *your* Mac, from the same rules `agentacl run` loads:
credential files and cloud drives (protected or readable), company data
services reachable over the network (Google APIs, Dropbox, Box, Microsoft
365, Slack, Notion, Atlassian, GitHub, S3, each on several hosts), MCP
servers (Claude Code, Codex, Cursor, Gemini, VS Code, Windsurf, Claude
Desktop configs) and tokens written into their configs, keychain access,
secret environment variables and grants made from the console. It is a
report, not a control. It finds tokens by name (in `env`, headers,
`--token`-style arguments and URL parameters), so a value under an unusual
name isn't flagged. It never prints a secret value or a drive account
(`exposure::tests`, `ui::tests::audit_endpoint`).

## Reading this table honestly

- ENFORCED means "for supervised agents, with a test". It does not mean
  "system-wide".
- The enforcement backend today is macOS Seatbelt (`sandbox-exec`), the
  same deprecated-but-shipped mechanism major agent vendors use. AgentACL
  didn't invent it; it compiles policy into it.
- No authorization decision uses a language model. Every decision is made by
  deterministic code from your policy.
- Found a gap? Please report it privately: [SECURITY.md](../SECURITY.md).
