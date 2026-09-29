# AgentFence Threat Model

Status: design, iteration 1 (MVP = Seatbelt backend + proxy). The ES column
shows what changes with the Endpoint Security backend (macos-enforcement.md §3).

## 1. What we protect

| Asset | Examples |
|---|---|
| Credentials and secrets | `.env*`, `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config`, Terraform credentials and state, git/npm/pypi/docker credentials, GPG keys |
| Code and data outside the project | Other repos, `~/Documents`, and the rest of `$HOME` |
| Credential-bearing channels | The ssh-agent socket, the Docker socket, keychain, cloud metadata endpoints |
| AgentFence itself | Policy files, the SQLite audit log, the supervisor process, and sandbox profiles |
| Integrity of the audit trail | Events are complete enough to reconstruct what an agent tried and what was stopped |

## 2. Actors and trust

| Actor | Trust |
|---|---|
| **Human user** (uid running `agentfence run`) | Trusted. They own the machine and write the user policy. AgentFence doesn't defend against the user |
| **AI agent session** and all its descendants | **Untrusted.** Treat it as if it were prompt-injected: it may actively try to read secrets, exfiltrate data, disable AgentFence, or escape supervision. It runs as the **same uid** as the human |
| Repository content (including `.agentfence/policy.yaml`) | Untrusted. Written by whoever authored the repo |
| Other local software, macOS, the kernel | Trusted |
| Root-level malware | Out of scope |

Key constraint: **same uid.** Unix permissions give nothing here. Every boundary
comes from the kernel sandbox (MVP) or ES (later).

## 3. Threats

Status legend: **M** = mitigated in the MVP, **P** = partially mitigated,
**O** = open / accepted, **ES** = closed by the Endpoint Security backend.

| # | Threat | MVP mitigation | Status | With ES |
|---|---|---|---|---|
| T1 | Agent reads secret files directly | Seatbelt deny rules from `protect-secrets`, compiled last (deny wins) | M | M |
| T2 | Path tricks: symlink, hard link, case variants, `/tmp` vs `/private/tmp`, `..`, rename-then-read | Kernel checks the resolved vnode path; patterns are canonicalized; matching is case-insensitive. Verified: symlink, case, and *creating* a hard link are denied. Rename-then-read is closed by the implied rename/unlink/link deny (policy-model §4). **Pre-existing hard links**: at startup the supervisor checks `st_nlink` on every concrete protected path and on every protected file found by walking `${PROJECT}`. If it finds `st_nlink > 1`, `run` **refuses to start** unless the user passes `--accept-hardlink <path>`, which is recorded in the session. Residual: glob-protected files elsewhere in `${HOME}` are not walked, and a link to one in `/private/tmp` would be readable | P | P |
| T3 | Rename an ancestor directory to move a secret out from under a path rule | Compiler denies unlink/rename of ancestor literals of every anchored secret path. Verified necessary and effective | M | M |
| T4 | Tampering with AgentFence: editing the policy, SQLite log or profile, or adding allows to the project policy | Sandbox denies writes to the state dir, user policy and `${PROJECT}/.agentfence/**`; project policy is restrict-only; the profile is read before exec | M | M |
| T5 | Killing or ptracing the supervisor | The sandbox is kernel-attached and survives supervisor death, so **enforcement continues**; only auditing stops. SBPL `signal` targets parse (verified), but `(target self)`+`(target children)` also stops grandchildren from signalling the agent, which breaks job control (verified). Plan: the agent is the session leader on a supervisor-owned pty (architecture §5), with `(target pgrp)`. If that breaks real agents, signal protection is dropped and this row stays P. The supervisor is signed with hardened runtime and without `get-task-allow` | P | M (`AUTH_SIGNAL`, `AUTH_GET_TASK`, `AUTH_PROC_SUSPEND_RESUME`) |
| T6 | Using credentials without reading them: ssh-agent (`SSH_AUTH_SOCK`), gpg-agent, `docker.sock` (≈ root-equivalent via bind mounts), keychain via `securityd` | `SSH_AUTH_SOCK`/`GPG_AGENT_INFO` removed from the env **and** a `(remote unix-socket (path-literal …))` deny on the sockets. The latter is verified to work, including through symlinks/hard links. Keychain: exec-denying `git-credential-osxkeychain` is **not** a boundary. The boundary is whether the Mach service `com.apple.SecurityServer` is in the allowlist. Agents that store their login in the keychain (Claude Code) need it, which leaves T9 | P | M (`AUTH_UIPC_CONNECT`, `AUTH_EXEC`) |
| T7 | **Escape via launchd/XPC/Apple Events**: asking another, unsandboxed process to act (`osascript` → Terminal `do script`, `open -a`, `launchctl`, login items) | The main lever is the Mach-service allowlist under `(deny default)` (macos-enforcement §2.2). `launchservicesd`, `appleevents`, pasteboard, `mds`, and `nsurlsessiond` are excluded. Writes to LaunchAgents and shell rc files are denied (`exec-persistence` built-in). Verified: `deny appleevent-send` alone does **not** stop `osascript` → Finder. Each excluded service needs a probe in the E2E suite | **O** until the probes pass | P: `AUTH_EXEC` can deny the agent tree from exec'ing `osascript`/`open`/`launchctl`, but the resulting unsandboxed process is **not** re-linkable via `responsible_audit_token` (its responsible process is Terminal/launchd) |
| T8 | Network exfiltration to arbitrary hosts, including DNS tunnelling | All egress except the proxy is denied (DNS included, verified); the proxy enforces the host allowlist | M | M |
| T8a | **Inbound exfiltration**: a sandboxed process listens on a port and something outside the sandbox reads from it (verified with `nc -l` under an egress-only profile) | `network-bind`/`network-inbound` are on the never-allow list except loopback ports in `network.listen` | M | M |
| T9 | Exfiltration **through an allowed host** (e.g. a gist on `github.com`, or reading keychain items the agent already has access to) | None. Allowed means allowed. Keychain access goes through `securityd` over Mach, and the agent may need it for its own login | O (documented) | O (needs NE + TLS inspection; out of scope) |
| T10 | Argument-level abuse (`git push --force`, `terraform destroy`) | Observed only; events are `enforcement=observed` (shown as NOT BLOCKED). Executable-level deny is enforced | P | M (`AUTH_EXEC` argv) |
| T11 | Copying or renaming a denied binary (`cp …/terraform ./tf`) to dodge path-based exec deny | Not caught by path. Note: *setuid/setgid* binaries (`sudo`, `su`, `ps`, `login`) can't be exec'd under any Seatbelt profile at all (`forbidden-exec-sugid`, verified), so `sudo` is denied regardless of policy | P | M (matching by `signing_id`/`cdhash`) |
| T12 | Agent runs outside `agentfence run` | `discover` / `agents --all` report it as **UNSUPERVISED** | O (observed) | M (system-wide ES, matched by signature) |
| T13 | Spoofing agent identity (`AGENTFENCE_SESSION`, fake process name) | Session membership comes from the process tree, not the env; agent identity comes from path + hash + code signature, not the process name | M (for launch) | M |
| T14 | PID reuse confusing attribution | Tree nodes are keyed by `(pid, start_time)`, and log events are matched on pid within the node's lifetime | P | M (`audit_token` includes pidversion) |
| T15 | Log-stream loss (rate limits, parse errors, supervisor dead) → incomplete audit | Documented lower bound; `backend_warning` events; enforcement unaffected | P | M |
| T15a | **Forged denial events**: any process can `os_log` a line that looks like `Sandbox: cat(…) deny(1) …` (verified with a dylib named `Sandbox`) | The log predicate requires `processIdentifier == 0` (kernel) as well as `sender == "Sandbox"`. Worst case for a forger is a fake *deny* in the log, never a fake allow | M | M |
| T15b | **Terminal/notification spoofing**: attacker-chosen file names containing ANSI/OSC escape sequences are rendered by `events --follow`, the summary, or `--notify`. They can hide lines or write to the clipboard (OSC 52) | All renderers escape control characters (C0/C1, ESC) in every attacker-influenced field | M | M |
| T15c | **TTY injection**: a sandboxed process pushes keystrokes into the human's terminal (`TIOCSTI`) | The agent runs on a supervisor-owned pty, not the human's TTY. `hid-control` is on the never-allow list (verified: denied under `(deny default)`) | M | M |
| T16 | Malicious project policy widening access | Restrict-only unless trusted by hash | M | M |
| T17 | Malicious agent binary substitution (`claude` on PATH points elsewhere) | `discover`/`run` show the resolved path and signer; an unexpected signer for a known agent id is flagged with a prominent warning; a policy may require `team_id` | P | M |
| T18 | TOCTOU between the policy check and the operation | No separate check: the kernel decides at syscall time | M | M |
| T19 | **Delayed execution outside the sandbox**: the agent writes a file that a tool later executes on the *human's* behalf, unsandboxed. Verified vectors: `.git/config` `core.fsmonitor`, `.git/commondir`, and swapping `.git` for a gitfile, each triggered by the human's next `git status`. Also: `.git/hooks`, direnv `.envrc`, shell rc files, LaunchAgents, project agent configs (`.claude/`, `.mcp.json`, `.codex/`, `.vscode/`), `package.json` scripts, `Makefile`, and user-level agent hook/MCP configs and the scripts they reference, when used by a later *unsupervised* session | The `exec-persistence` built-in (policy-model §5): git dirs are write-denied except an allowlist of data files, the `.git` entry itself can't be replaced, project and user agent configs are write-denied, and referenced hook scripts are write-denied. Files that must stay writable (build scripts, `~/.claude.json`) are hashed at session start and end, and the summary lists changes as **REVIEW BEFORE RUNNING** | P (pending E2E probes for each vector; build files are inherently code the human runs) | P |
| T20 | **Orphaned descendants** keep running after the agent exits (double-fork / `&`). They stay sandboxed but aren't audited (verified) | The agent is the session leader on a supervisor-owned pty (architecture §5). At session end the supervisor sends SIGTERM then SIGKILL to every tracked descendant. Unobserved short-lived forks may survive; they remain sandboxed | P | M (tree is exact) |

## 4. Out of scope (iteration 1)

- Root or kernel compromise, SIP-disabled machines, physical access.
- Attacks by the human user on AgentFence.
- Confidentiality of data the policy explicitly allows the agent to read, and
  exfiltration via allowed destinations (T9).
- Prompt-injection detection. AgentFence constrains **capability**, not intent,
  and no decision uses an LLM.
- GUI agents (Cursor app, IDE-embedded agents) launched outside `agentfence run`.
  They're discoverable, but not supervised in the MVP.

## 5. Security invariants (tested)

1. Every emitted SBPL profile places all deny rules after all allow rules.
2. Adding an allow rule never flips an *explicit* deny (property test on the evaluator).
3. `run` never starts the agent if policy loading, expansion, profile
   generation, or `sandbox-exec` fails.
4. No event with `enforcement=enforced` is produced except from a kernel sandbox
   report (pid 0, sender `Sandbox`) or a proxy decision.
5. The built-in `protect-secrets`, `exec-persistence` and `agentfence-self` rules are present in
   every compiled profile unless `builtin.disable` names the group; `agentfence-self` and
   `exec-persistence` can't be disabled.
6. No generated profile contains an allow for an item on the never-allow list (policy-model §5.1).
