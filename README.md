# AgentFence

Identity, authorization and audit for AI coding agents on macOS.

Humans have identity. Machines have identity. Workloads have identity.
AgentFence gives **AI agents** their own identity. It knows which agent is
running, for which human, in which project, and what it spawned. It then
enforces a policy on what that agent can touch. Enforcement happens in the
kernel, not in the agent's own instructions.

```
$ agentfence run -- claude
...
> cat .env
cat: .env: Operation not permitted

$ agentfence events --follow
AGENTFENCE DENIED

Agent:      Claude Code
Action:     Read
Resource:   /Users/you/src/app/.env
Chain:      claude-code → zsh → cat
Policy:     protect-secrets (env-files)
Reason:     Environment secret files are protected
```

## What it does

- **Discovers agents.** `agentfence discover` finds Claude Code, Codex, Gemini
  CLI, Copilot CLI and OpenCode, installed or running. It identifies each one by
  code signature, executable path or package entry point, never by process
  name alone. Running agents that AgentFence isn't supervising are flagged.
- **Gives each run an identity.** A session (`agt_…`) records the human, the
  machine, the agent and its version, the binary and its hash, the signer, the
  project and the policy hash.
- **Enforces policy in the kernel.** `agentfence run` launches the agent inside a
  Seatbelt sandbox compiled from YAML policy. The sandbox covers every process
  the agent spawns, and it keeps enforcing even if AgentFence itself dies.
  Explicit deny always wins.
- **Protects secrets by default.** Built-in rules cover:
  - `.env*`
  - `~/.ssh`
  - AWS, GCP and Azure credentials
  - kubeconfig
  - Terraform state and credentials
  - git and package-registry credentials
  - private keys and GPG

  Built-ins also block:
  - the ssh-agent and docker sockets
  - secret environment variables such as `*_TOKEN` and `AWS_*`
  - writes to files that later run outside the sandbox: `.git/config`, hooks,
    shell rc files, LaunchAgents and agent hook configs
- **Controls network egress.** All traffic is forced through a local proxy that
  enforces a host allowlist. The proxy resolves names only after the host is
  allowed, and refuses loopback, link-local and private addresses unless an
  address rule names them.
- **Audits honestly.** Every decision goes to a local SQLite log, and
  `agentfence events --json` prints it as NDJSON.
  - An event is marked `enforced` only when the kernel or the proxy actually
    refused the operation.
  - Rules the MVP can't enforce, such as `git push *`, are logged as
    **OBSERVED — NOT BLOCKED**.

## Enforced vs. observed (MVP)

| Control | Status |
|---|---|
| Reading and writing secrets, and writes outside the project | **Enforced** (kernel). Symlinks, case variants, hard-link creation, rename-then-read and move-away-and-back are all covered |
| Network egress by host | **Enforced** (proxy + sandbox egress lock) |
| Running a denied executable (`terraform *`) | **Enforced**, by executable name and path |
| ssh-agent and docker sockets | **Enforced** |
| Keystroke injection into your terminal | **Enforced**: the agent runs on its own pty, and `TIOCSTI` is denied |
| Argument-level rules (`git push *`, `kubectl delete *`) | **Observed only**. Needs Endpoint Security |
| Agents not started with `agentfence run` | **Observed only** (`discover`, `agents --all`) |
| Escapes through other apps (Apple Events, `open -a`) | Mitigated by a Mach-service allowlist. **Not fully closed** |

`docs/macos-enforcement.md` has the full matrix, and `docs/threat-model.md`
has the threat list.

## Install

Requirements: macOS on Apple Silicon or Intel, and Rust 1.85 or later.

```sh
cargo install --path crates/agentfence-cli
```

## Usage

```sh
agentfence discover                      # installed and running agents
agentfence run -- claude                 # launch Claude Code under supervision
agentfence run --dry-run -- claude       # show identity, rules and the sandbox profile
agentfence agents [--all]                # supervised sessions (and unsupervised agents)
agentfence status                        # backend, capabilities, active sessions
agentfence policy check                  # effective rules and how each is enforced
agentfence policy check --path .env      # evaluate a single request, with a trace
agentfence events [--follow] [--json]    # audit log
```

## Policy

Your policy lives at `~/.config/agentfence/policy.yaml`. When it's absent, a
built-in default applies: the project is readable and writable, everything
else is denied, and network is deny-by-default. Example:

```yaml
version: v1
defaults:
  filesystem: deny
  network: deny
  process: allow
filesystem:
  allow_read:  ["${PROJECT}/**"]
  allow_write: ["${PROJECT}/**"]
process:
  deny: ["sudo *"]
  require_approval: ["terraform apply *", "git push *"]
network:
  allow: ["api.anthropic.com", "github.com", "*.githubusercontent.com"]
```

A repository can ship `.agentfence/policy.yaml`, but that file can only
**restrict**: it can't widen access unless you trust its exact hash in
`~/.config/agentfence/config.yaml`. The full language is described in
`docs/policy-model.md`.

## Known limitations

- **Seatbelt limits.** Seatbelt (`sandbox-exec`) is deprecated by Apple, but
  it's what the major agent vendors use. The Endpoint Security backend is
  designed (`docs/macos-enforcement.md` §3) but not built. It needs Apple's
  `com.apple.developer.endpoint-security.client` entitlement.
- **The sandbox profile is fixed at launch.** A policy change applies to the
  next session.
- **No interactive approval yet.** Filesystem `ask` rules fail closed, and
  argument-level process rules are observed only.
- **Agents that sandbox themselves can't nest inside AgentFence.** AgentFence
  becomes the outer boundary. The Codex provider passes
  `--sandbox danger-full-access` for this reason. For Claude Code, leave its
  own sandbox setting off.
- **Claude Code needs keychain access.** It keeps its login in the macOS
  keychain, so its provider grants read access to the keychain files and
  securityd. Keychain items stay protected by their ACLs. To avoid this, use
  `ANTHROPIC_API_KEY`.
- **Git config is locked during sessions.** Commands that edit `.git/config`
  (`git remote add`, `git push -u`) and interactive rebase fail inside a
  session. This is deliberate: those files run code outside the sandbox.

## Layout

```
crates/agentfence-policy   pure policy engine: parse, expand, match, evaluate (no I/O)
crates/agentfence-core     agents, process facts, identity, Seatbelt backend, proxy, supervisor, audit
crates/agentfence-cli      the `agentfence` binary
docs/                      architecture, threat model, policy model, macOS enforcement
```

## License

Apache-2.0
