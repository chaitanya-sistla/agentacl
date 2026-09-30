# AgentACL guide

**Access control for AI coding agents on macOS.** AgentACL runs Claude Code,
Codex, Gemini CLI, Copilot CLI and OpenCode inside a kernel sandbox. They can
work on your project, but they can't read your SSH keys, cloud credentials,
`.env` files or browser cookies. Every block is recorded.

```
$ agentacl run -- claude
> cat .env
cat: .env: Operation not permitted

AgentACL session agt_01M3R5TD4JXJNHSNNFS45QM0BK ended (exit 0)
  Blocked by policy: 1    Blocked by sandbox default: 0    Observed (not blocked): 0
  BLOCKED   filesystem.read  /Users/you/src/app/.env (protect-secrets/env-files)
  Withheld environment variables: SSH_AUTH_SOCK
```

## Why

A coding agent runs shell commands **as you**. Anything you can read, it can
read: `~/.ssh`, `~/.aws/credentials`, `.env`, Terraform state, your browser's
saved logins. It can also send that data anywhere on the internet. Instructions
such as "don't read secrets" and the agent's own settings are not security
boundaries: a prompt injection in a README, an issue or a dependency can
override them.

AgentACL puts the boundary **outside the agent**, in the macOS kernel:

| | Without AgentACL | With AgentACL |
|---|---|---|
| Agent reads `~/.ssh/id_ed25519` | Succeeds | `Operation not permitted` (kernel) |
| Agent reads `.env` in your project | Succeeds | Blocked; project files stay readable |
| Agent uploads to an unknown host | Succeeds | Refused by the egress proxy |
| Agent edits `.git/hooks` or `~/.zshrc` to run code later | Succeeds | Blocked |
| Child processes (`sh`, `python`, `curl`) | Inherit everything | Inherit the same sandbox |
| You find out what happened | You don't | Every block is in the audit log, with agent, process chain and rule |
| An agent is running unprotected | Invisible | `agentacl discover` and the console flag it |

## Guarantees

Each statement below is either enforced or explicitly marked as not enforced.

- **Enforced by the kernel** (macOS Seatbelt) for the agent **and every
  process it starts**:
  - reading and writing protected files (symlinks, case variants, hard links
    and rename tricks are covered);
  - writes outside the project;
  - running denied programs (by executable path);
  - access to the ssh-agent and docker sockets;
  - keystroke injection into your terminal.
- **Enforced by the proxy:** network access by host. Private, loopback and
  link-local addresses are refused unless a rule names them.
- **Precedence is fixed.**
  - An explicit block always wins over an allow.
  - Built-in protections always win over your rules.
  - A repository's own policy can only **restrict**, never widen.
- **Observed, not enforced:**
  - argument-level rules such as `git push *` (these need Apple's Endpoint
    Security entitlement);
  - agents you started without `agentacl run`.

  These are labelled **OBSERVED — NOT BLOCKED** and are never reported as
  blocked.
- **Fixed at launch:** a running agent keeps the rules it started with (a
  Seatbelt property). A restart applies changes; Claude Code resumes its
  conversation.

[`macos-enforcement.md`](macos-enforcement.md) has the full matrix, and [`threat-model.md`](threat-model.md)
lists every threat considered.

## Install

Requirements: macOS 13 or later, on Apple Silicon or Intel.

Download the latest release from
[Releases](https://github.com/chaitanya-sistla/agentacl/releases/latest).
Each release is built by GitHub Actions from a tagged commit on `main`. It
ships a universal binary, per-architecture binaries, `SHA256SUMS` and a
build-provenance attestation.

```sh
V=0.1.0
curl -LO https://github.com/chaitanya-sistla/agentacl/releases/download/v$V/agentacl-$V-macos-universal.tar.gz
curl -LO https://github.com/chaitanya-sistla/agentacl/releases/download/v$V/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing          # must print: OK
gh attestation verify agentacl-$V-macos-universal.tar.gz -R chaitanya-sistla/agentacl   # optional
tar xzf agentacl-$V-macos-universal.tar.gz
sudo install -m 755 agentacl-$V-macos-universal/agentacl /usr/local/bin/agentacl
agentacl --version                                     # agentacl 0.1.0
```

Or build from source (Rust 1.85 or later):

```sh
cargo install --locked --git https://github.com/chaitanya-sistla/agentacl agentacl-cli
```

## Quick start

```sh
cd ~/src/my-app
agentacl discover                 # which agents are installed and running
agentacl run -- claude            # start Claude Code protected (any agent works: codex, gemini, …)
agentacl ui                       # open the console in your browser
```

To always start an agent protected, add an alias, e.g.
`alias claude="agentacl run -- claude"`.

Check a decision without running anything:

```
$ agentacl policy check --path ~/.ssh/id_ed25519
Decision:  DENY
Policy:    protect-secrets (ssh)
Reason:    SSH keys and configuration are protected
```

## Protected by default

| Group | What |
|---|---|
| `env-files` | `.env`, `.env.*` (except `.env.example` and similar), `.envrc`, anywhere |
| `ssh` | `~/.ssh/**` |
| `aws`, `gcp`, `azure` | `~/.aws/credentials`, SSO and CLI caches, `~/.config/gcloud/**`, `~/.azure/**` |
| `kube` | `~/.kube` |
| `terraform` | `*.tfstate`, `terraform.tfvars`, `~/.terraform.d/credentials.tfrc.json` |
| `git-creds`, `package-creds` | `~/.git-credentials`, `gh` tokens, `.npmrc`, `.pypirc`, `.netrc`, docker and cargo credentials |
| `keys`, `gpg` | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `~/.gnupg/**` |
| `browsers` | Chrome, Brave, Edge, Arc, Firefox and Safari profiles, `~/Library/Cookies` |
| *always on* | git config and hooks, shell startup files, LaunchAgents, agent settings, AgentACL's own files; secret environment variables (`*_TOKEN`, `AWS_*`, …) are withheld |

A secret group can be switched off in the console or with
`builtin: { disable: [browsers] }`. An allow rule under a group has no effect
while the group is on, and `agentacl policy check` warns when you write one.

## Console

`agentacl ui` opens a local console at `127.0.0.1`. It works from any
directory and covers the whole machine.

- **Overview:** blocks in the last 24 hours, and agents running with or
  without protection.
- **Agents:** installed and running agents. Restart or stop a protected
  agent, or see how to protect an unprotected one.
- **Projects:** every folder agents work in, with project-only rules.
- **Policies:**
  - an **access graph** from agent → areas → folders and files, coloured by
    what the agent can do;
  - a rules editor with Finder pickers;
  - built-in protection switches;
  - an access tester and the raw YAML.
  
  **Review & save** shows exactly what changes, then offers to restart the
  agents still using the old rules.
- **Activity:** the audit log, with filters, pagination and CSV export.

The console opens with a single-use link. Supervised agents can't reach it,
and it can do nothing the CLI can't (`ui.md`).

## Policy

Rules live in `~/.config/agentacl/policy.yaml` (all projects) and optionally
in `<project>/.agentacl/policy.yaml` (restrict-only). With no file, the
built-in default applies:
- the project is readable and writable;
- everything else is blocked;
- the network is blocked except what each agent needs.

```yaml
version: v1
defaults:
  filesystem: deny
  network: deny
  process: allow
filesystem:
  allow_read:  ["${PROJECT}/**", "${HOME}/shared-docs/**"]
  allow_write: ["${PROJECT}/**"]
  deny_read:   ["${PROJECT}/customer-data/**"]
process:
  deny: ["sudo *", "terraform apply *"]
network:
  allow: ["github.com", "*.githubusercontent.com", "registry.npmjs.org"]
```

[`policy-model.md`](policy-model.md) describes the full language, including variables,
globs, `except`, `match.agents` and trusting a repository's policy by hash.

## Commands

```
agentacl discover                     installed and running agents (unprotected ones flagged)
agentacl run [--dry-run] -- <agent>   run an agent protected; --dry-run prints identity, rules and sandbox profile
agentacl ui                           local console
agentacl status                       backend, capabilities, active sessions
agentacl agents [--all]               supervised sessions (and unsupervised agents)
agentacl policy check [--path|--exec|--host X]   effective rules, or one decision with its trace
agentacl policy trust --sha256 <sha>  let this project's policy widen access (exact bytes only)
agentacl events [--follow] [--json]   audit log (NDJSON with --json)
agentacl restart [session]            relaunch under current rules, conversation kept
agentacl stop [session]               stop a supervised agent
```

## Limitations

- **Seatbelt.** `sandbox-exec` is deprecated by Apple but is what the major
  agent vendors use. The Endpoint Security backend is designed, not built: it
  needs Apple's `com.apple.developer.endpoint-security.client` entitlement.
- **No interactive approval yet.** `ask` rules fail closed.
- **Nesting.** Agents that sandbox themselves can't nest inside AgentACL, so
  AgentACL becomes the outer boundary. Codex runs with
  `--sandbox danger-full-access`; leave Claude Code's own sandbox off.
- **Keychain.** Claude Code keeps its login in the keychain, so its provider
  can reach keychain files and `securityd`. Items stay protected by their
  ACLs. Use `ANTHROPIC_API_KEY` to avoid this.
- **Git config.** `git remote add`, `git push -u` and interactive rebase fail
  inside a session, by design: those files run code outside the sandbox.

## Releases

- Versions follow [Semantic Versioning](https://semver.org).
- `CHANGELOG.md` records every release, and a release is published only when
  every check passes. [`releasing.md`](releasing.md) describes the process.
- Tags are `vX.Y.Z` (or `vX.Y.Z-rc.N` for pre-releases).

## Development

```sh
git config core.hooksPath .githooks   # authorship and format checks on commit/push
scripts/check.sh                      # every CI check, locally
cd crates/agentacl-cli/web && npm ci && npm run build   # rebuild the console (output is committed)
```

```
crates/agentacl-policy   policy engine: parse, expand, match, evaluate (no I/O)
crates/agentacl-core     agents, identity, Seatbelt backend, proxy, supervisor, audit
crates/agentacl-cli      the agentacl binary and the console (web/ is its React source)
docs/                    architecture, threat model, policy model, macOS enforcement, console
```

AgentACL is written and maintained by Chaitanya Sistla; every commit is his.
CI rejects commits by anyone else or with co-author or tool-attribution
trailers. Issues and ideas are welcome.

## License

Apache-2.0. See `LICENSE`.
