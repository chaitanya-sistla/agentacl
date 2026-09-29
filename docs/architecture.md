# AgentFence Architecture

Status: design, iteration 1 (pre-implementation). Platform: macOS only.

AgentFence gives AI coding agents their own identity, and it authorizes what they
do on a developer machine. This document covers the component boundaries, the
language choice, the data flow of `agentfence run`, and the repository layout.
Companion documents:

- [threat-model.md](threat-model.md): what we defend against and what we don't
- [policy-model.md](policy-model.md): the policy language and how it is evaluated
- [macos-enforcement.md](macos-enforcement.md): Seatbelt now, Endpoint Security later, and exactly what each one can enforce

## 1. Principles

1. **An agent is a principal.** Each agent session gets an identity that is
   separate from the human who launched it: an agent, a session, a delegation
   chain, and the human it acts for.
2. **Deterministic authorization.** Every decision comes from a pure function of
   (policy, identity, action, resource). No LLM, no heuristics and no network
   calls happen on the decision path.
3. **Explicit deny wins.** Allows never override an explicit deny. See the policy model.
4. **Honest enforcement.** Every event carries a `decision` (`allow` / `deny` /
   `ask`) and an `enforcement` (`enforced` / `observed`). `enforced` is set only
   when a kernel mechanism (Seatbelt today, Endpoint Security later) or an
   AgentFence-owned choke point (the network proxy) actually made that decision
   take effect. A `deny` + `observed` event is rendered as **OBSERVED — NOT
   BLOCKED**. The CLI must never overstate what it did.
5. **Fail closed for sensitive resources.** If AgentFence can't build a sandbox
   profile, can't resolve `${PROJECT}`, or can't load the built-in secret
   policy, `agentfence run` refuses to start the agent. It never starts the agent unconfined.
6. **Local-first.** No servers, no accounts, no Docker. State lives under
   `~/Library/Application Support/AgentFence/`.

## 2. Language decision

The MVP needs a CLI, process introspection (libproc/sysctl), code-signature
checks (Security.framework), a policy engine, SQLite and a small HTTP CONNECT
proxy. Later it needs an Endpoint Security (ES) client that answers AUTH events
within a kernel deadline.

| Criterion | Rust | Go |
|---|---|---|
| Memory safety on a security-critical path | Yes, with no GC | Yes, with GC |
| Embedding the policy engine inside the ES extension (C ABI) | Natural: a `staticlib` with an `extern "C"` API and no runtime | `-buildmode=c-archive` works, but it pulls the Go runtime, its threads, signal handlers and GC into the extension process |
| Latency predictability for AUTH deadlines | No GC pauses | GC pauses are small but nonzero, and there's a scheduler in the loop |
| macOS FFI (libproc, sysctl, Security.framework, ES headers) | `libc`, `security-framework`, bindgen; the `endpoint-sec` crate exists | cgo; ES handler **blocks** are awkward from cgo |
| Iteration speed and contributor pool | Slower compile, steeper curve | Faster, simpler |
| YAML | Weak spot: `serde_yaml` is deprecated. Use a maintained fork (`serde_yaml_ng` / `serde_norway`), pinned | `go.yaml.in/yaml/v3` is fine |
| SQLite | `rusqlite` (bundled) | `modernc.org/sqlite` (pure Go) or `mattn` (cgo) |

**Decision: Rust for the core (CLI, supervisor, policy engine, audit), plus a
small Swift system extension for Endpoint Security later.**

The deciding factor is **one policy evaluator**. The ES extension has to make
AUTH decisions in-process, because a user-space IPC round trip per `open(2)` is
too slow and fragile under ES deadlines. If the core were Go, we'd either embed
a Go runtime in the system extension or reimplement the evaluator in Swift. The
second option gives us two evaluators that will drift apart, and in an
authorization system drift is a vulnerability. With Rust, the `agentfence-policy`
crate compiles into the CLI and, unchanged, into a `staticlib` that the Swift
extension links.

Why the ES client itself is Swift (or Objective-C) and not Rust:

- The ES API is block-based C (`es_new_client` takes a handler block), and
  Apple's samples, entitlement flow, system-extension packaging
  (`OSSystemExtensionRequest`), notarization and Xcode signing all assume a
  Swift or Objective-C target inside an `.app` bundle.
- Keeping the extension a **thin sensor/enforcer** means the Swift code only
  does four things: receive an ES message, marshal it into a C struct, call
  `af_policy_evaluate()`, and respond. It has little logic and is easy to audit.

Rejected alternative: all-Swift. It gives the best macOS integration, but
it's a poor fit for a portable, cross-platform core (a future `LinuxBackend`), and a
weaker CLI and library ecosystem.

## 3. Components

```
                        ┌───────────────────────────────────────────────┐
  agentfence CLI ──────▶│ agentfence-core                               │
  (clap)                │  config   paths, policy file discovery        │
                        │  agents   AgentProvider registry + providers  │
                        │  proc     libproc/sysctl, codesign, proc tree │
                        │  identity Human, Machine, AgentIdentity       │
                        │  session  Session lifecycle, agt_ ids         │
                        │  enforce  EnforcementBackend trait            │
                        │     ├─ seatbelt  (MVP, real enforcement)      │
                        │     └─ endpoint_security (stub: Unavailable)  │
                        │  netproxy CONNECT proxy (network allowlist)   │
                        │  supervisor  wires it together for `run`      │
                        │  audit    Event model + SQLite store          │
                        └──────────────┬────────────────────────────────┘
                                       │ uses
                        ┌──────────────▼────────────────────────────────┐
                        │ agentfence-policy (no I/O, no macOS deps)      │
                        │  parse YAML → Policy → compile → evaluate      │
                        │  PolicyEngine trait (native now, OPA later)    │
                        │  built-ins: protect-secrets, runtime, default  │
                        └───────────────────────────────────────────────┘
        later:  macos/AgentFenceES (Swift system extension) ──links──▶ agentfence-policy (staticlib + C ABI)
```

| Module | Responsibility | Depends on |
|---|---|---|
| `config` | Resolves state dir, policy search path (built-in → `~/.config/agentfence/policy.yaml` → `<project>/.agentfence/policy.yaml`), and CLI flags | none |
| `agents` | `AgentProvider` trait and one provider per agent; `discover()` over installed binaries and running processes | `proc` |
| `proc` | macOS process facts: pid list, ppid, executable path (`proc_pidpath`), argv (`KERN_PROCARGS2`), start time, code-signing identity (team ID, signing ID, cdhash) and SHA-256 | libc, Security.framework |
| `identity` | Plain data types: `Human`, `Machine`, `AgentIdentity`, `DelegationChain` | none |
| `session` | Creates `Session` (`agt_` + ULID), persists it and marks it ended | `identity`, `audit` store |
| `policy` (crate) | Parsing, variable expansion, validation, evaluation, enforceability classification | none (pure) |
| `enforce` | `EnforcementBackend` trait; `SeatbeltBackend`; `MacOSEndpointSecurityBackend` stub that reports `Unavailable` | `policy` |
| `netproxy` | Local HTTP CONNECT/HTTP proxy that evaluates `network.*` rules per destination host | `policy`, `audit` |
| `supervisor` | Orchestrates `run`: identify → load policy → create session → prepare backend → spawn → monitor → finalize | everything above |
| `audit` | `Event` schema, SQLite store (WAL), queries for `events` / `status` / `agents` | rusqlite |
| `cli` | Argument parsing, human and `--json` rendering. **No policy logic.** | core |

### 3.1 Key interfaces (sketch)

```rust
// agents
pub trait AgentProvider: Send + Sync {
    fn id(&self) -> &'static str;                 // "claude-code"
    fn display_name(&self) -> &'static str;       // "Claude Code"
    fn match_process(&self, p: &ProcessFacts) -> Option<Match>; // exe, argv, signature, parent
    fn install_candidates(&self, env: &Env) -> Vec<PathBuf>;    // known install paths
    fn runtime_requirements(&self, env: &Env) -> RuntimeReqs;   // paths, hosts, Mach services the agent needs
    fn launch_adjustments(&self) -> LaunchAdjustments;          // e.g. disable the agent's own inner sandbox (nesting fails)
    fn protected_configs(&self, env: &Env) -> Vec<PathBuf>;     // hook/MCP configs: write-denied or diffed (threat T19)
}
pub struct Match { pub confidence: Confidence, pub evidence: Vec<Evidence> }

// policy crate
pub trait PolicyEngine {
    fn evaluate(&self, req: &Request) -> Decision;          // deterministic
    fn explain(&self) -> Vec<RuleEnforceability>;           // for `policy check`
}

// enforce
pub trait EnforcementBackend {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;   // which (action, rule-shape) pairs it can enforce
    fn prepare(&self, session: &Session, policy: &CompiledPolicy) -> Result<LaunchPlan>;
    fn observe(&self, session: &Session, sink: &dyn EventSink) -> Result<ObserverHandle>;
}
```

`Capabilities` lets `agentfence policy check` report, for each rule, whether the
active backend **enforces** it, **observes** it, or **can't see** it. That's
how the product stays honest by construction instead of by convention.

### 3.2 Adding a new agent

1. Create `crates/agentfence-core/src/agents/<name>.rs` implementing `AgentProvider`.
2. Register it in `agents/mod.rs` (a single `vec![...]`).
3. Add fixture-based tests (`ProcessFacts` samples) under `tests/fixtures/agents/`.

Providers are code, not data, because matching needs real logic (argv shapes,
Node entrypoints, and helper processes that must *not* match). The facts they
match on, such as Team IDs, package names and install paths, live as constants
at the top of each provider file.

## 4. Identity model

```json
{
  "session_id": "agt_01J9Z6R8Q3K4M5N6P7Q8R9S0T1",
  "human":   { "user": "chaitanya", "uid": 501 },
  "machine": { "id": "mch_<sha256(IOPlatformUUID)[:16]>", "hostname": "..." },
  "agent":   { "id": "claude-code", "version": "2.1.2",
               "binary": "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
               "binary_sha256": "…", "team_id": "Q6L2SF6YDW", "signing_id": "com.anthropic.claude-code" },
  "pid": 18322, "parent_pid": 18300,
  "project": "/Users/chaitanya/src/ops0",
  "policy":  { "name": "default", "sha256": "…" },
  "backend": "seatbelt",
  "started_at": "2026-09-29T10:12:03Z"
}
```

- **Human**: the uid/username of the process that invoked `agentfence run`. MVP
  trusts the local account and does no further authentication (see threat model).
- **Machine**: a hash of `IOPlatformUUID`. The raw hardware UUID is never stored.
- **Agent**: identified by the provider. Code-signature identity (Team ID +
  signing ID) is the strongest evidence when it exists. For example, the Claude
  Code binary on this machine is signed `Developer ID Application: Anthropic PBC
  (Q6L2SF6YDW)`, even when installed via npm. For script-based agents
  (Node/Bun), the identity is the interpreter **plus** the resolved entry script
  and its package metadata, with the hash taken of the entry script.
- **Project**: the git worktree root of the working directory, else the working
  directory itself. It can be overridden with `--project`. `/`, `$HOME`, and
  **any ancestor of `$HOME`** (e.g. `/Users`) are refused as projects.
- **Session**: `agt_` + a ULID, created by `agentfence run`. It's exported to the
  child as `AGENTFENCE_SESSION` for correlation only. It is **not** an
  authorization input, because the agent could forge it.

### 4.1 Delegation chain

The chain is the list of processes from the supervised agent root down to the
acting process, e.g. `["claude-code", "bash", "terraform"]`. The MVP builds it by
polling the process table (`proc_listallpids` + ppid) every 100 ms and keeping
the tree rooted at the agent's pid in memory, including exited nodes for
attribution. Polling is **observational**: a process that lives for less than
a poll interval may be missed in the recorded chain.

This is safe because enforcement doesn't depend on the tree. The Seatbelt
sandbox is inherited by every descendant through `fork`/`exec` in the kernel,
whether or not we observed it. Under Endpoint Security the chain becomes exact
without polling: every message carries the acting `es_process_t`, with
`audit_token`, `parent_audit_token`, `ppid` and `original_ppid`. Fork
notifications are asynchronous, so membership is decided per message
(macos-enforcement §3.3).

## 5. `agentfence run` data flow (MVP)

```
agentfence run [--project P] [--policy F] [--dry-run] -- claude [args…]
 1. resolve argv[0] on PATH → realpath; provider match → AgentIdentity   (no provider match ⇒ agent id "custom:<basename>", or --agent-id; still fully supervised)
 2. load policies: built-ins (protect-secrets, exec-persistence, agentfence-self, runtime; default if no user policy)
    + user + project (closed schema); expand variables; validate  (any error ⇒ refuse to start)
 3. create Session and its private TMPDIR, persist `session_start` event;
    st_nlink check on protected files (T2: refuse to start on a hit unless --accept-hardlink);
    hash the T19 watch-list files
 4. SeatbeltBackend.prepare() → SBPL profile (policy rules + provider runtime reqs + self-protection)
 5. start netproxy on 127.0.0.1:<ephemeral>; child env gets HTTPS_PROXY/HTTP_PROXY/ALL_PROXY
 6. spawn: /usr/bin/sandbox-exec -f <profile> -- <agent binary> args…
    on a supervisor-owned pty: the agent is session leader + controlling terminal there, and the
    supervisor relays bytes and window size to/from the human's TTY (threat model T15c, T5, T20)
 7. observe (supervisor threads, outside the sandbox):
      a. proc-tree poller          → process.exec events (observed; process rules evaluated → enforcement=observed)
      b. `log stream` Sandbox       → kernel denials tagged `af:<this session>|<policy>|<rule>` → events, enforcement=enforced
      c. netproxy decisions         → network.connect events, decision=allow|deny, enforcement=enforced
 8. forward SIGINT/SIGTERM/SIGWINCH via the pty;
    on child exit: SIGTERM→SIGKILL remaining tracked descendants, flush, `session_end`,
    print summary (denials, observed violations, T19 file changes marked REVIEW BEFORE RUNNING)
```

**Where denials are shown.** The agent owns the terminal (for example, Claude
Code's TUI), so writing a box into its TTY would corrupt the screen. Instead:

- Every decision lands in SQLite immediately, and `agentfence events --follow`
  in another pane shows the `AGENTFENCE DENIED` card live.
- When the session ends, `run` prints a summary with counts, the top denied
  resources, and any observed-but-not-blocked policy violations.

The agent itself sees `EPERM` ("Operation not permitted") from the kernel, which
coding agents already handle and report. Every renderer escapes control
characters in attacker-influenced fields such as paths and argv (threat model T15b).

**No daemon in the MVP.** Each `run` process supervises its own session, and
`status`/`agents` read the shared SQLite store and check pid liveness. A
long-lived `agentfenced` (a per-user LaunchAgent, in Rust) and the root ES system extension come
with Endpoint Security, when there is system-wide state to own. Adding one now
would be infrastructure without a job.

## 6. Commands

| Command | MVP behavior |
|---|---|
| `agentfence discover` | Installed agents (known install paths + PATH + app bundles) and running agent processes, each with evidence: path, signer, version, hash, whether it's supervised |
| `agentfence agents` | Active **supervised** sessions: agent, pid, project, policy. `--all` also lists unsupervised running agents, flagged `UNSUPERVISED` |
| `agentfence status` | Backend in use and its capabilities, ES availability, active sessions and their effective policy |
| `agentfence policy check [--agent A] [--project P]` | Validates and merges policies, prints every effective rule with its enforceability (`enforced` / `enforced-coarse` / `observed` / `requires-es`, policy-model §7), plus the Mach-service allowlist and provider runtime grants. `--path X --action read` evaluates a single request and prints the decision trace |
| `agentfence events [--session S] [--decision deny] [--follow] [--json]` | Audit log. `--json` emits NDJSON, one event per line |
| `agentfence restart [session]` | Relaunches a running session under the current policy. The supervisor gets SIGUSR1, stops the agent (SIGTERM, then SIGKILL after 5 s), reloads policy, and relaunches with the provider's resume args (`claude --continue`). Each launch is a new session with its own id. Needed because a Seatbelt profile can't change after launch |
| `agentfence run [opts] -- <cmd…>` | Supervised launch as in §5. `--dry-run` prints the identity, the compiled profile and the enforceability report without launching. `--keep-env NAME` passes a secret-looking env var through (T21). `--accept-hardlink PATH` acknowledges a hard link to a protected file (T2) |

## 7. Repository layout

```
AgentFence/
├── Cargo.toml                    # workspace
├── crates/
│   ├── agentfence-policy/        # pure: model, parse, expand, glob, evaluate, enforceability
│   │   ├── src/{lib,model,parse,expand,glob,eval,enforceability}.rs
│   │   ├── builtin/protect-secrets.yaml   # data-driven secret rules (include_str!)
│   │   ├── builtin/runtime.yaml           # OS runtime baseline allows
│   │   ├── builtin/default.yaml           # starter policy, used when no user policy exists
│   │   └── tests/
│   ├── agentfence-core/
│   │   └── src/
│   │       ├── config.rs  identity.rs  session.rs  supervisor.rs
│   │       ├── proc/{mod,macos,tree,codesign}.rs
│   │       ├── agents/{mod,claude,codex,gemini,copilot,opencode}.rs
│   │       ├── enforce/{mod,seatbelt,endpoint_security}.rs
│   │       ├── netproxy.rs
│   │       └── audit/{mod,event,store}.rs
│   └── agentfence-cli/           # bin "agentfence": clap + rendering only
│       └── src/{main,render}.rs
├── macos/                        # LATER: Xcode project for the ES system extension (not in iteration 1)
├── docs/{architecture,threat-model,policy-model,macos-enforcement}.md
└── tests/e2e/                    # macOS-only integration tests that exercise sandbox-exec for real
```

Three crates is the minimum that serves a real boundary. `agentfence-policy`
must stay I/O-free so it can be linked into the ES extension. The CLI stays
thin so the core is testable without a terminal.

## 8. Storage

`~/Library/Application Support/AgentFence/agentfence.db` (SQLite, WAL mode):

Event shape (the `--json` output; one object per line):

```json
{
  "id": "evt_01J9Z7…", "timestamp": "2026-09-29T10:14:22.311Z",
  "human": "chaitanya", "machine": "mch_3f2a…", "agent": "claude-code", "agent_version": "2.1.2",
  "session": "agt_01J9Z6…", "pid": 18410,
  "delegation_chain": ["claude-code", "bash", "cat"],
  "action": "filesystem.read", "resource": "/Users/chaitanya/src/ops0/.env",
  "decision": "deny", "enforcement": "enforced", "backend": "seatbelt", "source": "sandbox-log",
  "policy": "protect-secrets", "rule_id": "env-files",
  "reason": "Environment secret files are protected"
}
```

`source` ∈ `sandbox-log | proxy | proc-monitor | supervisor | es`. Lifecycle
events (`session_start`, `session_end`, `backend_warning`) use the same envelope
with `action` set to the event kind.

- `sessions(session_id PK, identity_json, policy_sha256, backend, started_at, ended_at, exit_code)`
- `events(id PK, ts, session_id, action, resource, decision, enforcement, backend, source, policy, rule_id, reason, delegation_chain_json, pid, raw_json)`
  with indexes on `(session_id, ts)` and `(decision, ts)`.

Every SBPL profile denies the supervised agent write access to the state
directory and to the policy files (see threat model T4). The profile is written
to a fresh per-session temp directory created with mode 0700; the agent needs no
access to it, because `sandbox-exec` reads the profile before exec.

## 9. Testing strategy

- **Policy crate:** table-driven unit tests for glob→matcher, variable expansion,
  precedence (deny > ask > allow > default), the two-phase network decision,
  and each built-in rule against positive and negative paths. Property tests
  confirm that adding an allow never turns an *explicit* deny into an allow.
  A profile test asserts the never-allow list (policy-model §5.1).
- **Seatbelt compiler:** golden-file tests (policy → SBPL). A macOS integration
  suite then runs real `sandbox-exec` against a temp tree containing a fake
  `.env`, `~/.ssh`-shaped directory, symlinks, hard links, case variants and
  ancestor renames, rename-then-read, the git `commondir`/gitfile vectors,
  inbound listeners, and `TIOCSTI`, and asserts that each one fails. Where possible it also asserts that the
  denial appears in the event store with `decision=deny, enforcement=enforced`.
- **Agents:** fixture `ProcessFacts` for each agent, including negative fixtures
  (for example, ChatGPT.app's Codex *helper* processes must not match as agents).
- **Audit:** store round-trip; `--json` schema snapshot.
- **E2E:** `agentfence run -- /bin/sh -c 'cat $PROJECT/.env'` exits nonzero with
  one `deny`/`enforced` event, and `cat $PROJECT/README` succeeds.

## 10. Out of scope for iteration 1

The ES extension implementation, NetworkExtension, a hosted/remote UI (the local `agentfence ui` is specified in [ui.md](ui.md)), SaaS or remote
policy distribution, authentication servers, Linux, OpenShell, OPA, interactive
approval (see policy model §6), and TLS interception.
