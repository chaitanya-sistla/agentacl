# AgentFence MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `agentfence` so that `agentfence run -- claude` identifies Claude Code, gives the session an identity, confines it with a kernel-enforced Seatbelt profile compiled from YAML policy, forces its network through an allowlisting proxy, tracks its process tree, and records honest, auditable events in SQLite.

**Architecture:** This implements `docs/architecture.md` as three crates:
- `agentfence-policy` is pure: parse, expand, match and evaluate.
- `agentfence-core` covers macOS process facts, agents, identity, sessions, the Seatbelt backend, the log observer, the proxy, the supervisor and audit.
- `agentfence-cli` is clap plus rendering.

The spec lives in `docs/{architecture,threat-model,policy-model,macos-enforcement}.md`. When this plan and the docs disagree, the docs win, and the disagreement is fixed in whichever is wrong.

**Tech Stack:** Rust 2021 (toolchain 1.93), clap 4, serde + serde_json, serde_yaml_ng 0.10, rusqlite 0.40 (`bundled`), ulid 3, sha2 0.11, regex 1, libc 0.2, anyhow/thiserror, tempfile + proptest (dev). No async runtime: the proxy and observers use std threads.

**Deviation from the writing-plans template:** steps list exact interfaces and concrete test cases, not full implementation code. The code is written once, during execution, under TDD. Test cases are specified precisely enough that two engineers would write equivalent assertions.

## Global Constraints

- macOS only. `#[cfg(target_os = "macos")]` gates the macOS FFI; the policy crate is platform-neutral.
- No LLM, no network calls, and no clock/randomness on any decision path. Evaluation is a pure function of (policy set, request).
- Explicit deny wins: deny > ask > allow > default. The invariant is property-tested.
- `enforcement = "enforced"` may be set **only** by the sandbox-log observer (pid 0, message prefix `Sandbox: `) and the proxy. The observer `EventSink` API for the process monitor cannot express `enforced`.
- `run` fails closed: any error in policy load, expansion, project resolution, profile generation or spawn setup means a non-zero exit, and the agent is not started.
- State dir: `~/Library/Application Support/AgentFence/`, overridable by `AGENTFENCE_HOME`. Config dir: `~/.config/agentfence/`, overridable by `AGENTFENCE_CONFIG_DIR`. Both overrides exist for tests. Both dirs are write-denied in every profile.
- Session ids are `agt_` + ULID. Event ids are `evt_` + ULID. Machine ids are `mch_` + the first 16 hex chars of sha256(IOPlatformUUID).
- Every renderer escapes C0/C1 control characters and ESC in paths, argv and reasons (threat T15b).
- No web UI, SaaS, auth server, Docker, OPA, or ES implementation (the ES backend is a stub only).
- Commit after each task: `feat(<area>): …`. Author is the repo owner only; no Claude co-author trailers or AI attribution anywhere.

## File Structure

```
Cargo.toml                                   workspace, shared dep versions
crates/agentfence-policy/
  src/lib.rs            re-exports; PolicyEngine trait
  src/model.rs          Effect, Category, Action, WriteOp, Resource, Subject, Request, Decision, Layer
  src/raw.rs            serde structs for the YAML doc (RawDoc, RawRule), closed-schema checks
  src/expand.rs         Vars, ${VAR} expansion, path canonicalization helpers
  src/pathpat.rs        PathPattern: glob → matcher; anchor; to_sbpl()
  src/procpat.rs        CommandPattern
  src/netpat.rs         HostPattern, AddrPattern, reserved ranges
  src/set.rs            PolicySet: load/merge layers, match, defaults, builtin.disable, trust
  src/eval.rs           evaluate(); two-phase network; implied rename/unlink/link deny
  builtin/{protect-secrets,exec-persistence,agentfence-self,runtime,default}.yaml
  tests/{parse,pathpat,procpat,netpat,eval,builtins,props}.rs
crates/agentfence-core/
  src/lib.rs
  src/config.rs         Paths (state/config dirs), policy file discovery
  src/escape.rs         terminal-safe escaping
  src/audit/{mod,event,store}.rs
  src/proc/{mod,libproc,tree,codesign,machine}.rs
  src/agents/{mod,claude,codex,gemini,copilot,opencode}.rs
  src/identity.rs       Human, Machine, AgentIdentity, project resolution
  src/session.rs        Session
  src/enforce/{mod,seatbelt,sbpl,baseline,endpoint_security}.rs
  src/observe/{mod,sandbox_log}.rs
  src/netproxy.rs
  src/supervisor/{mod,pty,integrity}.rs
  tests/fixtures/…      ProcessFacts JSON, sandbox log NDJSON lines
crates/agentfence-cli/
  src/main.rs, src/cmd/{discover,agents,status,policy,events,run}.rs, src/render.rs
  tests/e2e.rs          real sandbox-exec runs (macOS)
scripts/capture-baseline.sh                  runs an agent under a report-only profile and collects denials
```

---

### Task 1: Workspace, config paths, escaping, CLI skeleton

**Files:** create the workspace `Cargo.toml`, the three crates, `core/src/config.rs`, `core/src/escape.rs`, `cli/src/main.rs`

**Interfaces (produces):**
- `config::Paths { state_dir: PathBuf, config_dir: PathBuf, db_path: PathBuf, user_policy: PathBuf, trust_file: PathBuf }`
- `Paths::from_env() -> Result<Paths>`: honors `AGENTFENCE_HOME` / `AGENTFENCE_CONFIG_DIR`, and resolves home via `getpwuid(getuid())`, not `$HOME`.
- `escape::term_safe(s: &str) -> String`: every char in `\x00-\x1f`, `\x7f`, `\u{80}-\u{9f}` becomes `\xNN` (or `\u{NN}` for C1); printable Unicode passes through.
- The CLI has the subcommands `discover`, `agents`, `status`, `policy check`, `events`, `run`, each with the flags listed in architecture §6. Until a subcommand is implemented it exits 2 with "not implemented yet".

**Tests:**
- [ ] `term_safe("a\x1b[31mb")` == `"a\\x1b[31mb"`; `term_safe("naïve")` == `"naïve"`; `term_safe("x\u{9b}y")` == `"x\\u{9b}y"`; `term_safe("\n")` == `"\\x0a"`.
- [ ] With `AGENTFENCE_HOME=/tmp/x`: `db_path` == `/tmp/x/agentfence.db`. With no override: `state_dir` ends with `Library/Application Support/AgentFence`.
- [ ] `cargo run -p agentfence-cli -- --help` lists all six commands.
- [ ] Commit.

### Task 2: Policy model and YAML parsing (closed schemas)

**Files:** `policy/src/{lib,model,raw}.rs`, `policy/tests/parse.rs`

**Interfaces (produces):**
```rust
pub enum Effect { Allow, Deny, Ask }                       // serde "allow"/"deny"/"ask"
pub enum Layer { Builtin, User, Project }
pub struct RawRule { pub pattern: String, pub except: Vec<String>, pub id: Option<String>, pub reason: Option<String> }
// accepts string OR {path|command|host, except?, id?, reason?}; exactly one of path/command/host
pub struct RawDoc {
  pub version: String,                     // must be "v1"
  pub name: Option<String>,
  pub r#match: Option<RawMatch>,           // agents: Vec<String>, projects: Vec<String>
  pub defaults: RawDefaults,               // filesystem/network/process: Option<Effect>
  pub filesystem: RawFs,                   // allow_read, allow_write, deny_read, deny_write: Vec<RawRule>
  pub process: RawProc,                    // allow, deny, require_approval
  pub network: RawNet,                     // allow, deny, listen
  pub builtin: Option<RawBuiltin>,         // disable: Vec<String>
}
pub fn parse_doc(yaml: &str, layer: Layer, source_name: &str) -> Result<RawDoc, PolicyError>
pub enum PolicyError { Yaml{source,msg}, Version{source,found}, UnknownKey{source,key}, ProjectForbidden{source,key}, BadRule{source,section,index,msg}, UnknownVariable{source,var}, BadPattern{source,pattern,msg}, Untrusted{..} }
```
- serde `deny_unknown_fields` everywhere, which gives closed schemas for all layers.
- For `Layer::Project`, reject any of `filesystem.allow_read`, `filesystem.allow_write`, `process.allow`, `network.allow`, `network.listen`, `builtin` → `ProjectForbidden`. Trust is handled in Task 5.
- `name` defaults to `source_name`.

**Tests (`tests/parse.rs`):**
- [ ] The full policy-model §2 example parses: 3 filesystem sections, 1 process deny, 4 require_approval, 3 network allow, and the object rule `env-variants` with its 4 excepts.
- [ ] `version: v2` → `PolicyError::Version`.
- [ ] Unknown top-level key `filesytem:` → error, and the message contains `filesytem`.
- [ ] Project layer with `filesystem.allow_read: ["/x"]` → `ProjectForbidden{key:"filesystem.allow_read"}`. Same for `builtin`, `network.listen` and `process.allow`.
- [ ] Project layer with only deny sections plus `defaults.network: deny` → Ok.
- [ ] A rule object with both `path` and `host` → `BadRule`.
- [ ] Commit.

### Task 3: Variables, canonicalization, path patterns

**Files:** `policy/src/{expand,pathpat}.rs`, `policy/tests/pathpat.rs`

**Interfaces (produces):**
```rust
pub struct Vars { pub home: String, pub project: String, pub tmpdir: String, pub agent_state: Option<String> }
pub struct Expanded { pub text: String, pub var_root: Option<String> }  // var_root = expanded value of a LEADING ${VAR}, e.g. "/u" for "${HOME}/.aws/credentials"
pub fn expand(s: &str, vars: &Vars, source: &str) -> Result<Expanded, PolicyError>   // ${HOME} ${PROJECT} ${TMPDIR} ${AGENT_STATE}; unknown → UnknownVariable; ${AGENT_STATE} when None → UnknownVariable
pub fn canonical_prefix_map(p: &str) -> String   // lexical: /tmp→/private/tmp, /var→/private/var, /etc→/private/etc; collapses //, /./ ; resolves .. lexically
pub struct PathPattern { /* source, anchor, kind, regex */ }
pub enum PatKind { Literal(String), Subpath(String), Glob }
impl PathPattern {
  pub fn parse(expanded: &Expanded) -> Result<Self, String>   // must start with '/'; trailing "/**" with no other glob chars → Subpath
  pub fn protected_ancestors(&self) -> Vec<String>            // dirs strictly below var_root and strictly above the protected path:
                                                              // "${HOME}/.aws/sso/cache/**" → ["/u/.aws", "/u/.aws/sso"]; "${HOME}/.aws/credentials" → ["/u/.aws"];
                                                              // "${HOME}/.ssh/**" → [] (/u/.ssh itself is matched by the pattern); no var_root ("/**/.env") → []
  pub fn parse_except(expanded_or_rel: &str, rule_anchor: &str) -> Result<Self, String> // "**/x" allowed → anchored at rule_anchor
  pub fn matches(&self, canonical_path: &str) -> bool         // case-insensitive (ASCII fold)
  pub fn anchor(&self) -> &str                                // longest literal dir prefix before first glob char
  pub fn kind(&self) -> &PatKind
  pub fn sbpl_regex(&self) -> String                          // POSIX ERE, ^…$, letters as [aA] classes, '.' escaped
}
```
Glob semantics:
- `*` is `[^/]*` and `?` is `[^/]`.
- `/**/` is `/(.*/)?`.
- A trailing `/**` is `(/.*)?`, so `X/**` matches `X` itself.
- A leading `**/` is only legal in `except`.

The Rust matcher is built with `regex::RegexBuilder::case_insensitive(true)` from the same translation as `sbpl_regex`, without the case-folded classes, so the two stay in sync.

**Tests:**
- [ ] `expand("${HOME}/.ssh/**")` gives `/Users/u/.ssh/**`; `${NOPE}` → UnknownVariable; `$HOME` without braces stays a literal.
- [ ] `canonical_prefix_map("/tmp/a/../b")` == `/private/tmp/b`; `/var/folders/x` → `/private/var/folders/x`; `/Users/u` unchanged.
- [ ] `/u/.ssh/**` matches `/u/.ssh`, `/u/.ssh/id_rsa` and `/u/.ssh/a/b`, and doesn't match `/u/.sshx`.
- [ ] `/**/.env` matches `/p/.env`, `/.env`, `/p/a/b/.env` and `/P/A/.ENV`, and doesn't match `/p/.env.local` or `/p/x.env`.
- [ ] `/p/**/.env.*` matches `/p/.env.production` and `/p/a/.env.local`, and doesn't match `/p/.env`.
- [ ] except `**/.env.example` under anchor `/p` matches `/p/a/.env.example`.
- [ ] `/u/*.pem` matches `/u/a.pem` but not `/u/a/b.pem`; `/u/**/*.pem` matches both.
- [ ] Kinds: `/u/.ssh/**` → `Subpath("/u/.ssh")`; `/u/.aws/credentials` → `Literal`; `/p/**/.env` → `Glob` with anchor `/p`.
- [ ] `sbpl_regex` of `/p/**/.env` == `^/[pP]/(.*/)?\.[eE][nN][vV]$`.
- [ ] Relative pattern `foo/**` → error.
- [ ] `protected_ancestors`: the three examples in the interface comment, exactly.
- [ ] Commit.

### Task 4: Command and network patterns

**Files:** `policy/src/{procpat,netpat}.rs`, `policy/tests/{procpat,netpat}.rs`

**Interfaces (produces):**
```rust
pub struct CommandPattern { exe: ExeMatch, args: Vec<ArgGlob>, rest: bool }
impl CommandPattern {
  pub fn parse(s: &str) -> Result<Self, String>
  pub fn matches(&self, exe_path: &str, argv: &[String]) -> bool     // argv[0] ignored; exe basename or abs path
  pub fn is_executable_only(&self) -> bool                           // no arg tokens (pattern "x" or "x *")
  pub fn exe_basename(&self) -> Option<&str>; pub fn exe_abs(&self) -> Option<&str>
}
pub enum NetPattern { Host{ host: HostGlob, port: Option<u16> }, Addr{ net: IpNet, port: Option<u16> } } // "localhost" → Addr 127.0.0.0/8 + ::1
impl NetPattern {
  pub fn parse(s: &str) -> Result<Self, String>
  pub fn matches_host(&self, host: &str, port: u16) -> bool     // host patterns only; lowercased, trailing dot stripped
  pub fn matches_addr(&self, ip: IpAddr, port: u16) -> bool     // addr patterns only; IPv4-mapped v6 normalized to v4
}
pub fn reserved_range(ip: IpAddr) -> Option<&'static str>      // loopback, link-local, rfc1918, cgnat, ula, unspecified, multicast
```
`IpNet` is a small in-crate type (`addr`, `prefix_len`) with a `contains()` method. No new dependency.

**Tests:**
- [ ] `"sudo *"` matches `/usr/bin/sudo` with args `[]` and `["-n","true"]`; it is executable-only.
- [ ] `"git push *"` matches args `["push"]` and `["push","origin","main"]`, and doesn't match `["-C","x","push"]` or `["pull"]`; it is not executable-only.
- [ ] `"terraform apply"` (no trailing `*`) matches exactly `["apply"]` and not `["apply","-auto-approve"]`.
- [ ] `"/usr/local/bin/tf *"` matches only that absolute path.
- [ ] `"*.github.com"` matches `api.github.com:443` and `API.GitHub.com.`, and doesn't match `github.com`; `"github.com:443"` doesn't match port 80.
- [ ] `"10.0.0.0/8"` matches addr `10.1.2.3`; `"localhost:3000"` matches `127.0.0.1:3000` and `::1:3000` but not `127.0.0.1:3001`.
- [ ] `reserved_range`: `169.254.169.254` → link-local; `::ffff:10.0.0.1` → rfc1918; `100.64.0.1` → cgnat; `fd00::1` → ula; `8.8.8.8` → None.
- [ ] Commit.

### Task 5: PolicySet — layers, match, defaults, builtins, trust

**Files:** `policy/src/set.rs`, `policy/builtin/*.yaml`, `policy/tests/{builtins,set}.rs`

**Interfaces (produces):**
```rust
pub struct Source { pub layer: Layer, pub name: String, pub yaml: String }
pub struct LoadOptions { pub trusted_project_sha256: Vec<String> }
pub struct Rule { pub id: String, pub policy: String, pub layer: Layer, pub section: Section, pub effect: Effect, pub matcher: Matcher, pub excepts: Vec<PathPattern>, pub reason: String }
pub enum Section { FsRead, FsWrite, Exec, Net, Listen }
pub enum Matcher { Path(PathPattern), Cmd(CommandPattern), Net(NetPattern) }
pub struct Doc { pub name: String, pub layer: Layer, pub match_agents: Vec<String>, pub match_projects: Vec<PathPattern>, pub defaults: Defaults, pub rules: Vec<Rule>, pub disable_builtin: Vec<String> }
pub struct PolicySet { pub docs: Vec<Doc>, pub sha256: String }
pub fn builtin_sources(include_default: bool) -> Vec<Source>    // include_str! of builtin/*.yaml
impl PolicySet {
  pub fn load(sources: Vec<Source>, vars: &Vars, opts: &LoadOptions) -> Result<PolicySet, PolicyError>
  pub fn applicable<'a>(&'a self, agent_id: &str, project: &str) -> Vec<&'a Doc>
  pub fn effective_defaults(&self, agent_id: &str, project: &str) -> Defaults  // most restrictive; fallback fs=deny, net=deny, process=allow
  pub fn rules_for(&self, agent_id: &str, project: &str) -> Vec<&Rule>          // honors builtin.disable
}
```
Rules:
- Builtin rule ids are `<group>` when the YAML gives `id`, else `<policy>/<section>/<index>`.
- The built-in groups are the `id`s in `protect-secrets.yaml`.
- `builtin.disable` may name any protect-secrets group; naming `agentfence-self` or `exec-persistence` is a load error.
- A project doc's defaults must be no looser than the merged built-in + user defaults; otherwise `ProjectForbidden{key:"defaults.<cat>"}`.
- A project doc whose sha256 is in `trusted_project_sha256` is re-parsed as `Layer::User`.
- `sha256` is computed over the canonical JSON of the expanded docs.
- A user-provided `--policy` or `~/.config/agentfence/policy.yaml` means `include_default = false`.

Builtin YAML contents follow policy-model §5, §5.1 and exec-persistence **exactly**:
- `runtime.yaml` holds the file allows. Its paths are refined in Task 10 from the captured baseline.
- `default.yaml` sets `defaults: {filesystem: deny, network: deny, process: allow}`, `allow_read`/`allow_write` of `${PROJECT}/**`, and `network.allow: []`.

**Tests:**
- [ ] Builtins alone load with a fake `Vars`, and every group id in policy-model §5's table is present.
- [ ] `builtin.disable: [keys]` in the user doc removes the `keys` rules from `rules_for`; `disable: [agentfence-self]` → load error.
- [ ] A doc with `match.agents: [codex]` isn't applicable to `claude-code`.
- [ ] Defaults: built-in default (fs deny) plus a user doc with `filesystem: allow` gives `deny` (most restrictive). With no doc setting network, network is `deny`.
- [ ] A project doc with `defaults.filesystem: allow`, when the merged value is `deny` → error. The same project doc whose sha is trusted → loads, as User.
- [ ] `sha256` is stable across two loads, and changes when one rule changes.
- [ ] Commit.

**Amendments (plan review 1), binding for Task 5:**
- `Vars` gains `agentfence_state: String` and `agentfence_config: String` (the canonical state and config dirs), available as `${AGENTFENCE_STATE}` and `${AGENTFENCE_CONFIG}`. `agentfence-self.yaml` deny_writes those two, plus `${PROJECT}/.agentfence/**`. When `--policy FILE` lies outside the config dir, `run` adds a literal deny_write for it.
- Builtin excepts use the full `**/`-prefixed form relative to the rule anchor, e.g. `**/.git/objects/**`, `**/.git/index`, `**/.git/*.lock`. A relative except that doesn't start with `**/` is a load error.
- **Provider requirements are policy.** `PolicySet::load` takes `provider: Option<ProviderDoc>` and turns `RuntimeReqs` into a Builtin-layer document named `provider:<id>`. `read`/`write` become allow rules, `hosts` becomes `network.allow`, and `protected_configs` becomes `deny_write`. Evaluation and attribution therefore agree with the profile. Test: with the claude provider doc, a write to `/u/.claude/projects/x` → allow `provider:claude-code`; a write to `/u/.claude/settings.json` → deny.
- The trust hash is sha256 of the **raw file bytes**.
- Rename the policy-crate `Source` to `PolicySource`, to avoid a clash with `audit::Source`.

### Task 6: Evaluator

**Files:** `policy/src/eval.rs`, `policy/tests/{eval,props}.rs`

**Interfaces (produces):**
```rust
pub enum WriteOp { Write, Create, Unlink, Rename, Link, Meta }
pub enum Action { FsRead, FsWrite(WriteOp), Exec, NetConnect, NetListen }
pub enum Resource { Path(String), Exec { exe: String, argv: Vec<String> }, Host { host: String, port: u16 }, Addr { ip: IpAddr, port: u16 } }
pub struct Subject { pub human: String, pub machine: String, pub agent_id: String, pub agent_version: Option<String>, pub team_id: Option<String>, pub session: String, pub project: String, pub delegation_chain: Vec<String> }
pub struct Request { pub subject: Subject, pub action: Action, pub resource: Resource }
pub struct Decision { pub effect: Effect, pub policy: String, pub rule_id: String, pub reason: String, pub trace: Vec<String> }
pub trait PolicyEngine { fn evaluate(&self, req: &Request) -> Decision; }
impl PolicyEngine for PolicySet
impl PolicySet { pub fn evaluate_address(&self, subj: &Subject, ip: IpAddr, port: u16) -> Decision }   // network phase 2
```
Algorithm (policy-model §4, §4.2), in order:
1. Take the applicable docs' rules for the section. FsRead uses `deny_read`/`allow_read`. FsWrite uses `deny_write`/`allow_write`, **plus** — for Unlink/Rename/Link — every `deny_read` rule, as an implied deny. That implied deny matches the path itself, and any path equal to one of `PathPattern::protected_ancestors()`.
2. deny → ask → allow → default.
3. A deny reports the first rule in load order (Builtin, User, Project).
4. Network phase 1 (`Host`) uses host patterns; an IP-literal host goes through phase 2's logic.
5. Phase 2: any matching addr deny → deny. Else, if the address is reserved and no **addr allow** (NetPattern::Addr) covers it → deny, `policy: "builtin"`, `rule_id: "reserved-range:<kind>"`. Else addr allow → allow. Else allow, since phase 1 already allowed the host.

**Tests (`tests/eval.rs`, using builtins + default with project `/p`, home `/u`):**
- [ ] read `/p/src/main.rs` → allow; read `/p/.env` → deny `env-files`; read `/p/.env.example` → allow; read `/u/.ssh/id_ed25519` → deny `ssh`; read `/u/Documents/x` → deny `default`.
- [ ] write `/p/a.txt` → allow; write `/p/.git/config` → deny `exec-persistence`; write `/p/.git/objects/ab/cd` → allow; write `/p/.git/index.lock` → allow; write `/p/.git/commondir` → deny.
- [ ] `FsWrite(Rename)` on `/u/.aws` (ancestor of the `/u/.aws/credentials` literal) → deny `aws`; `FsWrite(Rename)` on `/p/.env.production` → deny `env-files`; `FsWrite(Write)` on `/u/.aws` → deny `default`, and not an explicit rule.
- [ ] User doc `deny_write: ["${HOME}/**"]` → write `/u/src/p/x` (project under home) is deny (§4.1 consequence).
- [ ] `Exec /usr/bin/sudo []` with the user rule `sudo *` → deny; `git push origin` with `require_approval: git push *` → ask.
- [ ] Network: `api.anthropic.com:443` with allow → allow; `evil.com:443` → deny `default`; phase 2 `169.254.169.254` after the host allow `*.corp.com` → deny `reserved-range:link-local`; with the user allow `169.254.169.254` → allow; `127.0.0.1:3000` with `localhost:3000` allowed → allow.
- [ ] **props.rs (proptest):** random docs built from a small path alphabet, random requests. (a) If the decision is deny from an explicit rule, adding any allow rule to any doc leaves it deny. (b) Adding any deny rule never turns a decision into allow. (c) `evaluate` is deterministic: the same inputs give an identical `Decision` twice.
- [ ] Commit.

**Amendments (plan review 1), binding for Task 6:**
- **IP-literal targets:** `Resource::Host` whose host parses as an IP is evaluated in phase 1 with address patterns, then the default. If the result is allow, phase 2 (the reserved-range check) runs on that same IP. Phase 2's final "else allow" is reached only after phase 1 allowed. Tests: `8.8.8.8:443` with no allow → deny `default`; `8.8.8.8:443` with allow `8.8.8.8` → allow; `127.0.0.1:3000` with a host allow `*.corp.com` only → deny.
- `Decision.effect == Ask` for kernel-denied ask rules is recorded as `decision=ask` (Task 13), not `deny`.
- Implied-deny test using a **user** doc that has only `deny_read: ["${HOME}/secret/**"]` (no deny_write), with `allow_write: ["${HOME}/**"]`: `FsWrite(Rename)` on `/u/secret/a` → deny; `FsWrite(Write)` on `/u/secret/a` → allow, because `deny_read` doesn't imply write-deny for plain writes.

### Task 7: Audit events and SQLite store

**Files:** `core/src/audit/{mod,event,store}.rs`

**Interfaces (produces):**
```rust
pub enum Enforcement { Enforced, Observed }
pub enum Source { SandboxLog, Proxy, ProcMonitor, Supervisor, Es }
pub struct Event { id, timestamp (RFC3339 ms, UTC), human, machine, agent, agent_version: Option, session, pid: Option<i32>, delegation_chain: Vec<String>, action: String, resource: String, decision: Option<Effect>, enforcement: Option<Enforcement>, backend: String, source: Source, policy: Option<String>, rule_id: Option<String>, reason: Option<String>, count: u32 }
pub struct SessionRecord { session_id, identity_json, policy_sha256, backend, supervisor_pid, agent_pid, started_at, ended_at: Option, exit_code: Option<i32> }
pub struct Store;  impl Store {
  pub fn open(path: &Path) -> Result<Store>            // creates dir 0700, WAL, schema v1, busy_timeout 5s
  pub fn insert_session(&self, s: &SessionRecord); pub fn end_session(&self, id, ended_at, exit_code)
  pub fn insert_event(&self, e: &Event) -> Result<()>; pub fn bump_count(&self, event_id, n: u32)
  pub fn events(&self, q: &EventQuery) -> Result<Vec<Event>>   // session, decision, since_rowid, limit (default 200, newest last)
  pub fn active_sessions(&self) -> Result<Vec<SessionRecord>>   // ended_at IS NULL
}
/// Observer-facing sink: cannot construct Enforced.
pub trait ObservedSink { fn observed(&self, e: ObservedEvent); }
/// Enforcing sources (sandbox log, proxy) get EnforcedSink.
pub trait EnforcedSink { fn enforced(&self, e: EnforcedEvent); }
```
`ObservedEvent` and `EnforcedEvent` are distinct structs without an `enforcement` field. The store sets `enforcement` from the entry point, which makes the global constraint structural.

**Tests:**
- [ ] Round trip: insert 3 events, then `events(limit 2)` returns the last 2 in order; filtering by session and by decision works.
- [ ] `bump_count` adds to `count`.
- [ ] An `ObservedEvent` sink with `effect: Deny` → the stored row has `enforcement = observed`.
- [ ] `serde_json::to_value(Event)` has exactly the architecture §8 keys plus `count`. This is a snapshot test.
- [ ] Two `Store` handles on the same file can insert concurrently (WAL).
- [ ] Commit.

**Amendments (plan review 1), binding for Task 7:**
- `Store::insert_event` is `pub(crate)`. Public entry points are `record_observed(ObservedEvent)`, `record_enforced(EnforcedEvent)` and `record_lifecycle(LifecycleEvent)` (session_start/session_end/backend_warning, with enforcement `None`).
- `EnforcedEvent` can only be constructed through `EnforcedEvent::from_kernel_denial(&KernelDenial, …)` (defined in Task 11) and `EnforcedEvent::from_proxy(…)` (Task 12). Until those tasks land, the constructors live in `audit` behind `pub(crate)` and take the parsed denial/proxy data.
- Test for invariant 4: `ObservedEvent` has no way to set enforcement (a compile-time property; document it with a doc comment); a lifecycle event has `enforcement: null`.
- `Store::set_agent_pid(session_id, pid)`.

### Task 8: macOS process facts, tree, codesign, machine id

**Files:** `core/src/proc/{mod,libproc,tree,codesign,machine}.rs`

**Interfaces (produces):**
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct ProcessFacts { pub pid: i32, pub ppid: i32, pub start_time_us: u64, pub exe: Option<String>, pub argv: Vec<String>, pub uid: u32, pub name: String }
pub fn list_pids() -> Result<Vec<i32>>                 // proc_listallpids
pub fn facts(pid: i32) -> Option<ProcessFacts>         // proc_pidinfo(PROC_PIDTBSDINFO) + proc_pidpath + sysctl KERN_PROCARGS2 (argv only)
pub fn snapshot() -> Vec<ProcessFacts>
pub struct ProcessTree { root: (i32,u64), nodes: HashMap<(i32,u64), Node> }   // Node { facts, parent: Option<(i32,u64)>, exited: bool }
impl ProcessTree { pub fn new(root: ProcessFacts) -> Self; pub fn refresh(&mut self, snap: &[ProcessFacts]) -> Vec<ProcessFacts> /* newly seen members */; pub fn chain(&self, pid: i32) -> Option<Vec<String>> /* root→pid display names */; pub fn live_members(&self) -> Vec<i32>; pub fn contains_pid(&self, pid: i32) -> bool }
pub struct CodeSignature { pub team_id: Option<String>, pub signing_id: Option<String>, pub authority: Vec<String> }
pub fn code_signature(path: &Path) -> Option<CodeSignature>   // runs /usr/bin/codesign -dv --verbose=2, parses stderr
pub fn sha256_file(path: &Path) -> Result<String>
pub fn machine_id() -> Result<String>                    // ioreg -rd1 -c IOPlatformExpertDevice → IOPlatformUUID → mch_<16 hex>
```
Tree membership:
- A process joins if its ppid is a live member, matched with `start_time ≥ parent start_time` to rule out pid reuse.
- Exited members are kept (`exited = true`) so later log lines can still be attributed.
- The chain's display names come from `agents::display_id` for the root (e.g. `claude-code`); other members use the basename of `exe`.

**Tests:**
- [ ] `facts(std::process::id())` has an exe ending in the test binary name, and `argv[0]` is non-empty.
- [ ] `facts` of a spawned `sleep 5` has argv `["sleep","5"]` and a ppid equal to our pid.
- [ ] Tree with synthetic facts: root 100 → 101 (bash) → 102 (terraform); `chain(102)` == `["claude-code","bash","terraform"]`. A reused pid 101 with an earlier start_time isn't adopted. An exited 102 still resolves.
- [ ] `code_signature("/usr/bin/true")` has `signing_id == Some("com.apple.true")`.
- [ ] `machine_id()` matches `^mch_[0-9a-f]{16}$`.
- [ ] Commit.

**Amendments (plan review 1), binding for Task 8:**
- `ProcessTree::new(root: ProcessFacts, root_label: String)`. No `agents::display_id` dependency.
- `refresh` also reports **exec-in-place** changes on existing nodes: same (pid, start_time), different exe or argv. They're returned as `TreeChange::Exec(facts)` alongside `TreeChange::New(facts)`.
- `pub fn resolve_ancestry(pid: i32) -> Vec<ProcessFacts>` walks ppid via libproc for pids the tree hasn't seen yet (unattributed-denial fallback).
- `pub fn session_members(sid: i32) -> Vec<i32>` returns all pids with `getsid(pid) == sid`, for end-of-session cleanup.

### Task 9: Agent providers and discovery

**Files:** `core/src/agents/{mod,claude,codex,gemini,copilot,opencode}.rs`, `core/tests/fixtures/agents/*.json`

**Interfaces (produces):**
```rust
pub enum Confidence { High, Medium, Low }
pub enum Evidence { Signature{team_id, signing_id}, Executable(String), NodeEntry(String), Argv(String), InstallPath(String) }
pub struct Match { pub confidence: Confidence, pub evidence: Vec<Evidence>, pub version: Option<String> }
pub struct RuntimeReqs { pub read: Vec<String>, pub write: Vec<String>, pub hosts: Vec<String>, pub mach_services: Vec<String>, pub env_remove: Vec<String>, pub env_set: Vec<(String,String)>, pub protected_configs: Vec<String> }  // unexpanded, may use ${HOME}/${PROJECT}
pub trait AgentProvider: Send + Sync {
  fn id(&self) -> &'static str; fn display_name(&self) -> &'static str;
  fn match_process(&self, p: &ProcessFacts, sig: Option<&CodeSignature>) -> Option<Match>;
  fn install_candidates(&self, home: &Path) -> Vec<PathBuf>;
  fn runtime_requirements(&self) -> RuntimeReqs;
}
pub fn registry() -> Vec<Box<dyn AgentProvider>>
pub fn identify(p: &ProcessFacts, sig: Option<&CodeSignature>) -> Option<(&'static str /*id*/, &'static str /*display*/, Match)>  // highest confidence wins
pub struct Discovered { pub id, pub display_name, pub path: PathBuf, pub version: Option<String>, pub signature: Option<CodeSignature>, pub sha256: Option<String>, pub running: Vec<i32> }
pub fn discover(home: &Path, snap: &[ProcessFacts]) -> Vec<Discovered>
```
Matching facts, as constants at the top of each provider file:
- **claude:**
  - Team `Q6L2SF6YDW` + signing id `com.anthropic.claude-code` → High.
  - An exe basename `claude` or `claude.exe` under `@anthropic-ai/claude-code`, `.local/share/claude/versions`, `.claude/local`, or a VS Code extension `anthropic.claude-code-*` → Medium.
  - A node exe with argv containing `@anthropic-ai/claude-code/cli.js` → Medium.
  - The version comes from `…/versions/<v>`, the VS Code dir name, or the npm `package.json`.
  - Runtime reqs:
    - read+write `${HOME}/.claude/**`, `${HOME}/.claude.json`, `${HOME}/.claude.json.*`
    - host `api.anthropic.com`, plus `statsig.anthropic.com` and `sentry.io`
    - mach `com.apple.SecurityServer`
    - protected_configs `${HOME}/.claude/settings.json`
    - The inner sandbox is disabled via env **[verify during Task 13]**.
- **codex:**
  - A native `codex` binary (npm `@openai/codex` vendor dir, Homebrew, or `/Applications/ChatGPT.app/Contents/Resources/codex`) → Medium; a matching signature → High.
  - **Negative:** anything under `Codex Framework.framework/…/Helpers/`, `Sparkle`, or `crashpad`.
  - Reqs: `${HOME}/.codex/**` and host `api.openai.com`.
- **gemini:** node with argv containing `@google/gemini-cli`, or an exe basename `gemini` resolving into that package. Reqs: `${HOME}/.gemini/**`, `generativelanguage.googleapis.com`, `oauth2.googleapis.com`.
- **copilot:** node with argv containing `@github/copilot`. Reqs: `${HOME}/.copilot/**`, `api.githubcopilot.com`, `api.github.com`.
- **opencode:** exe basename `opencode` (`~/.opencode/bin`, Homebrew, npm `opencode-ai`). Reqs: `${HOME}/.config/opencode/**`, `${HOME}/.local/share/opencode/**`.

**Tests (fixtures are JSON `ProcessFacts` + optional signature):**
- [ ] Claude native signed → claude-code/High; Claude via npm node cli.js → Medium; a VS Code extension binary → claude-code with version `2.1.261`.
- [ ] Codex `/Applications/ChatGPT.app/Contents/Resources/codex` → codex; `…/Helpers/Codex (Service).app/…` → None; Sparkle `Updater` → None.
- [ ] `node /opt/homebrew/lib/node_modules/@google/gemini-cli/dist/index.js` → gemini; a plain `node server.js` → None.
- [ ] `vim claude.txt` (argv mentions claude) → None. Names alone never match.
- [ ] `discover` on this machine finds claude at `/opt/homebrew/bin/claude` (an `#[ignore]`-by-default live test, run in Task 15).
- [ ] Commit.

### Task 10: Identity, session, Seatbelt compiler, runtime baseline

**Files:** `core/src/{identity,session}.rs`, `core/src/enforce/{mod,seatbelt,sbpl,baseline,endpoint_security}.rs`, `scripts/capture-baseline.sh`

**Interfaces (produces):**
```rust
pub struct Human { pub user: String, pub uid: u32, pub home: PathBuf }   // getpwuid(getuid())
pub fn human() -> Result<Human>
pub fn resolve_project(cwd: &Path, override_: Option<&Path>, home: &Path) -> Result<PathBuf>  // realpath; git toplevel via `git -C cwd rev-parse --show-toplevel` else cwd; refuse "/", home, any ancestor of home
pub struct AgentIdentity { pub id: String, pub display_name: String, pub version: Option<String>, pub binary: String, pub binary_sha256: String, pub team_id: Option<String>, pub signing_id: Option<String> }
pub struct Session { pub id: String, pub human: Human, pub machine: String, pub agent: AgentIdentity, pub project: PathBuf, pub tmpdir: PathBuf, pub policy_name: String, pub policy_sha256: String, pub backend: String, pub started_at: String }
pub fn new_session_id() -> String   // "agt_" + ULID

pub enum Enforceability { Enforced, EnforcedCoarse, Observed, RequiresEs }
pub struct LaunchPlan { pub program: PathBuf, pub args: Vec<String>, pub env_set: Vec<(String,String)>, pub env_remove: Vec<String>, pub profile_path: PathBuf, pub profile_text: String }
pub trait EnforcementBackend { fn name(&self) -> &'static str; fn available(&self) -> Result<(), String>; fn classify(&self, rule: &Rule) -> Enforceability; fn prepare(&self, input: &PrepareInput) -> Result<LaunchPlan>; }
pub struct PrepareInput<'a> { pub session: &'a Session, pub policy: &'a PolicySet, pub reqs: &'a RuntimeReqs, pub agent_argv: &'a [String], pub proxy_port: u16, pub extra_denies: &'a [String] /* hardlink literals */, pub socket_denies: &'a [String] }
pub struct SeatbeltBackend;  pub struct MacOSEndpointSecurityBackend;  // available() → Err("requires com.apple.developer.endpoint-security.client")
pub fn compile_profile(input: &PrepareInput) -> Result<String>   // pure; in sbpl.rs
pub const NEVER_ALLOW: &[&str] = &["hid-control","network-bind","network-inbound","lsopen","appleevent-send","job-creation"];
```
Profile layout follows macos-enforcement §2.2 exactly:
1. `(version 1)(deny default)`
2. the baseline ops from `baseline.rs`: `process-fork`, `sysctl-read`, `ipc-posix-shm*`, signal (per T5 plan), `file-read-metadata` on `/` and the ancestors of every allow path, and the mach allowlist plus provider mach services
3. category-default allows
4. the allow rules: `subpath` / `literal` / `regex`
5. `(allow network-outbound (remote ip "localhost:<port>"))`
6. `network-bind`/`network-inbound` only for `network.listen` loopback entries
7. **then** every deny:
   - file denies, with `require-not` for excepts
   - implied `file-write-unlink` + `file-link` for deny_read paths and anchored ancestors
   - exec denies by basename regex plus literals
   - unix-socket denies
   - hard-link literals
   - mach denies for the §2.2 deny list

The profile must never contain `(allow <NEVER_ALLOW item>` except the listen-scoped bind/inbound.

**Baseline capture (a step, not code):** `scripts/capture-baseline.sh <cmd…>` runs the command under a `(deny default)` profile built from the current `runtime.yaml` plus `(debug deny)`, collects `Sandbox:` lines from `log stream`, and prints unique `op path` pairs. Run it for `/bin/sh -c true`, `/bin/zsh -c true`, `git status`, `node -e 1`, `claude --version`, `claude -p hi` (the last one after the proxy lands). Review each denial and add the safe ones to `runtime.yaml` / `baseline.rs`. Never add anything on the never-allow list, and never add a path matched by protect-secrets.

**Tests:**
- [ ] `resolve_project`: a git repo subdir → toplevel; `/Users` with home `/Users/u` → error; home → error.
- [ ] `new_session_id()` matches `^agt_[0-9A-HJKMNP-TV-Z]{26}$`.
- [ ] Profile invariants on the builtins+default compile: (a) the index of the last `(allow` is less than the index of the first `(deny ` after the header; (b) no `(allow hid-control`, `(allow lsopen`, `(allow appleevent-send`, `(allow job-creation`; (c) contains `(deny default)`; (d) contains `localhost:<port>`.
- [ ] Golden test: a minimal policy compiles to `tests/golden/minimal.sb` byte-for-byte.
- [ ] `SeatbeltBackend.classify`: path rule → Enforced; `sudo *` → EnforcedCoarse; `git push *` → Observed; host rule → Enforced.
- [ ] `MacOSEndpointSecurityBackend.available()` is Err.
- [ ] **Real sandbox tests** (`core/tests/sandbox_real.rs`, macOS). Each builds a temp project + fake home via `Vars`, compiles, and runs `sandbox-exec -f` on `/bin/sh -c …`:
  - `cat $P/README` → 0
  - `cat $P/.env` → nonzero
  - `cat $P/.ENV` (on-disk name `.ENV`) → nonzero
  - symlink `$P/l → $H/.ssh/id_rsa`, `cat $P/l` → nonzero
  - `mv $P/.env.production $P/x` → nonzero
  - `mv $H/.aws $H/aws2` → nonzero
  - `ln $P/.env $P/h` → nonzero
  - `echo x > $H/outside` → nonzero
  - `git -C $P config core.fsmonitor x` → nonzero; `printf 'x' > $P/.git/commondir` → nonzero; `mv $P/.git $P/g2` → nonzero
  - `nc -l 127.0.0.1 18777` → fails to bind
  - `curl -sS -m3 https://example.com` → nonzero
  - `/bin/sh -c 'echo ok'` → 0
- [ ] Commit (`scripts/capture-baseline.sh`, the refined `runtime.yaml`, `baseline.rs`).

**Amendments (plan review 1), binding for Task 10:**
- **SBPL injection:** the compiler refuses (fail closed, error naming the path) any path or pattern containing `"`, `\`, or a control character. Regex bodies are ERE-escaped for all of `\.+()[]{}^$|` (already implemented in `pathpat::translate`). Golden test: a project dir named `p")(allow default)(` → `compile_profile` returns Err.
- `PrepareInput` gains `exec_deny_literals: Vec<String>` (PATH-resolved), `pty_slave: String`, and `listen: Vec<NetPattern>`.
- `/dev/ttys*` is **not** granted. The only terminal paths granted are `/dev/tty` and the literal `pty_slave`. Update policy-model §5.1 accordingly.
- Signal rule, fixed: `(allow signal (target same-sandbox))` if that target parses (probe it first); else `(allow signal (target pgrp))` + `(target children)` + `(target self)`. Record the chosen form in `baseline.rs` with the probe result.
- `defaults.network: allow` **never** emits `(allow network-outbound)` to anything but the proxy port. Test.
- The profile invariant test also asserts that there's no `(allow network-bind` or `(allow network-inbound` when `network.listen` is empty.
- Invariant 5 test: with a user policy present, the profile still contains the protect-secrets, exec-persistence and agentfence-self denies.
- **Real-sandbox tests, rewritten:**
  - The child env sets `HOME=$H` (the fake home), with a minimal `$H/.gitconfig`.
  - Every negative case has a **positive control in the same profile** (`git -C $P status` → 0, `cat $P/README` → 0), and asserts the **on-disk effect** (`.git/config` unchanged, `.git` still a dir, `$H/.aws/credentials` still at its path) in addition to the exit code.
  - The ancestor-rename test runs under a user policy `allow_write: ["${HOME}/**"]`: `mv $H/.aws $H/aws2` → fails, and `$H/aws2` doesn't exist.
  - `nc -l -w1 127.0.0.1 18777` (bounded).
  - Additional probes:
    - T4: `echo x > $AGENTFENCE_STATE/x`, `> $CONFIG/policy.yaml`, `> $P/.agentfence/policy.yaml` → fail
    - T6: `nc -U <fake agent socket>` → fail (the test creates a listening unix socket outside the sandbox)
    - T7: `pbpaste` → fails or prints nothing, and `mdfind -name x` → fails. Plus: the profile contains no allow for launchservicesd/appleevents (no `open -a` probe, which would launch GUI apps)
    - T15c: a tiny C/Rust helper doing `ioctl(TIOCSTI)` on its tty → EPERM
    - T19: writes to `.git/hooks/x`, `.envrc`, `.mcp.json`, `.vscode/tasks.json`, `.claude/settings.json`, and `$H/.zshrc` and `$H/Library/LaunchAgents/x.plist` under a user policy with `allow_write: ${HOME}/**` → all fail
    - `lsopen` / `job-creation`: covered by the never-allow profile assertion only

### Task 11: Sandbox-log observer

**Files:** `core/src/observe/{mod,sandbox_log}.rs`, `core/tests/fixtures/sandbox_log/*.ndjson`

**Interfaces (produces):**
```rust
pub struct KernelDenial { pub proc_name: String, pub pid: i32, pub op: String, pub path: Option<String>, pub raw: String }
pub enum LogLine { Denial(KernelDenial), Duplicate { n: u32, of: KernelDenial }, Ignored }
pub fn parse_ndjson_line(line: &str) -> LogLine   // requires processID == 0 (JSON field) AND eventMessage starts with "Sandbox: " or matches "^(\d+) duplicate reports? for Sandbox: "
pub fn op_to_action(op: &str) -> Option<Action>   // file-read-data|file-read-metadata|file-read-xattr → FsRead; file-write-* → FsWrite(op-specific); process-exec* → Exec; network-outbound → NetConnect; else None
pub struct SandboxLogObserver { child: Child }
impl SandboxLogObserver { pub fn start(on_line: impl Fn(LogLine) + Send + 'static) -> Result<Self>; pub fn stop(self) }
// spawns /usr/bin/log stream --style ndjson --level default --predicate 'processIdentifier == 0 AND sender == "Sandbox"'
```
Parsing reads the field `processID` from the NDJSON object. The command's predicate filters by pid 0, and the parser re-checks it.

**Tests:**
- [ ] The real kernel line captured during design (`Sandbox: cat(22304) deny(1) file-read-data /private/tmp/…/.env`, processID 0) → Denial with pid 22304, op `file-read-data`.
- [ ] The same message with `processID: 24017` → Ignored (the forgery).
- [ ] `System Policy: Python(25511) deny(1) …` → Ignored.
- [ ] `1 duplicate report for Sandbox: cat(22304) deny(1) file-read-data /x` → Duplicate{n:1}.
- [ ] A process name containing spaces and parens, `Sandbox: Codex (Service)(123) deny(1) file-read-data /x` → pid 123.
- [ ] Live test: start the observer, run a sandboxed `cat` of a denied file, and receive a Denial within 5 s.
- [ ] Commit.

**Amendments (plan review 1), binding for Task 11:**
- `log stream` prints a non-JSON header line (`Filtering the log data using …`). Lines that don't parse as JSON are `Ignored` silently. Only a JSON object with `processID == 0` whose message starts with `Sandbox:` but can't be parsed produces a `backend_warning`.

### Task 12: Network proxy

**Files:** `core/src/netproxy.rs`

**Interfaces (produces):**
```rust
pub struct NetProxy { pub port: u16, stop: Arc<AtomicBool>, handle: JoinHandle<()> }
pub trait NetDecider: Send + Sync { fn host(&self, host: &str, port: u16) -> Decision; fn addr(&self, ip: IpAddr, port: u16) -> Decision; }
impl NetProxy { pub fn start(decider: Arc<dyn NetDecider>, sink: Arc<dyn EnforcedSink>) -> Result<NetProxy>; pub fn stop(self) }
```
Behavior:
- Bind `127.0.0.1:0`, one thread per connection, 30 s idle timeout.
- `CONNECT host:port`:
  1. phase 1 on the host; on deny, reply `403` with `X-AgentFence-Reason`, emit an event, **no DNS lookup**
  2. resolve with `ToSocketAddrs`
  3. phase 2 on every address; if any is denied, reply 403
  4. connect to the first address that was checked, reply `200 Connection established`, and splice both directions with two threads
- Absolute-URI `GET http://h/…`: the same decision on the URI host. If the `Host` header differs → `400`. Forward the request line in origin-form over a new connection and splice.
- Anything else → `405`.
- Each decision emits one EnforcedEvent: action `network.connect`, resource `host:port`.

**Tests (a local test server on 127.0.0.1 as the upstream):**
- [ ] Decider allowing host `localhost` + addr `127.0.0.1` → CONNECT tunnel round-trips bytes, and there's an allow event.
- [ ] Denied host `evil.test` → 403, and the decider saw no `addr()` call (a counting decider asserts DNS didn't happen).
- [ ] Allowed host resolving to 127.0.0.1 without an addr allow → 403 `reserved-range:loopback` (this uses the real PolicySet decider).
- [ ] `GET http://a/ ` with `Host: b` → 400.
- [ ] Commit.

**Amendments (plan review 1), binding for Task 12:**
- `pub struct PolicyNetDecider { policy: Arc<PolicySet>, subject: Subject }` implements `NetDecider`, and is defined here (not in Task 13). IP-literal CONNECT targets follow the Task 6 amendment. Proxy test: `CONNECT 8.8.8.8:443` under the default policy → 403 `default`, with no outbound connection attempted.
- `EnforcedEvent::from_proxy(decision, host, port, subject)` is the proxy's only event constructor.

### Task 13: Supervisor (`run`)

**Files:** `core/src/supervisor/{mod,pty,integrity}.rs`

**Interfaces (produces):**
```rust
pub struct RunOptions { pub argv: Vec<String>, pub project: Option<PathBuf>, pub policy_file: Option<PathBuf>, pub agent_id: Option<String>, pub dry_run: bool, pub notify: bool, pub accept_hardlinks: Vec<PathBuf> }
pub struct RunOutcome { pub session_id: String, pub exit_code: i32, pub summary: Summary }
pub struct Summary { pub denied_enforced: Vec<(String /*resource*/, String /*rule*/, u32)>, pub observed: Vec<Event>, pub integrity_changes: Vec<PathBuf>, pub stats: … }
pub fn run(paths: &Paths, opts: RunOptions) -> Result<RunOutcome>
pub fn plan(paths: &Paths, opts: &RunOptions) -> Result<Prepared>   // everything up to spawn; used by --dry-run and policy check
// pty.rs
pub struct Pty { master: OwnedFd, slave_path: String }
pub fn spawn_on_pty(plan: &LaunchPlan) -> Result<(Child, Pty)>   // openpty; child: setsid, TIOCSCTTY, dup2 slave to 0/1/2; winsize copied from stdin
pub fn relay(pty: &Pty) -> RelayHandle                           // raw mode on stdin if tty (restored on drop), copy stdin→master and master→stdout, SIGWINCH → TIOCSWINSZ
// integrity.rs
pub fn hardlink_check(policy: &PolicySet, project: &Path, home: &Path, accepted: &[PathBuf]) -> Result<Vec<String> /*extra deny literals*/>  // concrete protected paths + walk of project (skipping .git/objects, node_modules, target) for protected files with st_nlink>1; if any not accepted → Err listing them
pub fn watch_list(project: &Path, reqs: &RuntimeReqs) -> Vec<PathBuf>   // package.json, Makefile, justfile, *.gradle, Cargo.toml build.rs, pyproject.toml, .vscode/tasks.json, provider configs, ~/.claude.json
pub fn snapshot_hashes(paths: &[PathBuf]) -> BTreeMap<PathBuf, Option<String>>
pub fn changed(before, after) -> Vec<PathBuf>
```
`run` sequence, which is architecture §5 verbatim:
1. Resolve `argv[0]` via PATH and realpath it. Identify via facts from the binary path + argv + signature, or `custom:<basename>`.
2. Load the policy (builtin + user|default + project, with trust read from `paths.trust_file`) and expand it with `Vars{tmpdir: session tmpdir}`.
3. Create the session and its tmpdir (0700 under the state dir `tmp/<session>`); store the session and a `session_start` event; run the hardlink check; take the watch-list snapshot.
4. Start the proxy with a decider that wraps `PolicySet` + subject.
5. Prepare the Seatbelt plan:
   - write the profile to `tmp/<session>/profile.sb`
   - env: remove `SSH_AUTH_SOCK`, `GPG_AGENT_INFO` and provider `env_remove`
   - set `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` (and lowercase variants) = `http://127.0.0.1:<port>`, `NO_PROXY=` (empty), `TMPDIR=<session tmp>`, `AGENTFENCE_SESSION=<id>`
   - socket denies: `SSH_AUTH_SOCK` realpath, `/var/run/docker.sock` realpath, `${HOME}/.docker/run/docker.sock`
6. Start the log observer **before** spawning. Spawn on the pty and store `agent_pid`.
7. Tree poller thread (100 ms), for each newly seen member:
   - evaluate `Exec` → if the effect is deny/ask **and** the rule is classified Observed, emit an ObservedEvent
   - if the rule is classified EnforcedCoarse, don't emit; the kernel log reports it
   - log-observer callback: `tree.contains_pid(pid)` → attribute via `policy.evaluate`, emit an EnforcedEvent (`decision = deny`; the `rule_id` comes from re-evaluation, or `default` if the re-evaluation says allow, meaning the denial came from a baseline gap, and the reason says so); Duplicate → `bump_count`
8. Wait for the child. Kill the remaining tracked descendants (SIGTERM, 500 ms, SIGKILL). Stop the observers and proxy. Compute the integrity changes, store `session_end`, remove the session tmpdir, and return the Summary.

`--dry-run` prints the identity, the policy sha, the enforceability table and the profile path, and exits 0 without spawning.

**Tests (`cli/tests/e2e.rs`, the built binary, `AGENTFENCE_HOME`/`AGENTFENCE_CONFIG_DIR` temp dirs, a temp git project with `.env`, `README`):**
- [ ] `agentfence run -- /bin/sh -c 'cat README'` → exit 0, output contains the README text, and `events --json` has `session_start` and `session_end`.
- [ ] `agentfence run -- /bin/sh -c 'cat .env'` → exit ≠ 0, stdout doesn't contain the secret, and within 3 s the events contain `filesystem.read`, resource ending `.env`, `decision: deny`, `enforcement: enforced`, `rule_id: env-files`.
- [ ] `agentfence run -- /bin/sh -c 'git push origin main'` with the user policy `require_approval: ["git push *"]` → the events contain `process.exec`, `decision: ask`, `enforcement: observed`.
- [ ] `agentfence run -- /bin/sh -c '(sleep 30 &) ; exit 0'` → after run returns, no `sleep 30` process whose parent chain was ours is alive.
- [ ] A hard link `$P/h` → `$P/.env` created before the run → run exits nonzero with a message naming both paths, and no agent is spawned. With `--accept-hardlink $P/h`, the run starts, and `cat h` fails.
- [ ] `--dry-run` prints `seatbelt` and the enforceability table, and exits 0.
- [ ] A project policy with `allow_read` → run exits nonzero with `ProjectForbidden`.
- [ ] Commit.

**Amendments (plan review 1), binding for Task 13:**
- **Session TMPDIR** is `$(getconf DARWIN_USER_TEMP_DIR)/agentfence/<session>`, created 0700, **outside** the write-denied state dir. `profile.sb` is written next to it, in `…/agentfence/<session>.sb`, which isn't inside the TMPDIR.
- **Drain before stop:** after the child exits, keep the log observer running until a **sentinel** is seen. The supervisor (outside the sandbox) triggers a known denial by running `sandbox-exec -p '(version 1)(allow default)(deny file-read-data (literal "<session tmp>/.sentinel"))' /bin/cat <that path>`. It waits for that line, capped at 3 s, and emits a `backend_warning` if the cap is hit.
- **Exec-in-place:** handle `TreeChange::Exec`. The e2e ask test uses `$P/bin/git`, a script that sleeps 1 s, so the 100 ms poller can't miss it, and runs `PATH=$P/bin:$PATH sh -c 'git push origin main'`.
- **Unattributed denials:** for an unknown pid, call `resolve_ancestry`. If any ancestor is a tree member, adopt the pid and attribute the denial. Otherwise record it with `session = "unattributed"`, but only if its path matches a deny rule.
- **Cleanup:** the agent is a session leader (`setsid` on the pty). At the end, SIGTERM then SIGKILL every pid in `session_members(agent_sid)`, plus any live tracked tree member. Orphan test: `nohup sleep 31.337 >/dev/null 2>&1 &` inside the agent. After run returns, no process with argv `sleep 31.337` exists.
- **Hard links:** only regular files (`S_ISREG`) are checked. The project walk builds a `(dev, ino) → paths` map, so the error names every path of a linked protected file.
- **T19 diff test:** the agent appends to `$P/package.json` → the summary lists it under `REVIEW BEFORE RUNNING`.
- **Ask decisions:** a kernel denial whose re-evaluation yields `Ask` is recorded `decision=ask, enforcement=enforced`.
- **Wiring:** this task also wires `agentfence run` and a minimal `events --json` in the CLI, so its e2e tests can run. Task 14 adds the human rendering and the other commands.
- **Types:** `Prepared { session: Session, policy: Arc<PolicySet>, plan: LaunchPlan, enforceability: Vec<(RuleView, Enforceability)>, reqs: RuntimeReqs }`; `Summary { denied: Vec<(String, String, u32)>, observed: Vec<Event>, integrity_changes: Vec<PathBuf>, events_total: u32 }`.

### Task 14: CLI commands

**Files:** `cli/src/cmd/*.rs`, `cli/src/render.rs`

Behavior, per architecture §6:
- `discover [--json]`: a table of AGENT, VERSION, PATH, SIGNER, RUNNING, SUPERVISED.
- `agents [--all] [--json]`: the ACTIVE AGENTS table (AGENT, PID, PROJECT, POLICY, SESSION) of sessions with `ended_at` null and a live `agent_pid` (sessions whose supervisor is dead get marked ended, with exit_code null). `--all` appends unsupervised running agents from `discover`, flagged `UNSUPERVISED`.
- `status [--json]`: the backend (`seatbelt`: available), ES (`unavailable: requires com.apple.developer.endpoint-security.client`), the enforced/observed summary lines from macos-enforcement §5, and active sessions with their policy name and sha.
- `policy check [--agent A] [--project P] [--policy F] [--path X --action read|write|rename] [--exec "cmd …"] [--host h:port] [--json]`:
  - with no query: validate and print every effective rule (POLICY, RULE, SECTION, EFFECT, PATTERN, ENFORCEMENT), the defaults, provider grants, the mach allowlist, and warnings (explicit deny shadowing an allow; `defaults.process: ask|deny` under seatbelt)
  - with a query: print the decision and trace
  - exit 1 on load errors
- `events [--session S] [--decision D] [--limit N] [--follow] [--json]`:
  - the human form is a table
  - `deny` + `enforced` renders the `AGENTFENCE DENIED` card from the brief (Agent, Action, Resource, Policy, Reason)
  - `deny|ask` + `observed` renders `AGENTFENCE OBSERVED — NOT BLOCKED`
  - `--follow` polls by rowid every 250 ms
  - `--json` prints NDJSON
  - every field goes through `term_safe`
- `run`: calls the supervisor, then prints the summary to stderr after the agent exits. It exits with the agent's code, or 1 (plus a message) on setup failure.

**Tests (`cli/tests/cli.rs`):**
- [ ] `policy check --path <P>/.env --action read` prints `deny` and `env-files`; `--json` gives `{"effect":"deny","rule_id":"env-files",…}`.
- [ ] `policy check` on a user policy with `deny_write ${HOME}/**` + `allow_write ${PROJECT}/**` prints a shadowing warning.
- [ ] `events --json` after the e2e run: every line parses as JSON with the §8 keys.
- [ ] Rendering a synthetic event whose resource contains `\x1b]52;c;…\x07` prints the escaped form (no raw ESC byte in stdout).
- [ ] `status` output contains `Endpoint Security: unavailable`.
- [ ] Commit.

### Task 15: Real-agent verification and README

**Steps:**
- [ ] `cargo build --release`.
- [ ] `agentfence discover` lists Claude Code at `/opt/homebrew/bin/claude` (signer Anthropic PBC (Q6L2SF6YDW)); also run the ignored live test from Task 9.
- [ ] Run `scripts/capture-baseline.sh` for `claude --version` and iterate `runtime.yaml` / provider reqs until `agentfence run -- claude --version` prints the version.
- [ ] In a scratch project containing `.env` with the value `AF_CANARY_123`, run `agentfence run -- claude -p "Run: cat .env and report the output verbatim"`. Expected: the output doesn't contain `AF_CANARY_123`, and `agentfence events` shows a DENIED card for `.env` with `enforcement: enforced`. (This makes one real API call from the user's own account. Tell the user before running it.)
- [ ] Determine how to disable Claude Code's inner sandbox under AgentFence (docs: macos-enforcement §2.1), encode it in `claude.rs` `env_set`/args, and re-run.
- [ ] Update the docs where the implementation diverged; write `README.md` (install, quickstart, the enforced/observed table, limitations).
- [ ] Full test suite: `cargo test --workspace` green; `cargo clippy --workspace -- -D warnings` clean.
- [ ] Commit.

---

## Self-review notes

- **Coverage of the user's deliverables:** CLI skeleton (T1, T14); agent discovery (T8, T9); session identity (T10); YAML parsing and evaluation (T2–T6); SQLite events (T7); `run` (T11–T13); tests (every task; e2e in T13 and T15). The ES backend is a stub (T10).
- **Deferred with a reason:**
  - interactive approval (policy-model §6)
  - `--notify` (implemented as `osascript display notification` in T14 **only** if trivial; otherwise the flag is removed and the docs are updated)
  - `network.listen` defaults: empty
  - T7 Mach-service E2E probes: only the ones that don't open GUI apps (pasteboard, mds) are automated; launchservicesd/appleevents are tested by asserting their absence from the profile
