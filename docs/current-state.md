# AgentACL: current state (v0.6.0, 2026-10-09)

An audit of what exists today, written before the next round of work.
Every "enforced" claim below cites the test that exercises it. Anything
without a test is not called enforced. The status words match
[security-guarantees.md](security-guarantees.md):
- **ENFORCED**: blocked, with a test that proves it.
- **PARTIALLY ENFORCED**: blocked, with a known gap.
- **OBSERVED**: recorded but not blocked.
- **PLANNED**: not built.
- **NOT SUPPORTED**: not possible with the current design.

## 1. What AgentACL is today

A **supervised runtime**. The strong boundary exists only for agents started
with `agentacl run -- <agent>`. `agentacl run` does three things:

1. Compiles the effective policy (built-ins, then the user policy, then the
   project policy) into a macOS Seatbelt (SBPL) profile.
2. Starts the agent under `sandbox-exec` on its own pty. The kernel sandbox is
   inherited by every descendant process and outlives the supervisor.
3. Forces all network egress through a local proxy run by the supervisor.
   The proxy enforces host rules and, since v0.2.0, live console decisions.

Agents started any other way (plain `claude`, a GUI, an IDE) are only
**discovered and reported**. Nothing restricts them.

## 2. Components that exist and work

| Area | What exists | Where |
|---|---|---|
| Policy engine | YAML v1 with closed schema. Explicit deny wins. Built-ins, user and project layers; project policies are restrict-only unless trusted by hash. Variables (`${HOME}`, `${PROJECT}`, …), globs with `except`, per-agent `match`. Two-phase network decisions (host, then resolved addresses). Pure, no I/O | `crates/agentacl-policy` |
| Built-in protections | `protect-secrets` (13 groups: env files, ssh, aws, gcp, azure, kube, terraform, git and package credentials, keys, gpg, browsers, cloud drives). `exec-persistence`, `agentacl-self`, and the runtime baseline | `crates/agentacl-policy/builtin/*.yaml` (data, not code) |
| Seatbelt backend | Profile compiler (`(deny default)`, allows, then all denies last), a Mach-service allowlist, kernel-denial parsing with per-rule tags, dry-run | `crates/agentacl-core/src/enforce/` |
| Supervisor | Launches on a pty, strips secret env vars, fails closed on hard links, cleans up orphans, restarts on the same session, and flags build-file diffs at session end | `crates/agentacl-core/src/supervisor/` |
| Network | CONNECT and HTTP proxy. The sandbox allows egress only to the proxy port. Reserved ranges are refused. Live console rules, *Ask me* approvals and revocations | `netproxy.rs`, `netlive.rs` |
| Identity | `agt_` session ids, a machine id (hash of the hardware UUID), and the agent binary's path, SHA-256 and code signature at launch | `identity.rs`, `session.rs`, `proc/` |
| Discovery | Five providers (Claude Code, Codex, Gemini CLI, Copilot CLI, OpenCode). Identified by code signature where the binary is signed (Claude, Codex), otherwise by executable path and entry point. Running processes are also scanned | `crates/agentacl-core/src/agents/` |
| Delegation chain | Polled process tree (about 100 ms), attached to events. Short-lived intermediate processes may show as `…` | `proc/tree.rs`, `supervisor/mod.rs` |
| Audit | SQLite log with `--json` (NDJSON). An event is marked enforced only when it comes from a kernel report or a proxy decision | `crates/agentacl-core/src/audit/` |
| Console | `agentacl ui`: localhost-only React console. Overview, Requests inbox, Agents, Projects, Network (live allow and block, *Ask me*), Policies (access graph, editor, review and save, restart), Activity, Settings | `crates/agentacl-cli/src/ui/`, `crates/agentacl-cli/web/` |
| Release | A tag starts the release: full CI, arm64 and x86_64 builds, a universal binary, SHA256SUMS, a build-provenance attestation, and a GitHub release with notes taken from the changelog | `.github/workflows/release.yml`, `docs/releasing.md` |

## 3. Enforcement status (verified against tests)

**ENFORCED** (kernel or proxy; tests in parentheses):

- **Reading and overwriting built-in secret files, for the agent and every
  descendant.** All 13 `protect-secrets` groups are probed (37 fake files)
  under a policy that otherwise opens all of home, so the secret rules alone
  block them. Case variants and symlinks are covered; `.env.example` and
  similar stay readable. Tests: `enforce::tests::sandbox_every_builtin_secret_group`
  (added in this audit), `sandbox_reads`, `e2e::secret_read_blocked_and_audited`.
- **Delegation through interpreters and nested shells.** `bash` → `sh` →
  `python3` → file, Python `subprocess` and `os.system`, each with a positive
  control. Test: `sandbox_holds_through_python_and_nested_shells` (added in
  this audit).
- **Moving secrets out from under a rule.** Renaming or moving a protected
  file or its parent, creating a hard link, or moving the project away.
  Moving a folder that holds a name-matched secret (`certs/server.pem`) to a
  temp directory: the name stays denied there (fixed in this audit; before,
  the key was readable after `mv certs $TMPDIR/c`).
  Tests: `sandbox_location_protection`, `sandbox_moved_directory_keeps_secret_names`.
- **Persistence writes.**
  - Git: `core.fsmonitor`, `.git/commondir`, hooks, replacing `.git`.
  - Project files: `.envrc`, `.mcp.json`, `.vscode`, `.claude`.
  - Home files: `~/.zshrc`, LaunchAgents, `~/.gitconfig`.
  - AgentACL's own policy and state, and the project's `.agentacl/`.

  - Added in this audit: `.husky` hooks, project `__pycache__`, Python user
    site-packages (`.pth`) and Apple's Python cache.

  Test: `sandbox_writes_and_exec_persistence`.
- **Network.**
  - Direct egress that bypasses the proxy is refused, and listening on a port
    not in `network.listen` is refused (`sandbox_network_and_listen`).
  - The proxy default-denies hosts
    (`e2e::network_default_deny_through_proxy`, `netproxy::tests`).
  - Console blocks, allows, revocations and approvals are unit-tested against
    the real decider (`netlive::tests`), and an approval was verified end to
    end by hand.
- **Unix-socket connect deny** for the ssh-agent and docker sockets. The
  tests allow the socket as well, so only the deny can refuse it.
  Tests: `sandbox_unix_socket_deny`, `credential_sockets_are_denied`.
- **Executable-level exec deny by name.** Test: `sandbox_exec_deny`.
- **Mach services excluded from the allowlist are unreachable.**
  `launchservicesd`, `appleevents`, the pasteboard, `mds`, `nsurlsessiond`,
  `SecurityServer` (unless the provider needs it) and `dnssd`.
  Test: `sandbox_mach_services`.
- **Keystroke injection into the terminal** (`TIOCSTI`). Test:
  `sandbox_blocks_tiocsti`.
- **Reading other processes' command lines.** Test:
  `sandbox_cannot_read_other_processes_argv`.
- **Secret environment variables** are withheld from the agent. Test:
  `e2e::secret_env_is_withheld`.
- **Fail-closed on pre-existing hard links to protected files**, and on a
  project policy that tries to widen access (project policies are
  restrict-only). Tests: `e2e::hardlinks_fail_closed`,
  `e2e::dry_run_and_restrict_only_project_policy`.
- **Orphaned background processes are killed at session end.** Test:
  `e2e::orphans_are_cleaned_up`.

**PARTIALLY ENFORCED:**

- **Exec deny.** Enforced by name and the resolved path. A copied or renamed
  binary is not matched (threat model T11).
- **Moving a folder that holds a secret.** Covered as above, except under
  `defaults.filesystem: allow` (or a writable `/`), where a folder can be
  moved anywhere.
- **Planting code.** Each listed file is write-denied in place, but a folder
  prepared in a temp directory (holding a `__pycache__` or a nested `.git`)
  can be moved into the project. A sourceless `.pyc` outside `__pycache__`
  and `.pth` files in a project virtualenv are writable, like the rest of
  the project. Trade-off: deleting a folder that contains `__pycache__` or a
  nested `.git` fails inside the sandbox.
- **User `deny_read` rules** deny read, delete, rename and link, but not
  overwrite (built-ins deny both).
- **Hard links.** Links found at startup fail closed. Links elsewhere in
  `$HOME` that match glob rules are not scanned (T2 residual).
- **Escapes through other apps (T7).** The Mach allowlist is tested, but no
  end-to-end probe of `osascript` → Terminal `do script` or `open -a` is in the
  suite yet.
- **Keychain.** For Claude Code logged in with `/login`, the session can
  reach `securityd`, run the credential helpers items trust (git's returns
  saved GitHub tokens without asking; verified, T9) and read the encrypted
  keychain database. With a token in
  the environment (`claude setup-token`), it gets no keychain access.
- **Tamper resistance.** The kernel sandbox survives supervisor death, but
  auditing stops. Signalling the supervisor is only partly restricted (T5).

**OBSERVED** (recorded, never blocked):

- Argument-level process rules (`git push *`). Test:
  `e2e::argument_rule_is_observed_not_blocked`.
- Agents not started with `agentacl run` (`discover`, `agents --all`, the
  console).
- The delegation chain (polled).
- Changes to build files (`package.json`, `Makefile`), flagged "REVIEW BEFORE
  RUNNING".

**PLANNED** (not implemented):

- Endpoint Security backend (`crates/agentacl-es`, the `agentacl-esd`
  daemon): implemented, and verified on a development VM with SIP and AMFI
  off; needs Apple's entitlement for standard Macs
  ([design](design/endpoint-security.md)). The `MacOSEndpointSecurityBackend`
  launch backend still reports unavailable.
- System-wide enforcement for unsupervised agents.
- Interactive allow-once for **files and programs**. Network approvals exist;
  file and program approvals don't, because a Seatbelt profile is fixed at
  launch.
- Signed and notarized binaries (the release workflow supports it once
  secrets are configured).
- Homebrew bottles (so the tap install doesn't need Command Line Tools) and
  automatic formula updates on release.

**NOT SUPPORTED:**

- Exfiltration through an allowed host (T9), and TLS or SNI inspection.
- Linux and Windows.
- GUI or IDE agents started outside `agentacl run`.

## 4. Security-relevant technical debt

1. **Seatbelt is deprecated and undocumented** (`sandbox-exec`). It's what
   the major agent vendors use today, but Apple may change it. The
   Endpoint Security backend is the mitigation; its entitlement is not yet
   granted.
2. **The T7 end-to-end probes are missing** (above). Until they exist, "escape
   via other apps" stays PARTIALLY ENFORCED.
3. **The audit trail is a lower bound.** Kernel violation reports are
   rate-limited and deduplicated. Enforcement is unaffected.
4. **Stale documentation found in this audit:**
   - Threat model T22 said the console uses a bearer header "never a cookie";
     it uses an HttpOnly per-port cookie plus a required custom header (fixed
     in this audit).
   - Several design docs still say "design, iteration 1".
5. **Binaries are ad-hoc signed.** macOS Gatekeeper may warn on first run of
   a downloaded binary.
6. **Console supply chain.** The React console pulls about 95 npm packages
   at build time. The built output is committed and embedded, and CI runs
   `npm audit` and `cargo-deny`. Nothing is loaded at runtime (CSP `'self'`).
7. **The state directory was only write-protected.** Under a user policy
   that opened `${HOME}/**` for reading, an agent could read `agentacl.db`,
   which holds every session's events, including command lines. Fixed in
   this audit: `agentacl-self` now also denies reading the state directory
   (tested).
8. **Built-in paths are rooted at the real home directory.** Tests use a
   fixture home through the policy variables. `agentacl run` always uses the
   passwd home, so end-to-end tests of `~/.aws` and similar paths can't use
   fixture files without touching the real directory (relevant for
   AgentBreak).

## 5. Installation experience today

- Download the release tarball, verify SHA256SUMS, then
  `sudo install … /usr/local/bin/`. Six commands (README).
- Or `cargo install --locked --git … agentacl-cli`, which needs a Rust
  toolchain.
- Homebrew tap: `brew install chaitanya-sistla/agentacl/agentacl`
  ([homebrew-agentacl](https://github.com/chaitanya-sistla/homebrew-agentacl)).
  No bottles yet, so Homebrew requires up-to-date Command Line Tools; the
  formula's version is updated by hand at each release.
- No uninstall or upgrade documentation.

## 6. Test coverage today

- **152 Rust tests** across the workspace (plus 2 ignored tooling helpers):
  - policy parsing, evaluation and property tests;
  - real-sandbox and compiler tests on a fixture home (`enforce::tests`, 19, four added in this audit);
  - 13 end-to-end tests of `agentacl run`;
  - 11 console API tests;
  - proxy, live network, audit, discovery and identity tests.
- **CI** (`.github/workflows/ci.yml`):
  - macOS 14 and 15 runners run everything, including the real-sandbox and
    end-to-end tests;
  - an Intel build and the minimum Rust version (1.85);
  - console typecheck and build, with a check that the committed build
    matches the source;
  - `cargo-deny`, `npm audit`, `typos`, `shellcheck`, `actionlint`;
  - authorship.
- **Gaps:**
  - There is no vendor-neutral, machine-readable security test report
    (AgentBreak).
  - Nothing tests a real agent binary (Claude Code, Codex) in CI.
  - There are no T7 escape probes.

## 7. Release process today

Documented in [releasing.md](releasing.md):
1. Bump the version.
2. Write the changelog section.
3. Push an annotated `vX.Y.Z` tag on `main`.

The workflow then runs:
- **Preflight:** semver, versions agree, tag on `main`, created by the
  maintainer, dated changelog section, authorship.
- The **full CI**.
- **Builds:** arm64 and x86_64, then a universal binary with `lipo`.
- **Signing:** Developer ID signing and notarization when the secrets exist;
  otherwise an ad-hoc signature (the case today).
- **Smoke tests** of the packaged binary.
- **Archives** with SHA256SUMS and a GitHub build-provenance attestation.
- **Publish** to GitHub Releases.

Release tags are restricted to the maintainer (repository ruleset).

## 8. Extension points that already exist

- **Agent detection:** the `AgentProvider` trait, one file per agent in
  `crates/agentacl-core/src/agents/`, with unit tests in `agents/tests.rs`.
- **Policy packs:** built-in YAML files in `crates/agentacl-policy/builtin/`.
  `protect-secrets` groups are data. Adding a group means editing YAML, the
  group list in `tests/set.rs`, and a probe in
  `enforce::tests::sandbox_every_builtin_secret_group`, which fails if a
  group has none.
- **Enforcement:** the `EnforcementBackend` trait with the Seatbelt
  implementation, the Endpoint Security stub launch backend, and the
  `agentacl-es` engine's `PolicyProvider`.
- **Security tests:** there's no contributor-facing interface yet. Sandbox
  tests are Rust tests using `Fixture`.
