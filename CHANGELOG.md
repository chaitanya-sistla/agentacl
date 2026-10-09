# Changelog

All notable changes to AgentACL. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release workflow publishes the
section whose heading matches the tag, so every release needs one.

## [Unreleased]

### Added
- **Endpoint Security backend (preview, not yet run).** `agentacl-esd`, a
  root daemon designed to apply AgentACL's file and program rules to agents
  that `agentacl run` didn't launch: agents identified by code signature,
  every descendant tracked by audit token, file, metadata, exec (with
  arguments) and signal requests decided by the policy `agentacl run` loads,
  grants applied without a restart, and decisions in the usual audit log and
  console. Network rules aren't enforced by it, and some escapes remain open
  (see the design doc). Packaged as a LaunchDaemon and as `AgentACL.app`
  with a system extension. It needs a development Mac (SIP and AMFI off) or
  Apple's entitlement to run, so it isn't enabled and isn't a guarantee yet;
  see docs/design/endpoint-security.md.
- `agentacl es status`.

## [0.4.0] - 2026-10-08

**Know what your agents can reach, and keep them out of your company's
drives.** The question security teams ask first is "can it get into our
Google Drive?" This release answers it twice: synced cloud drives are now a
built-in protection, and `agentacl audit` shows, in one command, everything
an agent could reach on your Mac and what to fix first.

```sh
brew upgrade agentacl     # or: brew install chaitanya-sistla/agentacl/agentacl
agentacl audit
```

### Added
- **`agentacl audit`**, and "What can this agent reach?" on the console's
  Agents page: credential files and cloud drives (protected or readable),
  company data services reachable over the network (Google APIs, Dropbox,
  Box, Microsoft Graph, Slack, Notion, Atlassian, GitHub, S3), MCP servers
  and tokens written in plain text into config files the agent can read,
  keychain access, secret environment variables and console grants, each
  finding with its fix. `--json` for scripts, `--strict` to fail on a
  high-severity finding. Names only, never secret values.

### Security
- **Cloud drives are a built-in protection** (`cloud-drives`): Google Drive,
  OneDrive, Dropbox, Box and iCloud Drive folders, and the drive apps' own
  caches (Google Drive keeps copies of synced files there), are refused to
  an agent for reading, changing and deleting, even under a rule that opens
  all of home. A project
  that lives inside a cloud drive stays usable. If you rely on an agent
  reading a drive, switch the group off with
  `builtin: { disable: [cloud-drives] }`. Not covered: iCloud's "Desktop &
  Documents" sync and a Dropbox in a custom location (`agentacl audit`
  reports the first); `agentacl run` warns, and `audit` reports, when the
  project is or contains a drive (such as Google Drive's `My Drive`).
- Project folders whose path contains `*` or `?` are refused: those would
  act as wildcards in `${PROJECT}` rules.

## [0.3.1] - 2026-10-01

**Closing the side doors.** A sandbox is only as strong as the services it
still lets the agent talk to. This release probes every one of them for a
*confused deputy*, a service outside the sandbox that would act for the
agent, and closes the four that leaked: other apps' preferences, the live
system log, other processes' shared memory and, for Claude Code with a
token, the keychain. It also makes **Allow…** grant exactly the files an
agent asked for, not the folder around them.

If you use Claude Code with `/login`, read the keychain note below and
consider switching to a token (`claude setup-token`).

### Security
- **Confused deputies.** An agent could read any app's preferences through
  `cfprefsd`, which runs outside the sandbox, although the preference files
  themselves were denied. Preference reads are now limited to the global
  domain. An agent could also stream every process's unified log through
  `diagnosticd`; that service is now denied. It could read, change and
  delete another process's POSIX shared memory by name; shared memory is
  now limited to Python's own segments and Apple's system state
  (read-only). launchd jobs are probed for real in the test suite (no job
  runs).
- **Keychain.** A Claude Code session logged in with `/login` can reach the
  keychain, so it could run the credential helpers other items trust (git's
  returned a saved GitHub token without asking; verified) and read the
  encrypted keychain database. With
  `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`),
  `ANTHROPIC_API_KEY`, or Bedrock or Vertex set in the shell `agentacl run`
  starts from, the session now gets no keychain access at all. Keychain
  files can't be granted from a request.
  The docs no longer claim keychain items stay protected by their own
  access rules.

### Changed
- **Allow… grants exactly the files that were refused**, by default. The
  whole folder is a separate, explicit choice that says it also covers files
  the agent hasn't asked for, and that allowed reads aren't recorded.

## [0.3.0] - 2026-09-30

**Give each agent its own access, and decide without the noise.** v0.2.0
turned what the sandbox blocks into decisions. v0.3.0 makes those decisions
precise and calm: allow a folder or a site for one agent in one project,
take as long as you need to answer, get one notification a minute instead
of a stream, and see whether a restart actually worked. It also closes
sandbox gaps found in a security audit, and publishes a matrix of exactly
what AgentACL enforces, observes and doesn't do.

### Highlights

- **Per-agent, per-project access.** "Allow…" on a refused folder or site
  asks *for which agent* and *where*. Claude Code can get `~/o2` in one
  project without Codex, or any other project, getting it too.
- **Take your time.** Agents on a new site wait 30 s, 1, 2 or 5 minutes for
  you, with "+1 min" when you need longer.
- **One notification a minute, at most**, summarizing what's waiting and
  what was refused. Quiet mode for when you're focused.
- **Restarts you can trust.** The console shows whether the agent came
  back, or why it didn't.
- **Security audit fixes.** Moving a folder that holds a key no longer
  exposes it; more places to plant code that runs later are closed; agents
  can no longer read AgentACL's own audit log.
- **Honest guarantees.** [docs/security-guarantees.md](docs/security-guarantees.md)
  lists every capability as ENFORCED, PARTIALLY ENFORCED, OBSERVED, PLANNED
  or NOT SUPPORTED, with the test behind each claim.

Files still can't wait for your answer: the macOS sandbox refuses them
instantly. A refused folder becomes a request you allow with a scope, and
the agent picks it up on restart (the conversation resumes).

### Added
- `docs/current-state.md`: an audit of what exists, what is enforced (with
  the test behind each claim), what is observed and what is planned.
- `docs/security-guarantees.md`: the claims matrix, using only ENFORCED,
  PARTIALLY ENFORCED, OBSERVED, PLANNED and NOT SUPPORTED, each with its
  evidence.
- Sandbox tests for every built-in secret group (read and overwrite, under a
  policy that otherwise allows all of home), and for delegation through
  nested shells, Python and Python subprocesses.
- `scripts/demo/`: deterministic, repeatable demo scripts using only fake
  secrets in `/tmp/agentacl-demo`.

### Security
- `exec-persistence` now also write-protects `.husky` hooks, project
  `__pycache__`, Python user site-packages (`.pth` files run at every start)
  and Apple's Python bytecode cache.
- `agentacl-self` now also denies *reading* AgentACL's state directory (the
  audit log holds every session's events, including command lines).
- Moving a folder that holds a name-protected secret (`mv certs $TMPDIR/c`,
  then read `server.pem`) no longer exposes it: name rules such as
  `**/*.pem` are now also enforced in every other writable location.
- The `kube` group now protects all of `~/.kube`, not just files named
  `config`.

### Added (console)
- **Allow a request for one agent, in one project.** "Allow…" on a refused
  folder or site asks which agent (this one or all) and where (this
  project or everywhere), and for files, read or read and change. Saved as
  an access file in `~/.config/agentacl/access/`. Sites apply at once; files
  apply when the agent restarts. The Agents page lists every grant, with
  Remove.
- **Waiting requests on the Requests page**, with a countdown, "+1 min" and
  "always allow, for this agent only". The wait is now a setting: 30 s
  (default), 1, 2 or 5 minutes.
- **Notification digest and quiet mode.** At most one notification a minute
  across all agents; refused files and sites are summarized, each counted
  once; quiet for an hour or until turned back on.
- **Restart tracking.** After Restart, the console shows whether the agent
  came back, the restart was refused (and why) or the agent exited, instead
  of "Restarting" forever.

### Changed
- Python run by an agent always keeps its bytecode cache in the session's
  temp directory (`PYTHONPYCACHEPREFIX`), instead of probing
  `~/Library/Caches/com.apple.python`, which stays closed. Agent-run Python
  can read your user site-packages (read-only).
- README restructured: problem, demo, how it works, guarantees, then the
  agent-identity vision.

### Fixed
- Threat model T22 described the console's old bearer-token auth.

## [0.2.0] - 2026-09-30

**See and decide what your AI agents reach for.** v0.1.0 made AgentACL a
kernel boundary around Claude Code, Codex, Gemini CLI, Copilot CLI and
OpenCode. v0.2.0 turns what that boundary blocks into decisions you can act
on: a requests inbox, a live network firewall you control from the console,
and approvals that let an agent wait while you decide, with no restart.

### Highlights

- **Requests inbox.** Every action an agent tried and couldn't do, grouped
  into decisions instead of raw log lines. Each shows the site, secret,
  folder or program, how often, when, and which agent and project.
  - Actions: **Allow site**, **Always block**, **Review in access map**,
    **Dismiss**.
  - Server-side pagination and per-kind tabs.
  - Dismissed requests come back only if the agent tries again.
- **Network page.** Every site your agents reached or tried to reach.
  - Each site is labelled: AI provider, package registry, source hosting,
    telemetry, documentation or cloud API.
  - Allowed and blocked counts, and each site's current effective status.
  - **Allow** and **Block** apply to agents that are already running,
    immediately. Allow is only offered where it would actually work.
- **Live approvals ("Ask me").** Set unknown sites to *Ask me*, and a
  connection to a site no rule names waits up to 25 seconds for your answer
  in the console, with a macOS notification.
  - Allow the waiting connection, allow for the session, or always allow.
  - Block once or always.
  - No answer means blocked.
- **New overview.** Allowed and blocked actions per hour, blocks by kind,
  top blocked sites, most used sites, and most blocked files grouped by
  folder.

### Improved

- Sites are recognised by category, including Datadog's flat intake hosts.
- Activity shows console decisions in plain words.
- New dashboard cards (sites blocked, requests waiting) open their pages.

### Fixed

- Blocked writes to an agent's own settings (`~/.claude/...`) are shown as
  protected settings, not as "outside the project".

### Security

- **Console decisions never widen past your policy.**
  - A console allow only lifts a *default* denial; explicit and built-in
    blocks always stand.
  - Private and local addresses stay blocked even after you allow a name.
  - No site name is looked up in DNS before you answer, so an agent can't use
    made-up names to leak data while it waits.
- **Blocks and revocations reach running agents.**
  - A console block applies to every running agent at once.
  - Removing an allow from your policy revokes it for agents that already
    loaded it.
- **Agents can't approve themselves.** Approvals and live rules live in
  AgentACL's state directory, which agents can't write. Prompts are rate
  limited (per site, per session and for notifications).
- **Approvals are per site and port.** Approving `example.com:443` doesn't
  admit other ports.

### Upgrade notes

- **Rule id `default` is now reserved.** A policy rule with `id: default` is
  rejected; rename it.
- **Restart running agents** (`agentacl restart`, or Restart in the console)
  to give them live network decisions. Agents started by 0.1.0 keep working
  but only follow their start-time policy.
- **Restart `agentacl ui`** to get the new console.

### Known limitations

- A block you remove still applies to agents started while it existed, until
  they restart: explicit denials are never lifted on a running agent.
- File and program rules still apply from the next start (a macOS sandbox
  property). Network decisions are the ones that apply live.

## [0.1.0] - 2026-09-29

### Added
- `agentacl run`: supervises Claude Code, Codex, Gemini CLI, Copilot CLI and
  OpenCode under a macOS Seatbelt sandbox compiled from YAML policy
  (explicit deny wins), with built-in secret protection, a network proxy with
  two-phase host/address checks, secret-env stripping and exact kernel-denial
  attribution.
- `discover`, `agents`, `status`, `policy check`, `policy trust`, `events`,
  `restart` and `stop`.
- `agentacl ui`: a local console (127.0.0.1 only) with machine-wide agent
  discovery, projects, an access graph, a rules editor with reviewed saves and
  restart of affected sessions, built-in protection switches, access tests and
  a paginated audit log.
- SQLite audit log with JSON output.
