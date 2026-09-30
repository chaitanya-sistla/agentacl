# Changelog

All notable changes to AgentACL. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release workflow publishes the
section whose heading matches the tag, so every release needs one.

## [Unreleased]

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
