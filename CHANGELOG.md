# Changelog

All notable changes to AgentACL. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release workflow publishes the
section whose heading matches the tag, so every release needs one.

## [Unreleased]

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
