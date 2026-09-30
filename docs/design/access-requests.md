# Access requests, per-agent access and restart tracking

Status: approved 2026-09-30. Scope: the local console and the supervisor.

## Problem

- Only network requests can wait for a human. File refusals just show up in
  the Requests page, and every allow is global.
- "Ask me" waits a fixed 25 s. There is no way to take longer.
- Notifications fire per site, every 8 s at most per session. With several
  agents running this adds up.
- After **Restart** in the console, the badge says "Restarting" forever: the
  console never checks whether the agent came back.

## What Seatbelt allows

A Seatbelt profile is fixed when the agent starts. The kernel refuses a file
open immediately (`EPERM`) and AgentACL learns about it afterwards from the
kernel log. **A file request cannot wait for an answer** under this backend.
The only macOS mechanism that can hold a file open is Endpoint Security
(`ES_EVENT_TYPE_AUTH_OPEN`), which needs Apple's entitlement (roadmap).

So a file request is: refused now → shown as a request → you allow it for an
agent and a place → the agent restarts under the new rule and the
conversation resumes. The docs must never say that files wait.

## Design

### 1. Access files (per agent and per place)

Every allow made from a request is stored in
`${AGENTACL_CONFIG}/access/`, one ordinary policy document per scope:

| File | `match:` | Meaning |
|---|---|---|
| `all.yaml` | none | every agent, every project |
| `all@<p>.yaml` | `projects: [<project>]` | every agent, one project |
| `agent-<name>-<h>.yaml` | `agents: [<agent>]` | one agent, every project |
| `agent-<name>-<h>@<p>.yaml` | both | one agent, one project |

`<name>` is the agent id with anything outside `[A-Za-z0-9._-]` replaced by
`_`, and `<h>` the first 8 hex digits of the SHA-256 of the exact id, so two
ids never share a file (and no agent file is `all.yaml`). `<p>` is the first
12 hex digits of the SHA-256 of the project path. The project is the exact
folder the session uses (canonical, not its git root). A file whose name
isn't the one its own `match:` gives is refused, as is anything but plain
allow rules: `allow_read`, `allow_write`, and `network.allow` for lowercase
host names; no `except`; at most one literal agent id (no patterns) and one
literal project.

- Every access file is loaded at the User layer, after `policy.yaml`; the
  `match:` inside decides which sessions it applies to. The staleness check
  ("restart to apply") watches the four file names that can apply to a
  session, and only their file rules: sites reach running agents live.
- Write-protected from agents by `agentacl-self` (`${AGENTACL_CONFIG}/**`).
- Written by the console with the canonical emitter; every write is validated
  by loading the complete policy set first, and refused if that fails.
- A file that isn't a valid access file (a stray copy, a bad hand edit) is
  left out of every session, which loses only its grants (fail closed);
  `agentacl run` warns about it, and the console lists it with Remove.
- Built-in protections still win (deny wins): before saving, the console
  checks that the grant takes effect and refuses it, naming the protection,
  if it wouldn't.

### 2. Network rules with a scope

`LiveRule` gains optional `agent`, `project` and `source` (the access file
it mirrors). A rule without a scope applies to everyone (today's
behaviour). The proxy knows its session's agent and project and skips rules
for others. An Allow from the page, or "Always, for this agent only" on a
waiting request, writes the access file (for new sessions) **and** a scoped
live rule (for running ones). Removing it drops the live rule and revokes
that access document's allow (`Revocation.policy`) for sessions that loaded
it; every other access file (and the policy file) that still allows the host
gets its live rule re-added, so those agents keep it. When the console
reads the access files, live rules follow hand edits too: a site removed by
hand is revoked for running sessions, and one added by hand gets a live
rule. Blocks stay global and go to the user policy, as
before: blocking more is always safe.

### 3. Waiting: configurable, extendable

- `network-live.json` gains `ask_timeout_secs` ∈ {30, 60, 120, 300}
  (default 30). Read by the proxy when a prompt is created.
- **+1 min**: `POST /api/approvals/extend` records an extension for a
  pending prompt (at most 5 per prompt). The waiting connection re-reads it
  and moves its deadline; the prompt's `expires` is updated for display.
- Clients may give up earlier (curl `-m`, Node fetch). The page says so. The
  proxy can't tell when a waiting client gave up, so the prompt stays until
  it is answered or expires.

### 4. Notifications: digest and quiet mode

A shared notifier (`${AGENTACL_STATE}/notify.json`, under a file lock) used
by every supervisor:
- The first waiting site after a quiet minute notifies at once (an agent is
  stuck).
- Everything else (more sites, refused requests) is counted into a digest,
  sent at most once a minute: "Claude Code: waiting on 2 sites · 3 requests
  refused. Review in the AgentACL console (agentacl ui)."
- Quiet: off / on / until a time ("quiet for 1 hour"). Requests still arrive
  in the page.
- Notifications are plain macOS notifications via `osascript`; clicking one
  can't open the console (that needs an app bundle), so the text says where
  to go.
- Only requests the user can allow from the console count: sites and files
  in the home folder (outside `~/Library`) that no rule named (default
  denials), each counted once.
  Built-in protections, the user's own blocks and the macOS baseline's
  system lookups don't.

### 5. The Requests page

- **Waiting now**: pending network prompts with a countdown, Allow for the
  session, Block, "Always, for this agent only", "Always, for every agent",
  **+1 min**, and the wait-time setting. (The floating dock shows the same
  cards on other pages.)
- **Refused**: file and site requests (as today), with **Allow…** opening the
  scope picker (agent: this / all; place: this project / everywhere; files:
  read or read and change, for the folder the request is grouped under).
- **Pending restart bar**: agents whose rules changed, "Restart now (the
  conversation resumes)", tracked as below.
- Header: quiet toggle and "quiet for 1 hour".
- Agents page: one **Access you granted** list (every access file's rules,
  with who and where), with Remove.

### 6. Restart tracking

`GET /api/sessions/restart-status?session=<old>` returns:
- `restarted` + the new session id, when a session with the same supervisor
  pid started after the restart was requested (the relaunch is prepared,
  and stamped, before the old session ends; the request time is taken before
  the signal is sent);
- `refused` + the reason, when a `restart.refused` event exists for the old
  session after the request;
- `exited`, when the old session ended and its supervisor is gone;
- `restarting` otherwise.

The console polls it every second after Restart and shows the real outcome.
After 30 s it says "Taking longer than expected" (and keeps checking for
three minutes).

## Security properties

- No decision uses a language model.
- Answers, access files and settings live where agents can't write.
- An allow covers exactly the folder or host picked, for exactly the agent id
  and project folder picked (literal ids and paths only; one file per scope).
  Your home folder and top-level folders can't be granted from a request.
- Built-in protections can't be allowed from the console.

## Tests

- Policy: access files load with the right `match`; a Claude-only rule
  applies to Claude and not to Codex; a project-scoped rule only in that
  project; an access file with anything but rules is refused.
- Sandbox (real kernel): a per-agent allow opens a file for that agent only.
- Proxy: scoped live rules; configurable timeout; extension moves the
  deadline and is capped.
- Notifier: first-waiting immediate, digest rate limit, quiet mode.
- Console API: allow with each scope, remove, extend, restart status.
