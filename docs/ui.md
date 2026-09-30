# AgentACL Local UI — Design

Status: design, revised after cold reviews 1 and 2 (2026-09-29). This extends the
iteration-1 scope, which excluded a web UI, at the user's request.

## 1. Goal

Make policy easy to apply without editing YAML by hand:

- **Browse and pick.** Choose files and directories visually, and mark them allowed or denied.
- **See before saving.** See what an agent gets today and under the draft, for any path.
- **Save the same YAML the CLI uses.** Files stay the source of truth.
- **Watch and apply.** See live sessions and denials, and relaunch a session
  so a change takes effect (`agentacl restart`).

Non-goals:
- No hosted service, accounts, or remote access.
- No approval prompts.
- **No new authority.** Every UI action has a CLI equivalent that exists first
  (§4.6) and goes through the same validation.

## 2. Shape

`agentacl ui [--port N] [--no-open]` runs in the foreground; Ctrl-C stops it.

- **Server.** It listens on `127.0.0.1` at a random port, or `--port`.
- **Credentials.** It mints two values from `/dev/urandom`:
  - A **bootstrap code** (128 bits). It works **once**, and only within 60 s.
  - A **session token** (256 bits). The page gets it by exchanging the code.
    It is set as an `HttpOnly; SameSite=Strict; Path=/` cookie named `af_session_<port>` (browsers send cookies to every port of a host),
    so page script never sees it and reloads keep working. Every API request
    must **also** carry `X-AgentACL: 1`. A cross-site page can only send a
    custom header after a CORS preflight, which the server refuses (OPTIONS
    returns 405), and a present `Origin` must be the console's own. So the
    cookie on its own authorizes nothing. Tests and scripts may use
    `Authorization: Bearer <token>` instead. Each code exchange mints a new
    token and revokes the previous one. When the session ends, the page asks
    you to press Enter in the `agentacl ui` terminal, which opens a new tab
    with a fresh code.
  - **Replay.** If a code is presented a second time, the server records a
    `ui.code_replay` warning, revokes every token and exits. The page shows
    "this link was already used — possible interception".
- **Opening the page.** It runs
  `/usr/bin/open http://127.0.0.1:PORT/#code=<hex>` and prints the same URL.
  Anyone who sees the URL later (browser history, process argv) has a dead code.
- **Records its port.** It writes `${AGENTACL_STATE}/ui-<pid>.json`
  (`{pid, port, started}`, mode 0600, one file per instance) and removes it
  on exit. The proxy reads these files (§5, row 1).
- **Startup output.** One line: the URL, "press Enter to open it again,
  Ctrl-C to stop". Problems such as sessions started by an older AgentACL
  appear as a banner in the console, not as terminal noise.
- **Machine-wide.** Nothing depends on the directory `agentacl ui` was
  started from. Agents are discovered across the machine, and projects come
  from sessions, running agents and projects added in the console. The
  machine-wide (user) rules can be viewed with no project selected: a neutral
  empty directory (`/private/var/empty`) stands in for `${PROJECT}`. Project-scope
  operations refuse it.
- **Implementation.** The server is Rust, in `crates/agentacl-cli/src/ui/`,
  on `tiny_http`. The console is **React 19 + TypeScript + Vite + Tailwind
  CSS v4**, with shadcn-style components (Radix primitives, `cva`) in
  `crates/agentacl-cli/web/`. `npm run build` there writes fixed file names
  to `src/ui/dist/` (`index.html`, `assets/app.js`, `assets/app.css`). Those
  are committed and embedded with `include_str!`, so a plain `cargo build`
  needs no Node. The page loads nothing from a CDN or the network, and the
  CSP stays `'self'`-only. Radix's scroll-lock `<style>` tag is blocked by
  the CSP; the only effect is that the page behind an open dialog can still
  scroll.

## 3. Screens

The console is an IAM-style control plane over the CLI: **agents** are the
identities, **policies** their permissions, the **access map** what those
permissions reach, and **activity** the audit log.

1. **Overview.**
   - 24 h counts: blocked, secrets blocked, running agents (protected vs not),
     projects.
   - An hourly chart of blocked actions and the most-blocked resources.
   - A banner for agents running **without** AgentACL.
2. **Agents.**
   - *Running*: every known agent process on the machine, with its project
     (from its cwd), whether it is protected, whether its rules are stale, and
     actions (restart under current rules, stop, show in Finder). An
     unprotected agent gets "how to protect it" steps.
   - *Installed*: discovered binaries with version, location and code-signing
     publisher, plus the `agentacl run` command for each.
3. **Projects.** A searchable, paginated list: sessions, running agents,
   custom project rules and trust, blocked in the last 24 h. Projects can be
   added with the macOS folder chooser or a typed path. The detail page has
   *Overview*, *Access & rules* and *Activity* tabs. *Access & rules* edits
   either "this project only" (`.agentacl/policy.yaml`, restrict-only) or
   "all projects" (the user policy).
4. **Policies** (the user policy, which applies to every project). Choose the
   project and agent to preview with. The tabs:
   - **Access map.** Summary cards (this project, home, protected secrets,
     system), then either a **graph** (default) or a list. The graph lays out
     the agent → areas → folders and files left to right. Each connection
     is coloured by the access it grants: animated for allowed, dashed with
     a ✕ for blocked. The selected node's path is highlighted. It pans (drag
     or scroll), zooms (pinch, ⌘-scroll or buttons) and expands folders in
     place, showing 12 children at a time. The large groups (secrets,
     system) start folded. The list shows a tree of what agents can reach, colour-coded by status, with
     "N allowed / blocked inside" hints and paged children. Selecting a node
     explains its read and write decisions in plain words. It offers *Allow
     reading*, *Allow reading & changing*, *Make read-only* and *Block
     completely* as draft edits, with generation rules per §4.5.
   - **Rules.** A structured editor: files and folders, programs, network,
     defaults, and "applies to" agents. Paths can be picked with an in-app
     browser or in Finder.
   - **Built-in protections.** Secret groups as switches (off means
     `builtin.disable`), and the always-on protections.
   - **Test access.** Evaluate one request against the draft, like
     `policy check --path/--exec/--host`.
   - **YAML.** The raw file. Edits update the map and tests as you type.
   - **Starting from scratch.** When no user policy exists, the editor is
     seeded from the built-in default, renamed `user`. Saving creates the file.
5. **Activity.** Server-side paginated events, filtered by result, agent,
   project, time range and search. A detail panel shows the process chain,
   rule and session. Results export to CSV.
6. **Settings.** The machine, the enforcement backend, file locations and CLI
   equivalents.

**Save flow.** Edits stay a draft (sticky "unsaved changes" bar, discard,
guard on navigation). *Review & save* shows:
- what changes for agents (the effective-rule diff, in words);
- warnings, and the comment-loss notice;
- a required confirmation when agents would lose read access to the project;
- the file diff.

*Save* writes with the conflict check (§4.3). On a conflict you can reload
the current file or overwrite deliberately. The result dialog then names the
file and states the restart consequence. If no running session uses the
file, it says new agents pick the rules up automatically. Otherwise it lists
the affected sessions with *Restart* / *Restart all*, and explains that
macOS fixes a sandbox at launch.

## 4. Behaviour

### 4.1 API

Every `/api/*` route requires the session cookie plus `X-AgentACL: 1`, or
`Authorization: Bearer <token>`, except `POST /api/session`. JSON in and out.

| Method, path | Purpose |
|---|---|
| `POST /api/session` `{code}` | Exchanges the one-time code for a session: sets the `af_session_<port>` HttpOnly cookie and returns `{ok: true}` (the token is never in a body). Returns 401 once the code has been used or has expired |
| `GET /api/overview` | human, home, backend, ES status, dirs, recent projects |
| `GET /api/sessions` | active sessions, each with `stale` (§4.4) |
| `POST /api/sessions/restart` `{session}` | the same version and pid checks as `agentacl restart`, then SIGUSR1. The supervisor validates before stopping the agent (§4.7) |
| `GET /api/policy?scope&project&agent` | `{exists, yaml, sha256 (file bytes) \| null, doc, effective, warnings}` |
| `POST /api/policy/preview` `{scope, project, agent, yaml \| doc}` | `{ok, yaml, doc, effective: {rules, warnings, project_unreadable}, effective_diff, file_diff, comments_lost}`, or `{ok: false, error}` |
| `POST /api/policy/save` `{scope, project, agent, yaml \| doc, base_sha256 \| null, confirm: [...]}` | §4.3 |
| `POST /api/fs/list` `{path, scope, project, agent, draft}` | entries (name, kind, symlink target) with decisions; §4.5 |
| `POST /api/evaluate` `{scope, project, agent, draft, request}` | decision plus trace |
| `POST /api/map` `{scope, project, agent, draft}` | Access-map roots: the project, home, protected secrets that exist on this Mac, and system areas. Each node carries a status (full, read-only, partial, blocked, ask), counts of rules inside it, and rule actions. Children come from `fs/list` with `offset`/`limit` paging |
| `POST /api/pick-folder` `{purpose: project \| folder \| file}` | Opens the native macOS chooser (`osascript`), since the server runs locally as the user. For `project` the chosen path goes through `resolve_project`; for `folder` and `file` it is returned as chosen, to become a rule via `fs/node`. The endpoint is authenticated like the others |
| `POST /api/fs/node` `{path, scope, project, agent, draft}` | One node (decisions, status, rule actions) for an absolute path |
| `GET /api/status` | version, user, machine, backend, paths and `warnings` (e.g. sessions from an older AgentACL) |
| `GET /api/agents[?refresh=1]` | installed agents (discovery cached for 30 s) and live running agents with project, protected flag and session |
| `GET /api/projects`, `POST /api/projects/add` `{path}`, `POST /api/projects/remove` `{path}` | known projects; added ones are kept in `${AGENTACL_STATE}/ui-projects.json` |
| `GET /api/stats` | 24 h counts, hourly blocked timeline, top blocked resources |
| `GET /api/builtins` | secret groups (patterns, enabled) and the always-on protections |
| `POST /api/sessions/stop` `{session}` | Same checks and signal as `agentacl stop`: SIGTERM to the session's supervisor (verified as an `agentacl` binary that started no later than the session, so a reused pid is refused), which stops the agent |
| `POST /api/reveal` `{path}` | shows a path in Finder |
| `GET /api/events?page&size&kind&q&agent&project&policy&since` | Server-side pagination (`kind`: all, blocked, allowed, observed, system; `q` searches resource, action, rule, policy and agent; `policy` matches one policy exactly; `project` limits to sessions in that project). Also returns 24 h counts |

### 4.2 Model ↔ YAML

- **Structured editing** works on `RawDoc`, which gets `Serialize`/`Deserialize`.
- **Emitter** (`agentacl_policy::emit::to_yaml`, implemented):
  - fixed key order;
  - a rule that has only a pattern is emitted as a plain string, anything else as an object;
  - every string is JSON-quoted.
  - A round-trip test covers every built-in.
- **Server-side conversion.** A structured draft is converted to YAML *on the
  server* and then re-parsed, so the structured and raw paths validate the same
  bytes.
- **Comments.** Saving over a file that has comments drops them. The response
  warns first (`comments_lost: true` in the preview) and a backup is written.

### 4.3 Validation and save

1. **Parse.** The draft is substituted into the policy sources exactly as
   `run` would build them, via a side-effect-free
   `supervisor::load_from_sources(Vec<PolicySource>, …)` factored out of
   `load_policy_for_check`. A project draft is always parsed at
   `Layer::Project` (restrict-only). The UI refuses to save over a trusted
   project file (§3).
2. **Compile.** For the selected (agent, project) pair, run `PolicySet::load` + `compile_profile` with the same inputs
   `prepare` uses, but with no session dir, proxy port 0 and no pty. This
   catches what only the compiler rejects: `defaults.process: deny`, a
   `listen` entry without a port, quotes and backslashes. It is the new
   side-effect-free `supervisor::plan()`, which `prepare` also calls. The
   hard-link check runs in report mode and returns **warnings**. Every error
   is returned with the CLI's own text, and nothing is written.
3. **Guard the default.** If the selected pair, or, for the user policy,
   any known agent in any known project (sessions and projects added in the
   console, at most 50), would lose read access to `${PROJECT}`,
   return `409 needs_confirm: ["project-unreadable"]` until the request
   includes that confirmation.
4. **Conflict check.** `base_sha256` must equal the sha of the file's current
   bytes, or be `null` when the file doesn't exist yet. Otherwise return 409
   with the current bytes. The UI **keeps the draft** and shows it next to the
   on-disk version.
5. **Write safely** (`safe_write`, used for every policy and backup write):
   - Open the target's directory **one component at a time**. For the
     project: `open("/")` then `openat(..., O_NOFOLLOW|O_DIRECTORY)` per
     component. The final project fd's (dev, ino) must equal the canonical
     project's (dev, ino).
   - Then `mkdirat(".agentacl", 0700)` if missing, and
     `openat(".agentacl", O_NOFOLLOW|O_DIRECTORY)`. The user policy
     directory (`~/.config/agentacl`) is opened the same way from `$HOME`.
   - Read the existing file with `openat(O_NOFOLLOW|O_NONBLOCK)`, and require
     a regular file with `st_nlink == 1`.
   - Write the backup and then the new file. Each goes to a random-named temp
     file (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600), is `fsync`'d, and is
     `renameat`'d onto its target within the same dirfd.
   - Nothing is ever followed through a symlink. Any violation aborts the
     save with an explanation.
6. **Trusted files.** Never written by the UI (§3).
7. **Audit.** Record `policy.saved` (file, old sha, new sha) with
   `source: ui`.

### 4.4 Affected and stale sessions

Each session records its policy inputs in `identity_json`:

```
policy_sources: [{path, sha256 | null}]    # user or --policy file (canonicalized), project file,
                                           # and "config.yaml#<project>": a hash of only this project's trust entries
```

- **Affected** by a save: a session whose recorded paths include the saved file.
- **Stale**: any recorded sha differs from the file's current sha.
- A session started before this field existed shows **stale: unknown**.

At session start, the supervisor also logs a `policy.inputs` lifecycle event
with those shas. This means edits made in a text editor show up in the audit
trail when they take effect. (The UI doesn't claim edits outside it are
audited as they happen.)

### 4.5 Files view

- **Listing scope.** Any absolute path the user navigates to. Names and kinds
  only, never contents; symlinks are shown with their target.
  - **Privacy-protected folders.** `~/Desktop`, `~/Documents`, `~/Downloads`,
    `~/Library/Mobile Documents`, `~/Pictures`, `~/Movies`, `~/Music` and
    removable volumes are **not listed automatically**. The user clicks
    "List", because macOS may show a permission prompt.
  - **Size limit.** At most 200 entries per request (`offset`/`limit` paging).
- **Decisions.** Paths are canonicalized first, as `policy check` does.
  - For a directory, the view shows the decision for the directory itself,
    plus counts of allow and block rules that target things inside it
    ("partly allowed" when it is blocked but something inside is allowed).
  - For a symlink, it shows the decision for the resolved path, since that is
    what the kernel checks.
- **Symlinks.** A rule never names a symlink, and is never derived from one,
  for allow actions:
  - *Allow* actions are disabled on a symlink, and on any path with a
    symlinked component. Otherwise an agent could plant a link that turns
    "allow this folder" into access to another repo.
  - *Deny* actions on a symlink write the **resolved** canonical path, since
    that is what the kernel checks. The view warns that retargeting the link
    later doesn't carry the deny with it.
  - Every generated rule's exact text is shown before it joins the draft.
- **Rule generation.**
  - A file becomes a literal rule; a directory becomes `dir/**`.
  - **Project scope:** paths inside the project are written as `${PROJECT}/…`,
    and only *Deny read* / *Deny write* are offered.
  - **User scope:** paths are written as literal absolute paths, or as
    `${HOME}/…` when under home. They're **never** written as `${PROJECT}`
    unless the user picks "all projects", because `${PROJECT}` in a user policy
    applies to every project.
  - **Unrepresentable names.** A name containing `*`, `?`, `${`, `"`, `\` or a
    control character can't be written as a literal. The action is disabled,
    with an explanation.
- **Rendering.** The server sends each name twice: `name` (raw) and
  `display`, which is `term_safe` of it; rule text is generated on the server. `term_safe` visibly
  escapes, not strips, these:
  - C0/C1 control characters
  - bidi controls (U+202A–202E, U+2066–2069, U+200E/F, U+061C)
  - zero-width characters (U+200B–200D, U+FEFF)

  Distinct names therefore never look identical. The page inserts `display`
  with `textContent` only.

### 4.6 Trust (CLI only)

- **CLI.** A new command, `agentacl policy trust [--project P] --sha256 <sha>`:
  - It records `{project: <canonical path>, sha256}` in
    `~/.config/agentacl/config.yaml`, written with the same procedure as
    `safe_write`.
  - Only if the file's current bytes still hash to `<sha>`.
  - `policy check` prints the sha to pass.
- **Trust is bound to path + sha.** The loader (`LoadOptions`) matches the
  project path and the hash, so trusted bytes copied into another repo are
  not trusted.
- **Legacy entries.** Old hash-only entries (a bare string) are ignored, and
  `policy check` warns about them. This fails safe: the file falls back to
  restrict-only.
- **The UI never grants or changes trust.** Otherwise a user could re-trust
  bytes an agent edited in another repo without reviewing them.

### 4.7 Restart

`POST /api/sessions/restart` only signals, after the same version and
pid-identity checks as the CLI.

The **supervisor** validates, which avoids a validate-then-signal race and
uses the session's real `RunOptions`. On SIGUSR1 it runs `prepare` for the
relaunch **while the agent is still running**:
- If `prepare` fails, the agent keeps running. The supervisor records a
  `restart.refused` warning event with the error, and the UI shows it.
- Only if `prepare` succeeds does it stop the agent and relaunch.

### 4.8 Network decisions, approvals and requests

The proxy sits in the path of every agent connection, so network decisions can
change while an agent runs, which file decisions can't (a Seatbelt profile is
fixed at launch). `agentacl_core::netlive` carries them from the console to
every supervisor through two locations in `${AGENTACL_STATE}`. Agents can't
write there (`agentacl-self`). The supervisor reads them; the console writes
them.

- **`network-live.json`**: `{mode, rules}`.
  - `mode` is `block` (the default) or `ask`. It applies to sites that only
    the *default* decision refuses.
  - `rules` are per-host allow/block decisions made in the console.
- **How a host decision is made** (`LiveNetDecider`, before any DNS lookup):
  1. A console **block** refuses at once, in every session. It only
     restricts.
  2. If the policy allows the host, it is allowed.
  3. Otherwise, only a denial from the **default** (`rule_id: "default"`,
     an id rules can't use) can be lifted. Explicit and built-in denials
     always stand.
  4. It is lifted by one of:
     - a session-scoped approval (for that `host:port` only);
     - a console **allow** made *after* the session started. Sessions started
       later load the same rule from the policy file, so deleting it there
       removes it everywhere.
  5. With `mode: ask` (or an `ask` default), the connection waits for the
     human.

  IP literals and `localhost` are never lifted (address rules govern them),
  and the address phase runs unchanged after a host is allowed.

  A prompt is raised **before** any DNS lookup, as every host decision is.
  Resolving first would send names the agent invents to DNS before the human
  decides, which is a data exfiltration channel. So an approved name that
  resolves to a private or local address is still refused, and the console
  says so.
- **Approvals** (`approvals/<id>.json`, answer `<id>.answer`):
  - The proxy queues one prompt per `host:port`. Limits: at most 8 prompts
    per session; at most 16 connections waiting per site and 64 per session.
    Anything beyond those is refused at once.
  - The proxy posts a macOS notification at most every 8 s.
  - Every connection waiting on a prompt shares its deadline (25 s). No answer
    means blocked. An expired or already-answered prompt can't be answered.
  - Answers:
    - **once**: the connections waiting now;
    - **session**: this `host:port` for the rest of the session;
    - **always**: the console also saves an allow rule for the host, any
      port;
    - **block**;
    - **block-always**: also saves a block rule.
  - The notification text is passed to `osascript` as an argument, never as
    script source, so a hostile host name can't inject AppleScript.
  - Host names the console acts on must be plain names
    (`[a-z0-9.-_]`, ≤ 253 characters).
- **Site rules from the console** (Network page, Requests, approvals) are
  saved twice:
  - to `network.allow` / `network.deny` in the user policy, through the same
    validated, conflict-checked save as the editor (durable and reviewable);
  - to `network-live.json`, which applies them to running sessions.

  Every user-policy save (from the editor too) reconciles the live file:
  - A live rule the policy no longer has is dropped.
  - An **allow removed** from the policy is recorded as a revocation
    (`revoked: [{host, at}]`), unless another rule still allows the host.
    Sessions started before it treat the host as not allowed, even though
    their loaded policy still lists it. The agent's own needs are exempt.
  - A **block removed** from the policy stays in force for sessions started
    while it existed, until they restart: explicit denials are never lifted
    live.
  - If the policy can't be read, the live file is left alone. Each site shows its **effective** decision
  (machine-wide policy plus live rules). **Allow** is offered only when it
  would work: the site is blocked by the default, or by your own block.
- **Requests** (`/api/requests`): enforced denials grouped into decisions.
  - Grouping: network by host; secrets by protection group; protected
    settings (`exec-persistence`, `agentacl-self`, provider denials) by
    folder; programs by executable; other files by folder, at most three
    levels below home or `/`.
  - Each group has a count, first and last seen, agents, projects and up to
    five samples.
  - **Dismiss** records the time in `ui-dismissed.json`. A group comes back
    when it happens again.

Endpoints: `GET /api/network?days`, `POST /api/network/rule {host, effect:
allow|block|none}`, `POST /api/network/mode {mode}`, `GET /api/approvals`
(pending approvals, new requests, mode), `POST /api/approvals/answer {id,
answer}`, `GET /api/requests?days&dismissed`, `POST /api/requests/dismiss
{key | keys, undo?}`. `GET /api/stats` also returns hourly allowed/blocked
counts, top blocked and most used sites, and blocks by kind.

## 5. Security

| Threat | Control |
|---|---|
| A supervised agent drives the UI | **The proxy hard-denies the UI's ports.** For every connection, after resolution and IPv4-mapped normalization, any address that is loopback or unspecified (`0.0.0.0`, `::`), on a port listed in a live `ui-*.json`, is refused whatever the policy says (no user override). If the state directory can't be read, **all** loopback and unspecified destinations are refused (fail closed). `agentacl ui` warns about live sessions whose supervisors lack this check (session `features`). The agent can't read the session token: it lives only in an HttpOnly cookie in the human's browser (and is never returned in a response body), and the proxy refuses the UI's port, so the agent can't reach the API to use it. It also can't read the bootstrap code: other processes' argv is unreadable from the sandbox (threat T23, fixed), and the code is single-use and short-lived. The agent can't write policy files (`agentacl-self`). The UI also warns when a policy allows `localhost` without a port |
| A malicious web page (CSRF), including a page an agent serves on a `network.listen` port and the human opens | The browser attaches the session cookie (cookies ignore ports; the cookie is named `af_session_<port>`), but the cookie alone authorizes nothing: every API request must also carry `X-AgentACL: 1` or a bearer token, and a cross-origin page can only set those, or `Content-Type: application/json`, after a CORS preflight. SameSite=Strict keeps the cookie off cross-site requests entirely. The server sends no CORS headers and answers `OPTIONS` with 405. **Every POST must carry `Origin: http://127.0.0.1:PORT`** (browsers always send it on POST). `POST /api/session` needs the code, which never reaches another origin |
| DNS rebinding | `Host` must be exactly `127.0.0.1:PORT`, otherwise 421. The UI is only ever opened via `127.0.0.1` |
| Other local users | Loopback only. Credentials are compared in constant time |
| Credential exposure | The URL carries only the single-use, 60 s code, so history and session restore hold a dead value. The session token is never in a URL, page script or web storage; it is an HttpOnly session cookie. Residual: `/usr/bin/open` hands the URL to the registered http handler app; changing that registration requires unsandboxed same-uid code, which is trusted per the threat model |
| A confused deputy writes through a symlink the agent planted (e.g. `.bak` → `~/.zshrc`) | `O_NOFOLLOW`, regular-file checks, and dirfd-relative temp + rename (§4.3.5) |
| XSS through names, events or policy text | `textContent` only, plus a strict CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`. Also `nosniff` and `no-referrer`. Control, bidi and zero-width characters are visibly escaped (`term_safe`) |
| Clickjacking | `frame-ancestors 'none'` |
| The UI grants more than the CLI can | Same sources and dry-run as `run`. Built-ins are never in writable files. Project scope is restrict-only. Trust is bound to path + sha and has a CLI equivalent |
| A save breaks a running session on relaunch | Dry-run before restart (§4.7) |
| An agent approves its own connections | Approvals and live rules live in the state directory, which agents can't write (`agentacl-self`). The answer comes only from the authenticated console |
| An agent floods the human with prompts | One prompt per host, at most 8 waiting per session, a notification at most every 8 s. Unanswered means blocked |
| A console allow widens past policy | It lifts only a *default* denial, never an explicit or built-in one, and never for IP literals or localhost; address checks still run |

## 6. Audit vocabulary

`EventSource` gains `Ui`. The UI records these events with `agent: agentacl-ui`
and `session: ui_<ulid>` (the UI process's own id; it has no sessions row):

- `policy.saved`
- `session.restart_requested`
- `session.stop_requested`
- `network.allowed`, `network.blocked`, `network.rule_removed`, `network.mode`
- `network.answered`
- `ui.code_replay`

The supervisor records `policy.inputs` at every session start (implemented),
and `restart.refused` when a relaunch fails validation.

## 7. Testing

- **API tests.** A real server on an ephemeral port, driven by raw HTTP:
  - Credentials and request shape:
    - code exchange works once, then 401; an expired code gets 401
    - no token or wrong token → 401
    - bad `Host` → 421; foreign `Origin` → 403; a POST without JSON content type → 415; `OPTIONS` → 405
  - Validation:
    - a preview of an invalid draft returns the CLI's error text
    - `defaults.process: deny` is rejected by the dry-run
    - a project `allow_read` → error
    - `project-unreadable` requires confirmation
  - Saving:
    - conflict → 409 with the draft kept
    - `base_sha256: null` creates the file
    - a planted `.bak` symlink is not followed; the save refuses
    - saving over a trusted project file is refused
    - a symlinked `.agentacl` directory, or a symlinked project ancestor, aborts the save
    - a code presented twice revokes the token and exits the server
  - Consistency and audit:
    - `fs/list` decisions equal `evaluate`
    - saves appear in `events`
- **Proxy.** A connection to a live UI port is refused even under
  `network.allow: ["localhost"]`, whether addressed as `127.0.0.1`,
  `0.0.0.0`, `::ffff:127.0.0.1` or a name that resolves to loopback. An
  unreadable state dir refuses all loopback.
- **Restart.** A relaunch whose new policy is invalid keeps the old agent
  running and records `restart.refused`.
- **Emitter round-trip** (done).
- **Manual.** A headless Chrome screenshot of each screen.

## 8. Out of scope

Remote access, multiple users, approval prompts, editing built-ins, and running
the UI as a daemon.
