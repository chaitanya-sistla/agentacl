# AgentFence Local UI — Design

Status: design, revised after cold reviews 1 and 2 (2026-09-29). This extends the
iteration-1 scope, which excluded a web UI, at the user's request.

## 1. Goal

Make policy easy to apply without editing YAML by hand:

- **Browse and pick.** Choose files and directories visually, and mark them allowed or denied.
- **See before saving.** See what an agent gets today and under the draft, for any path.
- **Save the same YAML the CLI uses.** Files stay the source of truth.
- **Watch and apply.** See live sessions and denials, and relaunch a session
  so a change takes effect (`agentfence restart`).

Non-goals:
- No hosted service, accounts, or remote access.
- No approval prompts.
- **No new authority.** Every UI action has a CLI equivalent that exists first
  (§4.6) and goes through the same validation.

## 2. Shape

`agentfence ui [--port N] [--no-open]` runs in the foreground; Ctrl-C stops it.

- **Server.** It listens on `127.0.0.1` at a random port, or `--port`.
- **Credentials.** It mints two values from `/dev/urandom`:
  - A **bootstrap code** (128 bits). It works **once**, and only within 60 s.
  - A **bearer token** (256 bits). The page gets it by exchanging the code.
    It's held **only in a JS variable**, never in `sessionStorage`, because
    browsers persist session storage to disk. Reloading the page means getting
    a fresh code: press Enter in the `agentfence ui` terminal to open a new
    tab with a new code. Each code exchange mints a new token and revokes the
    previous one.
  - **Replay.** If a code is presented a second time, the server records a
    `ui.code_replay` warning, revokes every token and exits. The page shows
    "this link was already used — possible interception".
- **Opening the page.** It runs
  `/usr/bin/open http://127.0.0.1:PORT/#code=<hex>` and prints the same URL.
  Anyone who sees the URL later (browser history, process argv) has a dead code.
- **Records its port.** It writes `${AGENTFENCE_STATE}/ui-<pid>.json`
  (`{pid, port, started}`, mode 0600, one file per instance) and removes it
  on exit. The proxy reads these files (§5, row 1).
- **Implementation.** Rust, in `crates/agentfence-cli/src/ui/`, on `tiny_http`.
  The front end is HTML, vanilla JS and **Tailwind CSS v4**, all embedded with
  `include_str!`. Tailwind is compiled ahead of time by
  `scripts/build-ui-css.sh` (standalone CLI, no Node) from `assets/tailwind.css`
  into the committed `assets/app.css`. The page loads nothing from a CDN or the
  network, and the CSP stays `'self'`-only.

## 3. Screens

1. **Sessions and events.**
   - Each active session shows its agent, pid and project.
   - It carries a **stale** badge when a policy file it was built from has changed since launch (§4.4).
   - *Relaunch under current policy*: sends `restart`. The supervisor validates the new policy first and keeps the agent running if it's invalid (§4.7).
   - Recent events are listed with BLOCKED / OBSERVED — NOT BLOCKED labels, refreshed every second.
2. **Policy.**
   - **Scope.** *User policy* or *Project policy*. The project comes from recent
     sessions or a typed path. Either way it goes through
     `identity::resolve_project` (git toplevel, and `$HOME` and its ancestors
     are refused), so the UI edits the file sessions actually load.
   - A **trusted** project policy (§4.6) is shown **read-only**. Edit it in a
     text editor and re-trust it with the CLI; the UI never changes trust.
   - **Agent selector** (default `claude-code`). Effective rules depend on
     `match.agents` and the agent's provider grants.
   - **Structured editor.** For the project scope it offers only restrict-only
     fields.
   - **Raw YAML tab.**
   - **Effective-rules table** with enforceability, plus warnings, plus an
     **effective-rules diff** against what's on disk.
   - **Starting a user policy from scratch.** When no user policy exists, the
     editor is **seeded from the built-in default**. Saving a user policy
     replaces the default (policy-model §3). If the save would leave any
     known agent/project pair without read access to `${PROJECT}`, it's
     blocked unless the user confirms explicitly (§4.3).
3. **Files.**
   - A directory tree.
   - Each entry shows its read and write decision under the draft, and the
     rule that decided it. A lock marks a built-in protection.
   - Actions and rule generation follow §4.5.
4. **Test.** Evaluate one request against the draft, like
   `policy check --path/--exec/--host`.

## 4. Behaviour

### 4.1 API

Every `/api/*` route requires `Authorization: Bearer <token>`, except
`POST /api/session`. JSON in and out.

| Method, path | Purpose |
|---|---|
| `POST /api/session` `{code}` | Exchanges the one-time code for the bearer token. Returns 401 once the code has been used or has expired |
| `GET /api/overview` | human, home, backend, ES status, dirs, recent projects |
| `GET /api/sessions` | active sessions, each with `stale` (§4.4) |
| `POST /api/sessions/restart` `{session}` | the same version and pid checks as `agentfence restart`, then SIGUSR1. The supervisor validates before stopping the agent (§4.7) |
| `GET /api/events?after=<rowid>&limit=` | events plus rowids |
| `GET /api/policy?scope&project&agent` | `{exists, yaml, sha256 (file bytes) \| null, doc, effective, warnings}` |
| `POST /api/policy/preview` `{scope, project, agent, yaml \| doc}` | `{yaml, errors, effective, effective_diff, file_diff, warnings}` |
| `POST /api/policy/save` `{scope, project, agent, yaml \| doc, base_sha256 \| null, confirm: [...]}` | §4.3 |
| `POST /api/fs/list` `{path, scope, project, agent, draft}` | entries (name, kind, symlink target) with decisions; §4.5 |
| `POST /api/evaluate` `{scope, project, agent, draft, request}` | decision plus trace |
| `POST /api/map` `{scope, project, agent, draft}` | Access-map roots: the project, home, protected secrets that exist on this Mac, and system areas. Each node carries a status (full, read-only, partial, blocked, ask), counts of rules inside it, and rule actions. Children come from `fs/list` with `offset`/`limit` paging |
| `POST /api/pick-folder` | Opens the native macOS folder chooser (`osascript choose folder`), since the server runs locally as the user. The chosen path goes through `resolve_project`. The endpoint is authenticated like the others |
| `GET /api/events?page&size&kind&q` | Server-side pagination (`kind`: all, blocked, allowed, observed, system; `q` searches resource, action, rule and agent). Also returns 24 h counts |

### 4.2 Model ↔ YAML

- **Structured editing** works on `RawDoc`, which gets `Serialize`/`Deserialize`.
- **Emitter** (`agentfence_policy::emit::to_yaml`, implemented):
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
2. **Compile.** For the selected (agent, project) pair and every affected
   pair (§4.4), run `PolicySet::load` + `compile_profile` with the same inputs
   `prepare` uses, but with no session dir, proxy port 0 and no pty. This
   catches what only the compiler rejects: `defaults.process: deny`, a
   `listen` entry without a port, quotes and backslashes. It is the new
   side-effect-free `supervisor::plan()`, which `prepare` also calls. The
   hard-link check runs in report mode and returns **warnings**. Every error
   is returned with the CLI's own text, and nothing is written.
3. **Guard the default.** If any pair would lose read access to `${PROJECT}`,
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
   - Then `mkdirat(".agentfence", 0700)` if missing, and
     `openat(".agentfence", O_NOFOLLOW|O_DIRECTORY)`. The user policy
     directory (`~/.config/agentfence`) is opened the same way from `$HOME`.
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
  - **Size limit.** At most 2,000 entries per request.
- **Decisions.** Paths are canonicalized first, as `policy check` does.
  - For a directory, the view shows the decision for the directory itself and
    for a representative child (`dir/<x>`), because `dir/**` rules match both.
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
- **Rendering.** The server sends each name twice: `raw` (used only to build
  rules) and `display`, which is `term_safe` of it. `term_safe` visibly
  escapes, not strips, these:
  - C0/C1 control characters
  - bidi controls (U+202A–202E, U+2066–2069, U+200E/F, U+061C)
  - zero-width characters (U+200B–200D, U+FEFF)

  Distinct names therefore never look identical. The page inserts `display`
  with `textContent` only.

### 4.6 Trust (CLI only)

- **CLI.** A new command, `agentfence policy trust [--project P] --sha256 <sha>`:
  - It records `{project: <canonical path>, sha256}` in
    `~/.config/agentfence/config.yaml`, written with the same procedure as
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

## 5. Security

| Threat | Control |
|---|---|
| A supervised agent drives the UI | **The proxy hard-denies the UI's ports.** For every connection, after resolution and IPv4-mapped normalization, any address that is loopback or unspecified (`0.0.0.0`, `::`), on a port listed in a live `ui-*.json`, is refused whatever the policy says (no user override). If the state directory can't be read, **all** loopback and unspecified destinations are refused (fail closed). `agentfence ui` warns about live sessions whose supervisors lack this check (session `features`). The agent can't read the bearer token: it exists only in the page's JS memory. It also can't read the bootstrap code: other processes' argv is unreadable from the sandbox (threat T23, fixed), and the code is single-use and short-lived. The agent can't write policy files (`agentfence-self`). The UI also warns when a policy allows `localhost` without a port |
| A malicious web page (CSRF), including a page an agent serves on a `network.listen` port and the human opens | It needs the bearer token, which it can't read. Setting `Authorization` or `Content-Type: application/json` forces a CORS preflight. The server sends no CORS headers and answers `OPTIONS` with 405. **Every POST must carry `Origin: http://127.0.0.1:PORT`** (browsers always send it on POST). `POST /api/session` needs the code, which never reaches another origin |
| DNS rebinding | `Host` must be exactly `127.0.0.1:PORT`, otherwise 421. The UI is only ever opened via `127.0.0.1` |
| Other local users | Loopback only. Credentials are compared in constant time |
| Credential exposure | The URL carries only the single-use, 60 s code, so history and session restore hold a dead value. The bearer token is never in a URL or storage. Residual: `/usr/bin/open` hands the URL to the registered http handler app; changing that registration requires unsandboxed same-uid code, which is trusted per the threat model |
| A confused deputy writes through a symlink the agent planted (e.g. `.bak` → `~/.zshrc`) | `O_NOFOLLOW`, regular-file checks, and dirfd-relative temp + rename (§4.3.5) |
| XSS through names, events or policy text | `textContent` only, plus a strict CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`. Also `nosniff` and `no-referrer`. Control and bidi characters are stripped |
| Clickjacking | `frame-ancestors 'none'` |
| The UI grants more than the CLI can | Same sources and dry-run as `run`. Built-ins are never in writable files. Project scope is restrict-only. Trust is bound to path + sha and has a CLI equivalent |
| A save breaks a running session on relaunch | Dry-run before restart (§4.7) |

## 6. Audit vocabulary

`EventSource` gains `Ui`. The UI records these events with `agent: agentfence-ui`
and `session: ui_<ulid>` (the UI process's own id; it has no sessions row):

- `policy.saved`
- `session.restart_requested`
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
    - a symlinked `.agentfence` directory, or a symlinked project ancestor, aborts the save
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
