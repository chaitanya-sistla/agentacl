# AgentFence Local UI — Design

Status: design, revised after cold review 1 (2026-09-29). This extends the
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
- **Opening the page.** It runs
  `/usr/bin/open http://127.0.0.1:PORT/#code=<hex>` and prints the same URL.
  Anyone who sees the URL later (browser history, process argv) has a dead code.
- **Records its port.** It writes `${AGENTFENCE_STATE}/ui.json`
  (`{pid, port, started}`, mode 0600) and removes it on exit. The proxy reads
  it (§5, row 1).
- **Implementation.** Rust, in `crates/agentfence-cli/src/ui/`, on `tiny_http`.
  The front end is HTML, CSS and vanilla JS embedded with `include_str!`: no
  build step, no CDN, and no network loads.

## 3. Screens

1. **Sessions and events.**
   - Each active session shows its agent, pid and project.
   - It carries a **stale** badge when a policy file it was built from has changed since launch (§4.4).
   - *Relaunch under current policy*: a dry-run validation runs first, then `restart`.
   - Recent events are listed with BLOCKED / OBSERVED — NOT BLOCKED labels, refreshed every second.
2. **Policy.**
   - **Scope.** *User policy* or *Project policy*. The project comes from recent sessions or a path.
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
| `POST /api/sessions/restart` `{session}` | dry-run validation (§4.3) of that session's inputs, then the same checks and SIGUSR1 as `agentfence restart` |
| `GET /api/events?after=<rowid>&limit=` | events plus rowids |
| `GET /api/policy?scope&project&agent` | `{exists, yaml, sha256 (file bytes) \| null, doc, effective, warnings}` |
| `POST /api/policy/preview` `{scope, project, agent, yaml \| doc}` | `{yaml, errors, effective, effective_diff, file_diff, warnings}` |
| `POST /api/policy/save` `{scope, project, agent, yaml \| doc, base_sha256 \| null, confirm: [...]}` | §4.3 |
| `POST /api/fs/list` `{path, scope, project, agent, draft}` | entries (name, kind, symlink target) with decisions; §4.5 |
| `POST /api/evaluate` `{scope, project, agent, draft, request}` | decision plus trace |
| `POST /api/trust` `{project, sha256}` | §4.6 |

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
   `run` would build them. This means factoring
   `supervisor::load_from_sources(Vec<PolicySource>, …)` out of
   `load_policy_for_check`. A project draft is parsed at `Layer::Project`, so
   the restrict-only rules and trust apply.
2. **Dry-run.** For every *affected* (agent, project) pair (§4.4), plus the
   selected one, run the same `prepare` + `compile_profile` as
   `run --dry-run`, with proxy port 0. This catches what only the compiler
   rejects: `defaults.process: deny`, a `listen` entry without a port,
   quotes/backslashes, and hard links to newly protected files (the latter is
   reported, not blocking). Every error is returned with the CLI's own text,
   and nothing is written.
3. **Guard the default.** If any pair would lose read access to `${PROJECT}`,
   return `409 needs_confirm: ["project-unreadable"]` until the request
   includes that confirmation.
4. **Conflict check.** `base_sha256` must equal the sha of the file's current
   bytes, or be `null` when the file doesn't exist yet. Otherwise return 409
   with the current bytes. The UI **keeps the draft** and shows it next to the
   on-disk version.
5. **Write safely.**
   - Open the directory with `O_NOFOLLOW|O_DIRECTORY`, and refuse if
     `.agentfence` (or any path component the UI created) is a symlink.
   - Read the existing file with `O_NOFOLLOW|O_NONBLOCK` and require a regular file.
   - Write the backup (`policy.yaml.bak`) and the new file each through a temp
     file + `fsync` + `rename` relative to that directory fd, mode 0600.
   - A symlinked `.bak` or policy file is never followed.
6. **Trust after save.** If the project file was trusted and its bytes change,
   the response says the trust no longer applies and offers to re-trust the
   new sha (§4.6).
7. **Audit.** Record `policy.saved` (file, old sha, new sha) with
   `source: ui`.

### 4.4 Affected and stale sessions

Each session records its policy inputs in `identity_json`:

```
policy_sources: [{path, sha256 | null}]    # user or --policy file, trust file, project file
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
- **Rendering.** All names go through the same control- and bidi-character
  stripping as the CLI's `term_safe`, and are inserted with `textContent`.

### 4.6 Trust (CLI first)

- **CLI.** A new `agentfence policy trust [--project P] --sha256 <sha>`
  command records `{project: <canonical path>, sha256}` in
  `~/.config/agentfence/config.yaml`.
  - **Trust is bound to the project path**, not only the hash. The same bytes
    copied into another repo are not trusted. The loader matches on path + sha.
  - `agentfence policy check` shows the sha to pass.
- **UI.** It sends the sha of the bytes the user was shown. The server trusts
  only if the file's current bytes still hash to that value (no race).
- **Conflicts.** A trust change also checks `config.yaml`'s sha, and the change
  is audited.

### 4.7 Restart

`POST /api/sessions/restart` first dry-runs `prepare` with the session's
current inputs. If that fails, it returns the error and does **not** signal.

The supervisor's relaunch loop is hardened the same way: if `prepare` fails
after a restart request, it prints the error prominently. The agent has
already stopped at that point, so the user reruns `agentfence run` once the
policy is fixed.

## 5. Security

| Threat | Control |
|---|---|
| A supervised agent drives the UI | **The proxy hard-denies the UI's own port.** It reads `ui.json` for each loopback connection and refuses that port whatever the policy says (no user override). The agent can't read the bearer token: it's in page memory and `sessionStorage` only. It also can't read the bootstrap code: other processes' argv is unreadable from the sandbox (threat T23, fixed), and the code is single-use and short-lived. The agent can't write policy files (`agentfence-self`). The UI also warns when a policy allows `localhost` without a port |
| A malicious web page (CSRF) | It needs the bearer token, which it can't read. Setting `Authorization` or `Content-Type: application/json` forces a CORS preflight. The server sends no CORS headers and answers `OPTIONS` with 405. When `Origin` is present it must equal `http://127.0.0.1:PORT`. `POST /api/session` needs the code, which never reaches another origin |
| DNS rebinding | `Host` must be `127.0.0.1:PORT` or `localhost:PORT`, otherwise 421 |
| Other local users | Loopback only. Credentials are compared in constant time |
| Credential exposure | The URL carries only the single-use, 60 s code, so history and session restore hold a dead value. The bearer token is never in a URL |
| A confused deputy writes through a symlink the agent planted (e.g. `.bak` → `~/.zshrc`) | `O_NOFOLLOW`, regular-file checks, and dirfd-relative temp + rename (§4.3.5) |
| XSS through names, events or policy text | `textContent` only, plus a strict CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`. Also `nosniff` and `no-referrer`. Control and bidi characters are stripped |
| Clickjacking | `frame-ancestors 'none'` |
| The UI grants more than the CLI can | Same sources and dry-run as `run`. Built-ins are never in writable files. Project scope is restrict-only. Trust is bound to path + sha and has a CLI equivalent |
| A save breaks a running session on relaunch | Dry-run before restart (§4.7) |

## 6. Audit vocabulary

`EventSource` gains `Ui`. The UI records these events with `agent: agentfence-ui`
and `session: ui_<ulid>` (the UI process's own id; it has no sessions row):

- `policy.saved`
- `policy.trusted`
- `session.restart_requested`

The supervisor records `policy.inputs` at every session start.

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
    - trust with a mismatched sha is refused
  - Consistency and audit:
    - `fs/list` decisions equal `evaluate`
    - saves appear in `events`
- **Proxy.** A loopback connection to the port in `ui.json` is refused even
  under `network.allow: ["localhost"]`.
- **Emitter round-trip** (done).
- **Manual.** A headless Chrome screenshot of each screen.

## 8. Out of scope

Remote access, multiple users, approval prompts, editing built-ins, and running
the UI as a daemon.
