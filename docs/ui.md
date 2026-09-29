# AgentFence Local UI — Design

Status: design (pre-implementation). This extends the iteration-1 scope, which
excluded a web UI. The user asked for it on 2026-09-29.

## 1. Goal

Make policy easy to apply without editing YAML by hand:

- **Browse and pick.** Choose files and directories visually, and mark them allowed or denied.
- **See before saving.** For any file, see what an agent would get today and under the draft ("DENIED by protect-secrets/env-files").
- **Save the same YAML the CLI uses.** Files stay the source of truth, so the CLI, git and code review keep working.
- **Watch and apply.** See live sessions and denials, and relaunch a session so a policy change takes effect (`agentfence restart`).

Non-goals:
- No hosted service, accounts, or remote access. The UI is local only.
- Nothing the CLI or a text editor can't also do. The UI adds **no** new authority.
- No approval prompts. Interactive `ask` is still future work, see policy-model §6.

## 2. Shape

`agentfence ui [--port N] [--no-open] [--project P]`:

- Starts an HTTP server on `127.0.0.1` at a random port, or `--port`, in the
  foreground. Ctrl-C stops it.
- Generates a 256-bit random token and opens
  `http://127.0.0.1:PORT/#token=<hex>` in the default browser via `/usr/bin/open`.
- Prints the URL, so `--no-open` users can copy it.

It's implemented in the `agentfence` binary:

- Rust: `crates/agentfence-cli/src/ui/`, on the small synchronous `tiny_http` server.
- Front end: HTML, CSS and vanilla JS, embedded with `include_str!`. No Node
  toolchain, no build step, and no CDN, so the page loads nothing from the
  network.

## 3. Screens

1. **Sessions and events.** Active sessions (agent, pid, project, policy sha,
   started), each with a *Relaunch under current policy* button. Below them, a
   live list of recent events rendered like `events`, with BLOCKED /
   OBSERVED — NOT BLOCKED labels and the rule. It polls every second.
2. **Policy.**
   - **Scope picker.** The *User policy*, or the *Project policy* of a
     project chosen from recent sessions or typed in.
   - **Structured editor.** Defaults, then the filesystem, process and
     network lists, where each rule can carry a pattern, `except`, `id` and
     `reason`. For the project scope, only restrict-only fields are offered
     (policy-model §3).
   - **Raw YAML tab**, validated on the fly.
   - **Effective rules table.** The same rows as `policy check`, with their
     enforceability, plus warnings.
   - **Save.** Shows a diff first, then offers to relaunch the affected sessions.
   - When no user policy exists, the editor starts from the built-in default
     and explains that saving a user policy replaces it (policy-model §3).
3. **Files.**
   - A directory tree that starts at the project and can climb to `$HOME`
     or any absolute path.
   - Each entry shows the **read** and **write** decision under the draft
     policy, with the deciding rule. Built-in protections show a lock and
     can't be edited.
   - Actions on an entry: *Allow read*, *Allow read+write*, *Deny read*, *Deny write*.
     - A file becomes a literal rule; a directory becomes `dir/**`.
     - Paths under `$HOME` or the project are written with `${HOME}` / `${PROJECT}`.
     - Each action adds a rule to the draft; nothing is saved until **Save**.
4. **Test.** Evaluate one request (path + read/write/rename, a command, or
   host:port) against the draft. Returns the decision and trace, exactly like
   `policy check --path/--exec/--host`.

## 4. API

Every `/api/*` route requires the token (§5). JSON in and out.

| Method, path | Purpose |
|---|---|
| `GET /api/overview` | human, home, backend, ES status, state/config dirs, recent projects (from sessions) |
| `GET /api/sessions` | active sessions (the `agents` data) |
| `POST /api/sessions/restart` `{session}` | same checks as `agentfence restart` (version, pid identity), then SIGUSR1 |
| `GET /api/events?after=<rowid>&limit=` | events, newest last, with rowids for polling |
| `GET /api/policy?scope=user\|project&project=P` | `{exists, yaml, sha256 (file bytes), doc (structured), effective}` |
| `POST /api/policy/preview` `{scope, project, yaml \| doc}` | validate the draft, return `{yaml, errors, rules, warnings, diff}` |
| `POST /api/policy/save` `{scope, project, yaml \| doc, base_sha256}` | validate, check for a conflict, back up, write atomically; return `{sha256, affected_sessions}` |
| `POST /api/fs/list` `{path, scope, project, draft}` | directory entries (names and kinds only, **never contents**), each with a read/write decision under the draft |
| `POST /api/evaluate` `{scope, project, draft, agent, request}` | one decision plus its trace |
| `POST /api/trust` `{project}` | add the sha256 of the project policy's current bytes to `config.yaml`; the UI shows the diff first and requires confirmation |

- **Structured ↔ YAML.** The server owns both conversions:
  - `raw::to_yaml(&RawDoc)` is a canonical, stable emitter.
  - `parse_doc` goes the other way.
  - Saving a structured draft over a file that has comments drops the
    comments. The UI warns before that happens, and every save first writes
    `policy.yaml.bak`.
- **Validation is the same code path as `run`.** `supervisor::load_policy_for_check`
  runs with the draft substituted into its scope. Project drafts are parsed at
  `Layer::Project`, so the restrict-only rules apply. Anything `run` would
  reject is rejected on save, with the same error text.
- **Conflicts.** `base_sha256` must match the file's current bytes. If the file
  changed on disk in the meantime (CLI, editor, another tab), the save returns
  `409` and the UI reloads.
- **Atomic write.** The new file is written to a temp file in the same
  directory (mode 0600), fsync'd, then `rename`d into place.
- **Audit.** Every save and trust change is recorded as an event, for example:
  `action: policy.saved`, `resource: <file>`, `agent: agentfence-ui`,
  `session: ui_<start ulid>`, `source: supervisor`, and the new sha. Policy
  changes are auditable like everything else.

## 5. Security

This is a local web server that edits security policy. That makes it an
attack surface in its own right, so each boundary is explicit:

| Threat | Control |
|---|---|
| A supervised agent drives the UI to widen its own policy | The agent's sandbox allows egress only to the proxy port. The proxy refuses loopback unless a policy **names** that exact address and port. The token is never in the agent's environment or files, and sandboxed processes can't inspect processes outside their sandbox (`process-info` is `same-sandbox`). The agent also can't write policy files directly (`agentfence-self`). **The UI warns** if the effective policy allows `localhost` without a port, or the UI's own port |
| A malicious web page in the user's browser (CSRF) | Every API call needs `Authorization: Bearer <token>`. A cross-origin page can't read the token, which lives in the fragment and is never sent to the server. It can't set that header without a CORS preflight, and the server answers no preflight: no CORS headers, `OPTIONS` gets 405. State-changing routes also require `Content-Type: application/json` and, when `Origin` is present, `Origin == http://127.0.0.1:PORT` |
| DNS rebinding (`evil.com` → 127.0.0.1) | `Host` must be exactly `127.0.0.1:PORT` or `localhost:PORT`, otherwise 421. The token is still required |
| Other local users | Bound to 127.0.0.1. The token is compared in constant time. Other users can connect but have no token |
| The token leaks | The token lives in the URL fragment, so it doesn't appear in server logs, `Referer` or history-sync requests. The page moves it into `sessionStorage` (this tab only, so it survives a reload) and drops it from the address bar (`history.replaceState`). It's passed to `open` in argv, which is visible to same-uid, unsandboxed processes: those are trusted per the threat model (§2). A new token is minted per run |
| XSS through file names, event resources or policy text (attacker-influenced) | All dynamic text is inserted with `textContent`, never `innerHTML`. Responses carry a strict CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`. They also carry `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` |
| Clickjacking | `frame-ancestors 'none'` |
| The UI grants more than the CLI can | Same validation path. Built-ins (protect-secrets, exec-persistence, agentfence-self) aren't in any file the UI writes. `builtin.disable` goes through the same rules as the CLI, so `agentfence-self` and `exec-persistence` can't be disabled. The project scope is restrict-only unless trusted, and trust needs explicit confirmation |
| Listing reveals secrets | The listing returns names and kinds only, never contents. It's the user's own session, with the same visibility as `ls` |

## 6. Testing

- **API tests.** A real server on an ephemeral port, driven by raw HTTP over `TcpStream`:
  - no token → 401; wrong token → 401
  - bad `Host` → 421; foreign `Origin` on a POST → 403; POST without JSON content type → 415; `OPTIONS` → 405
  - preview of an invalid draft returns the same error text as `policy check`
  - project draft with `allow_read` → error; save conflict → 409; save writes a backup and is atomic
  - `fs/list` annotations match `evaluate`; `trust` writes the hash
  - policy saves appear in `events`
- **Emitter round-trip.** `parse_doc(to_yaml(doc)) == doc` for the policy-model
  §2 example and for every built-in.
- **Headless render smoke test.** If Chrome is present, headless Chrome
  screenshots each screen; this is a manual verification step, not CI.

## 7. Out of scope

Remote access, multiple users, approval prompts, editing built-in policies,
and running the UI as a daemon.
