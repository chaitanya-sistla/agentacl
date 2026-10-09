# Endpoint Security backend

Status: implemented, **not yet run on a real Endpoint Security client**.
Everything under "Tested here" was tested on a normal Mac without Endpoint
Security. Everything that needs the framework at run time waits for a
development VM (SIP and AMFI off) or Apple's entitlement. Nothing in this
document is a guarantee until it has run there: see "What has to be
verified".

## Why

Seatbelt (`agentacl run`) protects agents AgentACL launches. An agent started
any other way (plain `claude`, an IDE extension, a desktop app) is only seen,
not stopped. Apple's Endpoint Security (ES) lets one root process see and
decide file opens, execs and signals for every process on the Mac. With it,
AgentACL can apply its file and program rules to agents however they were
started.

## What it does

| Phase | Behaviour | Code |
|---|---|---|
| 1. See every agent | A session starts when one of the configured user's processes execs an agent binary, identified by its code signature (team and signing id from ES) or install path, with the provider registry `agentacl run` uses. Every process forked or exec'd from a member joins the session, by audit token (pid and pid version), never by name or environment. Agents already running when the daemon starts are adopted, with their descendants (best effort). Sessions end when their last process exits | `tracker.rs`, `engine.rs` |
| 2. Enforce file and program rules | File opens (read, write, truncate), create, rename, unlink, link, clone, copyfile, exchangedata and metadata changes (mode, owner, flags, extended attributes, ACL, times, `setattrlist`) are evaluated with the policy `agentacl run` loads for that agent and project (differences below). Exec rules see the arguments (`git push *`; see the limits below). Setuid and setgid programs are refused. So are programs that would start a process outside the session: `launchctl`, `osascript`, `at`, `batch`, `crontab`, and `open` unless all it opens is web addresses (matched by name and by signing id). Agents can't signal AgentACL's processes, or take control of processes outside their session (`task_for_pid`, `task_read_for_pid`). Unix sockets are allowed only in the system's, the temp and the project folders, never credential ones (ssh-agent, Docker, Podman, gpg-agent, 1Password) or `usbmuxd` (attached iPhones). A path ES couldn't give in full (truncated) is refused. Processes outside agent sessions are always allowed and never recorded | `engine.rs`, `adapter.rs` |
| 3. Grants without a restart | The policy for an agent and project is reloaded within a second of a change to the user policy, the access files, the project policy, the trust file or Claude Code's settings, so a grant made in the console applies to the agent's next attempt | `provider.rs` |
| 4. Packaging | A root LaunchDaemon (`agentacl-esd`), and an `AgentACL.app` with the daemon as its Endpoint Security system extension | `packaging/macos/`, `scripts/es/` |

Decisions reach the user's audit log through a journal: the daemon appends
JSON lines to `es/events.ndjson` in the user's state folder, writing as that
user (its writer thread takes the user's identity, so a link planted in the
folder can't make root write elsewhere). The console and `agentacl events`
ingest the lines (`agentacl_core::es_journal`), one at a time under a lock.
The console then shows ES sessions as protected sessions, and their
refusals as requests. A daemon (re)start is journalled and ends the
sessions it tracked before.

`agentacl es status` reports whether the daemon or the system extension runs.

## Differences from `agentacl run`

- **No network rules.** ES doesn't see the agent's network traffic, and
  this backend has no proxy for it. Under ES an agent's network access is
  not restricted (Seatbelt sessions keep theirs).
- **Policy.** The same files and built-ins, plus the protection of Claude
  Code's hook scripts. As under Seatbelt, a path the agent may write it may
  also read, unless a rule denies the read. Rule files must be regular
  files of at most 1 MiB (otherwise the built-ins apply). Not applied: read access to the agent's own install
  folder (granted per session by `agentacl run`), the pre-session hard-link
  check, and the per-session temp folder: `${TMPDIR}` is the user's whole
  temp folder, shared with other apps and sessions.
- **Keychain.** As with `agentacl run` without a token: the agent may open
  the keychain files itself (Claude Code's `/login` needs it). Requests to
  `securityd` aren't file opens, and ES can't narrow them (threat model T9).
- **`ask` rules** are refused at once and recorded as requests (the daemon
  can't wait on a person within an ES deadline); the grant applies to the
  next attempt.

## Known gaps

- **Other ways to start a process outside the session.** Only the
  command-line tools listed above are refused. A compiled program, or
  `python` or `swift`, can call launchd, LaunchServices or Apple Events
  directly, and anything already running may run a command on request: a
  tmux or screen server, an IDE, `ssh` to this Mac (Remote Login).
- **Argument rules match by position.** `git push *` doesn't match
  `git -C . push` or `git -c k=v push`, an alias, or a renamed copy of git.
- **Restarts.** After a daemon restart, agents are adopted from the process
  list (best effort); children forked between the restart and the adoption
  can be missed.
- **Dropped notifications.** ES can drop NOTIFY events under load. A child
  whose fork notification is lost is adopted through its parent's audit
  token, also when that parent has since exec'd or exited (a bounded memory
  of recent tokens). Whether ES still reports the original parent's token
  for a child whose parent exited is unverified.
- **Session liveness in the console** follows the agent's first process: a
  session can show as ended while its children still run.
- **A stuck policy loader** (a rule file on a hung network volume) keeps the
  last loaded policy in force; a policy never loaded gets the built-ins.
- **The journal** is the user's file. Agents can't write it
  (`agentacl-self`), but anything else running as the user can.

## Design choices

- **Thin adapter.** Only `adapter.rs` touches the framework (through the
  `endpoint-sec` crate, MIT/Apache, by HarfangLab, pinned to 0.6.0 for our
  minimum Rust version). The engine is plain Rust and fully unit-tested.
- **Never wait.** Every answer is computed in memory: no human prompt, no
  network, no child process (the project is found by looking for `.git`, not
  by running git), no file read (agents are identified without reading
  `package.json`). Policies are read by a loader thread acting as the user,
  which never downloads iCloud placeholders; the handler waits at most
  250 ms for a policy it has never had, then answers with the built-ins.
  The daemon mutes its own process, so its own reads don't wait on itself
  (ES delivers a client's messages one at a time).
- **No kernel caching** (`cache = false`). A cached allow could later apply
  to a request the engine should refuse: membership changes over time, and
  rules change at any moment. This costs performance; it has to be measured.
- **Fail open for the Mac, closed for agents.** An event the adapter doesn't
  understand is allowed, and so is every request if deciding panics: a bug
  must never wedge the Mac. An agent's request for an unknown or truncated
  path is refused before any rule is consulted. A policy that fails to load
  falls back to the built-in protections.
- **Membership by audit token.** A child whose first request arrives before
  its fork notification is adopted through its parent's audit token (ES
  message version 4+). An exec's old token is retired when the exec has
  happened (NOTIFY_EXEC), so a refused exec leaves the process enforced.
- **`agentacl run` stays with Seatbelt.** An agent AgentACL launches
  (agentacl, then `sandbox-exec`, then the agent) gets no second session
  here: its supervisor already enforces it and waits on `ask` rules, which
  this engine would refuse at once. Protection against signals follows the
  image, not the pid, so that agent can still stop its own children.
- **Root config.** The daemon serves one user, named in
  `/Library/Application Support/AgentACL/esd.json` (root-owned, not writable
  by group or others: the daemon refuses it otherwise), with that user's home
  and temp folder. Other users' agents (including `sudo claude`) get no
  session.

## Tested here (without Endpoint Security)

- Engine (`engine::tests`):
  - agents identified by signature (and not otherwise), only the configured
    user's;
  - a session protects the agent and every descendant (fork, exec,
    grandchildren) but not other processes, which aren't recorded;
  - adoption through the parent's audit token, also after the parent
    exec'd or exited; a late fork notification doesn't revive an exited
    child;
  - unknown (truncated) paths refused; a writable path readable unless a
    rule denies the read (`/dev/null`, `/dev/tty`, the temp folder);
  - a refused exec leaves the process enforced;
  - argument rules (`git push *`) and setuid refused;
  - `osascript`, `launchctl`, `open -a`, `crontab` and a renamed copy of
    `osascript` refused; `open https://…` allowed;
  - rename, link, clone, copyfile, exchangedata, unlink, truncate and
    metadata changes of protected files, and git-hook creation, refused;
  - signals to AgentACL refused (the human can still stop it);
  - `task_for_pid` outside the session refused;
  - credential and out-of-place Unix sockets refused, system and project
    ones allowed;
  - a rule change applies to the next attempt;
  - sessions end with their last process; an agent started inside another
    stays in its session;
  - `agentacl run` launches are left to Seatbelt, and only that exact
    launch path;
  - agents running before the daemon are adopted, except supervised ones
    and other users'.
- Policy provider (`provider::tests`): reload after a change; a broken
  policy, or a FIFO in place of a rule file, falls back to the built-ins;
  the background loader picks up a grant.
- Journal (`journal::tests`, `es_journal::tests`):
  - written owned by the user (0600);
  - ingested once;
  - partial lines waited for;
  - malformed lines skipped;
  - a rotated journal's unread tail, then the new file, read;
  - sessions opened and closed, including by a daemon restart.
- Daemon: `agentacl-esd --check` validates the config and loads every
  agent's policy; it refuses to run without root.
- Packaging: plists lint, scripts pass shellcheck, `scripts/es/build-app.sh`
  builds and verifies `AgentACL.app` (ad-hoc signed).

## What has to be verified (on the development VM)

1. The adapter's mapping of every event: paths, open flags (`O_TRUNC`),
   audit tokens, `cwd`, setuid bits, the signing ids of `launchctl`,
   `osascript`, `open`, `at` and `crontab`.
2. Deadlines and throughput with `cache = false` under a real workload (a
   build, `git`, `npm install`), and whether muting paths for non-agent
   processes is needed.
3. That an agent's runtime (dyld, caches, its install folder, temp files)
   isn't refused by the default rules when it isn't sandboxed by Seatbelt.
4. Session tracking for real agents: Claude Code, Codex, Gemini CLI, IDE
   extensions and desktop apps; adoption at daemon start; and that
   `agentacl run` launches arrive as fork, then exec of `sandbox-exec`, then
   exec of the agent.
5. Tamper: killing or stopping the daemon from an agent.
6. That the journal writer and the policy loader threads' change of
   identity (`pthread_setugid_np`) works under the daemon, and the 250 ms
   first-load wait is enough in practice.
7. Activation of the system extension and the Full Disk Access prompt.

Until these pass, `docs/security-guarantees.md` keeps system-wide
enforcement as PLANNED.

## Development VM

```sh
brew install cirruslabs/cli/tart
tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest agentacl-es
tart run --recovery agentacl-es       # Recovery → Utilities → Terminal:
#   csrutil disable
#   nvram boot-args="amfi_get_out_of_my_way=1"
tart run agentacl-es                   # then, in the VM (or over ssh):
scripts/es/install-dev.sh              # refuses to run where SIP is on
```

Then grant Full Disk Access to `/Library/PrivilegedHelperTools/agentacl-esd`, and watch
`agentacl events --follow`. For the app: `systemextensionsctl developer on`,
`scripts/es/build-app.sh`, copy `target/AgentACL.app` to `/Applications`, run
`AgentACL.app/Contents/MacOS/AgentACL activate`. The boot arguments and steps
are the usual ones for ES development; confirm them for the macOS version in
the VM.

The extension reads the same `esd.json`; today only `install-dev.sh` writes
it, so run that (or write the file) first. Run the LaunchDaemon or the
extension, not both: two clients would enforce, and journal, everything
twice (`scripts/es/uninstall.sh` removes the daemon).

## Production (needs Apple)

1. Apple Developer Program membership, a Developer ID certificate.
2. The Endpoint Security entitlement
   (`com.apple.developer.endpoint-security.client`), requested from Apple.
3. Provisioning profiles carrying the entitlements (ES for the extension,
   `system-extension.install` for the app), embedded in the bundles.
4. `SIGN_IDENTITY="Developer ID Application: …" TEAM_ID=… scripts/es/build-app.sh`,
   then notarization, then a signed installer package.
5. For companies: device management (MDM) profiles that pre-approve the
   system extension and Full Disk Access.
