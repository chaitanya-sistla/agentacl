# Fleet: an endpoint agent and a central server

Status: implemented (see docs/fleet.md to deploy it).

## Goal

A company installs AgentACL on every Mac (from a package its device
management pushes), and sees and governs AI coding agents across all of
them from one server it hosts:

- which Macs run AgentACL, which version, how it enforces (Endpoint
  Security, Seatbelt only), and when each last reported;
- on each Mac: its users, the agents they have installed and running, their
  sessions and the requests AgentACL refused;
- company rules: things no agent on any Mac may do.

## Principles

1. **Decisions stay on the Mac.** The server is never asked before a
   decision. Each Mac enforces with the rules it has, offline too, and
   reports afterwards (ES gives seconds to answer; a network outage must
   neither stall the Mac nor switch protection off).
2. **Company rules only forbid.** A company rule is an explicit deny: a
   path an agent may not read or write, a program it may not run, a host
   it may not reach. Explicit denies win over every allow (policy-model
   §4), so neither the user's policy, a trusted project policy, a console
   grant nor a live network approval can lift them. Company rules can't
   allow anything, change defaults, ask for approval, disable built-in
   protections, or be scoped to an agent or project (both of which the
   user can choose with `--agent` and `--project`), and may only name
   absolute paths or `${HOME}` (not `${PROJECT}` or `${TMPDIR}`, which the
   user chooses). So a server can never make a Mac looser than the user's
   own policy; a compromised one could remove company rules (policy
   versions only increase on a Mac, so an old policy can't be replayed).
   What each kind of rule does depends on the mode, as in
   docs/security-guarantees.md: under Seatbelt, a program rule with
   arguments (`git push *`) is only logged, and program rules match a
   name or path (a renamed copy gets past them); host rules match names,
   not addresses (deny address ranges too). The console warns about these
   when the admin saves the policy.
3. **Say where rules apply.** Without the Endpoint Security entitlement,
   AgentACL enforces only for agents started through it (`agentacl run`):
   a user can still start an agent directly. Company rules then apply to
   AgentACL sessions, and the server shows the agents running outside
   AgentACL. With the entitlement (the ES daemon), the file and program
   rules apply to every agent (network rules apply in `agentacl run`
   sessions only). The ES daemon leaves an agent to Seatbelt only when the
   root-owned copy of `agentacl`, signed with the hardened runtime (so its
   user can't inject code into it), launched it; any other `agentacl` gets
   an ES session like any agent. Users with admin rights can remove AgentACL;
   the server shows a Mac that stops reporting or reports an old policy,
   but can't prevent it.
4. **Least privilege on the Mac.** The reporting service runs as root to
   write the company rules and to read the process table. Everything it
   reads from a user's files it reads in a separate process running as that
   user (`initgroups`, `setgid`, `setuid`, an empty environment, then
   exec), which returns JSON within a time limit and a size limit. As
   root it reads only the process table (agents identified by their path,
   reading no file and running no program a user could stall). It never
   runs code from the server.
5. **Nothing secret in the open.** The device key is stored root-only
   (0600) and never passed on a command line. Enrollment tokens are
   limited (expiry, number of Macs) and only let a new Mac join; they can't
   act as an existing Mac.

## Parts

```
 Mac (pkg: /Library/Application Support/AgentACL/, root-owned)
 ├── bin/agentacl                  the CLI (root-owned copy)
 ├── fleet.json  (root, 0600)      server URL, device id, device key
 ├── fleet-state.json (root, 0600) cursors, last policy
 ├── managed/policy.yaml (root)    company rules, written by the service
 └── LaunchDaemon ai.agentacl.fleet: `agentacl fleet run`, every 60 s:
       collect → POST /api/v1/report → GET /api/v1/policy → write managed/

 Server (Linux or Mac, one binary or a container)
 └── agentacl-server: HTTP API + web console, SQLite; TLS by a reverse
     proxy (Caddy in the provided compose file)
```

### Enrollment

1. An admin creates an **enrollment token** in the server console: a name,
   an expiry (default 30 days) and a maximum number of Macs.
2. The Mac gets the server URL and the token:
   - a package built with `scripts/fleet/build-pkg.sh --server URL` (the
     token read from standard input; the package then contains it, so it is
     for distribution by device management only);
   - a configuration profile (managed preferences domain
     `ai.agentacl.fleet`: `ServerURL`, `EnrollmentToken`). Managed
     preferences are readable by any local user, so treat such a token as
     known to the Mac's users;
   - or `sudo agentacl fleet enroll --server URL` (token on standard input).
3. `POST /api/v1/enroll` with the token and the Mac's identity (machine id,
   hostname, serial, macOS version). The server creates a **new device**
   with a random **device key** (32 bytes) and stores only the key's
   SHA-256, and the current company policy. Enrolling never replaces
   another device's key: a Mac that enrolls again with the same machine id
   is a second device, shown with a "same machine id as …" warning, so a
   token holder can't take over a Mac.
4. The Mac writes the company policy (validated; `version: v1` if there is
   none), then `fleet.json` (root, 0600), and starts the LaunchDaemon, so
   an enrolled Mac always has company rules, offline too. A baked token
   file is deleted after enrollment. If the server can't be reached, the
   daemon retries enrollment.

Revoking a device makes its key stop working (401); the Mac keeps
enforcing its last company rules. A revoked device's machine id can't
enroll again until an admin allows it; the machine id is reported by the
Mac, so this stops a reinstalled Mac, not someone holding a token.
Anyone holding a token can create devices up to its limit, so the server
limits failed enrollments (10 a minute per client), report requests (12 a
minute per device), and events stored per device (50,000 a day; the
console shows how many weren't kept). Requests are served on a thread
each, and Caddy cuts off clients that send slowly.

### Reporting (every 60 s, and at start)

`POST /api/v1/report` with `Authorization: Bearer <device key>`:

- **machine** (read by the root service): hostname, macOS version,
  AgentACL version, enforcement (ES daemon or system extension running),
  company policy version applied, and the last policy error if any;
- **running agents** (root, from the process table): agent processes, their
  user, and whether they run under an `agentacl` supervisor, with that
  supervisor's executable path (the root-owned copy, or another);
- **per user** (accounts from the directory service with uid ≥ 501 and a
  home folder), collected by the per-user process: agents installed
  (`discover`, every 10 minutes, with the user's usual install folders in
  `PATH`), sessions active and recently ended (with the AgentACL version
  that ran each, and whether it loaded the company rules), and new events
  since the last report (the ES journal is ingested first). These come from
  the user's own files, so the console labels them as reported by the user.

Each report request is at most 4 MiB: each user's part is capped at
1 MiB (lists cut, then events from the end), then the largest part is
halved until the request fits; a cycle sends up to 10 requests. The cursor is (audit log id, row id): the audit log gets a random id
when created, so a deleted and recreated log starts a new cursor. Events
are unique on the server per (device, user, audit log id, row id), so a
resent batch isn't stored twice. A report includes full paths and hosts the
agents tried to reach, and command lines (cut at 1,024 characters, with
values of `--token`, `--password`, `--secret` and `*KEY=` style arguments
replaced); the console says so. The records of the ES daemon live in the
user's own folder before they are reported, so they are reported by the
user too.

### Company rules

**Format.** A policy document with only these sections:
`filesystem.deny_read`, `filesystem.deny_write`, `process.deny`,
`network.deny`. Anything else (allow rules, `require_approval`, `defaults`,
`builtin`, `match`, `network.listen`) is refused, by the server when the
admin saves it and again by the Mac. It loads as its own layer (`org`),
identified by where it was loaded from, not by its name. Network denies
apply in `agentacl run` sessions (through their proxy); the ES daemon
doesn't see network traffic.

**Delivery.** `GET /api/v1/policy` returns `{version, yaml}`. When the
version changes, the service validates the YAML on the Mac (company-rules
format, then a full policy load and Seatbelt profile compile with sample
values) and writes it atomically to `managed/policy.yaml`. A document that
fails is not written: the last good one stays, and the error is reported.
No company policy is written as `version: v1`. A Mac never applies a
version lower than the one it has.

A running `agentacl run` session keeps the rules it started with (its
sandbox is fixed): a new company policy marks it stale in the console, and
applies to the next session. The ES daemon applies it within a second.

**Loading.** Every policy load on the Mac (`agentacl run`, the ES daemon,
`agentacl policy check`, the console) adds `managed/policy.yaml` as the
`org` layer. It refuses to load (and so refuses to start a session) if:

- the file, or any folder from `/Library/Application Support/AgentACL` down
  to it, isn't owned by root, is writable by group or others, or is a
  symbolic link;
- or the Mac is enrolled (`fleet.json` exists) and the file is missing.

When an `org` layer is present, `builtin.disable` in any other document is
ignored, so the company can rely on the built-in protections (a user who
disabled one gets it back, even with an empty company policy). The company folder's
location is fixed: `AGENTACL_HOME` and `AGENTACL_CONFIG_DIR` don't move it. The ES
daemon includes the company rules in its built-ins fallback (used when a
user's policy fails to load), and reloads when the file changes.

### Server

- **Storage:** SQLite (one file; back it up).
- **Admin access:** one admin password, read at first start from the file
  named by `AGENTACL_SERVER_ADMIN_PASSWORD_FILE` (or typed at the prompt of
  `agentacl-server init`) and stored as a PBKDF2-SHA256 hash (600,000
  iterations, random salt). Sessions by cookie (`HttpOnly`,
  `SameSite=Strict`, `Secure`, 12-hour expiry, new id at login), a CSRF
  token on every form, the password asked again to save the company
  policy or create a token, sessions ended at logout, and failed logins
  slowed per client address (behind the proxy, from `X-Forwarded-For`,
  trusted only from the proxy's address): one attempt a second, then
  doubling after five failures, up to a minute.
- **Device API:** `/api/v1/enroll`, `/api/v1/report`, `/api/v1/policy`.
  Enrollment tokens and device keys are random 32-byte values, stored only
  as SHA-256 hashes and looked up by hash. Request bodies are capped
  (8 MiB).
- **Console (server-rendered HTML):** every value from a Mac is escaped,
  and pages are served with a strict Content Security Policy (no scripts,
  `frame-ancestors 'none'`) and `X-Content-Type-Options: nosniff`. Pages: Machines (last seen, enforcement, version, users, agents
  running, agents running outside AgentACL, refusals in 24 h, policy
  version, warnings); a Machine page (users, agents, sessions, recent
  events); Events (filter by machine, user, agent, decision); Company
  policy (edit, validate, version history); Enrollment tokens (create,
  revoke); revoke a Mac.
- **TLS:** terminated by a reverse proxy. The provided `docker-compose.yml`
  runs the server behind Caddy, which obtains a certificate for the domain;
  the server's own port is reachable only from Caddy.

### On the Mac, HTTP

The service calls the server with `/usr/bin/curl`, `-q` first (no
`.curlrc`), with the system trust store when curl has it
(`CURL_SSL_BACKEND=secure-transport`, so a company CA installed on the Mac
is trusted; curl falls back to its own CA list silently, so the service
sets it only when `curl -V` lists SecureTransport), `--proto =https` (plain
HTTP only to `127.0.0.1`, for tests), no redirects, timeouts, and a
response size limit enforced while reading. A proxy, if the network needs
one, is set in `fleet.json`. The device key is in a curl config read from standard input; the
request body is in a root-only temporary file.

### Which `agentacl` the users run

The package installs only into AgentACL's own folder (the installer
resets the owner and modes of folders in a payload), the CLI root-owned in
`/Library/Application Support/AgentACL/bin` and links
`/usr/local/bin/agentacl` to it (only if that folder is owned by root; on
Intel Macs with Homebrew it isn't). A user who also installed AgentACL with
Homebrew on Apple silicon has `/opt/homebrew/bin` first in `PATH`; that
copy applies company rules only from the version that has them (0.6.0).
Each session's AgentACL version and whether it loaded company rules are
reported, and the console flags sessions without them.

## Distribution without Apple

- The package can be built and installed without Apple: `pkgbuild` and
  `productbuild` are part of macOS. An unsigned package installs with
  `sudo installer -pkg` and through management tools that run `installer`
  (Jamf, Munki and the like). The MDM install command
  (`InstallEnterpriseApplication`) needs a signed package. Opened from a
  browser download, Gatekeeper refuses an unsigned package until the user
  allows it in System Settings. Signing with a Developer ID Installer
  certificate and notarizing (Apple Developer Program, no review) removes
  both limits.
- macOS shows "Background Items Added" and lets an admin user switch the
  LaunchDaemon off in Login Items; device management can lock it on with a
  managed login items profile.
- Everything in this design works without the Endpoint Security
  entitlement: reporting, company rules for AgentACL sessions, the
  inventory of running agents. System-wide enforcement for agents started
  any other way needs the entitlement (docs/design/endpoint-security.md).

## Not in this version

- Approving a refused request from the server (grants stay local).
- Company rules that allow, or apply to one agent or project.
- Signed policy bundles: the policy's integrity rests on TLS. Company
  rules can only forbid, so a forged policy can't make a Mac looser than
  the user's own policy, but it can remove the company rules or stop
  agents working.
- Multi-tenant servers, SSO for admins, role-based admin access.
- Shipping events to other systems (OpenTelemetry export).
