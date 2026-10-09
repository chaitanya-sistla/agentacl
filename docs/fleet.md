# Running AgentACL across a fleet of Macs

AgentACL can report from every Mac in a company to one server you host,
and apply company rules (things no agent may do) on all of them. This page
is the how-to; the design and its security reasoning are in
[design/fleet.md](design/fleet.md).

```
 Macs (package from your device management)        Your server
 ┌────────────────────────────────────────┐        ┌──────────────────────────┐
 │ agentacl (root-owned copy)             │ HTTPS  │ agentacl-server          │
 │ fleet service (LaunchDaemon), every    │───────▶│  · Machines, users,      │
 │ minute: inventory, sessions, refusals  │◀───────│    agents, refusals      │
 │ company rules → enforced locally       │        │  · company policy        │
 └────────────────────────────────────────┘        │  · enrollment tokens     │
                                                   └──────────────────────────┘
```

What each Mac reports: its macOS and AgentACL versions, how it enforces
(Endpoint Security or `agentacl run` sessions only), the agents running
(and whether they run under AgentACL), and, for each user, the agents
installed, AgentACL sessions and the requests AgentACL refused. Paths,
hosts and command lines are included (command lines shortened, obvious
secrets replaced).

What the server can do to a Mac: only add company rules that forbid. It
can't allow an agent anything, change a Mac's defaults or run anything on
it. Decisions are always made on the Mac, offline too.

## 1. Run the server

You need a host with Docker and a DNS name pointing at it (ports 80 and 443
open for the certificate).

```sh
git clone https://github.com/chaitanya-sistla/agentacl && cd agentacl/deploy/fleet
printf '%s\n' 'a long admin password' > admin_password.txt
sudo chown 10001 admin_password.txt && sudo chmod 400 admin_password.txt   # the server's user in the container
FLEET_DOMAIN=fleet.example.com docker compose up -d --build
```

Caddy gets a certificate for the domain and forwards to the server; the
server's own port isn't published. The admin password is set from the
secret file at first start (at least 12 characters). Data lives in the
`data` volume (one SQLite file): back it up.

Without containers: build `agentacl-server` (`cargo build --release -p
agentacl-server`, Linux or macOS), run `agentacl-server init --db PATH`,
and use `deploy/fleet/agentacl-server.service` behind a TLS reverse proxy.

Sign in at `https://fleet.example.com`.

## 2. Create an enrollment token

**Enrollment** page, or on the server:

```sh
docker compose exec server agentacl-server token --db /data/agentacl-server.db --name "Engineering Macs" --days 30 --max 200
```

A token is shown once. Anyone holding it can enroll Macs up to its limit
until it expires; it can't act as an existing Mac. Revoke it when you are
done.

## 3. Install on the Macs

Build a package that enrolls on install (on a Mac with this repository):

```sh
echo "$TOKEN" | scripts/fleet/build-pkg.sh --server https://fleet.example.com
# → target/AgentACL-fleet-<version>.pkg
```

It installs `agentacl` (signed with the hardened runtime) root-owned in
`/Library/Application Support/AgentACL/bin`
(linked from `/usr/local/bin` where that folder is root's), and the
LaunchDaemon `ai.agentacl.fleet`, which enrolls, then reports every minute.

How to get it onto the Macs:

| Way | Notes |
|---|---|
| Jamf, Munki, Kandji custom package, or `sudo installer -pkg` | Works unsigned |
| MDM install command (`InstallEnterpriseApplication`) | Needs a signed package (below) |
| Double-click from a download | Unsigned: the user must allow it in System Settings |

A package built with `--server` contains the token: distribute it with
device management only. Alternatives:

- A generic package (`scripts/fleet/build-pkg.sh` without `--server`) plus a
  configuration profile with the managed preferences domain
  `ai.agentacl.fleet`: `ServerURL`, `EnrollmentToken` (and `Proxy` if your
  network needs one). Any local user can read managed preferences.
- By hand: `echo "$TOKEN" | sudo agentacl fleet enroll --server https://fleet.example.com`.

Check a Mac with `sudo agentacl fleet status`. The service logs to
`/var/log/agentacl-fleet.log`. macOS shows "Background Items Added"; to
stop users switching the service off, push a managed login items profile.

## 4. Company rules

**Company policy** page (the admin password is asked again), or
`agentacl-server policy --db PATH --file policy.yaml` (for policies kept in
git). Only denies, with absolute paths or `${HOME}`:

```yaml
version: v1
filesystem:
  deny_read: ["${HOME}/Company Shared/**"]
  deny_write: ["/Library/Company/**"]
process:
  deny: ["terraform apply *"]
network:
  deny: ["*.pastebin.com", "203.0.113.0/24"]
```

Each Mac checks a new policy (format, full load, Seatbelt profile) before
applying it, keeps the last good one if it fails (and reports why), and
never goes back to an older version. On the Mac, company rules can't be
lifted by the user's policy, a project policy, a console grant or a live
network approval, and built-in protections can't be disabled while they
are present. `agentacl policy check` shows them as the `org` document.

What each rule does depends on how the Mac enforces (the console warns when
you publish):

| Rule | `agentacl run` sessions | Endpoint Security (every agent) |
|---|---|---|
| File paths | Enforced (Seatbelt) | Enforced |
| Program, no arguments (`curl`) | Enforced, by name or path | Enforced, by name or path |
| Program with arguments (`git push *`) | Logged only | Enforced, by position |
| Hosts (`*.pastebin.com`) | Enforced by name (proxy); deny address ranges too | Not enforced (ES doesn't see network traffic) |

A running `agentacl run` session keeps the rules it started with; the
console marks it stale and the next session gets the new ones.

## 5. Where rules apply

Without Apple's Endpoint Security entitlement, AgentACL enforces only for
agents started through it (`agentacl run`); a user can still start an
agent directly. The Machines page shows agents running outside AgentACL,
and flags sessions that didn't load the company rules (for example, an
older AgentACL from Homebrew earlier in the user's `PATH`). With the
entitlement (docs/design/endpoint-security.md) the file and program rules
apply to every agent. Users with admin rights can remove AgentACL; the
server shows a Mac that stops reporting.

## 6. Signing (optional, needs Apple)

With an Apple Developer Program membership ($99 a year, no review), sign
the binary and the package:

```sh
echo "$TOKEN" | scripts/fleet/build-pkg.sh --server https://fleet.example.com \
  --app-sign "Developer ID Application: Your Company (TEAMID)" \
  --sign "Developer ID Installer: Your Company (TEAMID)"
xcrun notarytool submit target/AgentACL-fleet-*.pkg --keychain-profile notary --wait
xcrun stapler staple target/AgentACL-fleet-*.pkg
```

Signed and notarized, the package installs through the MDM command and
opens without warnings. System-wide enforcement additionally needs Apple
to grant the Endpoint Security entitlement.

## Revoking and removing

- **Revoke a Mac** on its page: its key stops working, it keeps its last
  company rules, and its machine id can't enroll again until you allow it.
- **Remove from a Mac:** `scripts/fleet/uninstall.sh`.

## Testing locally

`scripts/fleet/e2e-local.sh` runs a server on `127.0.0.1`, enrolls this Mac
into a temporary folder (no root needed, fake data), reports, pushes a
company policy and checks the console.
