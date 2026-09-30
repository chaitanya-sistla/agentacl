# AgentACL Policy Model

Status: design, iteration 1. The format is `version: v1`, YAML.

## 1. Goals

- Humans can read and review it, and it's small enough to audit in a PR.
- Evaluation is deterministic: the same (policy set, request) always gives the same decision.
- **Explicit deny wins.** No allow, from any layer, overrides an explicit deny.
- Enforceability is visible: every rule can be classified by whether the active
  backend actually enforces it (§7).
- The evaluator sits behind a `PolicyEngine` trait so an OPA/Rego engine can be
  added later without touching callers.

## 2. Document format

```yaml
version: v1
name: default                 # policy name reported in events; defaults to the file stem
match:                        # optional: which sessions this document applies to (all if omitted)
  agents: ["claude-code", "codex"]      # agent ids; "custom:*" globs allowed
  projects: ["${HOME}/src/**"]

defaults:
  filesystem: deny            # allow | deny | ask
  network: deny
  process: allow

filesystem:
  allow_read:
    - "${PROJECT}/**"
  allow_write:
    - "${PROJECT}/**"
  deny_read:
    - "${HOME}/.ssh/**"
    - path: "${PROJECT}/**/.env.*"
      except: ["**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist"]
      id: env-variants
      reason: "Environment secret files are protected"
  deny_write:
    - "${PROJECT}/.git/hooks/**"

process:
  deny:
    - "sudo *"
  require_approval:
    - "terraform apply *"
    - "terraform destroy *"
    - "kubectl delete *"
    - "git push *"

network:
  allow:
    - "api.anthropic.com"
    - "*.githubusercontent.com"
    - "github.com:443"
  deny:
    - "169.254.169.254"        # cloud metadata
```

A rule entry is either a string (the pattern) or an object
`{path|command|host, except?, id?, reason?}`. String entries get the
generated id `<policy>/<section>/<index>` and a generic reason.

### 2.1 Variables

| Variable | Value |
|---|---|
| `${HOME}` | The invoking user's home directory (from `getpwuid`, not `$HOME`) |
| `${PROJECT}` | The session's project root (see architecture §4) |
| `${TMPDIR}` | The per-user temp dir, canonicalized (`/private/var/folders/...`) |
| `${AGENT_STATE}` | The provider-declared state dir for the agent (e.g. `~/.claude`), if any |

An unknown variable is a **load error**. Expansion happens once, at session
start, and the expanded policy's SHA-256 is recorded on the session.

### 2.2 Path patterns

Patterns are matched against the **canonical absolute path**: `realpath` of the
longest existing prefix, with `/tmp`, `/var` and `/etc` mapped to `/private/...`.

| Syntax | Meaning |
|---|---|
| `*` | Any run of characters within one path segment (no `/`) |
| `?` | One character, not `/` |
| `**` | Zero or more whole segments. `X/**` matches `X` itself and everything under it |
| `**/name` | `name` at any depth, under the pattern's own anchor |

Every pattern must be anchored: it starts with `/`, or with a variable. Use
`/**/.env` for "anywhere on disk". Unanchored patterns are a load error.
The one exception is an `except` entry, which may start with `**/`, because
it narrows its own rule and inherits that rule's anchor.

Matching is **case-insensitive**, because APFS volumes are case-insensitive by
default. A case-sensitive matcher would let `.ENV` bypass a `.env` rule. On
case-sensitive volumes this over-matches, which is the safe direction. (The
Seatbelt backend matches on the vnode's canonical path; we verified that
`cat .ENV` of a denied `.env` is refused. We also saw a lowercase regex
deny a file whose on-disk name is `.ENV`, so Seatbelt path matching appears
case-insensitive on this volume. Because that's undocumented, the compiler still
emits case-folded character classes (`[eE][nN][vV]`) as defense in depth.)

### 2.3 Process patterns

A process rule matches **each exec**, never a shell string. `bash -c "git push"`
causes an exec of `git` with argv `["git","push"]`, and that exec is what
gets evaluated. Pattern grammar: whitespace-separated tokens, where

- token 1 matches the executable: either its basename, or an absolute path
  compared to the canonical executable path;
- the following tokens match argv[1..] positionally, and `*` as the **last** token
  matches zero or more remaining args;
- `*` inside a token is a glob within that argument.

So `"sudo *"` matches any exec of an executable named `sudo`. (Under Seatbelt,
setuid binaries like `sudo` can't be exec'd at all.) Likewise
`"git push *"` matches `git push` and `git push origin main`, but **not**
`git -C repo push`, because positional matching doesn't understand each tool's
global flags. That limit is accepted and documented. Argument matching narrows
*which* execs a rule targets. It isn't a security boundary on its own (see §7
for what's actually enforced).

### 2.4 Network patterns

An entry is a **host pattern** or an **address pattern**:

- A host pattern is an exact host, or `*.` + a domain for any subdomain (not
  the apex). `:port` is optional, and means any port if omitted.
- An address pattern is an IP literal or a CIDR, with an optional `:port`.
  `localhost` is shorthand for `127.0.0.0/8` and `::1`.

Either kind may appear in `allow` and in `deny`.

The destination is the host of the **request target only**: the CONNECT
authority, or the absolute-URI host of a plain-HTTP request. It's lowercased,
with a trailing dot stripped. A plain-HTTP request whose `Host` header differs
from the request-URI host is refused.

A `network.connect` decision is made in **two phases** (§4.2). Nothing is
resolved until phase 1 allows the host, so a denied name like
`<secret>.attacker.tld` never reaches DNS (T8).

`network.listen` lists the loopback ports the agent may bind and accept
connections on, e.g. `["localhost:3000"]`. It's empty by default, and
non-loopback listen entries are a load error (see macos-enforcement §2.2).

## 3. Policy layers and trust

Documents are loaded in this order and **merged**. Merging is a union of rules,
never a replacement.

1. **Built-in**, compiled into the binary as data
   (`crates/agentacl-policy/builtin/*.yaml`):
   `protect-secrets` (§5), `runtime` (§5.1), and `default`. `default` is the
   starter policy: filesystem, network and process defaults, plus project
   read/write allows. It applies **only when no user policy exists**.
2. **User** `~/.config/agentacl/policy.yaml` (or `--policy FILE`). Its
   presence replaces `default`. It never replaces `protect-secrets` or `runtime`.
3. **Project** `${PROJECT}/.agentacl/policy.yaml`.

Project policies live in the repository, so a cloned repo could ship one. A
project policy is therefore **restrict-only**, with a **closed schema**. The only
keys it may contain are:

- `version`, `name`, `match`
- `defaults.*`, each no looser than the value merged from built-in + user documents
- `filesystem.deny_read`, `filesystem.deny_write`
- `process.deny`, `process.require_approval`
- `network.deny`

**Any other key** is a load error. That includes every `allow*`,
`network.listen`, `builtin`, and `trusted_project_policies`. The only way
past this is for the user to trust the file's exact SHA-256 **for that
project path**, with `agentacl policy trust --sha256 <sha> [--project P]`.
This records `{project, sha256}` in `~/.config/agentacl/config.yaml`
(`trusted_project_policies`). Any change to the file invalidates the trust.
The same bytes in another project are not trusted. Legacy hash-only entries
are ignored.

For the same reason, the sandbox profile denies the agent write access to
`${PROJECT}/.agentacl/**`, all of `~/.config/agentacl/**` (user policy
and trust config), and the AgentACL state dir.

`match:` selects which documents apply to a session. Built-ins always apply.

## 4. Evaluation

```
Request  { subject: {human, machine, agent{id,version,team_id}, session, project, delegation_chain},
           action: filesystem.read | filesystem.write | process.exec | network.connect,
           resource: canonical path | {exe, argv} | {host, port} }
Decision { effect: allow | deny | ask, policy, rule_id, reason, trace[] }
```

Algorithm, the same for every action:

1. Take the documents whose `match` selects the subject.
2. Collect every rule in those documents whose section matches the action and
   whose pattern matches the resource and whose `except` does not.
3. If any matching rule is a **deny** → `deny` (report the first one in
   load order: built-in before user before project).
4. Else if any matching rule is **require_approval** → `ask`.
5. Else if any matching rule is an **allow** → `allow`.
6. Else → the category default. When several applicable documents set a
   default, the **most restrictive** applies (deny > ask > allow). A default
   decision is reported as `policy: <doc>`, `rule_id: default`.

`filesystem.write` covers create, write, truncate, unlink, rename (both source
and destination), link, clone, and attribute/mode/ownership changes.
`filesystem.read` covers open-for-read, readdir, and `readlink`.

**A deny protects the location too.** Every explicit filesystem deny, read or
write, implies a deny of *unlink, rename (as source) and link* on the paths it
matches, and on **every ancestor directory** of the protected location, up to
but excluding `/` (for a glob, that includes the glob's anchor directory).
Without this, two bypasses were verified:
- `mv .env.production leak.txt && cat leak.txt` reads the secret.
- `mv ~/.claude $TMPDIR/c`, then editing `c/settings.json`, then moving the
  directory back plants a hook. The same works with the whole project
  directory and `.git/config`.

The evaluator applies this rule, and the Seatbelt compiler emits the
corresponding `file-write-unlink` / `file-link` denies. Globs anchored at `/`,
like `/**/.env`, have no ancestors to protect: renaming a parent leaves the
file matched by the same glob.

**Fallback defaults.** If no applicable document sets a category default, it
is `deny` for filesystem and network, and `allow` for process (which is
observed-only under Seatbelt anyway, §6).

Invariant (property-tested): **adding an allow rule never changes an
*explicit* deny, and adding a deny rule never changes any decision to
`allow`.** A *default* deny can be turned into allow by an allow; that's
what allows are for (§4.1).

### 4.2 Network: two-phase decision

1. **Host phase.** Apply steps 1–6 above to the request-target host, using host
   patterns and (for IP-literal targets) address patterns. If the result is
   deny or ask, refuse (no DNS lookup).
2. **Address phase.** Resolve the host in the proxy. For **every** resulting
   address, evaluate the address patterns, plus the built-in **reserved-range
   deny list**: loopback, link-local (incl. `169.254.169.254`), RFC 1918, CGNAT
   `100.64/10`, ULA `fc00::/7`, and IPv4-mapped forms of all of these.
   Reserved ranges are an **explicit deny**, with one exception: an allow
   entry that names the address, a CIDR containing it, or `localhost[:PORT]`
   overrides them. A *host* allow (`*.corp.com`) never does. If any address is
   denied, refuse. Otherwise connect to exactly the address that was checked,
   so a second resolution can't rebind.

Both phases apply the same way regardless of `defaults.network`.

### 4.1 Explicit vs default deny: a consequence worth knowing

Explicit deny wins everywhere, so this combination:

```yaml
filesystem:
  allow_write: ["${PROJECT}/**"]
  deny_write:  ["${HOME}/**"]
```

denies **all** writes to a project under `$HOME`, because the explicit
`deny_write ${HOME}/**` also matches `${PROJECT}/foo`. To say "write only in the
project", use the default instead:

```yaml
defaults: { filesystem: deny }
filesystem:
  allow_write: ["${PROJECT}/**"]
```

A default deny is overridable by allow. An explicit deny is not.
`agentacl policy check` warns when an explicit deny fully shadows an
allow rule.

### 4.2 Subject conditions

Iteration 1 selects documents on `agent`, `project` and (implicitly) human.
Every event records `delegation_chain`, `agent_version` and `machine`, and they
appear in the `Request` so the evaluator (and a future OPA engine) can use them.
Rule-level conditions on them, such as "deny `terraform` only when the chain
includes `claude-code`", are deferred to v2 of the format. In iteration 1 every
supervised process is by definition inside an agent's chain.

## 5. Built-in `protect-secrets`

Rules are data (YAML), grouped with an id and a reason per group. Sketch:

| id | deny_read + deny_write |
|---|---|
| `env-files` | `/**/.env`, `/**/.env.*` (except `.env.example/.sample/.template/.dist`), `/**/.envrc` |
| `ssh` | `${HOME}/.ssh/**` (the directory itself included). Also: `SSH_AUTH_SOCK` is removed from the child env and connecting to the agent socket is denied (see threat model T6) |
| `aws` | `${HOME}/.aws/credentials`, `${HOME}/.aws/sso/cache/**`, `${HOME}/.aws/cli/cache/**` |
| `gcp` | `${HOME}/.config/gcloud/**` |
| `azure` | `${HOME}/.azure/**` |
| `kube` | `${HOME}/.kube/**` (the whole directory: kubeconfigs can sit at any depth, and a name rule such as `**/config` would also match every `.git/config`) |
| `terraform` | `${HOME}/.terraform.d/credentials.tfrc.json`; under `${HOME}` and `${PROJECT}`: `**/*.tfstate`, `**/*.tfstate.backup`, `**/terraform.tfvars` |
| `git-creds` | `${HOME}/.git-credentials`, `${HOME}/.config/gh/hosts.yml` |
| `package-creds` | `${HOME}/.npmrc`, `${HOME}/.pypirc`, `${HOME}/.netrc`, `${HOME}/.docker/config.json`, `${HOME}/.cargo/credentials.toml` |
| `keys` | under `${HOME}` and `${PROJECT}` only: `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.pfx`, `**/id_rsa*`, `**/id_ed25519*`. **Not** anchored at `/`: that would deny system trust stores like `/private/etc/ssl/cert.pem`, and we verified that it breaks TLS (`curl: (77)`) |
| `gpg` | `${HOME}/.gnupg/**` |
| `browsers` | `${HOME}/Library/Application Support/{Google/Chrome,BraveSoftware,Microsoft Edge,Arc,Firefox}/**`, `${HOME}/Library/Cookies/**`, `${HOME}/Library/Safari/**`, `${HOME}/Library/Containers/com.apple.Safari/**`: cookies, saved passwords and signed-in sessions |
| `exec-persistence` | deny_write only. **Git:** `${PROJECT}/**/.git/**` (this covers `config`, `hooks`, `commondir`, `info/attributes` and `modules/*/config`), **except** git's data files: `objects/**`, `refs/**`, `logs/**`, `index`, `HEAD`, `ORIG_HEAD`, `FETCH_HEAD`, `MERGE_*`, `COMMIT_EDITMSG`, `packed-refs`, `*.lock`, `rebase-merge/**`, `rebase-apply/**`, `sequencer/**`. Also denied: creating, unlinking or renaming `${PROJECT}/**/.git` itself, which blocks the gitfile swap. **Project agent configs:** `${PROJECT}/.claude/**`, `${PROJECT}/.mcp.json`, `${PROJECT}/.codex/**`, `${PROJECT}/.gemini/**`, `${PROJECT}/.vscode/**`, `${PROJECT}/.cursor/**`. **User:** `${HOME}/.gitconfig`, `${HOME}/.config/git/**`, shell rc files (`${HOME}/.zshrc`, `.zprofile`, `.zshenv`, `.bashrc`, `.bash_profile`, `.profile`), `${HOME}/Library/LaunchAgents/**`, plus provider-declared hook configs (e.g. `${HOME}/.claude/settings.json`) **and every script those configs reference**, which is parsed at session start. See threat model T19 |
| `agentacl-self` | deny_write only: AgentACL state dir, user policy, `${PROJECT}/.agentacl/**` |

Git's writable set is an **allowlist** of data files, because git reads
config-like indirections from more places than `config` alone (`commondir`
and gitfiles were both verified as bypasses of a `config`+`hooks`-only rule).
The cost: `git remote add`, `git config` and `git push -u` fail inside a session. That's accepted: `.git/config` can hold
commands (`core.fsmonitor`, `core.sshCommand`, filter drivers) that git later
runs outside the sandbox.

Built-ins also deny **write** to the same paths, so the agent can't replace a
credential file or plant a key. For each anchored path rule they also deny
unlink/rename of each ancestor directory below the anchor. We verified that
renaming the parent of a read-denied directory otherwise exposes its contents
under the new name.

`**/*.key` and `**/*.pem` will produce false positives in some repos, such as
test fixtures. That is intentional: default-deny for sensitive material.
Deny-wins means a user can't allow them back, but a user policy *can* shadow a
whole built-in group with `builtin: { disable: ["keys"] }`. That setting is
reported loudly by `policy check` and recorded in every session's identity.
The `agentacl-self` and `exec-persistence` groups can't be disabled.

### 5.1 Built-in `runtime` (default allows)

With `defaults.filesystem: deny`, an agent couldn't even load its own dylibs. So
the built-in `runtime` document supplies the **allow** rules that a process
needs on macOS. Because they're allows, they can never override a deny.

The list below is a **starting point, and it's known to be incomplete**. With only
these paths, `sh`, `git`, `node` and `claude` abort (SIGABRT), because they need
metadata reads on `/` and the `/var`, `/etc`, `/tmp` and `/opt` symlinks, plus
`/private/var/select/**`, `/dev/dtracehelper`, and several Mach services. The real
baseline is built empirically: run each supported agent under a logging
profile, collect the kernel denials, and review them into `runtime.yaml`. An E2E
test per agent (`agentacl run -- <agent> --version` and a scripted session)
keeps it from regressing.

- metadata (`stat`, not contents): `/` and every ancestor of an allowed path

- read: `/System/**`, `/usr/**` (excluding `/usr/local/var/**`), `/bin/**`, `/sbin/**`, `/Library/**`,
  `/opt/homebrew/{bin,lib,opt,Cellar,Caskroom,share,etc,libexec}/**` (not `var/`,
  which holds database data), the same subset of `/usr/local`, `/Applications/Xcode*.app/**`,
  `/private/etc/**`, `/dev/random`, `/dev/urandom`, `/dev/zero`, and the resolved
  agent binary and its package directory
- read, for developer tooling: `${HOME}/.gitconfig`, `${HOME}/.config/git/**`
  (read-only; see `exec-persistence`)
- read+write: the **per-session** temp dir (a fresh 0700 dir, exported as
  `TMPDIR`; the user's shared `${TMPDIR}` is not granted), `/private/tmp/**`
  (compatibility; see T2 residual), `/dev/null`, `/dev/tty`,
  the session pty slave (literal path only; other `/dev/ttys*` are other terminals of the same user), `/dev/ptmx`, `/dev/fd/**` (not `/dev/**`)
- from the provider's `runtime_requirements()`: the agent's own state, such as
  `~/.claude/**` and `~/.claude.json` (read+write) for Claude Code, and the
  hosts its API needs, such as `api.anthropic.com`

The provider's requirements are shown by `policy check`, so nothing is
granted invisibly.

**Never-allow list.** However the baseline evolves, the compiler refuses to
emit an allow for any of the following. A unit test asserts it on every
generated profile, and an E2E probe exists for each item.

- `hid-control`: a sandboxed child can otherwise inject keystrokes into the
  parent TTY with `TIOCSTI` (verified under `(allow default)`)
- `network-bind` / `network-inbound`, except the loopback ports in `network.listen`
- `lsopen`, `appleevent-send`, `job-creation`
- `mach-lookup` of the denied services in macos-enforcement §2.2
- `process-exec` of setuid binaries (the kernel forbids it anyway)

## 6. `ask` / `require_approval`

There's no interactive approval in iteration 1. `ask` is resolved like this:

| Backend | Filesystem `ask` | Process `ask` |
|---|---|---|
| Seatbelt (MVP) | Compiled to **deny** (fail closed). Event: `decision=ask, enforcement=enforced, reason="approval required; interactive approval not available"` | Executable-only patterns (`"foo *"`, `"foo"`): compiled to exec **deny**. Argument patterns (`"git push *"`): **cannot** be compiled; evaluated on observed execs → `enforcement=observed` (the event says it was *not* stopped) |
| Endpoint Security (later) | Kernel AUTH is answered **deny** within the deadline, and a pending approval is recorded. `agentacl approve <id>` grants a scoped, time-limited approval (session + exact resource/argv hash). The agent retries | Same as filesystem, keyed on the exact argv |

**Process defaults.** Under Seatbelt, `defaults.process: ask` can't be
enforced, because blocking every exec that isn't listed would stop the agent's
own shell. It's classified `observed`, and a warning is printed.
`defaults.process: deny` is enforced as an exec allowlist (`allow` +
provider runtime binaries), and `policy check` warns that it's likely to break
agents.

We never block an ES AUTH message waiting for a human, because the kernel
deadline makes that unsafe (see macos-enforcement.md).

## 7. Enforceability classification

`agentacl policy check` prints every effective rule with one of these:

| Class | Meaning |
|---|---|
| `enforced` | The active backend refuses matching operations in the kernel or at an AgentACL-owned choke point |
| `enforced-coarse` | Enforced, but at coarser granularity than written (e.g. `terraform *` enforced as "no exec of the resolved terraform binary") |
| `observed` | Evaluated on observed activity. Violations are logged with `enforcement=observed`, **not prevented** |
| `requires-es` | Needs the Endpoint Security backend. Not evaluated at all under Seatbelt |

`defaults.process: deny` is rejected by the Seatbelt backend. It would need an
exec allowlist, so `run` refuses to start, and `policy check` warns.
`network.listen` entries must name a loopback address **and** a port.

For each rule shape, the Seatbelt backend classifies as follows:

| Rule shape | Seatbelt |
|---|---|
| filesystem allow/deny, any path glob | `enforced` |
| filesystem ask | `enforced` (as deny) |
| process deny/ask, executable-only | `enforced-coarse`: deny exec of any path whose **basename** matches (`(regex #"/terraform$")`), plus the canonical paths found on `PATH` at launch. So `./bin/terraform` and shims are covered too, but a renamed copy is not (T11) |
| process deny/ask with argument tokens | `observed` |
| network allow/deny by host | `enforced` (proxy decides; the sandbox blocks all other egress) |
| unix-socket deny (ssh-agent, docker.sock) | `enforced` (verified: `(remote unix-socket (path-literal …))`) |

## 8. Future: OPA/Rego

`PolicyEngine::evaluate(&Request) -> Decision` is the only integration point. An
OPA engine would receive `Request` serialized as `input`, and the YAML documents
as `data`. It must return the same `Decision` shape, and it must be
deterministic: no `http.send`, no time-dependent rules. Iteration 1 ships only
the native engine, and there's no OPA dependency.
