# Demo scripts

Deterministic scripts for recording the AgentACL demo. They are safe to run
repeatedly:
- **Everything lives in `/tmp/agentacl-demo`.** `_lib.sh` refuses any other
  directory. The one exception is `agentacl run` itself, which keeps each
  session's temporary directory in your user temp directory
  (`$(getconf DARWIN_USER_TEMP_DIR)agentacl`), as it always does.
- **Every secret is generated and marked `FAKE`.**
- **Your real secrets are never read.** `agentacl` itself checks and names
  its real built-in paths as it always does, but the scripts only ever open
  the fake fixtures.
- **No personal environment in the recording.** `agentacl` runs with a
  minimal environment, so your environment variable names don't appear in
  the session summary.
- **A tampered demo directory is refused.** It must be yours, contain no
  symlinks, and every fixture must still be fake.
- **AgentACL runs with a demo config and state**
  (`AGENTACL_CONFIG_DIR`, `AGENTACL_HOME` under the demo directory), so your
  real policy and audit log are untouched.

## What each script shows

| Script | Shows |
|---|---|
| `setup-demo.sh` | Creates the demo project (`.env`, `README.md`, `read.py`), a fake home (`.aws/credentials`, `.ssh/id_ed25519`) and the demo policy |
| `unprotected-secret-read.sh` | Without AgentACL, `cat` and Python read the fake secrets: the agent runs as you |
| `protected-secret-read.sh` | The same reads under `agentacl run`: `Operation not permitted`. The project's README still reads fine |
| `child-process-read.sh` | The boundary holds through `bash -c 'sh -c …'`, Python, and Python `subprocess` |
| `protected-file-write.sh` | Planting a git hook, `.envrc` or `.claude/settings.json` is refused; ordinary project files stay writable |
| `network-deny.sh` | `example.com` (allowed by the demo policy) works; `example.org` is refused by the proxy (curl and Python); a raw socket that ignores the proxy is refused by the kernel. Needs internet; prints SKIPPED without it |
| `console.sh` | Opens `agentacl ui` on the demo's state, to show what was blocked |
| `run-all.sh` | Everything above, in recording order |
| `cleanup-demo.sh` | Removes `/tmp/agentacl-demo` |

`.env` is protected by AgentACL's real built-in rule. The fake home stands in
for `~/.aws` and `~/.ssh`. The built-in rules for those are rooted at your
real home directory, which the demo never touches, so the demo policy
protects the fake home with equivalent rules. Each blocked line in the
session summary names the rule that stopped it.

## Recording

```sh
scripts/demo/setup-demo.sh
DEMO_PAUSE=1.5 scripts/demo/run-all.sh      # pause between steps, in seconds
scripts/demo/console.sh                      # optional: the console with the demo's events
scripts/demo/cleanup-demo.sh
```

- `DEMO_PAUSE=0` runs without pauses.
- `AGENTACL_BIN=/path/to/agentacl` uses a specific build.
- A terminal around 110×30 fits the output without wrapping.

## Recording with a real agent

The same fixtures work with Claude Code, which keeps its own login:

```sh
scripts/demo/setup-demo.sh
cd /tmp/agentacl-demo/project
AGENTACL_CONFIG_DIR=/tmp/agentacl-demo/config AGENTACL_HOME=/tmp/agentacl-demo/state agentacl run -- claude
```

Then ask it, for example: "Read .env and
/tmp/agentacl-demo/fake-home/.aws/credentials, then use Python to read them."
Claude's reads, and those of every command it runs, get
`Operation not permitted`.
