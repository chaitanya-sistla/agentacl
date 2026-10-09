#!/usr/bin/env bash
# End-to-end checks of agentacl-esd on a DEVELOPMENT Mac (a VM with SIP and
# AMFI off, after scripts/es/install-dev.sh and Full Disk Access). Uses a
# stand-in agent: a copy of zsh at Claude Code's install path, which the
# daemon identifies as Claude Code (by path). Every credential is a fake
# fixture written here.
#
#   AGENTACL=path/to/agentacl scripts/es/smoke-test.sh
#
# Commands for the agent are single-quoted on purpose: its shell expands them.
# shellcheck disable=SC2016
set -uo pipefail
agentacl="${AGENTACL:-agentacl}"
pass=0
fail=0
ok() { printf 'PASS  %s\n' "$1"; pass=$((pass + 1)); }
no() { printf 'FAIL  %s\n' "$1"; fail=$((fail + 1)); }
expect() { # expect allow|deny "label" command...
  local want="$1" label="$2"
  shift 2
  if "$@" >/dev/null 2>&1; then got=allow; else got=deny; fi
  if [[ "$got" == "$want" ]]; then ok "$label"; else no "$label (wanted $want, got $got)"; fi
}

if ! pgrep -qx agentacl-esd && ! pgrep -qx ai.agentacl.app.esd; then
  echo "neither agentacl-esd nor the AgentACL system extension is running (sudo launchctl kickstart -k system/ai.agentacl.esd)" >&2
  exit 2
fi

agent_dir="$HOME/.local/share/claude/versions"
agent="$agent_dir/0.0.0-smoke"
mkdir -p "$agent_dir" "$HOME/.aws" "$HOME/notes" "$HOME/proj" "$HOME/.config/agentacl"
cp /bin/zsh "$agent"
printf '[default]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\n' >"$HOME/.aws/credentials"
echo "plan" >"$HOME/notes/plan.md"
policy="$HOME/.config/agentacl/policy.yaml"
[[ -f "$policy" ]] && cp "$policy" "$policy.smoke-backup"
# A user policy replaces the default one: start from it (the project only).
write_policy() { # $1: extra read patterns, appended to the project's
  cat >"$policy" <<EOF
version: v1
defaults: {filesystem: deny, network: deny, process: allow}
process:
  deny: ["touch blocked-by-rule *"]
filesystem:
  allow_read: ["\${PROJECT}/**"$1]
  allow_write: ["\${PROJECT}/**"]
EOF
}
write_policy ""
sleep 2 # the daemon reloads within a second

# Runs a command as the stand-in agent, in the project.
as_agent() { (cd "$HOME/proj" && "$agent" -f -c "$1"); }

echo "== a process that isn't an agent is untouched"
expect allow "plain shell reads the (fake) AWS credentials" cat "$HOME/.aws/credentials"

echo "== the agent and its children"
expect deny "agent reads AWS credentials" as_agent 'cat ~/.aws/credentials'
expect deny "grandchild reads AWS credentials" as_agent '/bin/sh -c "cat ~/.aws/credentials"'
expect allow "agent writes and reads in its project" as_agent 'echo hi > ~/proj/a.txt && cat ~/proj/a.txt'
expect allow "agent uses /dev/null and the temp folder" as_agent 'echo x > /dev/null && echo x > "$TMPDIR/smoke" && cat "$TMPDIR/smoke"'
expect deny "agent reads outside the project (default)" as_agent 'cat ~/notes/plan.md'
expect deny "agent renames a credential file into the project" as_agent 'mv ~/.aws/credentials ~/proj/stolen'
chmod 644 "$HOME/.aws/credentials"
expect deny "agent changes a credential file's mode" as_agent 'chmod 600 ~/.aws/credentials'
expect deny "argument rule: touch blocked-by-rule" as_agent 'touch blocked-by-rule ~/proj/f'
expect allow "same program, other arguments" as_agent 'touch ~/proj/g'
expect deny "setuid program (sudo)" as_agent 'sudo -n true'
expect deny "osascript (Apple Events)" as_agent 'osascript -e "return 1"'
expect deny "launchctl submit" as_agent 'launchctl submit -l ai.agentacl.smoke -- /usr/bin/true'
expect deny "open -a Terminal" as_agent 'open -a Terminal /tmp'

echo "== AgentACL's processes"
"$agentacl" events --follow >/dev/null 2>&1 &
watcher=$!
sleep 1
expect deny "agent signals an agentacl process" as_agent "kill -CONT $watcher"
expect allow "the human signals it" kill -CONT "$watcher"
kill "$watcher" 2>/dev/null

echo "== a grant applies without a restart"
write_policy ", \"$HOME/notes/**\""
sleep 2
expect allow "agent reads ~/notes after the grant" as_agent 'cat ~/notes/plan.md'

echo "== decisions reach the audit log"
sleep 1
if "$agentacl" events --limit 200 2>/dev/null | grep -q "credentials"; then ok "agentacl events shows the refusals"; else no "agentacl events shows the refusals"; fi

echo "== cost (no agent involved; compare with the daemon stopped)"
start=$(date +%s)
find /usr/lib /usr/share -type f 2>/dev/null | head -20000 | xargs cat >/dev/null 2>&1
echo "reading 20000 system files: $(($(date +%s) - start)) s"

rm -f "$agent"
if [[ -f "$policy.smoke-backup" ]]; then mv "$policy.smoke-backup" "$policy"; else rm -f "$policy"; fi
echo
echo "$pass passed, $fail failed"
((fail == 0))
