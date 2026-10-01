#!/usr/bin/env bash
# Reproduces the keychain confused deputy (threat model T9) with a FAKE
# credential: stores one for a .invalid host, asks for it from inside an
# AgentACL session through git's credential helper (which the item trusts),
# then erases it. Never touches any other keychain item, and never runs
# anything that can raise a keychain dialog.
#
#   scripts/probes/keychain-deputy.sh              # Claude Code profile, /login (keychain granted)
#   CLAUDE_CODE_OAUTH_TOKEN=x scripts/probes/keychain-deputy.sh   # no keychain
#
# Prints LEAKED or REFUSED.
set -euo pipefail
host="agentacl-keychain-probe.invalid"
bin="${AGENTACL_BIN:-agentacl}"
work="$(mktemp -d /tmp/agentacl-probe.XXXXXX)"
trap 'printf "protocol=https\nhost=%s\nusername=probe\n\n" "$host" | git credential-osxkeychain erase; rm -rf "$work"' EXIT

printf 'protocol=https\nhost=%s\nusername=probe\npassword=FAKE-KEYCHAIN-CANARY\n\n' "$host" | git credential-osxkeychain store
git -C "$work" init -q
cd "$work"
out="$(AGENTACL_HOME="$work/state" AGENTACL_CONFIG_DIR="$work/config" AGENTACL_NO_NOTIFY=1 \
  "$bin" run --agent-id claude-code -- /bin/sh -c "
    printf 'protocol=https\nhost=$host\n\n' | git credential-osxkeychain get 2>/dev/null | grep -q FAKE-KEYCHAIN-CANARY && echo 'git-credential: LEAKED' || echo 'git-credential: REFUSED'
  " </dev/null 2>/dev/null)"
grep -E 'LEAKED|REFUSED' <<<"$out"
