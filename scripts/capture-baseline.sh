#!/bin/sh
# Runs a command under a Seatbelt profile and prints the unique kernel sandbox
# denials it caused ("op path"), for refining the runtime baseline
# (crates/agentacl-policy/builtin/runtime.yaml, crates/agentacl-core/src/enforce/baseline.rs).
#
# Usage: scripts/capture-baseline.sh PROFILE.sb CMD [ARGS...]
#
# Review every line before adding it to the baseline. Never add a path that
# protect-secrets matches, and never add an operation on the NEVER_ALLOW list.
set -eu
profile=$1
shift
out=$(mktemp -t afcap)
/usr/bin/log stream --style ndjson --predicate 'processIdentifier == 0 AND sender == "Sandbox"' >"$out" 2>/dev/null &
logpid=$!
sleep 1.5
/usr/bin/sandbox-exec -f "$profile" "$@" || echo "exit=$?" >&2
sleep 1.5
kill "$logpid" 2>/dev/null || true
wait "$logpid" 2>/dev/null || true
grep -o '"eventMessage":"Sandbox: [^"]*"' "$out" |
  sed -e 's/^"eventMessage":"Sandbox: //' -e 's/"$//' -e 's/\\\//\//g' -e 's/^[^)]*) deny([0-9]*) //' |
  sort -u
rm -f "$out"
