#!/usr/bin/env bash
# End-to-end check of the fleet on this Mac, without root: a server on
# 127.0.0.1, a Mac enrolled into a temporary folder (--root), a report, a
# company policy push, and the console. Uses no real credentials.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cargo build -q --release --locked -p agentacl-cli -p agentacl-server --manifest-path "$root/Cargo.toml"
bin="$root/target/release"
t="$(mktemp -d)"
trap 'kill "${server_pid:-0}" 2>/dev/null || true; rm -rf "$t"' EXIT
pass=0
check() { if eval "$2"; then echo "PASS  $1"; pass=$((pass + 1)); else echo "FAIL  $1"; exit 1; fi; }

db="$t/server.db"
printf 'e2e admin password\n' >"$t/pw"
AGENTACL_SERVER_ADMIN_PASSWORD_FILE="$t/pw" "$bin/agentacl-server" init --db "$db" >/dev/null
token="$("$bin/agentacl-server" token --db "$db" --name e2e --max 2 2>/dev/null)"
port=$((20000 + RANDOM % 20000))
"$bin/agentacl-server" serve --db "$db" --listen "127.0.0.1:$port" --public-url "http://127.0.0.1:$port" --insecure-cookies 2>"$t/server.log" &
server_pid=$!
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$port/login" && break; sleep 0.1; done

mac="$t/mac/AgentACL"
# This user's AgentACL data for the test: fake, in the temporary folder.
export AGENTACL_HOME="$t/state" AGENTACL_CONFIG_DIR="$t/config"
mkdir -p "$AGENTACL_CONFIG_DIR"
printf 'version: v1\n' >"$AGENTACL_CONFIG_DIR/policy.yaml"
check "enroll" "echo '$token' | '$bin/agentacl' fleet enroll --root '$mac' --server 'http://127.0.0.1:$port' >/dev/null"
check "enrolled: key root-only, empty company policy written first" "[[ \$(stat -f %Lp '$mac/fleet.json') == 600 && -f '$mac/managed/policy.yaml' ]]"
check "a second enrollment of an enrolled Mac is refused" "! echo '$token' | '$bin/agentacl' fleet enroll --root '$mac' --server 'http://127.0.0.1:$port' 2>/dev/null"
check "report" "'$bin/agentacl' fleet run --once --root '$mac'"
check "the server has the Mac and its user" "[[ \$(sqlite3 '$db' 'SELECT COUNT(*) FROM devices WHERE last_seen IS NOT NULL') == 1 && \$(sqlite3 '$db' 'SELECT user FROM device_users') == \"\$(id -un)\" ]]"

# shellcheck disable=SC2016 # ${HOME} is for the policy, not the shell
printf 'version: v1\nfilesystem:\n  deny_read: ["${HOME}/Company/**"]\nprocess:\n  deny: ["git push *"]\n' >"$t/policy.yaml"
check "publish a company policy" "'$bin/agentacl-server' policy --db '$db' --file '$t/policy.yaml' >/dev/null 2>&1"
printf 'version: v1\nnetwork:\n  allow: ["evil.example"]\n' >"$t/bad.yaml"
check "an allow rule is refused by the server" "! '$bin/agentacl-server' policy --db '$db' --file '$t/bad.yaml' 2>/dev/null"
check "the Mac applies it at its next report" "'$bin/agentacl' fleet run --once --root '$mac' && grep -q Company '$mac/managed/policy.yaml'"
check "fleet status shows version 1" "'$bin/agentacl' fleet status --root '$mac' | grep -q 'Company policy version: 1'"

# The console: sign in, see the Mac.
jar="$t/jar"
check "console sign-in" "curl -s -c '$jar' -o /dev/null -w '%{http_code}' -d 'password=e2e admin password' 'http://127.0.0.1:$port/login' | grep -q 303"
check "console lists the Mac" "curl -s -b '$jar' 'http://127.0.0.1:$port/' | grep -q \"\$(hostname | sed 's/[.].*//')\""
check "the device key is refused once revoked" "dev=\$(sqlite3 '$db' 'SELECT id FROM devices'); sqlite3 '$db' \"UPDATE devices SET revoked = 1 WHERE id = '\$dev'\"; ! '$bin/agentacl' fleet run --once --root '$mac' 2>/dev/null"
echo
echo "$pass checks passed"
