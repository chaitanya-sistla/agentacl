#!/usr/bin/env bash
# Installs agentacl-esd as a LaunchDaemon on a DEVELOPMENT Mac: a VM with SIP
# and AMFI off (docs/design/endpoint-security.md). It refuses to run where SIP
# is on: without Apple's entitlement the daemon can't start there anyway, and
# this script must never be pointed at a Mac people use.
#
#   scripts/es/install-dev.sh            build, sign ad hoc, install, start
#   scripts/es/install-dev.sh --dry-run  print what it would do
#   ESD_BIN=path scripts/es/install-dev.sh   use a prebuilt agentacl-esd
#                                            (a VM without Rust)
set -euo pipefail
dry=0
[[ "${1:-}" == "--dry-run" ]] && dry=1
run() { if ((dry)); then printf '+ %s\n' "$*"; else "$@"; fi; }

if csrutil status 2>/dev/null | grep -q "enabled"; then
  echo "SIP is enabled on this Mac. Use a development VM with SIP and AMFI off (see docs/design/endpoint-security.md)." >&2
  ((dry)) || exit 1
fi
if [[ "$(id -u)" == 0 ]]; then
  echo "Run this as the user whose agents it should protect (it uses sudo where needed)." >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${ESD_BIN:-$root/target/release/agentacl-esd}"
ent="$root/packaging/macos/es/agentacl-esd.entitlements"
plist="$root/packaging/macos/es/ai.agentacl.esd.plist"
conf_dir="/Library/Application Support/AgentACL"

if [[ -z "${ESD_BIN:-}" ]]; then
  run cargo build --release --locked -p agentacl-es --manifest-path "$root/Cargo.toml"
fi
# Ad-hoc signature with the ES entitlement: accepted only with AMFI off.
# Signed on a copy, so a read-only source (a shared folder) works.
signed="$(mktemp -d)/agentacl-esd"
run cp "$bin" "$signed"
run codesign --force --sign - --entitlements "$ent" "$signed"
bin="$signed"

# The daemon's config: this user, home and temp folder. Written root-owned so
# agents (running as this user) can't re-point it.
for v in "$HOME" "$(id -un)"; do
  if [[ "$v" == *[\"\\]* ]]; then echo "Unsupported character in $v" >&2; exit 1; fi
done
config="$(printf '{"user":"%s","uid":%d,"gid":%d,"home":"%s","tmpdir":"%s"}' \
  "$(id -un)" "$(id -u)" "$(id -g)" "$HOME" "$(getconf DARWIN_USER_TEMP_DIR)")"
run sudo mkdir -p "$conf_dir"
if ((dry)); then echo "+ write $conf_dir/esd.json: $config"; else printf '%s\n' "$config" | sudo tee "$conf_dir/esd.json" >/dev/null; fi
run sudo chown -R root:wheel "$conf_dir"
run sudo chmod 755 "$conf_dir"
run sudo chmod 644 "$conf_dir/esd.json"

run sudo install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools
run sudo install -m 755 "$bin" /Library/PrivilegedHelperTools/agentacl-esd
run sudo "/Library/PrivilegedHelperTools/agentacl-esd" --check
run sudo install -m 644 "$plist" /Library/LaunchDaemons/ai.agentacl.esd.plist
run sudo launchctl bootout system/ai.agentacl.esd 2>/dev/null || true
run sudo launchctl bootstrap system /Library/LaunchDaemons/ai.agentacl.esd.plist

cat <<'MSG'

Next, once: System Settings → Privacy & Security → Full Disk Access → add
/Library/PrivilegedHelperTools/agentacl-esd and switch it on. Then:

  sudo launchctl kickstart -k system/ai.agentacl.esd
  sudo tail -f /var/log/agentacl-esd.log      # "watching every process for …"
  agentacl events --follow                    # its decisions, as they happen
MSG
