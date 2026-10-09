#!/usr/bin/env bash
# Builds an AgentACL package for a fleet (docs/fleet.md).
#
#   scripts/fleet/build-pkg.sh                               generic package
#   echo "$TOKEN" | scripts/fleet/build-pkg.sh --server URL  enrolls on install
#
# Options: --proxy URL (if the Macs need one), --app-sign "Developer ID
# Application: …" (sign agentacl; ad hoc by default, always with the hardened
# runtime), --sign "Developer ID Installer: …" (sign the package; with both,
# it can be notarized), --out FILE, and AGENTACL_BIN=path to package a
# prebuilt binary (e.g. the universal one from a release).
#
# A package built with --server contains the enrollment token: distribute it
# with device management only. Without --sign it is unsigned: it installs
# with `sudo installer -pkg` and tools that run installer (Jamf, Munki), not
# with the MDM InstallEnterpriseApplication command or by double-click from
# a download.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
server="" proxy="" sign="" app_sign="-" out=""
while (($#)); do
  case "$1" in
    --server) server="$2"; shift 2 ;;
    --proxy) proxy="$2"; shift 2 ;;
    --sign) sign="$2"; shift 2 ;;
    --app-sign) app_sign="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)"
out="${out:-$root/target/AgentACL-fleet-$version.pkg}"
url_re='^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$'
token=""
if [[ -n "$server" ]]; then
  [[ "$server" =~ $url_re ]] || { echo "--server must be an https:// URL" >&2; exit 2; }
  [[ -z "$proxy" || "$proxy" =~ ^https?://[A-Za-z0-9.:@-]+/?$ ]] || { echo "--proxy must be an http(s):// URL" >&2; exit 2; }
  read -r token
  [[ "$token" =~ ^aet_[0-9a-f]{64}$ ]] || { echo "expected an enrollment token (aet_…) on standard input" >&2; exit 2; }
fi

bin="${AGENTACL_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -q --release --locked -p agentacl-cli --manifest-path "$root/Cargo.toml"
  bin="$root/target/release/agentacl"
fi
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
# The payload is AgentACL's own folder only (installed at its location):
# never system folders, whose owner and modes the installer would reset.
# The LaunchDaemon plist goes in with the install scripts.
install -d -m 755 "$stage/root/bin" "$stage/scripts"
install -m 755 "$bin" "$stage/root/bin/agentacl"
# The hardened runtime: no injected libraries or debugger from the user,
# whose sessions the Endpoint Security daemon trusts this binary to start.
ts=()
[[ "$app_sign" != "-" ]] && ts=(--timestamp)
codesign --force --options runtime ${ts[@]+"${ts[@]}"} --sign "$app_sign" "$stage/root/bin/agentacl"
install -m 755 "$root/packaging/macos/fleet/scripts/preinstall" "$root/packaging/macos/fleet/scripts/postinstall" "$stage/scripts/"
install -m 644 "$root/packaging/macos/fleet/ai.agentacl.fleet.plist" "$stage/scripts/"
if [[ -n "$server" ]]; then
  umask 077
  if [[ -n "$proxy" ]]; then
    printf '{"server":"%s","token":"%s","proxy":"%s"}\n' "$server" "$token" "$proxy" >"$stage/root/enroll.json"
  else
    printf '{"server":"%s","token":"%s"}\n' "$server" "$token" >"$stage/root/enroll.json"
  fi
  chmod 600 "$stage/root/enroll.json"
fi
# No extended attributes where they can be removed (macOS keeps
# com.apple.provenance; the installer restores it as an attribute, not as
# files).
xattr -cr "$stage/root" 2>/dev/null || true
export COPYFILE_DISABLE=1
pkgbuild --quiet --root "$stage/root" --scripts "$stage/scripts" --identifier ai.agentacl.fleet \
  --version "$version" --ownership recommended --install-location "/Library/Application Support/AgentACL" "$stage/agentacl.pkg"
if [[ -n "$sign" ]]; then
  productbuild --quiet --package "$stage/agentacl.pkg" --sign "$sign" "$out"
else
  productbuild --quiet --package "$stage/agentacl.pkg" "$out"
fi
echo "Built $out${server:+ (enrolls with $server)}"
