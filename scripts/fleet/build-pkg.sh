#!/usr/bin/env bash
# Builds an AgentACL package for a fleet (docs/fleet.md).
#
#   scripts/fleet/build-pkg.sh                               generic package
#   echo "$TOKEN" | scripts/fleet/build-pkg.sh --server URL  enrolls on install
#
# Options: --proxy URL (if the Macs need one), --sign "Developer ID Installer:
# …" (sign the package; then notarize it), --out FILE, and AGENTACL_BIN=path
# to package a prebuilt binary (e.g. the universal one from a release).
#
# A package built with --server contains the enrollment token: distribute it
# with device management only. Without --sign it is unsigned: it installs
# with `sudo installer -pkg` and tools that run installer (Jamf, Munki), not
# with the MDM InstallEnterpriseApplication command or by double-click from
# a download.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
server="" proxy="" sign="" out=""
while (($#)); do
  case "$1" in
    --server) server="$2"; shift 2 ;;
    --proxy) proxy="$2"; shift 2 ;;
    --sign) sign="$2"; shift 2 ;;
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
dest="$stage/root/Library/Application Support/AgentACL"
install -d -m 755 "$dest/bin" "$stage/root/Library/LaunchDaemons"
install -m 755 "$bin" "$dest/bin/agentacl"
install -m 644 "$root/packaging/macos/fleet/ai.agentacl.fleet.plist" "$stage/root/Library/LaunchDaemons/"
if [[ -n "$server" ]]; then
  umask 077
  if [[ -n "$proxy" ]]; then
    printf '{"server":"%s","token":"%s","proxy":"%s"}\n' "$server" "$token" "$proxy" >"$dest/enroll.json"
  else
    printf '{"server":"%s","token":"%s"}\n' "$server" "$token" >"$dest/enroll.json"
  fi
  chmod 600 "$dest/enroll.json"
fi
# No extended attributes (they become "._" files in the payload).
xattr -cr "$stage/root"
export COPYFILE_DISABLE=1
pkgbuild --quiet --root "$stage/root" --scripts "$root/packaging/macos/fleet/scripts" --identifier ai.agentacl.fleet \
  --version "$version" --ownership recommended --install-location / "$stage/agentacl.pkg"
if [[ -n "$sign" ]]; then
  productbuild --quiet --package "$stage/agentacl.pkg" --sign "$sign" "$out"
else
  productbuild --quiet --package "$stage/agentacl.pkg" "$out"
fi
echo "Built $out${server:+ (enrolls with $server)}"
