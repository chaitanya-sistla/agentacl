#!/usr/bin/env bash
# Assembles target/AgentACL.app: the host app plus agentacl-esd as its
# Endpoint Security system extension.
#
#   SIGN_IDENTITY="Developer ID Application: …" TEAM_ID=… scripts/es/build-app.sh
#
# Default identity "-" (ad hoc): such an app activates its extension only on a
# development Mac (SIP off, `systemextensionsctl developer on`). Production
# needs Developer ID, Apple-provisioned entitlements in provisioning profiles,
# and notarization (docs/design/endpoint-security.md).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
pkg="$root/packaging/macos"
id="${SIGN_IDENTITY:--}"
# Endpoint Security extensions name a Mach service prefixed with the team id.
team="${TEAM_ID:-AGENTACLDEV}"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)"
app="$root/target/AgentACL.app"
ext="$app/Contents/Library/SystemExtensions/ai.agentacl.app.esd.systemextension"

cargo build --release --locked -p agentacl-es --manifest-path "$root/Cargo.toml"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$ext/Contents/MacOS"
swiftc -O -framework SystemExtensions "$pkg/app/main.swift" -o "$app/Contents/MacOS/AgentACL"
sed "s/VERSION/$version/" "$pkg/app/Info.plist" > "$app/Contents/Info.plist"
sed -e "s/VERSION/$version/" -e "s/TEAMID/$team/" "$pkg/app/extension-Info.plist" > "$ext/Contents/Info.plist"
cp "$root/target/release/agentacl-esd" "$ext/Contents/MacOS/ai.agentacl.app.esd"

# Inside out: the extension first, then the app around it.
codesign --force --options runtime --sign "$id" --entitlements "$pkg/es/agentacl-esd.entitlements" "$ext"
codesign --force --options runtime --sign "$id" --entitlements "$pkg/app/app.entitlements" "$app"
codesign --verify --deep --strict "$app"
echo "Built $app (signed: $id)"
