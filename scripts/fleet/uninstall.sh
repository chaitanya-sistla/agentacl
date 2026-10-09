#!/usr/bin/env bash
# Removes the fleet package from this Mac: the service, its files, and its
# enrollment. The server shows the Mac as not reporting; revoke it there.
set -euo pipefail
R="/Library/Application Support/AgentACL"
sudo launchctl bootout system/ai.agentacl.fleet 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/ai.agentacl.fleet.plist
if [[ "$(readlink /usr/local/bin/agentacl 2>/dev/null)" == "$R/bin/agentacl" ]]; then
  sudo rm -f /usr/local/bin/agentacl
fi
sudo rm -rf "$R/bin" "$R/managed" "$R/tmp" "$R/fleet.json" "$R/fleet-state.json" "$R/enroll.json"
sudo pkgutil --forget ai.agentacl.fleet >/dev/null 2>&1 || true
echo "AgentACL's fleet service is removed."
