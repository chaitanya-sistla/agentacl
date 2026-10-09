#!/usr/bin/env bash
# Stops and removes the agentacl-esd LaunchDaemon (development installs).
set -euo pipefail
sudo launchctl bootout system/ai.agentacl.esd 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/ai.agentacl.esd.plist /Library/PrivilegedHelperTools/agentacl-esd
sudo rm -f "/Library/Application Support/AgentACL/esd.json"
echo "agentacl-esd removed. Remove it from Full Disk Access in System Settings too."
