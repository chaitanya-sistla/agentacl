#!/usr/bin/env bash
# Opens the console on the demo's own state (to show what was blocked).
source "$(dirname "$0")/_lib.sh"
need_setup
exec env AGENTACL_CONFIG_DIR="$AGENTACL_CONFIG_DIR" AGENTACL_HOME="$AGENTACL_HOME" "$AGENTACL_BIN_PATH" ui
