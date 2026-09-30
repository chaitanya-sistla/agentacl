#!/usr/bin/env bash
# Removes the demo directory (and nothing else).
source "$(dirname "$0")/_lib.sh"
rm -rf "$DEMO_DIR"
echo "Removed $DEMO_DIR"
