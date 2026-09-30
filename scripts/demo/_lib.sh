#!/usr/bin/env bash
# Shared helpers for the AgentACL demo scripts. Sourced, not run.
#
# Safety:
# - Every demo file lives under $DEMO_DIR (default /tmp/agentacl-demo), which
#   must be yours and contain no symlinks.
# - Every secret is generated, says FAKE, and is checked before it is shown.
# - The scripts never read your real secrets.
# - `agentacl` runs with a minimal environment (so your environment variable
#   names never appear in a recording) and with its own demo config and state
#   (AGENTACL_CONFIG_DIR / AGENTACL_HOME), so your real policy and audit log are
#   untouched.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/agentacl-demo}"
# Refuse anything but a dedicated directory directly under /tmp, matched as a
# literal (no "..", no symlink tricks): cleanup runs rm -rf on it.
if [[ ! "$DEMO_DIR" =~ ^/(private/)?tmp/agentacl-demo[A-Za-z0-9_-]*$ ]]; then
  echo "refusing: DEMO_DIR must be /tmp/agentacl-demo[-name] (got $DEMO_DIR)" >&2
  exit 2
fi
# An existing demo dir must be ours and free of symlinks (anyone can create
# names in /tmp; a symlinked fixture could point at a real secret).
check_demo_dir() {
  [[ -e "$DEMO_DIR" || -L "$DEMO_DIR" ]] || return 0
  if [[ -L "$DEMO_DIR" || ! -O "$DEMO_DIR" ]]; then
    echo "refusing: $DEMO_DIR is a symlink or not owned by you" >&2
    exit 2
  fi
  if [[ -n "$(find "$DEMO_DIR" -type l -print -quit)" ]]; then
    echo "refusing: $DEMO_DIR contains symlinks; run cleanup-demo.sh" >&2
    exit 2
  fi
}
check_demo_dir

PROJECT="$DEMO_DIR/project"
# shellcheck disable=SC2034  # used by the scripts that source this file
FAKE_HOME="$DEMO_DIR/fake-home"
export AGENTACL_CONFIG_DIR="$DEMO_DIR/config"
export AGENTACL_HOME="$DEMO_DIR/state"
AGENTACL_BIN_PATH="$(command -v "${AGENTACL_BIN:-agentacl}" || true)"
# Absolute, because the demo steps run from inside the demo project.
if [[ -n "$AGENTACL_BIN_PATH" && "$AGENTACL_BIN_PATH" != /* ]]; then
  AGENTACL_BIN_PATH="$(cd "$(dirname "$AGENTACL_BIN_PATH")" && pwd)/$(basename "$AGENTACL_BIN_PATH")"
fi

# `agentacl` as the demo runs it: minimal environment, demo config and state.
agentacl() {
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$HOME" USER="${USER:-demo}" TERM="${TERM:-xterm-256color}" \
    AGENTACL_CONFIG_DIR="$AGENTACL_CONFIG_DIR" AGENTACL_HOME="$AGENTACL_HOME" "$AGENTACL_BIN_PATH" "$@"
}
export -f agentacl
export AGENTACL_BIN_PATH
# Seconds to wait between steps (set DEMO_PAUSE=0 for a fast run).
DEMO_PAUSE="${DEMO_PAUSE:-1.2}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim() { printf '\033[2m%s\033[0m\n' "$*"; }
title() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
pause() { sleep "$DEMO_PAUSE"; }

# Prints a command like a prompt, then runs it (output shown; failure allowed).
show() {
  printf '\033[1;32m$\033[0m %s\n' "$*"
  pause
  (cd "$PROJECT" && bash -c "$*") || true
  pause
}

need_setup() {
  if [[ ! -f "$PROJECT/.env" || ! -f "$AGENTACL_CONFIG_DIR/policy.yaml" ]]; then
    echo "Run scripts/demo/setup-demo.sh first." >&2
    exit 1
  fi
  if [[ -z "$AGENTACL_BIN_PATH" ]]; then
    echo "agentacl not found on PATH (or set AGENTACL_BIN)." >&2
    exit 1
  fi
  # Every fixture must be a regular file we created, and fake.
  for f in "$PROJECT/.env" "$FAKE_HOME/.aws/credentials" "$FAKE_HOME/.ssh/id_ed25519"; do
    if [[ -L "$f" || ! -f "$f" || ! -O "$f" ]] || ! grep -q FAKE "$f"; then
      echo "refusing: $f is not the demo's fake fixture; re-run setup-demo.sh" >&2
      exit 1
    fi
  done
}
