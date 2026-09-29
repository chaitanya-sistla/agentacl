#!/bin/sh
# Regenerates crates/agentfence-cli/src/ui/assets/app.css from tailwind.css
# using the Tailwind v4 standalone CLI (no Node). The output is committed and
# embedded in the binary, so the UI never loads anything from the network.
#
#   TAILWIND=/path/to/tailwindcss scripts/build-ui-css.sh
set -eu
TW=${TAILWIND:-$HOME/.cache/agentfence-dev/tailwindcss}
if [ ! -x "$TW" ]; then
  echo "Tailwind standalone CLI not found at $TW" >&2
  echo "Download: https://github.com/tailwindlabs/tailwindcss/releases (tailwindcss-macos-arm64)" >&2
  exit 1
fi
cd "$(dirname "$0")/../crates/agentfence-cli/src/ui/assets"
"$TW" -i tailwind.css -o app.css --minify
