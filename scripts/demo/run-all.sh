#!/usr/bin/env bash
# The whole demo, in recording order.
set -euo pipefail
d="$(dirname "$0")"
"$d/setup-demo.sh"
"$d/unprotected-secret-read.sh"
"$d/protected-secret-read.sh"
"$d/child-process-read.sh"
"$d/protected-file-write.sh"
"$d/network-deny.sh"
