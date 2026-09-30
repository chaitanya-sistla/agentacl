#!/usr/bin/env bash
# Network: only sites the policy allows (the demo policy allows example.com).
source "$(dirname "$0")/_lib.sh"
need_setup
title "Network: allowed sites only"
if ! curl -sS -m 5 -o /dev/null https://example.com 2>/dev/null; then
  echo "SKIPPED: no internet access (this demo needs https://example.com)."
  exit 0
fi
show "agentacl run -- curl -sS -m 10 -o /dev/null -w 'example.com: HTTP %{http_code}\n' https://example.com"
show "agentacl run -- curl -sS -m 10 -o /dev/null https://example.org"
show "agentacl run -- python3 -c \"import urllib.request; urllib.request.urlopen('https://example.org', timeout=10)\" 2>&1 | grep -m1 '^urllib.error'"
# A tool that ignores the proxy and opens a raw socket: refused by the kernel.
show "agentacl run -- /usr/bin/nc -z -w 3 1.1.1.1 443"
