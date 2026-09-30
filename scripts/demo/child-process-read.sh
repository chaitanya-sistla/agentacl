#!/usr/bin/env bash
# The boundary is inherited: shells, nested shells, Python and its subprocesses.
source "$(dirname "$0")/_lib.sh"
need_setup
title "Child processes inherit the boundary"
show "agentacl run -- bash -c 'sh -c \"cat .env\"'"
show "agentacl run -- python3 read.py $FAKE_HOME/.aws/credentials"
show "agentacl run -- python3 -c \"import subprocess; subprocess.run(['cat', '.env'])\""
