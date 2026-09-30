#!/usr/bin/env bash
# Without AgentACL: an agent runs as you, so it reads whatever you can read.
source "$(dirname "$0")/_lib.sh"
need_setup
title "Without AgentACL: the agent runs as you"
dim "(all secrets here are FAKE demo fixtures)"
show "cat .env"
show "cat $FAKE_HOME/.aws/credentials"
show "python3 read.py $FAKE_HOME/.ssh/id_ed25519"
