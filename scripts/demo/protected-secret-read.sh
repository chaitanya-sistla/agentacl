#!/usr/bin/env bash
# With AgentACL: the same reads, refused by the macOS kernel sandbox.
source "$(dirname "$0")/_lib.sh"
need_setup
title "With AgentACL: the operating system refuses"
show "agentacl run -- cat .env"
show "agentacl run -- cat $FAKE_HOME/.aws/credentials"
show "agentacl run -- cat README.md"
dim "The project stays readable; secrets don't."
