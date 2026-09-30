# Changelog

All notable changes to AgentACL. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release workflow publishes the
section whose heading matches the tag, so every release needs one.

## [Unreleased]

## [0.1.0] - 2026-09-29

### Added
- `agentacl run`: supervises Claude Code, Codex, Gemini CLI, Copilot CLI and
  OpenCode under a macOS Seatbelt sandbox compiled from YAML policy
  (explicit deny wins), with built-in secret protection, a network proxy with
  two-phase host/address checks, secret-env stripping and exact kernel-denial
  attribution.
- `discover`, `agents`, `status`, `policy check`, `policy trust`, `events`,
  `restart` and `stop`.
- `agentacl ui`: a local console (127.0.0.1 only) with machine-wide agent
  discovery, projects, an access graph, a rules editor with reviewed saves and
  restart of affected sessions, built-in protection switches, access tests and
  a paginated audit log.
- SQLite audit log with JSON output.
