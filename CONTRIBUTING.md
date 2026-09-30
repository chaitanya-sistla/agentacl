# Contributing to AgentACL

Thanks for helping make AI coding agents safer to run. Bug reports, fixes,
docs and new ideas are all welcome.

## Ground rules

- **Open an issue first for anything non-trivial.** A short discussion saves
  you from building something that can't be merged. Use the issue templates.
- **Security problems go to [private advisories](https://github.com/chaitanya-sistla/agentacl/security/advisories/new)**,
  never public issues. See [SECURITY.md](SECURITY.md).
- **Never widen access implicitly.** AgentACL's rule: explicit deny wins,
  built-in protections always win, and anything the proxy or sandbox can't
  enforce is reported as observed, never as blocked. Changes must keep that
  true, and the [threat model](docs/threat-model.md) says why.
- **People author commits, not tools.** You may use any editor or assistant,
  but commits and pull requests must be authored by you. CI rejects commits
  authored by bots or AI tools, `Co-authored-by` trailers that credit an AI
  tool, and "Generated with ..." lines, in commits and in the pull request
  description.

## Development setup

Requirements: macOS 13 or later, Rust (the version in `rust-toolchain.toml` is
installed automatically by rustup), Node 22 for the console.

```sh
git clone https://github.com/<you>/agentacl && cd agentacl
cargo build
cargo test --workspace          # includes real sandbox tests; macOS only
cd crates/agentacl-cli/web && npm ci && npm run build   # the console
```

The console's build output (`crates/agentacl-cli/src/ui/dist`) is committed so
`cargo build` needs no Node. If you change anything in `web/src`, rebuild and
commit `dist` too; CI checks they match.

## Before you open a pull request

Run every check CI runs:

```sh
brew install typos-cli          # spell check (optional locally, required in CI)
scripts/check.sh
```

It covers formatting, clippy (warnings are errors), rustdoc, tests, the
minimum supported Rust (1.85), the console build, dependency policy
(`cargo-deny`) and spelling.

Then:

1. Branch from `main` (`fix/…`, `feat/…`, `docs/…`).
2. Keep the change focused; one pull request per concern.
3. Add or update tests. Enforcement changes need a test that runs the real
   sandbox (see `crates/agentacl-core/src/enforce/tests.rs`).
4. Update docs where behaviour changes, and add a line under **Unreleased**
   in [CHANGELOG.md](CHANGELOG.md).
5. Fill in the pull request template.

## Review and merge

- `main` is protected. Changes land by pull request, squash-merged, after a
  review from the maintainer (`CODEOWNERS`) and green CI, with all review
  conversations resolved.
- New commits after an approval dismiss it, so the approved code is the
  merged code.
- CI for first-time contributors runs after a maintainer approves it.

## Releases

Releases are cut by the maintainer from tags on `main`; see
[docs/releasing.md](docs/releasing.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
