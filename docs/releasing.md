# Releasing AgentACL

Releases are cut by pushing an annotated tag on `main`. Every step after the
tag push is automated and gated. If any check fails, nothing is published.

## 1. Prepare (on `main`)

1. Pick the version (SemVer): breaking policy or CLI changes bump MAJOR (MINOR
   while < 1.0), features bump MINOR, fixes bump PATCH.
2. Set it in both places:
   - `Cargo.toml` → `[workspace.package] version`
   - `crates/agentacl-cli/web/package.json` → `"version"`

   Then run `cargo build` (updates `Cargo.lock`) and `npm install` in
   `crates/agentacl-cli/web` (updates `package-lock.json`).
3. In `CHANGELOG.md`, move **Unreleased** entries under
   `## [X.Y.Z] - YYYY-MM-DD`, and leave an empty `## [Unreleased]` above it.
4. Run `scripts/check.sh`. It must end with "All checks passed".
5. Commit as yourself: `git commit -m "Release vX.Y.Z"`. Push, and wait for
   CI to be green on `main`.

## 2. Tag

```sh
git tag -a vX.Y.Z -m "AgentACL vX.Y.Z"
git push origin vX.Y.Z
```

Pre-releases use `vX.Y.Z-rc.N` (or `-alpha.N`, `-beta.N`) and are marked as
pre-releases on GitHub. To rehearse without publishing, run the **Release**
workflow manually with `dry_run` checked.

## 3. What the Release workflow checks and does

| Stage | Gate |
|---|---|
| Preflight | Tag is `vX.Y.Z[-pre.N]`; tag, `Cargo.toml` and `package.json` versions agree; the tagged commit is on `main`; the tag is annotated and created by Chaitanya Sistla; `CHANGELOG.md` has a dated section for the version; every commit in history passes the authorship check (no AI or bot attribution) |
| Full CI | Everything in `ci.yml`: authorship, repo hygiene, `rustfmt`, `clippy -D warnings`, `rustdoc -D warnings`, tests on two macOS versions, the Intel build, the minimum supported Rust, the console typecheck and build with committed-output check, `npm audit`, `cargo-deny` (advisories, licenses, bans, sources), `shellcheck`, `actionlint` |
| Build | `--release --locked` for `aarch64-apple-darwin` and `x86_64-apple-darwin` (macOS 13+), with architecture and version checks |
| Package | Universal binary (`lipo`). Code signing and notarization when the signing secrets exist (ad-hoc signature otherwise). Smoke tests of the packaged binary (`--version`, `status`, `discover`, secret denials, a `run --dry-run`). Archives for universal, arm64 and x86_64. `SHA256SUMS`, verified. A GitHub build-provenance attestation |
| Publish | GitHub release named `AgentACL vX.Y.Z`, notes taken from the changelog section, archives and `SHA256SUMS` attached |

## 4. Optional: Developer ID signing

Add these repository secrets to ship signed and notarized binaries:

| Secret | Value |
|---|---|
| `MACOS_CERT_P12` | base64 of the Developer ID Application `.p12` |
| `MACOS_CERT_PASSWORD` | its password |
| `MACOS_SIGN_IDENTITY` | e.g. `Developer ID Application: Chaitanya Sistla (TEAMID)` |
| `NOTARY_APPLE_ID`, `NOTARY_TEAM_ID`, `NOTARY_PASSWORD` | Apple ID, team id and an app-specific password, for `notarytool` |

## 5. Authorship

`scripts/check-authorship.sh` has two modes.

- **Contributor mode** runs in CI and in release preflight. Anyone may author
  a commit, but it rejects:
  - commits authored or committed by bots or AI tools;
  - `Co-authored-by` trailers that credit an AI tool;
  - "Generated with ..." lines.

  CI applies the same check to the pull request description.
- **Maintainer mode** runs in the local hooks (`git config core.hooksPath
  .githooks`) and in `scripts/check.sh`. In addition:
  - the maintainer's own commits must be authored by Chaitanya Sistla;
  - they carry no co-author trailers.

Only the maintainer can create release tags (tag ruleset, and preflight
checks the tagger).
