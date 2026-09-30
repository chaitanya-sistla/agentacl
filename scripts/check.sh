#!/usr/bin/env bash
# Every check CI runs, locally, in the same order. Run before pushing:
#   scripts/check.sh          # everything
#   scripts/check.sh --quick  # skip the slow end-to-end sandbox tests
set -euo pipefail
cd "$(dirname "$0")/.."

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "Authorship (commits not yet on origin/main)"
base=$(git merge-base HEAD origin/main 2>/dev/null || true)
if [[ -n "$base" ]]; then scripts/check-authorship.sh --maintainer "$base..HEAD"; else scripts/check-authorship.sh --maintainer --all; fi

step "No leftover old product name"
if git grep -nIi 'agentfence' -- . ':!.gitignore' ':!CHANGELOG.md' ':!scripts/check.sh' ':!.github/workflows/ci.yml'; then
  echo "found 'agentfence' above; the product is AgentACL" >&2
  exit 1
fi

step "Spelling (typos), if installed"
if command -v typos >/dev/null; then typos; else echo "brew install typos-cli  # to run this check"; fi

step "Formatting"
cargo fmt --all --check

step "Clippy (warnings are errors)"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "Docs (warnings are errors)"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked -q

step "Tests"
if [[ $quick -eq 1 ]]; then
  cargo test --workspace --locked --lib --bins
else
  cargo test --workspace --locked
fi

step "Minimum supported Rust ($(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml))"
msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
if rustup toolchain list | grep -q "^$msrv"; then
  cargo "+$msrv" check --workspace --all-targets --locked -q
else
  echo "rustup toolchain install $msrv --profile minimal  # to run this check"
fi

step "Console: typecheck, build, and the committed build is current"
(cd crates/agentacl-cli/web && npm ci --no-audit --no-fund && npm run build)
git diff --exit-code --stat -- crates/agentacl-cli/src/ui/dist || {
  echo "src/ui/dist is stale: commit the rebuilt console" >&2
  exit 1
}

step "Dependency policy (cargo-deny), if installed"
if command -v cargo-deny >/dev/null; then cargo deny check; else echo "cargo install cargo-deny --locked  # to run this check"; fi

printf '\n\033[1;32mAll checks passed.\033[0m\n'
