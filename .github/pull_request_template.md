## What and why

<!-- What does this change, and what problem does it solve? Link the issue: Fixes #123 -->

## How it was tested

<!-- Commands you ran, and for enforcement changes, the sandbox test you added. -->

## Checklist
- [ ] `scripts/check.sh` passes locally (format, clippy, tests, console build, spelling)
- [ ] Tests added or updated
- [ ] Docs updated (`docs/`, `README.md`) where behaviour changed
- [ ] `CHANGELOG.md` has a line under **Unreleased**
- [ ] Console changes: rebuilt with `npm run build` in `crates/agentacl-cli/web` and the new `src/ui/dist` committed
- [ ] Security-relevant: no access is widened implicitly; `docs/threat-model.md` reviewed
- [ ] Commits and this description don't credit an AI tool (no `Co-authored-by` for tools, no "Generated with ...")
