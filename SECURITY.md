# Security policy

AgentACL is a security boundary around AI coding agents, so we take reports
seriously and respond quickly.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/chaitanya-sistla/agentacl/security/advisories/new).

Include:
- what an agent (or a web page, or another local user) can do that it
  shouldn't, and what it gains;
- steps or a proof of concept, using test files, never real secrets;
- the AgentACL version (`agentacl --version`) and macOS version.

You'll get an acknowledgement within 3 working days and a status update at
least weekly until it's resolved. Fixes ship in a patch release with credit to
you in the release notes, unless you'd rather stay anonymous.

## In scope

- An agent run with `agentacl run` reading or writing something its policy
  denies, reaching a site it shouldn't, or escaping the sandbox.
- An agent changing its own rules, approving its own requests, or influencing
  the console.
- The console (`agentacl ui`) being driven by a web page or another local user.
- AgentACL reporting something as blocked when it wasn't (or the reverse).

## Known limitations (not vulnerabilities)

These are documented in the [guide](docs/guide.md) and
[threat model](docs/threat-model.md):
- argument-level process rules (e.g. `git push *`) are observed, not
  enforced;
- agents not started with `agentacl run` are observed only;
- the Seatbelt profile is fixed when an agent starts.

## Supported versions

Security fixes go into the latest release.
