# Contributing

Thanks for helping improve AgentShield. Because this project influences security-sensitive decisions, predictable behavior and clear limitations matter more than adding features quickly.

## Local setup

- Use Node.js 20 or newer. CI covers Node.js 20, 22, and 24.
- Run `npm ci` to use the checked-in lockfile.
- Run `npm run check` before opening a pull request.

## Changes to policy behavior

- Add regression tests for both the intended decision and nearby edge cases.
- Keep decisions deterministic; optional AI explanations must never override rules.
- Default to review or denial when evaluation is ambiguous.
- Treat regex checks as heuristics; do not claim that a policy regex is guaranteed safe from catastrophic backtracking.
- Keep audit records minimal and ensure concurrent writer and stale-lock behavior are tested.
- Never log raw tool output, full environment variables, or real credentials.
- Update README and the threat model when a new integration changes the trust boundary.

## Pull requests

Describe the risk addressed, the behavior before/after, and commands/tests actually run. Mark checks that were not run. Keep the patch focused and avoid unrelated formatting changes.

## Reporting security issues

Do not publish real credentials or a working exploit against active systems in an issue. Follow the private reporting guidance in SECURITY.md.
