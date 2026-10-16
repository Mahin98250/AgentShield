# Contributing

Thanks for helping improve AgentShield. Because this project influences security-sensitive decisions, predictable behavior and clear limitations matter more than adding features quickly.

## Local setup

- Use Node.js 20 or newer.
- Run `npm install`.
- Run `npm run check` before opening a pull request.

## Changes to policy behavior

- Add regression tests for both the intended decision and nearby edge cases.
- Keep decisions deterministic; optional AI explanations must never override rules.
- Default to review or denial when evaluation is ambiguous.
- Never log raw tool output, full environment variables, or real credentials.
- Update README and the threat model when a new integration changes the trust boundary.

## Pull requests

Describe the risk addressed, the behavior before/after, and commands/tests actually run. Mark checks that were not run. Keep the patch focused and avoid unrelated formatting changes.

## Reporting security issues

Do not publish real credentials or a working exploit against active systems in an issue. Follow the private reporting guidance in SECURITY.md.
