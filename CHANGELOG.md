# Changelog

## Unreleased

- Harden audit writes with cooperating-process locking, projected size checks, and symlink/special-file checks.
- Minimize audit records and sanitize custom policy reasons at engine and hook output boundaries.
- Reject common high-risk regex shapes, bound policy lists, and fail closed on malformed Claude Code hook envelopes.
- Protect policy initialization from symlink targets and harden the local viewer against cross-origin requests.
- Extend CI to Node.js 24, enable stricter TypeScript checks, and add weekly Dependabot updates.
- Add security operations guidance for hook validation, incident response, and audit-lock recovery.

- Add a branded local activity dashboard with decision counts.
- Check protected file reads and protect AgentShield/Claude Code settings from hook-mediated edits.
- Expand destructive command matching and fail-closed Claude Code hook configuration.
- Add a short usage guide and integration branding.


User-visible changes are recorded here. This project is early-stage; version 0.x is not a production security certification.

## 0.1.0 — Initial engineering milestone

- Add a local TypeScript/Node.js policy CLI.
- Add strict parsing for the documented YAML policy subset.
- Add conservative command decisions with human-review fallback.
- Add initial Claude Code PreToolUse support for shell and file-write tools.
- Add protected-path checks, best-effort command redaction, JSONL audit events, and a loopback-only viewer.
- Add regression tests, GitHub Actions CI, a threat model, security guidance, and contribution templates.
