# AgentShield

A local-first safety layer for AI coding agents. AgentShield checks commands and protected-file operations against explicit rules before a supported agent tool runs. Decisions are deterministic and local; no paid model API, hosted service, or telemetry is required.

> Early development: AgentShield is not a sandbox. Text rules cannot fully parse every shell form, and a hook can only protect actions that pass through it. Use OS/container isolation appropriate to the risk.

## Included in this first milestone

- TypeScript CLI with a YAML policy format and strict validation.
- Conservative command rules: destructive patterns block; unfamiliar commands ask for approval.
- Claude Code PreToolUse adapter for Bash, PowerShell, Write, and Edit.
- Protected-path checks for file writes/edits covered by the hook.
- Local JSONL activity log, basic secret redaction, and a loopback-only read-only viewer.
- Regression tests, security notes, and GitHub Actions CI.

## Requirements and quick start

Requires Node.js 20+ and npm.

    npm install
    npm run check
    node dist/cli.js init
    node dist/cli.js check --command "npm test"
    node dist/cli.js log
    node dist/cli.js viewer

The init command creates .agentshield/policy.yml. The check command is advisory and does not execute a command.

## Claude Code integration

Build AgentShield, create a local policy, and copy examples/claude-settings.json into .claude/settings.json (or merge its hooks section into your existing settings). The example expects AgentShield to be checked out at the root of the protected project.

- A block or evaluation error returns an explicit Claude Code deny decision.
- An approval-required decision returns ask, so Claude Code requests human confirmation.
- An allow decision adds no hook decision; Claude Code's normal permission flow still applies.
- Writes/edits to configured protected paths are denied. Other edits continue under Claude Code's own permission controls.

Test with safe and deliberately blocked commands before relying on it. Claude Code hook schemas can change; see the [official Hooks reference](https://code.claude.com/docs/en/hooks).

## Policy

See rules/default.yml for the starter policy. The active policy file defaults to .agentshield/policy.yml and uses version, defaults, protected_paths, dangerous_patterns, and secret_patterns. Each rule needs a unique ID, a JavaScript regular expression, a human-readable reason, and an action of block or approve. Unknown commands require approval by default.

The policy parser intentionally supports a conservative YAML subset and rejects unsupported or malformed input rather than silently guessing. Patterns are evaluated case-insensitively against command text. Review regex rules carefully: they are not a shell parser.

## Commands

- init [--force] — create or replace the starter policy.
- check --command "npm test" [--policy path] — evaluate a command and record a decision.
- hook [--policy path] — generic stdin/stdout adapter accepting a JSON command field.
- claude-hook [--policy path] — Claude Code PreToolUse JSON protocol.
- log [--limit 50] — show recent decisions.
- viewer [--port 4173] — serve the activity viewer on 127.0.0.1 only.

## Privacy and limits

The CLI makes no network requests and collects no analytics. Audit events contain a short redacted command summary, decision, reason, timestamp, and optional rule ID; raw command output is not captured. Redaction is best-effort and cannot guarantee all credentials are removed. The viewer is read-only, loopback-bound, escapes log text, and disables script execution with a Content Security Policy.

AgentShield does not provide sandboxing, network controls, OS-level filesystem authorization, full shell parsing, process-tree mediation, or protection from someone intentionally bypassing the hook. Protected-file checks apply only to supported tools/events the hook receives. Do not use this as the only protection for production credentials or untrusted code.

## Development and security

Run npm run check for the build and automated tests. See docs/THREAT_MODEL.md for the initial threat model and SECURITY.md for vulnerability reporting. This is an engineering baseline, not a formal security audit or certification.

## Roadmap

- [x] Rule engine and strict policy validation
- [x] Initial Claude Code hook adapter
- [x] Local audit log and activity viewer
- [x] Tests, CI, and initial threat model
- [ ] Expand cross-platform and adversarial shell-bypass testing
- [ ] Review Windows and UNC protected-path edge cases
- [ ] Approval receipts/identity binding and release automation
- [ ] Optional local Ollama explanations (advisory only)

MIT License. See LICENSE.