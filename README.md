<p align="center">
  <img src="docs/assets/agentshield-mark.svg" alt="AgentShield shield mark" width="82">
</p>

<h1 align="center">AgentShield</h1>

<p align="center">A local-first safety layer for AI coding agents.</p>

<p align="center">
  <a href="https://github.com/Mahin98250/AgentShield/actions/workflows/ci.yml"><img src="https://github.com/Mahin98250/AgentShield/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <img src="https://img.shields.io/badge/Node.js-20%2B-417e38" alt="Node.js 20 or newer">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

<p align="center">
  <a href="https://claude.com/product/claude-code"><img src="docs/assets/claude-code-mark.svg" alt="Claude Code integration" height="40"></a>
</p>

AgentShield checks commands and protected-file operations against explicit rules before a supported agent tool runs. Decisions are deterministic and local; no paid model API, hosted service, or telemetry is required.

> Early development: AgentShield is not a sandbox. Text rules cannot fully parse every shell form, and a hook can only protect actions that pass through it. Use OS/container isolation appropriate to the risk.

## Included in this first milestone

- TypeScript CLI with a YAML policy format and strict validation.
- Conservative command rules: known destructive patterns block; compound shell operators, redirection, substitutions, and unfamiliar commands ask for approval.
- Claude Code PreToolUse adapter for Bash, PowerShell, Write, Edit, and Read.
- Protected-path checks for secret files, policy files, and Claude Code settings covered by the hook.
- Local JSONL decision log with bounded reads, minimal recorded data, and a loopback-only read-only viewer.
- Regression tests, security notes, and GitHub Actions CI.

## Requirements and quick start

Requires Node.js 20+ and npm.

    npm ci
    npm run check
    node dist/cli.js init
    node dist/cli.js check --command "npm test"
    node dist/cli.js log
    node dist/cli.js viewer

The init command creates .agentshield/policy.yml. The check command is advisory and does not execute a command.

## Claude Code integration

<p align="left"><a href="https://claude.com/product/claude-code"><img src="docs/assets/claude-code-mark.svg" alt="Claude Code" height="38"></a></p>

Build AgentShield, then choose a configuration example. Use examples/claude-settings.json if AgentShield is in the same repository. If you keep it in a separate folder, use examples/claude-settings.external.json and replace its placeholder with the absolute path to AgentShield/dist/cli.js. Merge the hooks section into the target project's existing .claude/settings.json—do not replace the whole file. Run AgentShield init from the target project to create its local .agentshield/policy.yml.

- A block decision returns deny and stops the tool call.
- A command needing review returns ask, which brings back the normal confirmation prompt.
- For an ordinary command, AgentShield stays quiet; Claude Code's usual permission checks still apply.
- The hook checks Bash/PowerShell commands and Read/Write/Edit paths. Configured protected files, AgentShield policy files, and Claude Code settings are blocked.
- onFailure: block tells Claude Code to stop the action if the hook fails or times out.

See the [Claude Code hooks documentation](https://code.claude.com/docs/en/hooks) for current settings. Claude Code is a product of Anthropic; AgentShield is independent and is not affiliated with Anthropic.

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

## Can I use it in a web browser?

AgentShield is a local CLI, not a hosted web app or browser extension. Its activity viewer opens in your browser at http://127.0.0.1:4173 and reads the audit log stored on your own computer. It does not run inside GitHub.com and cannot protect commands from a remote coding agent unless those commands pass through the configured local hook.

## Privacy and limits

The CLI makes no network requests and collects no analytics. Audit events deliberately record only the decision, a normalized timestamp, and fixed generic text; raw commands, dynamic policy reasons, and rule IDs are omitted to reduce accidental disclosure. Redaction elsewhere is best-effort only: it cannot guarantee detection of every unusual, encoded, multiline, or embedded credential. Do not put secrets in command arguments or policy messages, and do not treat sanitized summaries as a secrecy boundary. Audit logs are limited to 10 MiB, and a write is rejected when the projected size would exceed that limit. Audit reads and writes validate regular-file targets, use no-follow open flags where supported, and compare the opened handle with the path entry to reduce symlink/replacement races; these checks still depend on platform and filesystem semantics and are not an OS-level isolation boundary. Archive the file before continuing if the limit is reached. The viewer is read-only, loopback-bound, escapes log text, and disables script execution with a Content Security Policy.

AgentShield does not provide sandboxing, network controls, OS-level filesystem authorization, full shell parsing, process-tree mediation, or protection from someone intentionally bypassing the hook. Protected-file checks apply only to supported tools/events the hook receives. Do not use this as the only protection for production credentials or untrusted code.

## Development and security

Run npm run check for the build and automated tests; CI also runs npm pack --dry-run to inspect the package contents. See docs/USAGE.md for a short walkthrough, docs/THREAT_MODEL.md for the initial threat model, CONTRIBUTING.md for the contributor workflow, CHANGELOG.md for release notes, and SECURITY.md for vulnerability reporting. This is an engineering baseline, not a formal security audit or certification.

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