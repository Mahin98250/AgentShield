# Threat model (initial draft)

## Goal

Reduce accidental high-impact actions made by supported AI coding-agent tools by applying a local, understandable ruleset before the tool executes.

## Assets

- Repository source and history.
- Local credentials and key files, including .env, SSH keys, and private-key files.
- Developer workstation and reachable services.
- Audit metadata about commands and developer activity.

## Addressed in this milestone

- A command contains a known destructive pattern.
- A command downloads and pipes a script into a shell.
- A command resembles a credential assignment and might leak into logs.
- A supported Claude Code Write or Edit tool targets a configured protected path.
- An unfamiliar command or shell substitution requires an explicit user prompt.
- Malformed policy must not be silently accepted.
- Common catastrophic-backtracking regex patterns are rejected by conservative static heuristics.
- Malformed Claude Code hook envelopes produce a deny decision rather than silently passing through.
- Policy initialization refuses symlinked policy targets and symlinked `.agentshield` directories.

## Out of scope / not guaranteed

- Full shell-language parsing or semantic understanding.
- Protection from a user intentionally bypassing or deleting hooks.
- Actions launched from another terminal, editor, agent, shell, scheduled job, or process not covered by the configured hook.
- OS-level filesystem/network isolation, sandboxing, process-tree mediation, or protection against a compromised host.
- Complete secret detection; redaction is best-effort and pattern-based.
- Security of a policy modified by an untrusted actor.

## Trust boundaries

1. Agent to hook: stdin is size-limited and JSON-validated.
2. Policy to engine: structure, rule count, regex length, IDs, regex compilation, and several common ReDoS shapes are checked. Static regex heuristics are not a proof of bounded execution time; only trusted policy files should be loaded.
3. Engine to audit log: only fixed generic decision metadata is recorded. The writer uses a cooperating-process lock, a projected size limit, restrictive permissions, no-follow flags where supported, and file identity checks. A crashed writer can leave a stale lock that requires manual recovery.
4. Browser to viewer: loopback-bound, read-only routes, Host/origin checks, escaped log text, and CSP that blocks client-side scripts.
5. Hook to agent: Claude Code receives a documented PreToolUse decision. The integration intentionally does not return allow, preserving normal permission checks.

## Recommendations

- Run agents with least privilege and keep secrets out of untrusted execution contexts.
- Test safe and blocked cases before enabling the hook.
- Protect .claude/settings.json, .agentshield/policy.yml, and the AgentShield executable from untrusted edits.
- Use OS/container isolation for high-risk work. Do not treat this tool as a sandbox.
- Review rules whenever the agent tool schema or threat model changes.

Residual risks: regex heuristics can miss expensive patterns; filesystem race defenses depend on OS semantics; stale lock files can deny audit writes; lexical protected-path matching cannot resolve filesystem aliases or symlinks; and unsupported tools or bypassed hooks are outside the enforcement boundary. This is an engineering threat model, not a formal audit or security certification.