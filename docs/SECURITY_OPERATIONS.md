# Security operations

This runbook is for developers maintaining or adopting AgentShield. It complements the [threat model](THREAT_MODEL.md); it does not turn AgentShield into a sandbox.

## Before enabling the hook

1. Use a supported Node.js version (20, 22, or 24 in CI) and install reproducibly with `npm ci`.
2. Run `npm run check`.
3. Generate a starter policy with `node dist/cli.js init`, then read every rule before enabling the hook.
4. Merge the relevant example from `examples/` into the project's existing Claude Code settings; do not overwrite unrelated settings.
5. Use Claude Code v2.1.295 or newer for the example's `onFailure: "block"` setting.
6. Test a known safe command, a known blocked command, an unfamiliar command that should ask for approval, and a protected-file read/write.
7. Confirm the hook is actually running in the environment where the agent runs. Hooks do not protect other shells, tools, processes, or remote sessions unless those actions pass through the hook.

## Audit log behavior

Audit records intentionally omit raw commands, custom reasons, and rule IDs. That reduces accidental disclosure but also limits forensic detail. The writer enforces a 10 MiB cap and serializes cooperating AgentShield writers with an exclusive lock.

If a writer is killed while holding the lock, a sibling file ending in `.lock` can remain and audit writes will fail closed. Before removing it:

1. Stop active AgentShield/Claude Code sessions that may be writing the log.
2. Inspect the lock file's PID text if present and check whether that process is still an AgentShield writer.
3. Remove only the stale lock file, not the audit log or policy.
4. Retry the operation and confirm that a new audit event is written.

Do not delete a lock merely because it is old. PID reuse and platform differences mean the file is only a recovery hint, not a perfect ownership proof. If uncertain, stop all relevant writers first.

## Policy change review

- Prefer short, simple regexes. The parser rejects some common high-risk regex shapes, but static checks cannot prove a regex has bounded execution time.
- Add a regression test for every policy change, including a near-miss that should not trigger.
- Keep unknown commands at `approve` or stricter unless a reviewed threat model justifies otherwise.
- Treat path patterns as lexical checks, not OS-level access control. Review Windows drive, UNC, symlink, and path-alias cases on the actual platforms you support.
- Never put real credentials in commands, policy reasons, test fixtures, issues, or pull-request logs.

## If you suspect a leak or bypass

1. Disable or remove the affected hook while preserving the evidence needed to investigate.
2. Rotate any credential that may have appeared in terminal output, process arguments, CI output, or other logs. Do not rely on redaction to prove a secret was not exposed.
3. Record the affected version, OS, tool/event, expected decision, and actual decision without including secrets.
4. Add a regression test and update the threat model before re-enabling the integration.
5. Report exploitable details privately using the guidance in [SECURITY.md](../SECURITY.md), not in a public issue.

## Mandatory independent security review gate

Do not mark a release candidate ready or publish a release until an independent reviewer who did not author the changes has reviewed the security-sensitive implementation and recorded findings. A green CI run is necessary but not sufficient.

The review must explicitly cover:

- [ ] Shell parsing and command classification: POSIX shell, Bash, PowerShell, quoting/escaping, nested shells, command substitutions, newlines, control operators, redirections, here-documents, environment assignments, and platform-specific syntax.
- [ ] Whether the current heuristic can incorrectly allow an unsafe command; provide minimized counterexamples and regression tests.
- [ ] Regex denial-of-service risks in user-controlled policy files, including adversarial inputs and worst-case execution behavior.
- [ ] Protected-path matching, path normalization, symlink/hard-link and filesystem race assumptions on supported operating systems.
- [ ] Claude Code hook failure, timeout, malformed-input and version-compatibility behavior.
- [ ] Audit locking, crash recovery, log privacy and error paths.
- [ ] Explicit written recommendation: approve, approve with tracked limitations, or block release.

If the reviewer determines that reliable shell classification cannot be achieved with the current heuristic, keep the release blocked until AgentShield uses a reviewed shell parser or a stricter fail-closed design, with platform-specific tests. Do not describe heuristic matching as complete shell parsing.

## Release checklist

- [ ] `npm ci` and `npm run check` pass on supported Node.js versions.
- [ ] `npm pack --dry-run` contains only intended package files.
- [ ] Hook configuration is validated against the currently installed Claude Code version.
- [ ] Tests cover allow, ask, deny, malformed input, policy parse failure, and audit write failure.
- [ ] README, changelog, usage guide, and threat model describe the same behavior.
- [ ] Independent security review is complete and its written disposition is recorded; shell parsing is explicitly in scope.\n- [ ] No unresolved release-blocking security findings remain.\n- [ ] No claim implies full secret detection, complete shell parsing, sandboxing, or formal security certification.
