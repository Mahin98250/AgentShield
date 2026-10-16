# Security policy

AgentShield is an early-stage guardrail, not a sandbox or complete authorization boundary. Do not rely on it as the only protection around untrusted agents or production credentials.

## Reporting a vulnerability

Use GitHub private vulnerability reporting if it is enabled for this repository. If unavailable, contact a maintainer privately. Do not include secrets or exploitable proof-of-concept details in public issues.

## In-scope reports

- Command-policy bypasses or unsafe decision mapping.
- Sensitive data exposed in audit logs or viewer output.
- Protected-path checks that fail in supported configurations.
- Policy parsing and regular-expression handling problems.
- Hook failures that allow an action that should have been denied.

Please include the affected version, platform, minimal reproduction, and expected versus actual decision. Remove real credentials and personal data.
