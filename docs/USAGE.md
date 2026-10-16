# Using AgentShield

AgentShield works alongside your coding agent. It does not replace the agent or execute approved commands itself.

## 1. Install and build

Install Node.js 20 or newer, then run:

```sh
git clone https://github.com/Mahin98250/AgentShield.git
cd AgentShield
npm install
npm run check
node dist/cli.js init
```

The init command creates .agentshield/policy.yml. Review the rules before enabling a hook.

## 2. Try a decision

```sh
node dist/cli.js check --command "npm test"
node dist/cli.js check --command "rm -rf ./build"
node dist/cli.js log
```

The first command is on the low-risk allowlist; the second should be blocked by the starter policy. The check command only evaluates a command. It does not run it.

## 3. Connect Claude Code

1. Build AgentShield with npm run build.
2. Choose the configuration that matches your layout:
   - Same repository: use examples/claude-settings.json.
   - Separate AgentShield checkout: use examples/claude-settings.external.json and replace its placeholder with the absolute path to AgentShield/dist/cli.js.
3. Merge the selected hooks section into the target project's .claude/settings.json. Do not overwrite existing settings.
4. From the target project folder, run the matching AgentShield CLI with init to create that project's local .agentshield/policy.yml. For an external checkout, use the same absolute path configured above.
5. Start Claude Code in that project and test a safe command, a blocked command, and a read of a protected file.

The hook checks Bash/PowerShell and Read/Write/Edit calls that Claude Code sends to its PreToolUse hook. The example uses `onFailure: "block"`, which requires Claude Code v2.1.295 or newer. Without support for that setting, a hook timeout or crash may not block the tool call. Verify the installed Claude Code version and test the deny path before relying on enforcement. See the official [Claude Code hooks guide](https://code.claude.com/docs/en/hooks) for the current format.

## 4. Open the activity view

```sh
node dist/cli.js viewer
```

Open http://127.0.0.1:4173 in your browser. The page reads the local audit file; it is not a public hosted dashboard.

## Important

- Unknown commands require review by default.
- Secret redaction is best-effort; never intentionally put credentials into commands.
- Shell matching is not a complete shell parser, and a hook can be bypassed by actions outside its scope.
- Use least privilege and OS/container isolation for higher-risk work.
