#!/usr/bin/env node
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPolicy } from "./policy.js";
import { evaluate } from "./engine.js";
import { evaluateClaudeInput, formatClaudeResponse } from "./claude-hook.js";
import { readAudit, writeAudit } from "./audit.js";
import { startViewer } from "./viewer.js";

const POLICY = ".agentshield/policy.yml";
const AUDIT = ".agentshield/audit.jsonl";
function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function help(): void {
  console.log(`AgentShield — local-first policy guard for coding agents

Usage:
  agentshield init [--force]
  agentshield check --command "npm test" [--policy path]
  agentshield hook [--policy path]
  agentshield claude-hook [--policy path]
  agentshield log [--limit 50]
  agentshield viewer [--port 4173]`);
}
async function readStdin(maxBytes = 64_000): Promise<string> {
  let raw = "";
  for await (const chunk of process.stdin) {
    raw += chunk.toString();
    if (Buffer.byteLength(raw, "utf8") > maxBytes) throw new Error("Input exceeds size limit");
  }
  return raw;
}
function claudeDeny(reason: string): void {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason.slice(0, 500) } }) + "\n");
}
async function main(): Promise<void> {
  const command = process.argv[2];
  if (!command || command === "--help" || command === "-h") { help(); return; }
  if (command === "init") {
    const path = resolve(POLICY);
    await mkdir(resolve(".agentshield"), { recursive: true, mode: 0o700 });
    if (!process.argv.includes("--force")) {
      try { await access(path); console.error(`${POLICY} already exists. Use --force to replace it.`); process.exitCode = 1; return; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    const template = fileURLToPath(new URL("../rules/default.yml", import.meta.url));
    await writeFile(path, await readFile(template, "utf8"), { encoding: "utf8", mode: 0o600 });
    console.log(`Created ${POLICY}`);
    return;
  }
  if (command === "check") {
    const shellCommand = arg("--command");
    if (!shellCommand) throw new Error("check requires --command");
    const policy = await loadPolicy(arg("--policy") ?? POLICY);
    const result = evaluate(shellCommand, policy);
    await writeAudit(result);
    console.log(JSON.stringify(result, null, 2));
    if (result.decision !== "allow") process.exitCode = 2;
    return;
  }
  if (command === "hook") {
    const input: unknown = JSON.parse(await readStdin());
    if (typeof input !== "object" || input === null || !("command" in input) || typeof input.command !== "string") throw new Error("Hook input must contain a string command field");
    const policy = await loadPolicy(arg("--policy") ?? POLICY);
    const result = evaluate(input.command, policy);
    await writeAudit(result);
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.decision !== "allow") process.exitCode = 2;
    return;
  }
  if (command === "claude-hook") {
    try {
      const input: unknown = JSON.parse(await readStdin());
      if (typeof input !== "object" || input === null) throw new Error("Invalid Claude Code hook input");
      const policy = await loadPolicy(arg("--policy") ?? POLICY);
      const result = evaluateClaudeInput(input, policy);
      if (!result) return;
      await writeAudit(result);
      const response = formatClaudeResponse(result);
      if (response) process.stdout.write(JSON.stringify(response) + "\n");
      return;
    } catch (error) {
      console.error(`AgentShield hook error: ${error instanceof Error ? error.message : "unexpected error"}`);
      claudeDeny("AgentShield could not safely evaluate this action. Check local policy and audit-log permissions.");
      return;
    }
  }
  if (command === "log") {
    const limit = Number(arg("--limit") ?? "50");
    console.log((await readAudit(AUDIT, Number.isFinite(limit) ? limit : 50)).map(event => `${event.timestamp}  ${event.decision.toUpperCase().padEnd(7)} ${event.reason}\n  ${event.commandSummary}`).join("\n") || "No audit events yet.");
    return;
  }
  if (command === "viewer") {
    const port = Number(arg("--port") ?? "4173");
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be an integer from 1 to 65535");
    await startViewer(port);
    return;
  }
  throw new Error(`Unknown command: ${command}`);
}
main().catch(error => {
  console.error(`AgentShield: ${error instanceof Error ? error.message : "unexpected error"}`);
  process.exitCode = 1;
});
