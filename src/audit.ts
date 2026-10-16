import { appendFile, chmod, mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { AuditEvent, Evaluation } from "./types.js";
import { redact } from "./engine.js";

export async function writeAudit(evaluation: Evaluation, path = ".agentshield/audit.jsonl"): Promise<void> {
  const fullPath = resolve(path);
  await mkdir(dirname(fullPath), { recursive: true, mode: 0o700 });
  const event: AuditEvent = { ...evaluation, commandSummary: redact(evaluation.commandSummary), event: "decision" };
  await appendFile(fullPath, JSON.stringify(event) + "\n", { encoding: "utf8", mode: 0o600, flag: "a" });
  try { await chmod(fullPath, 0o600); } catch { /* platform may not support POSIX permissions */ }
}

export async function readAudit(path = ".agentshield/audit.jsonl", limit = 50): Promise<AuditEvent[]> {
  try {
    const text = await readFile(resolve(path), "utf8");
    return text.split(/\r?\n/).filter(Boolean).slice(-Math.max(1, Math.min(limit, 500))).flatMap(line => {
      try {
        const value: unknown = JSON.parse(line);
        if (typeof value === "object" && value !== null && "decision" in value && "timestamp" in value) return [value as AuditEvent];
        return [];
      } catch { return []; }
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}
