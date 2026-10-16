import { appendFile, chmod, lstat, mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { AuditEvent, Evaluation } from "./types.js";
import { redact } from "./engine.js";

const MAX_AUDIT_BYTES = 10 * 1024 * 1024;

export async function writeAudit(evaluation: Evaluation, path = ".agentshield/audit.jsonl"): Promise<void> {
  const fullPath = resolve(path);
  await mkdir(dirname(fullPath), { recursive: true, mode: 0o700 });
  try {
    const existing = await lstat(fullPath);
    if (existing.isSymbolicLink() || !existing.isFile()) throw new Error("Audit log must be a regular file, not a symlink or special file.");
    if (existing.size > MAX_AUDIT_BYTES) throw new Error("Audit log reached the 10 MiB safety limit; archive it before continuing.");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const event: AuditEvent = {
    ...evaluation,
    commandSummary: redact(evaluation.commandSummary),
    reason: redact(evaluation.reason).slice(0, 500),
    event: "decision"
  };
  await appendFile(fullPath, JSON.stringify(event) + "\n", { encoding: "utf8", mode: 0o600, flag: "a" });
  try { await chmod(fullPath, 0o600); } catch { /* platform may not support POSIX permissions */ }
}

export async function readAudit(path = ".agentshield/audit.jsonl", limit = 50): Promise<AuditEvent[]> {
  try {
    const fullPath = resolve(path);
    const info = await lstat(fullPath);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error("Audit log must be a regular file, not a symlink or special file.");
    if (info.size > MAX_AUDIT_BYTES) throw new Error("Audit log exceeds the 10 MiB safety limit.");
    const text = await readFile(fullPath, "utf8");
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(Math.trunc(limit), 500)) : 50;
    return text.split(/\r?\n/).filter(Boolean).slice(-safeLimit).flatMap(line => {
      try {
        const value: unknown = JSON.parse(line);
        if (typeof value !== "object" || value === null || Array.isArray(value)) return [];
        const v = value as Record<string, unknown>;
        if (v.event !== "decision" || !["allow", "approve", "block", "error"].includes(String(v.decision)) ||
            typeof v.timestamp !== "string" || typeof v.reason !== "string" ||
            typeof v.commandSummary !== "string" || v.commandSummary.length > 240) return [];
        return [{
          event: "decision",
          decision: v.decision,
          timestamp: v.timestamp.slice(0, 64),
          reason: redact(v.reason).slice(0, 500),
          commandSummary: redact(v.commandSummary),
          ...(typeof v.ruleId === "string" ? { ruleId: v.ruleId.slice(0, 64) } : {})
        } as AuditEvent];
      } catch { return []; }
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}
