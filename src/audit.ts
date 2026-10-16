import { constants } from "node:fs";
import { lstat, mkdir, open as openFile, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { AuditEvent, Evaluation } from "./types.js";

const MAX_AUDIT_BYTES = 10 * 1024 * 1024;
const NOFOLLOW_FLAG = constants.O_NOFOLLOW ?? 0;

function unsafeAuditPath(): Error {
  return new Error("Audit log must be a regular file, not a symlink or special file.");
}

async function rejectUnsafeParentDirectory(fullPath: string): Promise<void> {
  const parentInfo = await lstat(dirname(fullPath));
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) {
    throw new Error("Audit directory must be a real directory, not a symlink or special file.");
  }
}

async function rejectUnsafeExistingPath(fullPath: string): Promise<void> {
  try {
    const existing = await lstat(fullPath);
    if (existing.isSymbolicLink() || !existing.isFile()) throw unsafeAuditPath();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

interface AuditLock {
  path: string;
  handle: FileHandle;
  dev: number;
  ino: number;
}

async function acquireAuditLock(auditPath: string): Promise<AuditLock> {
  const lockPath = `${auditPath}.lock`;
  let handle: FileHandle | undefined;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      handle = await openFile(
        lockPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW_FLAG,
        0o600
      );
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (attempt === 99) {
        throw new Error("Audit log is busy or has a stale lock; retry, and remove the .lock file only after confirming no AgentShield writer is active.");
      }
      await delay(10);
    }
  }
  if (!handle) throw new Error("Unable to acquire audit lock.");

  let info: { dev: number; ino: number } | undefined;
  try {
    const stats = await handle.stat();
    info = { dev: stats.dev, ino: stats.ino };
    await handle.writeFile(`${process.pid}\n`, "utf8");
    return { path: lockPath, handle, dev: stats.dev, ino: stats.ino };
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (info) {
      try {
        const pathInfo = await lstat(lockPath);
        if (!pathInfo.isSymbolicLink() && pathInfo.dev === info.dev && pathInfo.ino === info.ino) await unlink(lockPath);
      } catch { /* preserve the original lock-write failure */ }
    }
    throw error;
  }
}

async function releaseAuditLock(lock: AuditLock): Promise<void> {
  try {
    const pathInfo = await lstat(lock.path);
    if (!pathInfo.isSymbolicLink() && pathInfo.isFile() && pathInfo.dev === lock.dev && pathInfo.ino === lock.ino) {
      await unlink(lock.path);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  } finally {
    await lock.handle.close();
  }
}

// Validate the opened handle against the directory entry as well as using O_NOFOLLOW
// where the platform supports it. The handle stays bound to this file if the path is
// replaced after opening; the lstat/fstat comparison catches common replacement races.
async function verifyOpenedAuditFile(fullPath: string, handle: FileHandle): Promise<void> {
  const [pathInfo, handleInfo] = await Promise.all([lstat(fullPath), handle.stat()]);
  if (
    pathInfo.isSymbolicLink() ||
    !pathInfo.isFile() ||
    !handleInfo.isFile() ||
    pathInfo.dev !== handleInfo.dev ||
    pathInfo.ino !== handleInfo.ino
  ) {
    throw unsafeAuditPath();
  }
}

export async function writeAudit(evaluation: Evaluation, path = ".agentshield/audit.jsonl"): Promise<void> {
  const fullPath = resolve(path);
  await mkdir(dirname(fullPath), { recursive: true, mode: 0o700 });
  await rejectUnsafeParentDirectory(fullPath);
  const lock = await acquireAuditLock(fullPath);
  try {
    await rejectUnsafeExistingPath(fullPath);

    // Audit records intentionally omit command text, dynamic reasons, and rule IDs.
    // Sanitization cannot reliably discover arbitrary secrets in arbitrary text.
    const decision = ["allow", "approve", "block", "error"].includes(evaluation.decision)
      ? evaluation.decision
      : "error";
    const parsedTimestamp = typeof evaluation.timestamp === "string" ? Date.parse(evaluation.timestamp) : NaN;
    const event: AuditEvent = {
      event: "decision",
      decision,
      timestamp: Number.isFinite(parsedTimestamp) ? new Date(parsedTimestamp).toISOString() : new Date().toISOString(),
      commandSummary: "[omitted for privacy]",
      reason: "Policy decision recorded; sensitive details omitted."
    };
    const line = JSON.stringify(event) + "\n";
    const lineBytes = Buffer.byteLength(line, "utf8");
    if (lineBytes > MAX_AUDIT_BYTES) throw new Error("Audit event exceeds the safety limit.");

    // O_NOFOLLOW prevents following a final-component symlink on supporting platforms.
    const handle = await openFile(
      fullPath,
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | NOFOLLOW_FLAG,
      0o600
    );
    try {
      await verifyOpenedAuditFile(fullPath, handle);
      const info = await handle.stat();
      if (info.size + lineBytes > MAX_AUDIT_BYTES) {
        throw new Error("Audit log would exceed the 10 MiB safety limit; archive it before continuing.");
      }
      await handle.chmod(0o600).catch(() => { /* platform may not support POSIX permissions */ });
      await handle.writeFile(line, { encoding: "utf8" });
    } finally {
      await handle.close();
    }
  } finally {
    await releaseAuditLock(lock);
  }
}

export async function readAudit(path = ".agentshield/audit.jsonl", limit = 50): Promise<AuditEvent[]> {
  const fullPath = resolve(path);
  let handle: FileHandle;
  try {
    await rejectUnsafeParentDirectory(fullPath);
    await rejectUnsafeExistingPath(fullPath);
    handle = await openFile(fullPath, constants.O_RDONLY | NOFOLLOW_FLAG);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }

  try {
    await verifyOpenedAuditFile(fullPath, handle);
    const info = await handle.stat();
    if (info.size > MAX_AUDIT_BYTES) throw new Error("Audit log exceeds the 10 MiB safety limit.");
    const text = await handle.readFile("utf8");
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(Math.trunc(limit), 500)) : 50;
    return text.split(/\r?\n/).filter(Boolean).slice(-safeLimit).flatMap(line => {
      try {
        const value: unknown = JSON.parse(line);
        if (typeof value !== "object" || value === null || Array.isArray(value)) return [];
        const v = value as Record<string, unknown>;
        if (v.event !== "decision" || !["allow", "approve", "block", "error"].includes(String(v.decision)) ||
            typeof v.timestamp !== "string" || typeof v.reason !== "string" ||
            typeof v.commandSummary !== "string" || v.commandSummary.length > 240) return [];
        const parsedTimestamp = Date.parse(v.timestamp);
        return [{
          event: "decision",
          decision: v.decision,
          timestamp: Number.isFinite(parsedTimestamp) ? new Date(parsedTimestamp).toISOString() : new Date(0).toISOString(),
          reason: "Policy decision recorded; sensitive details omitted.",
          commandSummary: "[omitted for privacy]"
        } as AuditEvent];
      } catch { return []; }
    });
  } finally {
    await handle.close();
  }
}
