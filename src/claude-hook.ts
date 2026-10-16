import type { Evaluation, Policy } from "./types.js";
import { evaluate, evaluateFilePath, redact } from "./engine.js";

export interface ClaudeHookInput {
  tool_name?: unknown;
  tool_input?: unknown;
}
export interface ClaudeHookResponse {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "deny" | "ask";
    permissionDecisionReason: string;
  };
}

/** Null means AgentShield has no objection; Claude Code's normal permission flow still applies. */
export function evaluateClaudeInput(input: ClaudeHookInput, policy: Policy): Evaluation | null {
  if (typeof input.tool_name !== "string" || !input.tool_input || typeof input.tool_input !== "object") return null;
  const toolInput = input.tool_input as Record<string, unknown>;
  if (input.tool_name === "Bash" || input.tool_name === "PowerShell") {
    if (typeof toolInput.command !== "string") return { decision: "error", reason: "Shell tool input has no command string.", commandSummary: "[invalid shell input]", timestamp: new Date().toISOString() };
    return evaluate(toolInput.command, policy);
  }
  if (input.tool_name === "Write" || input.tool_name === "Edit" || input.tool_name === "Read") {
    const filePath = toolInput.file_path ?? toolInput.path;
    if (typeof filePath !== "string") return { decision: "error", reason: "File tool input has no file path.", commandSummary: "[invalid file input]", timestamp: new Date().toISOString() };
    const result = evaluateFilePath(filePath, policy);
    return result.decision === "allow" ? null : result;
  }
  return null;
}

export function formatClaudeResponse(evaluation: Evaluation): ClaudeHookResponse | null {
  if (evaluation.decision === "allow") return null;
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: evaluation.decision === "approve" ? "ask" : "deny",
      permissionDecisionReason: redact(evaluation.reason).slice(0, 500)
    }
  };
}
