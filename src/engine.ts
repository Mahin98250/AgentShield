import type { Evaluation, Policy, PatternRule } from "./types.js";

const SECRET_ASSIGNMENT = /((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token|secret|password|passwd|authorization)\s*(?:[=:]\s*|\s+))(?:"[^"]*"|'[^']*'|[^\s"';&|<>]+)/gi;
const BEARER = /\bBearer\s+[^\s,;]+/gi;
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const MAX_COMMAND_LENGTH = 8_000;

/**
 * Best-effort log sanitization, not a guarantee that arbitrary secrets are detectable.
 * Keep callers from accidentally logging non-string runtime values.
 */
export function redact(value: unknown): string {
  if (typeof value !== "string") return "[REDACTED_INVALID_VALUE]";
  return value
    .replace(PEM, "[REDACTED_PRIVATE_KEY]")
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(/(authorization\s*[:=]\s*)(?:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)/gi, "$1[REDACTED]")
    .replace(/(\b(?:x-api-key|api-key|api_key|proxy-authorization)\s*:\s*)[^\r\n]+/gi, "$1[REDACTED]")
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(SECRET_ASSIGNMENT, "$1[REDACTED]")
    .replace(/(gh[pousr]_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16})/g, "[REDACTED_TOKEN]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]")
    .slice(0, 240);
}

function safeReason(reason: string): string {
  return redact(reason).slice(0, 500);
}
function matchesRule(rule: PatternRule, command: string): boolean {
  return new RegExp(rule.pattern, "i").test(command.slice(0, MAX_COMMAND_LENGTH));
}
function globRegex(pattern: string): RegExp {
  let escaped = "";
  const specials = new Set(["\\", ".", "^", "$", "+", "(", ")", "[", "]", "{", "}", "|"]);
  for (const character of pattern) {
    if (character === "*") escaped += "[^/]*";
    else if (character === "?") escaped += "[^/]";
    else if (specials.has(character)) escaped += "\\" + character;
    else escaped += character;
  }
  return new RegExp("^" + escaped + "$", "i");
}

/** Match a file path lexically. This is a policy check, not filesystem access control. */
export function protectedPathMatch(filePath: string, patterns: string[]): string | undefined {
  const normalized = filePath.replace(/\\/g, "/").replace(/^[A-Za-z]:/, "");
  const segments = normalized.split("/").filter(Boolean);
  const joined = segments.join("/");
  for (const rawPattern of patterns) {
    const pattern = rawPattern.replace(/\\/g, "/").replace(/^\.\//, "");
    if (pattern.endsWith("/**")) {
      const prefix = pattern.slice(0, -3).replace(/\/$/, "");
      if (joined === prefix || joined.startsWith(prefix + "/") || segments.includes(prefix)) return rawPattern;
    } else if (pattern.includes("/")) {
      if (globRegex(pattern).test(joined) || joined.endsWith("/" + pattern)) return rawPattern;
    } else if (segments.some(segment => globRegex(pattern).test(segment))) {
      return rawPattern;
    }
  }
  return undefined;
}

export function evaluateFilePath(filePath: string, policy: Policy, now = new Date()): Evaluation {
  const base = { commandSummary: "[file operation]", timestamp: now.toISOString() };
  if (!filePath || filePath.length > 4_096) return { ...base, decision: "error", reason: "File path is missing or too long." };
  const pattern = protectedPathMatch(filePath, policy.protected_paths);
  if (pattern) return { ...base, decision: "block", reason: safeReason("File operation targets protected path pattern " + pattern + "."), ruleId: "protected-path" };
  return { ...base, decision: "allow", reason: "Path is not covered by a protected-path rule.", ruleId: "protected-path-check" };
}

export function evaluate(command: unknown, policy: Policy, now = new Date()): Evaluation {
  const timestamp = now.toISOString();
  if (typeof command !== "string") {
    return { decision: "error", reason: "A non-empty command string is required.", commandSummary: "[invalid command input]", timestamp };
  }
  if (!command.trim()) {
    return { decision: "error", reason: "A non-empty command string is required.", commandSummary: "[empty command]", timestamp };
  }
  if (command.length > MAX_COMMAND_LENGTH) {
    return { decision: "approve", reason: "Command exceeds the inspection limit; manual review required.", commandSummary: "[command omitted: exceeds inspection limit]", timestamp, ruleId: "command-too-long" };
  }
  const commandSummary = redact(command);
  const base = { commandSummary, timestamp };
  // Explicit block rules take precedence over ambiguity escalation.
  for (const rule of policy.dangerous_patterns) {
    if (rule.action === "block" && matchesRule(rule, command)) {
      return { ...base, decision: "block", reason: safeReason(rule.reason), ruleId: rule.id };
    }
  }
  // The engine does not parse shell grammar. Compound operators and substitutions therefore require review.
  if (/(?:\x60|\$\(|\$\{|(?:^|[;&|])\s*(?:sh|bash|zsh|fish)\s+-c\b|&&|\|\||[;&|<>\r\n])/i.test(command)) {
    return { ...base, decision: "approve", reason: "Compound shell syntax, redirection, or substitution needs manual review.", ruleId: "ambiguous-shell" };
  }
  for (const rule of policy.dangerous_patterns) {
    if (rule.action !== "block" && matchesRule(rule, command)) {
      return { ...base, decision: rule.action, reason: safeReason(rule.reason), ruleId: rule.id };
    }
  }
  for (const rule of policy.secret_patterns) {
    if (matchesRule(rule, command)) return { ...base, decision: rule.action, reason: safeReason(rule.reason), ruleId: rule.id };
  }
  const pathInCommand = command.match(/(?:^|\s)(?:['"]([^'"]+)['"]|([^\s;&|<>]+))/g) ?? [];
  const normalizedTokens = pathInCommand.map(token => token.trim().replace(/^['"]|['"]$/g, ""));
  for (const token of normalizedTokens) {
    const match = protectedPathMatch(token, policy.protected_paths);
    if (match) return { ...base, decision: "approve", reason: safeReason("Command references protected path pattern " + match + "."), ruleId: "protected-path" };
  }
  const approval = policy.defaults.require_approval.find(item => command.toLowerCase().includes(item.toLowerCase()));
  if (approval) return { ...base, decision: "approve", reason: safeReason("Command matches approval requirement: " + approval + "."), ruleId: "required-approval" };
  const normalized = command.trim().replace(/\s+/g, " ");
  if (/^(?:npm|pnpm|yarn) (?:test|run (?:test|lint|typecheck|build))$|^node --check [^;&|<>]+$|^git (?:status|diff|log|show|branch --show-current)$|^pwd$|^ls(?: -[alh]+)?$|^cat [^;&|<>]+$/i.test(normalized)) {
    return { ...base, decision: "allow", reason: "Command matches the built-in low-risk command allowlist.", ruleId: "safe-allowlist" };
  }
  return { ...base, decision: policy.defaults.unknown_command, reason: "Command is not on the built-in low-risk allowlist." };
}
