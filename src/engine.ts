import type { Evaluation, Policy, PatternRule } from "./types.js";

const SECRET_ASSIGNMENT = /((?:api[_-]?key|access[_-]?token|secret|password)\s*[=:]\s*)[^\s"'\x60]+/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const MAX_COMMAND_LENGTH = 8_000;

export function redact(text: string): string {
  return text.replace(PEM, "[REDACTED_PRIVATE_KEY]")
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(SECRET_ASSIGNMENT, "$1[REDACTED]")
    .replace(/(gh[pousr]_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9_-]{12,})/g, "[REDACTED_TOKEN]")
    .slice(0, 240);
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
  if (pattern) return { ...base, decision: "block", reason: "File operation targets protected path pattern " + pattern + ".", ruleId: "protected-path" };
  return { ...base, decision: "allow", reason: "Path is not covered by a protected-path rule.", ruleId: "protected-path-check" };
}

export function evaluate(command: string, policy: Policy, now = new Date()): Evaluation {
  const commandSummary = redact(command);
  const base = { commandSummary, timestamp: now.toISOString() };
  if (typeof command !== "string" || !command.trim()) {
    return { ...base, decision: "error", reason: "A non-empty command string is required." };
  }
  if (command.length > MAX_COMMAND_LENGTH) return { ...base, decision: "approve", reason: "Command exceeds the inspection limit; manual review required.", ruleId: "command-too-long" };
  if (/(?:\x60|\$\(|\$\{|(?:^|[;&|])\s*(?:sh|bash|zsh|fish)\s+-c\b)/i.test(command)) {
    return { ...base, decision: "approve", reason: "Shell substitution or nested shell syntax needs manual review.", ruleId: "ambiguous-shell" };
  }
  for (const rule of policy.dangerous_patterns) {
    if (matchesRule(rule, command)) return { ...base, decision: rule.action, reason: rule.reason, ruleId: rule.id };
  }
  for (const rule of policy.secret_patterns) {
    if (matchesRule(rule, command)) return { ...base, decision: rule.action, reason: rule.reason, ruleId: rule.id };
  }
  const pathInCommand = command.match(/(?:^|\s)(?:['"]([^'"]+)['"]|([^\s;&|<>]+))/g) ?? [];
  const normalizedTokens = pathInCommand.map(token => token.trim().replace(/^['"]|['"]$/g, ""));
  for (const token of normalizedTokens) {
    const match = protectedPathMatch(token, policy.protected_paths);
    if (match) return { ...base, decision: "approve", reason: "Command references protected path pattern " + match + ".", ruleId: "protected-path" };
  }
  const approval = policy.defaults.require_approval.find(item => command.toLowerCase().includes(item.toLowerCase()));
  if (approval) return { ...base, decision: "approve", reason: "Command matches approval requirement: " + approval + ".", ruleId: "required-approval" };
  const normalized = command.trim().replace(/\s+/g, " ");
  if (/^(?:npm|pnpm|yarn) (?:test|run (?:test|lint|typecheck|build))$|^node --check [^;&|<>]+$|^git (?:status|diff|log|show|branch --show-current)$|^pwd$|^ls(?: -[alh]+)?$|^cat [^;&|<>]+$/i.test(normalized)) {
    return { ...base, decision: "allow", reason: "Command matches the built-in low-risk command allowlist.", ruleId: "safe-allowlist" };
  }
  return { ...base, decision: policy.defaults.unknown_command, reason: "Command is not on the built-in low-risk allowlist." };
}
