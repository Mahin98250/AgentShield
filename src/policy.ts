import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { PatternRule, Policy } from "./types.js";

export const DEFAULT_POLICY: Policy = {
  version: 1,
  defaults: { unknown_command: "approve", require_approval: ["git push", "npm publish"] },
  protected_paths: [".env", ".env.*", "*.pem", "*.key", "id_rsa", ".ssh/**", ".agentshield/**", ".claude/settings.json", ".claude/settings.local.json"],
  dangerous_patterns: [
    { id: "recursive-force-delete", pattern: "\\brm\\b(?=[^\\n]*(?:\\s-[^\\s]*r|\\s--recursive\\b))(?=[^\\n]*(?:\\s-[^\\s]*f|\\s--force\\b))", reason: "Recursive forced deletion is forbidden.", action: "block" },
    { id: "powershell-recursive-delete", pattern: "\\bRemove-Item\\b(?=[^\\n]*\\s-(?:Recurse|r)\\b)(?=[^\\n]*\\s-(?:Force|f)\\b)", reason: "Recursive forced deletion in PowerShell is blocked.", action: "block" },
    { id: "remote-script-pipe", pattern: "\\b(?:curl|wget)\\b[^\\n]*\\|\\s*(?:sh|bash|zsh)\\b", reason: "Remote script piped to a shell is blocked.", action: "block" }
  ],
  secret_patterns: [
    { id: "credential-assignment", pattern: "(?:api[_-]?key|access[_-]?token|secret|password)\\s*[=:]\\s*[^\\s]+", reason: "Command may expose a credential.", action: "approve" }
  ]
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function onlyKeys(value: Record<string, unknown>, allowed: string[], where: string): void {
  const unknown = Object.keys(value).filter(key => !allowed.includes(key));
  if (unknown.length) throw new Error(`${where} contains unsupported key(s): ${unknown.join(", ")}`);
}
function parseScalar(raw: string): unknown {
  const value = raw.trim();
  if (value === "[]") return [];
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^-?\d+$/.test(value)) return Number(value);
  if (value.startsWith('"') && value.endsWith('"')) {
    try { return JSON.parse(value); } catch { throw new Error("Invalid double-quoted YAML string"); }
  }
  if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1).replace(/''/g, "'");
  return value;
}

/**
 * Parse the safe YAML subset used by AgentShield policies. It supports mappings,
 * lists, strings, numbers, booleans, and quoted scalars—not arbitrary YAML features.
 * Rejecting unsupported YAML is intentional: a typo must never silently change policy.
 */
function parseYamlSubset(text: string): Record<string, unknown> {
  if (text.length > 256_000) throw new Error("Policy is larger than the 256 KB limit");
  const root: Record<string, unknown> = {};
  const sourceLines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  let section = "";
  let currentRule: Record<string, unknown> | null = null;
  let defaultListKey: string | null = null;
  for (let index = 0; index < sourceLines.length; index++) {
    const raw = sourceLines[index]!;
    if (/\t/.test(raw.match(/^\s*/)?.[0] ?? "")) throw new Error(`Tabs are not supported for indentation (line ${index + 1})`);
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    if (indent === 0) {
      const match = /^([a-z_]+):(?:\s*(.*))?$/.exec(line);
      if (!match) throw new Error(`Unsupported YAML at line ${index + 1}`);
      const key = match[1]!;
      const rest = match[2] ?? "";
      if (Object.hasOwn(root, key)) throw new Error(`Duplicate key "${key}" at line ${index + 1}`);
      if (key === "version") root[key] = parseScalar(rest);
      else if (key === "defaults" && (!rest || rest === "{}")) root[key] = {};
      else if (["protected_paths", "dangerous_patterns", "secret_patterns"].includes(key) && (!rest || rest === "[]")) root[key] = [];
      else throw new Error(`Unsupported top-level key or value at line ${index + 1}: ${key}`);
      section = key;
      currentRule = null;
      defaultListKey = null;
      continue;
    }
    if (indent === 2 && section === "defaults") {
      const match = /^([a-z_]+):(?:\s*(.*))?$/.exec(line);
      if (!match) throw new Error(`Unsupported defaults entry at line ${index + 1}`);
      const key = match[1]!;
      const rest = match[2] ?? "";
      const defaults = root.defaults as Record<string, unknown>;
      if (Object.hasOwn(defaults, key)) throw new Error(`Duplicate defaults key "${key}"`);
      if (key === "require_approval" && !rest) {
        defaults[key] = [];
        defaultListKey = key;
      } else {
        defaults[key] = parseScalar(rest);
        defaultListKey = null;
      }
      currentRule = null;
      continue;
    }
    if (indent === 2 && ["protected_paths", "dangerous_patterns", "secret_patterns"].includes(section)) {
      if (!line.startsWith("- ")) throw new Error(`Expected list item at line ${index + 1}`);
      const rest = line.slice(2).trim();
      if (section === "protected_paths") {
        (root[section] as unknown[]).push(parseScalar(rest));
        currentRule = null;
      } else {
        const match = /^([a-z_]+):\s*(.*)$/.exec(rest);
        if (!match) throw new Error(`Rule must start with "- id:" at line ${index + 1}`);
        currentRule = { [match[1]!]: parseScalar(match[2]!) };
        (root[section] as unknown[]).push(currentRule);
      }
      continue;
    }
    if (indent === 4 && section === "defaults" && line.startsWith("- ") && defaultListKey) {
      ((root.defaults as Record<string, unknown>)[defaultListKey] as unknown[]).push(parseScalar(line.slice(2)));
      continue;
    }
    if (indent === 4 && currentRule) {
      const match = /^([a-z_]+):\s*(.*)$/.exec(line);
      if (!match) throw new Error(`Expected rule field at line ${index + 1}`);
      const key = match[1]!;
      if (Object.hasOwn(currentRule, key)) throw new Error(`Duplicate rule field "${key}" at line ${index + 1}`);
      currentRule[key] = parseScalar(match[2]!);
      continue;
    }
    throw new Error(`Unsupported YAML structure at line ${index + 1}`);
  }
  return root;
}

function validateStringList(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || !value.every(item => typeof item === "string" && item.length <= 500)) {
    throw new Error(`${where} must be a list of strings (each at most 500 characters)`);
  }
  return value as string[];
}
function parseRules(value: unknown, where: string): PatternRule[] {
  if (!Array.isArray(value)) throw new Error(`${where} must be a list`);
  if (value.length > 200) throw new Error(`${where} may contain at most 200 rules`);
  const ids = new Set<string>();
  return value.map((raw, index) => {
    const at = `${where}[${index}]`;
    if (!isRecord(raw)) throw new Error(`${at} must be a mapping`);
    onlyKeys(raw, ["id", "pattern", "reason", "action"], at);
    const { id, pattern, reason, action } = raw;
    if (typeof id !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) throw new Error(`${at}.id is invalid`);
    if (ids.has(id)) throw new Error(`${where} has duplicate id "${id}"`);
    ids.add(id);
    if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > 500) throw new Error(`${at}.pattern must contain 1–500 characters`);
    if (typeof reason !== "string" || reason.length === 0 || reason.length > 500) throw new Error(`${at}.reason must contain 1–500 characters`);
    if (action !== "approve" && action !== "block") throw new Error(`${at}.action must be "approve" or "block"`);
    try { new RegExp(pattern, "i"); } catch { throw new Error(`${at}.pattern is not a valid JavaScript regular expression`); }
    return { id, pattern, reason, action };
  });
}

export function parsePolicyText(text: string): Policy {
  const value = parseYamlSubset(text);
  onlyKeys(value, ["version", "defaults", "protected_paths", "dangerous_patterns", "secret_patterns"], "Policy");
  if (value.version !== 1) throw new Error("Policy version must be 1");
  if (!isRecord(value.defaults)) throw new Error("defaults must be a mapping");
  onlyKeys(value.defaults, ["unknown_command", "require_approval"], "defaults");
  const unknownCommand = value.defaults.unknown_command;
  if (unknownCommand !== "allow" && unknownCommand !== "approve" && unknownCommand !== "block") {
    throw new Error("defaults.unknown_command must be allow, approve, or block");
  }
  const requireApproval = validateStringList(value.defaults.require_approval, "defaults.require_approval");
  const protectedPaths = validateStringList(value.protected_paths, "protected_paths");
  return {
    version: 1,
    defaults: { unknown_command: unknownCommand, require_approval: requireApproval },
    protected_paths: protectedPaths,
    dangerous_patterns: parseRules(value.dangerous_patterns, "dangerous_patterns"),
    secret_patterns: parseRules(value.secret_patterns, "secret_patterns")
  };
}

export async function loadPolicy(path = ".agentshield/policy.yml"): Promise<Policy> {
  return parsePolicyText(await readFile(resolve(path), "utf8"));
}
