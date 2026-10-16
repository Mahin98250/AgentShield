export type Decision = "allow" | "approve" | "block" | "error";
export type RuleAction = "approve" | "block";

export interface PatternRule {
  id: string;
  pattern: string;
  reason: string;
  action: RuleAction;
}
export interface Policy {
  version: 1;
  defaults: {
    unknown_command: "allow" | "approve" | "block";
    require_approval: string[];
  };
  protected_paths: string[];
  dangerous_patterns: PatternRule[];
  secret_patterns: PatternRule[];
}
export interface Evaluation {
  decision: Decision;
  reason: string;
  ruleId?: string;
  commandSummary: string;
  timestamp: string;
}
export interface AuditEvent extends Evaluation {
  event: "decision";
}
