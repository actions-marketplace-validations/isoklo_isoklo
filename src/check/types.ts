/** Shapes shared by every Isoklo rule, so the reports, JSON, SARIF and receipts treat all rules the same way. */

export type Level = "blocked" | "review" | "info";

/** How serious the problem is, independent of whether it blocks. Shown in reports, SARIF and receipts. */
export type Severity = "critical" | "high" | "medium" | "info";

/** The v2 rule suites. Every rule id is `<suite>/<name>`, for example `tamper/assertions-removed`. */
export type Suite = "agent" | "mcp" | "tamper" | "deps" | "sec" | "scope";

/** v1 rule groups keep their names so v1 JSON consumers keep working; new rules use their suite as the group. */
export type RuleGroup = "weakened-tests" | "unknown-packages" | "agent-config" | Suite;

export interface Evidence {
  path: string;
  line: number;
  text: string;
  /**
   * For removed lines: where the change sits in the NEW version of the file (path and line), so GitHub can draw an
   * annotation on the pull request. `line` above stays the line the text had before it was removed.
   */
  anchor?: { path: string; line: number };
}

export interface Finding {
  rule: RuleGroup;
  id: string;
  level: Level;
  /** Verdict first, in the examiner voice. */
  message: string;
  fix: string;
  evidence: Evidence[];
  /** Set when a reviewable allow marker, a maintainer's reason, or the baseline downgraded this finding. */
  allowedBecause?: string;
  /** v2: the canonical rule id (`suite/name`). The engine fills it in from the rule registry. */
  ruleId?: string;
  /** v2: how serious it is. The engine fills it in from the rule registry when a rule does not set it. */
  severity?: Severity;
  /** v2: stable id for this finding (rule, file and evidence text, not line numbers), for baselines and SARIF. */
  fingerprint?: string;
}

export interface RuleResult {
  rule: RuleGroup;
  findings: Finding[];
  /** Plain statements of what was checked and found fine. */
  passes: string[];
  stats: Record<string, number>;
}
