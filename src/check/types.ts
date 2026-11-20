/** Shapes shared by every `isoklo check` rule, so the report and JSON output treat all rules the same way. */

export type Level = "blocked" | "review" | "info";

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
  rule: "weakened-tests" | "unknown-packages" | "agent-config";
  id: string;
  level: Level;
  /** Verdict first, in the examiner voice. */
  message: string;
  fix: string;
  evidence: Evidence[];
  /** Set when a reviewable allow marker downgraded this finding. */
  allowedBecause?: string;
}

export interface RuleResult {
  rule: Finding["rule"];
  findings: Finding[];
  /** Plain statements of what was checked and found fine. */
  passes: string[];
  stats: Record<string, number>;
}
