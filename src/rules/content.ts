/**
 * Content rules: patterns that matter wherever they appear. In `check` mode they read the lines a change adds; in `scan`
 * mode, every line of every file. One finding per rule and file, with every matching line as evidence.
 */
import type { Finding, Level, RuleGroup, Severity } from "../check/types.js";
import type { NumberedLine } from "../engine/text.js";
import type { Mode } from "../engine/registry.js";

export interface ContentUnit {
  path: string;
  /** check: lines the change adds (moved lines excluded). scan: every line. */
  lines: NumberedLine[];
  mode: Mode;
  /** check: what the change did to the file. */
  status?: "added" | "deleted" | "modified" | "renamed";
  /** scan: whether git tracks the file (false: untracked but not ignored, so `git add .` would commit it). */
  tracked?: boolean;
}

export interface Hit {
  line: number;
  text: string;
  level: Level;
  severity: Severity;
  what: string;
}

/** Build one finding for a rule and file from its hits: the most serious hit decides the level and severity. */
export function findingFrom(
  rule: RuleGroup,
  id: string,
  path: string,
  hits: Hit[],
  message: (whats: string[], hits: Hit[]) => string,
  fix: string,
): Finding | null {
  if (hits.length === 0) return null;
  const order = ["critical", "high", "medium", "info"] as const;
  const levelOrder = ["blocked", "review", "info"] as const;
  const level = levelOrder.find((l) => hits.some((h) => h.level === l)) ?? "info";
  const severity = order.find((s) => hits.some((h) => h.severity === s && h.level === level)) ?? "info";
  const whats = [...new Set(hits.filter((h) => h.level === level).map((h) => h.what))];
  return {
    rule, id, level, severity,
    message: message(whats, hits),
    fix,
    evidence: hits.map((h) => ({ path, line: h.line, text: h.text })),
  };
}
