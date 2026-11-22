/**
 * The AI-agent security posture grade (pure). A repository starts at 100 and loses points for each problem in its
 * files (from `isoklo scan`) and each missing safeguard (from the posture checks). Repeated findings of one rule
 * count at most twice, so one noisy rule cannot sink the grade on its own. Any critical finding caps the grade at D.
 */
import type { Finding, Severity } from "../check/types.js";

export type Grade = "A" | "B" | "C" | "D" | "F";
export type CheckStatus = "pass" | "warn" | "fail";

export interface PostureCheck {
  id: string;
  title: string;
  status: CheckStatus;
  severity: Severity;
  detail: string;
  fix?: string;
}

export interface Posture {
  grade: Grade;
  score: number;
  checks: PostureCheck[];
  /** Points lost, by source, so the grade can always be explained. */
  deductions: { source: string; points: number }[];
}

export const PENALTY: Record<Severity, number> = { critical: 25, high: 12, medium: 4, info: 0 };

export function grade(findings: Finding[], checks: PostureCheck[]): Posture {
  const deductions: { source: string; points: number }[] = [];
  const perRule = new Map<string, number>();
  for (const f of findings) {
    if (f.level === "info") continue;
    const sev = f.severity ?? "medium";
    const id = f.ruleId ?? f.id;
    const used = perRule.get(id) ?? 0;
    if (used >= 2) continue;
    perRule.set(id, used + 1);
    if (PENALTY[sev] > 0) deductions.push({ source: `${id} in ${f.evidence[0]?.path ?? "the repository"}`, points: PENALTY[sev] });
  }
  for (const c of checks) {
    if (c.status === "pass") continue;
    const points = c.status === "fail" ? PENALTY[c.severity] : Math.round(PENALTY[c.severity] / 2);
    if (points > 0) deductions.push({ source: c.title, points });
  }
  const score = Math.max(0, 100 - deductions.reduce((n, d) => n + d.points, 0));
  let letter: Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const critical = findings.some((f) => f.level !== "info" && f.severity === "critical") || checks.some((c) => c.status === "fail" && c.severity === "critical");
  if (critical && (letter === "A" || letter === "B" || letter === "C")) letter = "D";
  return { grade: letter, score, checks, deductions };
}

export const GRADE_MEANING: Record<Grade, string> = {
  A: "Agent changes are gated and the repository carries no serious findings.",
  B: "Well protected, with a few gaps worth closing.",
  C: "Agent changes can reach main without a deterministic check, or real problems are present.",
  D: "Serious problems: secrets, injected instructions or unsafe automation are present now.",
  F: "Unsafe for autonomous agents until the critical findings are fixed.",
};

export const gradeAtLeast = (g: Grade, min: Grade) => "ABCDF".indexOf(g) <= "ABCDF".indexOf(min);
