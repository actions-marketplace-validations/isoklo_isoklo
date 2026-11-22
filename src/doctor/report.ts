/**
 * Report (pure): format a DoctorReport as plain text (people) or JSON (CI and other tools).
 * Voice rules: verdict first, then evidence, then the fix; no exclamation marks; colour only when the terminal supports it.
 */
import type { DoctorReport } from "./analyze.js";
import { GRADE_MEANING, type Posture } from "./grade.js";
import type { Finding } from "../check/types.js";

const n = (x: number) => x.toLocaleString("en-US");

export interface TextOptions {
  color: boolean;
  root: string;
  /** v2: the security posture grade and checks, with the scan findings it was computed from. */
  posture?: { posture: Posture; findings: Finding[] };
}

/** The posture section of `isoklo doctor`: the grade, each safeguard, and what the file scan found. */
export function postureText(p: Posture, findings: Finding[], color: boolean): string[] {
  const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const gradeColor = p.grade === "A" || p.grade === "B" ? "1;32" : p.grade === "C" ? "1;33" : "1;31";
  const lines = [`Posture  ${paint(gradeColor, p.grade)} · ${p.score}/100 · ${GRADE_MEANING[p.grade]}`];
  for (const c of p.checks) {
    const tag = c.status === "pass" ? paint("32", "✓") : c.status === "fail" ? paint("31", "✕") : paint("33", "△");
    lines.push(`  ${tag} ${c.title}: ${c.detail}`);
    if (c.status !== "pass" && c.fix !== undefined) lines.push(`      fix: ${c.fix}`);
  }
  const serious = findings.filter((f) => f.level !== "info");
  const count = (s: string) => serious.filter((f) => f.severity === s).length;
  lines.push(serious.length === 0
    ? `  ${paint("32", "✓")} Files: no problems found by the scan.`
    : `  ${paint("31", "✕")} Files: ${[["critical", count("critical")], ["high", count("high")], ["medium", count("medium")]].filter(([, k]) => Number(k) > 0).map(([s, k]) => `${k} ${s}`).join(", ")} (${[...new Set(serious.map((f) => f.ruleId ?? f.id))].slice(0, 5).join(", ")}). Run \`npx isoklo\` to see each one.`);
  return lines;
}

export function toText(r: DoctorReport, opts: TextOptions): string {
  const paint = (code: string, s: string) => (opts.color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const warn = (s: string) => paint("33", s);
  const dim = (s: string) => paint("2", s);
  const lines: string[] = [`isoklo doctor · ${opts.root}`, ""];

  if (r.files.length > 0) {
    lines.push("Instruction files");
    const width = Math.max(...r.files.map((f) => f.path.length));
    for (const f of r.files) {
      const size = f.tokens === null ? "not read" : `~${n(f.tokens)} tokens`;
      const readers = f.readBy.length > 0 ? `read by ${f.readBy.join(", ")}` : "read by no agent";
      const note = f.note !== undefined ? dim(` (${f.note})`) : "";
      lines.push(`  ${f.path.padEnd(width)}   ${size.padStart(13)}   ${readers}${note}`);
    }
    lines.push("");
  }

  const reviews = r.findings.filter((f) => f.level === "review");
  const infos = r.findings.filter((f) => f.level === "info");
  if (r.findings.length > 0) {
    lines.push("Findings");
    for (const f of [...reviews, ...infos]) {
      const tag = f.level === "review" ? warn("! review") : dim("· info  ");
      lines.push(`  ${tag}  ${f.message}`);
      if (f.fix !== undefined) lines.push(`            fix: ${f.fix}`);
    }
    lines.push("");
  }

  if (opts.posture !== undefined) {
    lines.push(...postureText(opts.posture.posture, opts.posture.findings, opts.color), "");
  }

  const summary =
    reviews.length === 0
      ? "No problems found."
      : `${reviews.length} ${reviews.length === 1 ? "finding" : "findings"} to review.`;
  lines.push(`${summary} ${dim(`Estimated total: ~${n(r.totalTokens)} tokens of instructions. Doctor is advisory and never blocks a merge.`)}`);
  return lines.join("\n") + "\n";
}

export function toJson(r: DoctorReport, root: string, version: string, posture?: { posture: Posture; findings: Finding[] }): string {
  const extra = posture === undefined ? {} : {
    posture: {
      grade: posture.posture.grade,
      score: posture.posture.score,
      meaning: GRADE_MEANING[posture.posture.grade],
      checks: posture.posture.checks,
      deductions: posture.posture.deductions,
      scanFindings: posture.findings.map((f) => ({ ruleId: f.ruleId, level: f.level, severity: f.severity, message: f.message, path: f.evidence[0]?.path ?? null, line: f.evidence[0]?.line ?? null })),
    },
  };
  return JSON.stringify({ tool: "isoklo", command: "doctor", version, root, tokensAreEstimates: true, ...r, ...extra }, null, 2) + "\n";
}
