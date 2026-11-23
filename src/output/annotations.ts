/**
 * Line annotations for a pull request's diff, shared by the GitHub App's check run and the GitHub Action's workflow
 * commands, so both draw the same card the same way.
 *
 * One annotation per (file, line, rule). A removed line no longer exists in the new file, so it is anchored to where
 * it was removed; two deleted assertions next to each other used to land on the same line as two identical cards.
 * Now they draw one card that names both.
 */
import type { CheckSummary } from "../check/report.js";
import { findingsOf } from "../check/report.js";
import type { Finding, Level, Severity } from "../check/types.js";
import { ruleMeta } from "../engine/registry.js";

export interface LineAnnotation {
  path: string;
  line: number;
  level: Level;
  severity: Severity;
  ruleId: string;
  /** "Blocked · HIGH · tamper/test-disabled": the same title on the App's check and the Action's. */
  title: string;
  message: string;
  /** Why the rule exists, from the rule registry. */
  why: string | null;
}

const LABEL: Record<Level, string> = { blocked: "Blocked", review: "Review", info: "Note" };
const RANK: Record<Level, number> = { blocked: 0, review: 1, info: 2 };

export const annotationTitle = (f: Pick<Finding, "level" | "severity" | "ruleId" | "id">) =>
  `${LABEL[f.level]} · ${(f.severity ?? "info").toUpperCase()} · ${f.ruleId ?? f.id}`;

/** What to do about a finding, or why it is accepted. */
export function resolution(f: Finding): string {
  if (f.waiver !== undefined) return `Waived by ${f.waiver.by}: ${f.waiver.reason}`;
  if (f.allowedBecause !== undefined) return `Allowed: ${f.allowedBecause}`;
  return `Fix: ${f.fix}`;
}

const sameFile = (a: string, b: string) => a === b;
const joinLines = (lines: number[]) =>
  lines.length <= 1 ? `line ${lines[0]}` : `lines ${lines.slice(0, -1).join(", ")} and ${lines[lines.length - 1]}`;

/**
 * @param placesPerFinding  how many different lines one finding may annotate (the rest are in the summary). Evidence
 *                          that lands on a line already used counts once, so lines removed together stay together.
 */
export function lineAnnotations(s: CheckSummary, o: { placesPerFinding?: number } = {}): LineAnnotation[] {
  const per = o.placesPerFinding ?? 5;
  type Group = { a: LineAnnotation; messages: string[]; resolutions: string[]; removed: Map<string, number[]> };
  const groups = new Map<string, Group>();
  for (const f of findingsOf(s)) {
    const ruleId = f.ruleId ?? f.id;
    const places = new Set<string>();
    for (const e of f.evidence) {
      const at = e.anchor ?? { path: e.path, line: e.line };
      const line = Math.max(1, at.line);
      const key = `${at.path}\n${line}\n${ruleId}`;
      if (!places.has(key)) {
        if (places.size >= per) continue;
        places.add(key);
      }
      let g = groups.get(key);
      if (g === undefined) {
        g = {
          a: { path: at.path, line, level: f.level, severity: f.severity ?? "info", ruleId, title: "", message: "", why: ruleMeta(ruleId)?.why ?? null },
          messages: [], resolutions: [], removed: new Map(),
        };
        groups.set(key, g);
      } else if (RANK[f.level] < RANK[g.a.level]) {
        g.a.level = f.level;
      }
      if (!g.messages.includes(f.message)) g.messages.push(f.message);
      const r = resolution(f);
      if (!g.resolutions.includes(r)) g.resolutions.push(r);
      if (e.anchor !== undefined) {
        const lines = g.removed.get(e.path) ?? [];
        if (!lines.includes(e.line)) lines.push(e.line);
        g.removed.set(e.path, lines);
      }
    }
  }
  return [...groups.values()].map(({ a, messages, resolutions, removed }) => {
    const gone = [...removed.entries()].map(([path, lines]) =>
      `Removed here: ${joinLines(lines.sort((x, y) => x - y))} of the previous version${sameFile(path, a.path) ? "" : ` of ${path}`}.`);
    const title = `${LABEL[a.level]} · ${a.severity.toUpperCase()} · ${a.ruleId}`;
    return { ...a, title, message: [...messages, ...gone, ...resolutions].join("\n").slice(0, 64_000) };
  });
}
