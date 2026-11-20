/**
 * Check report (pure): verdict first, then evidence, then the fix. Text for people, JSON for CI.
 * Every rule's findings are shown together: blocked first, then review, then info.
 */
import type { Finding, RuleResult } from "./types.js";

export interface CheckSummary {
  base: string;
  head: string;
  filesChanged: number;
  results: RuleResult[];
}

const all = (s: CheckSummary) => s.results.flatMap((r) => r.findings);

export const verdictOf = (s: CheckSummary) => (all(s).some((f) => f.level === "blocked") ? "blocked" : "passed");

const MAX_EVIDENCE = 8;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function toText(s: CheckSummary, color: boolean): string {
  const paint = (code: string, t: string) => (color ? `\x1b[${code}m${t}\x1b[0m` : t);
  const red = (t: string) => paint("31", t);
  const yellow = (t: string) => paint("33", t);
  const green = (t: string) => paint("32", t);
  const dim = (t: string) => paint("2", t);

  const stat = (k: string) => s.results.reduce((n, r) => n + (r.stats[k] ?? 0), 0);
  const out: string[] = [
    `isoklo check · ${s.base}...${s.head} · ${plural(s.filesChanged, "file")} changed, ` +
      `${plural(stat("testFiles"), "test file")}, ${plural(stat("packagesAdded"), "new package")}, ${plural(stat("configFiles"), "config file")}`,
    "",
  ];

  const findings = all(s);
  const ordered: Finding[] = (["blocked", "review", "info"] as const).flatMap((lv) => findings.filter((f) => f.level === lv));
  for (const f of ordered) {
    const tag = f.level === "blocked" ? red("✕ blocked") : f.level === "review" ? yellow("! review ") : dim("· info   ");
    out.push(`${tag}  ${f.message}`);
    if (f.evidence.length > 0) {
      const width = Math.max(...f.evidence.map((e) => `${e.path}:${e.line}`.length));
      for (const e of f.evidence.slice(0, MAX_EVIDENCE)) {
        out.push(`             ${`${e.path}:${e.line}`.padEnd(width)}  ${dim(e.text)}`);
      }
      if (f.evidence.length > MAX_EVIDENCE) out.push(dim(`             and ${f.evidence.length - MAX_EVIDENCE} more`));
    }
    out.push(f.allowedBecause !== undefined ? `           allowed: ${f.allowedBecause}` : `           fix: ${f.fix}`);
    out.push("");
  }

  if (verdictOf(s) === "passed") {
    for (const p of s.results.flatMap((r) => r.passes)) out.push(`${green("✓ passed ")}  ${p}`);
    out.push("");
  }

  const blocked = findings.filter((f) => f.level === "blocked").length;
  const review = findings.filter((f) => f.level === "review").length;
  out.push(
    blocked > 0
      ? `${red("blocked")} · ${plural(blocked, "problem")} must be fixed before merge.`
      : `${green("passed")}${review > 0 ? ` · ${review} to review` : ""}.`,
  );
  return out.join("\n") + "\n";
}

export function toJson(s: CheckSummary, version: string): string {
  return JSON.stringify({ tool: "isoklo", command: "check", version, verdict: verdictOf(s), ...s }, null, 2) + "\n";
}
