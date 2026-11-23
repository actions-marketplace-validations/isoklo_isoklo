/**
 * Check and scan report (pure): verdict first, then evidence, then why it matters and the fix. Text for people, JSON
 * for CI. Every rule's findings are shown together: blocked first, then review, then info, most severe first.
 */
import { ruleMeta } from "../engine/registry.js";
import { visible } from "../engine/visible.js";
import type { Finding, RuleResult, Severity } from "./types.js";

export interface CheckSummary {
  /** check: a change against its base. scan: the files as they are. (v1 JSON had no mode: it was always check.) */
  mode?: "check" | "scan";
  /** check: the base ref. scan: the folder that was scanned. */
  base: string;
  head: string;
  /** check: files changed. scan: files read. */
  filesChanged: number;
  results: RuleResult[];
  /** Every rule (id and version) that ran, for receipts. */
  rulesRun?: { id: string; version: number }[];
  /** Where the policy came from, or null when the defaults applied. */
  configSource?: string | null;
}

const all = (s: CheckSummary) => s.results.flatMap((r) => r.findings);

export const verdictOf = (s: CheckSummary) => (all(s).some((f) => f.level === "blocked") ? "blocked" : "passed");

export const findingsOf = (s: CheckSummary): Finding[] => {
  const rank = { blocked: 0, review: 1, info: 2 } as const;
  const sev = { critical: 0, high: 1, medium: 2, info: 3 } as const;
  return all(s).slice().sort((a, b) => rank[a.level] - rank[b.level] || sev[a.severity ?? "info"] - sev[b.severity ?? "info"]);
};

export const countBySeverity = (findings: Finding[]) => {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, info: 0 };
  for (const f of findings) if (f.level !== "info" || f.severity === "info") out[f.severity ?? "info"]++;
  return out;
};

const MAX_EVIDENCE = 8;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export interface TextOptions {
  color: boolean;
  /** Show each rule's "why" (the attack it stops). On by default; --quiet style output can turn it off. */
  why?: boolean;
}

export function toText(s: CheckSummary, colorOrOptions: boolean | TextOptions): string {
  const o: TextOptions = typeof colorOrOptions === "boolean" ? { color: colorOrOptions } : colorOrOptions;
  const paint = (code: string, t: string) => (o.color ? `\x1b[${code}m${t}\x1b[0m` : t);
  const red = (t: string) => paint("31", t);
  const yellow = (t: string) => paint("33", t);
  const green = (t: string) => paint("32", t);
  const dim = (t: string) => paint("2", t);
  const bold = (t: string) => paint("1", t);
  const SEV: Record<Severity, string> = {
    critical: o.color ? paint("1;97;41", " CRITICAL ") : "CRITICAL",
    high: paint("1;31", "HIGH"),
    medium: paint("33", "MEDIUM"),
    info: paint("2", "INFO"),
  };

  const stat = (k: string) => s.results.reduce((n, r) => n + (r.stats[k] ?? 0), 0);
  const out: string[] = [
    s.mode === "scan"
      ? `isoklo scan · ${s.base} · ${plural(s.filesChanged, "file")} read, ${plural(s.rulesRun?.length ?? 0, "rule")}`
      : `isoklo check · ${s.base}...${s.head} · ${plural(s.filesChanged, "file")} changed, ` +
        `${plural(stat("testFiles"), "test file")}, ${plural(stat("packagesAdded"), "new package")}, ${plural(stat("configFiles"), "config file")}`,
    "",
  ];

  const findings = findingsOf(s);
  for (const f of findings) {
    const tag = f.level === "blocked" ? red("✕ blocked") : f.level === "review" ? yellow("! review ") : dim("· info   ");
    out.push(`${tag}  ${f.message}`);
    if (f.ruleId !== undefined) out.push(`           ${SEV[f.severity ?? "info"]} ${dim("·")} ${bold(f.ruleId)}`);
    if (f.evidence.length > 0) {
      // File names come from the repository too: never let one write control sequences to the terminal.
      const width = Math.max(...f.evidence.slice(0, MAX_EVIDENCE).map((e) => `${visible(e.path)}:${e.line}`.length));
      for (const e of f.evidence.slice(0, MAX_EVIDENCE)) {
        out.push(`             ${`${visible(e.path)}:${e.line}`.padEnd(width)}  ${dim(visible(e.text))}`);
      }
      if (f.evidence.length > MAX_EVIDENCE) out.push(dim(`             and ${f.evidence.length - MAX_EVIDENCE} more`));
    }
    const meta = f.ruleId === undefined ? undefined : ruleMeta(f.ruleId);
    if (o.why !== false && meta !== undefined && f.level !== "info") out.push(dim(`           why: ${meta.why}`));
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

export function toJson(s: CheckSummary, version: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ tool: "isoklo", command: s.mode ?? "check", version, verdict: verdictOf(s), ...s, ...extra }, null, 2) + "\n";
}
