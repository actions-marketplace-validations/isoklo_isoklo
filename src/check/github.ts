/**
 * GitHub Actions output (pure): workflow-command annotations that put each finding on the exact changed line of the
 * pull request, and a markdown job summary for the checks page.
 *
 * GitHub shows at most 10 annotations of each type per step (50 per job), so annotations favour blocked findings and
 * the job summary always lists everything.
 */
import type { Finding } from "./types.js";
import type { CheckSummary } from "./report.js";
import { verdictOf } from "./report.js";
import { cell as mdCell, code as mdCode } from "../output/markdown.js";

/** Escaping for the message part of a workflow command. */
export const escapeData = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

/** Escaping for property values (file=, title=): also colons and commas, which separate properties. */
export const escapeProperty = (s: string) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

const COMMAND = { blocked: "error", review: "warning", info: "notice" } as const;
export const PER_TYPE_LIMIT = 10;

export function annotations(s: CheckSummary): string[] {
  const findings = s.results.flatMap((r) => r.findings);
  const out: string[] = [];
  const used = { error: 0, warning: 0, notice: 0 };
  for (const level of ["blocked", "review", "info"] as const) {
    for (const f of findings.filter((x) => x.level === level)) {
      const cmd = COMMAND[f.level];
      const title = `Isoklo: ${f.level}`;
      const body = `${f.message}\n${f.allowedBecause !== undefined ? `allowed: ${f.allowedBecause}` : `fix: ${f.fix}`}`;
      // One annotation per finding, placed on its first piece of evidence (or on the file, or the run).
      if (used[cmd] >= PER_TYPE_LIMIT) continue;
      used[cmd]++;
      // Removed lines no longer exist in the new file: annotate where the removal happened instead.
      const e = f.evidence[0];
      const at = e?.anchor ?? (e === undefined ? undefined : { path: e.path, line: e.line });
      const where = at === undefined ? "" : ` file=${escapeProperty(at.path)},line=${Math.max(1, at.line)},`;
      out.push(`::${cmd}${where}${where === "" ? " " : ""}title=${escapeProperty(title)}::${escapeData(body)}`);
    }
  }
  return out;
}

/** Markdown cells must not break the table, and repository text must stay inert: the same escaping as the App's comment. */
const cell = mdCell;
const code = mdCode;
const ICON = { blocked: "✕ blocked", review: "! review", info: "· info" } as const;

export function jobSummary(s: CheckSummary): string {
  const findings: Finding[] = (["blocked", "review", "info"] as const)
    .flatMap((lv) => s.results.flatMap((r) => r.findings).filter((f) => f.level === lv));
  const verdict = verdictOf(s);
  const blocked = findings.filter((f) => f.level === "blocked").length;
  const review = findings.filter((f) => f.level === "review").length;
  const lines = [
    `## isoklo · ${verdict}`,
    "",
    verdict === "blocked"
      ? `**${blocked} ${blocked === 1 ? "problem" : "problems"} must be fixed before merge.**`
      : `**Passed.**${review > 0 ? ` ${review} to review.` : ""}`,
    "",
    `${code(`${s.base}...${s.head}`)} · ${s.filesChanged} ${s.filesChanged === 1 ? "file" : "files"} changed`,
    "",
  ];
  if (findings.length > 0) {
    lines.push("| | Finding | Where | Fix |", "|---|---|---|---|");
    for (const f of findings) {
      const where = f.evidence.slice(0, 3).map((e) => code(`${e.path}:${e.line}`)).join("<br>") +
        (f.evidence.length > 3 ? `<br>and ${f.evidence.length - 3} more` : "");
      const fix = f.allowedBecause !== undefined ? `allowed: ${f.allowedBecause}` : f.fix;
      lines.push(`| ${ICON[f.level]} | ${cell(f.message)} | ${where} | ${cell(fix)} |`);
    }
    lines.push("");
  }
  const passes = s.results.flatMap((r) => r.passes);
  if (verdict === "passed" && passes.length > 0) {
    lines.push(...passes.map((p) => `- ✓ ${cell(p)}`), "");
  }
  lines.push("<sub>Isoklo checks agent pull requests deterministically: the same change always gets the same verdict.</sub>", "");
  return lines.join("\n");
}

/** For exit 2: make "could not run" impossible to miss in the pull request, so the gate fails closed and visibly. */
export const couldNotRunAnnotation = (message: string) =>
  `::error title=${escapeProperty("Isoklo could not run")}::${escapeData(`${message}\nThe check failed closed: nothing was approved.`)}`;
