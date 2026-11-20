/**
 * Report (pure): format a DoctorReport as plain text (people) or JSON (CI and other tools).
 * Voice rules: verdict first, then evidence, then the fix; no exclamation marks; colour only when the terminal supports it.
 */
import type { DoctorReport } from "./analyze.js";

const n = (x: number) => x.toLocaleString("en-US");

export interface TextOptions {
  color: boolean;
  root: string;
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

  const summary =
    reviews.length === 0
      ? "No problems found."
      : `${reviews.length} ${reviews.length === 1 ? "finding" : "findings"} to review.`;
  lines.push(`${summary} ${dim(`Estimated total: ~${n(r.totalTokens)} tokens of instructions. Doctor is advisory and never blocks a merge.`)}`);
  return lines.join("\n") + "\n";
}

export function toJson(r: DoctorReport, root: string, version: string): string {
  return JSON.stringify({ tool: "isoklo", command: "doctor", version, root, tokensAreEstimates: true, ...r }, null, 2) + "\n";
}
