/**
 * Markdown summary of a run, for the GitHub App's check run and its single pull request comment. Verdict first, then
 * a table of findings with the exact place, then why and how to fix, then the evidence receipt. Kept under GitHub's
 * 65,535-character limit.
 */
import type { CheckSummary } from "../check/report.js";
import { findingsOf, verdictOf } from "../check/report.js";
import type { Finding, Severity } from "../check/types.js";
import { ruleMeta } from "../engine/registry.js";
import type { Receipt } from "../engine/receipt.js";
import { visible } from "../engine/visible.js";

export interface MarkdownOptions {
  receipt?: Receipt;
  /** Shown under the heading, for example "Isoklo Team · org policy from acme/.github". */
  subtitle?: string;
  /** Link for a "how to fix" footer. */
  detailsUrl?: string;
  maxFindings?: number;
  /** Include the full receipt JSON in a collapsed block (for audit trails). */
  receiptJson?: boolean;
}

/**
 * Text from the repository, made inert for a GitHub comment: no HTML or images (&lt;), no links ([ ]), no emphasis,
 * no table breaks (|), and no @mentions or #references (a zero-width space after the sign), so a file name or a line
 * of code cannot ping people, link issues or restyle the comment. One pass, so no replacement is escaped twice.
 */
const MD: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "\\|", "[": "\\[", "]": "\\]", "\\": "\\\\", "`": "\\`", "*": "\\*",
  _: "\\_", "~": "\\~", "@": "@\u200B", "#": "#\u200B",
};
export const cell = (s: string) =>
  visible(s)
    .replace(/[&<>|[\]\\`*_~@#]/g, (c) => MD[c] ?? c)
    // No autolinks either: a URL from the repository shows as text, not as a link in Isoklo's comment.
    .replace(/\b(https?|ftp):\/\//gi, "$1:\u200B//")
    .replace(/\bwww\./gi, "www\u200B.");
/** Inside a code span only the backtick and the table pipe need care; mentions do not trigger in code. */
export const code = (s: string) => "`" + visible(s).replace(/`/g, "ˋ").replace(/\|/g, "\\|") + "`";
const SEV: Record<Severity, string> = { critical: "**CRITICAL**", high: "**HIGH**", medium: "MEDIUM", info: "info" };
const ICON = { blocked: "✕ blocked", review: "! review", info: "· info" } as const;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function markdownSummary(s: CheckSummary, o: MarkdownOptions = {}): string {
  const findings = findingsOf(s);
  const verdict = verdictOf(s);
  const blocked = findings.filter((f) => f.level === "blocked").length;
  const review = findings.filter((f) => f.level === "review").length;
  const max = o.maxFindings ?? 50;
  const lines: string[] = [
    `## isoklo · ${verdict}`,
    "",
    verdict === "blocked" ? `**${plural(blocked, "problem")} must be fixed before merge.**${review > 0 ? ` ${review} more to review.` : ""}` : `**Passed.**${review > 0 ? ` ${review} to review.` : ""}`,
    "",
    `${s.mode === "scan" ? code(s.base) : code(`${s.base}...${s.head}`)} · ${plural(s.filesChanged, "file")} ${s.mode === "scan" ? "read" : "changed"} · ${plural(s.rulesRun?.length ?? 0, "rule")}${o.subtitle ? ` · ${cell(o.subtitle)}` : ""}`,
    "",
  ];
  const shown = findings.filter((f) => f.level !== "info").slice(0, max);
  if (shown.length > 0) {
    lines.push("| | Severity | Finding | Where |", "|---|---|---|---|");
    for (const f of shown) {
      const where = f.evidence.slice(0, 3).map((e) => code(`${e.path}:${e.line}`)).join("<br>") + (f.evidence.length > 3 ? `<br>and ${f.evidence.length - 3} more` : "");
      lines.push(`| ${ICON[f.level]} | ${SEV[f.severity ?? "info"]} | ${cell(f.message)}<br><sub>${code(f.ruleId ?? f.id)}</sub> | ${where} |`);
    }
    if (findings.filter((f) => f.level !== "info").length > max) lines.push("", `<sub>and ${findings.filter((f) => f.level !== "info").length - max} more; run \`npx isoklo check\` for the full list.</sub>`);
    lines.push("", "<details><summary>Why each finding matters, and how to fix it</summary>", "");
    const seen = new Set<string>();
    for (const f of shown) {
      const id = f.ruleId ?? f.id;
      const meta = ruleMeta(id);
      lines.push(`- **${cell(meta?.title ?? id)}** (${code(id)}): ${f.allowedBecause !== undefined ? `allowed: ${cell(f.allowedBecause)}` : `fix: ${cell(f.fix)}`}${meta !== undefined && !seen.has(id) ? `<br><sub>${cell(meta.why)}</sub>` : ""}`);
      seen.add(id);
    }
    lines.push("", "</details>", "");
  } else {
    const passes = s.results.flatMap((r) => r.passes).slice(0, 12);
    if (passes.length > 0) lines.push(...passes.map((p) => `- ✓ ${cell(p)}`), "");
  }
  // Waivers are never silent: who accepted what, and why, stays on the pull request.
  const waived = findings.filter((f) => f.waiver !== undefined);
  if (waived.length > 0) {
    lines.push(`**Waived by maintainers** (${waived.length})`, "");
    for (const f of waived.slice(0, max)) {
      lines.push(`- ${code(f.ruleId ?? f.id)} ${cell(f.message)} · waived by ${cell(f.waiver?.by ?? "")}: ${cell(f.waiver?.reason ?? "")}`);
    }
    lines.push("");
  }
  const infos: Finding[] = findings.filter((f) => f.level === "info" && f.waiver === undefined);
  if (infos.length > 0) lines.push(`<sub>${plural(infos.length, "note")} for the record: ${infos.slice(0, 5).map((f) => cell(f.message)).join(" · ")}</sub>`, "");

  if (o.receipt !== undefined) {
    const r = o.receipt;
    const sig = r.integrity.signature;
    const signed = sig === undefined ? " · unsigned" : sig.algorithm === "ed25519" ? ` · Ed25519-signed (key ${code(sig.keyId)})` : ` · HMAC-signed (${code(sig.keyId)})`;
    lines.push(
      `**Evidence receipt** ${code(`sha256:${r.integrity.digest.slice(0, 16)}…`)}${signed} · engine ${r.engineVersion} · ${plural(r.rules.length, "rule")} · ${r.createdAt.slice(0, 19).replace("T", " ")} UTC`,
      "",
    );
    if (o.receiptJson === true) {
      lines.push(
        "<details><summary>Receipt (canonical JSON) and how to verify it</summary>", "",
        "Save this as `receipt.json`, then run `npx isoklo@latest verify receipt.json`: it recomputes the SHA-256 digest" +
          (sig?.algorithm === "ed25519" ? " and checks the Ed25519 signature against the Isoklo GitHub App's published key." : "."),
        "", "```json", JSON.stringify(r, null, 2), "```", "", "</details>", "",
      );
    }
  }
  lines.push("<sub>Isoklo checks every pull request with fixed rules, not a model: the same change always gets the same verdict.</sub>");
  let out = lines.join("\n");
  if (out.length > 60_000) out = `${out.slice(0, 59_000)}\n\n<sub>Summary shortened to fit GitHub's limit.</sub>`;
  return out;
}
