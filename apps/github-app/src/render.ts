/** What the app writes on a pull request: the check run (with line annotations) and the one summary comment. */
import { findingsOf, markdownCode as code, markdownSummary, markdownText, ruleMeta, verdictOf, type CheckSummary, type Receipt } from "isoklo/engine";
import type { Annotation, CheckRunOutput } from "./github.js";
import type { Entitlements } from "./plans.js";

export const CHECK_NAME = "isoklo";
export const COMMENT_MARKER = "<!-- isoklo:summary -->";
const MAX_ANNOTATIONS = 200;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function annotationsFor(s: CheckSummary): Annotation[] {
  const out: Annotation[] = [];
  for (const f of findingsOf(s)) {
    for (const e of f.evidence.slice(0, 5)) {
      if (out.length >= MAX_ANNOTATIONS) return out;
      const at = e.anchor ?? { path: e.path, line: e.line };
      const meta = f.ruleId ? ruleMeta(f.ruleId) : undefined;
      out.push({
        path: at.path,
        start_line: Math.max(1, at.line),
        end_line: Math.max(1, at.line),
        annotation_level: f.level === "blocked" ? "failure" : f.level === "review" ? "warning" : "notice",
        title: `${f.level === "blocked" ? "Blocked" : f.level === "review" ? "Review" : "Note"} · ${(f.severity ?? "info").toUpperCase()} · ${f.ruleId ?? f.id}`,
        message: `${f.message}\n${f.allowedBecause !== undefined ? `Allowed: ${f.allowedBecause}` : `Fix: ${f.fix}`}`.slice(0, 64_000),
        ...(meta ? { raw_details: meta.why } : {}),
      });
    }
  }
  return out;
}

export interface Coverage {
  /** Files the API listed. */
  listed: number;
  /** Files GitHub says the pull request changes. */
  total: number;
  /** Text files whose changes could not be read at all. */
  unreadable: string[];
}

/**
 * The check run. A change Isoklo could not read in full never passes: files beyond GitHub's 3,000-file listing, or
 * text files whose diff GitHub left out and that could not be rebuilt, make the result action_required.
 */
export function checkRunOutput(s: CheckSummary, receipt: Receipt, ent: Entitlements, coverage: Coverage): { conclusion: "success" | "action_required"; output: CheckRunOutput } {
  const verdict = verdictOf(s);
  const findings = findingsOf(s);
  const blocked = findings.filter((f) => f.level === "blocked").length;
  const review = findings.filter((f) => f.level === "review").length;
  const unlisted = Math.max(0, coverage.total - coverage.listed);
  const incomplete = unlisted > 0 || coverage.unreadable.length > 0;
  const title = verdict === "blocked"
    ? `Blocked: ${plural(blocked, "problem")} to fix before merge`
    : incomplete ? `Not fully checked: ${plural(unlisted + coverage.unreadable.length, "file")} could not be read`
      : review > 0 ? `Passed, ${review} to review` : "Passed";
  const notes = [
    unlisted > 0 ? `${plural(unlisted, "file")} of ${coverage.total} were not listed by GitHub's API (it lists at most 3,000).` : "",
    coverage.unreadable.length > 0 ? `${plural(coverage.unreadable.length, "file")} could not be read through the GitHub API (a diff too large): ${coverage.unreadable.slice(0, 10).map((p) => code(p)).join(", ")}.` : "",
  ].filter(Boolean);
  const note = notes.length > 0
    ? `\n\n**Not everything was checked.** ${notes.join(" ")} Nothing was approved for those files: split the pull request, or run \`npx isoklo check\` in CI to cover them.`
    : "";
  return {
    conclusion: verdict === "blocked" || incomplete ? "action_required" : "success",
    output: {
      title,
      summary: markdownSummary(s, { receipt, subtitle: `plan: ${ent.plan} · policy: ${s.configSource ?? "defaults"}` }) + note,
      annotations: annotationsFor(s),
    },
  };
}

export function commentBody(s: CheckSummary, receipt: Receipt, ent: Entitlements, checkUrl: string | null): string {
  const body = markdownSummary(s, { receipt, receiptJson: ent.signedReceipts, maxFindings: 25 });
  return `${COMMENT_MARKER}\n${body}\n\n<sub>${checkUrl ? `[Line-by-line findings in the isoklo check](${checkUrl}) · ` : ""}This comment updates in place on every push.</sub>\n`;
}

export function upsellOutput(upgradeUrl: string, accountId: number): CheckRunOutput {
  const link = upgradeUrl.includes("?") ? `${upgradeUrl}&client_reference_id=${accountId}` : `${upgradeUrl}?client_reference_id=${accountId}`;
  return {
    title: "Private repositories need Isoklo Pro",
    summary: [
      "## isoklo · not checked",
      "",
      "This repository is private. Isoklo checks public repositories for free; private repositories are part of **Isoklo Pro** and **Isoklo Team**.",
      "",
      `- [Upgrade](${link}): private repositories, signed evidence receipts, alerts; Team adds organisation-wide policy.`,
      "- Or run the same checks yourself in CI with `npx isoklo init --ci`. The CLI is free for any repository.",
      "",
      "<sub>Nothing was approved: this check is neutral, so it does not pass a required gate.</sub>",
    ].join("\n"),
  };
}

export function couldNotRunOutput(message: string): CheckRunOutput {
  return {
    title: "Isoklo could not run",
    summary: `## isoklo · could not run\n\n${markdownText(message)}\n\nThe check failed closed: nothing was approved. Re-run the check, or run \`npx isoklo check\` locally.`,
  };
}

/**
 * A short Slack or Discord message when a pull request is blocked. Finding messages quote the repository, so they are
 * made inert: Slack's &, < and > are escaped (no <!channel> or <@user>), and Discord is told to ping nobody.
 */
export async function alert(url: string, s: CheckSummary, repo: string, prUrl: string, fetchImpl: typeof fetch): Promise<void> {
  const findings = findingsOf(s).filter((f) => f.level === "blocked");
  const slackSafe = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const lines = findings.slice(0, 5).map((f) => `• ${(f.severity ?? "").toUpperCase()} ${f.ruleId}: ${f.message}`);
  const discord = /discord(app)?\.com\/api\/webhooks/.test(url);
  const text = `isoklo blocked ${repo}: ${plural(findings.length, "problem")} in ${prUrl}\n${lines.join("\n")}`;
  const body = discord
    ? { content: text.slice(0, 1900), allowed_mentions: { parse: [] } }
    : { text: slackSafe(text) };
  try {
    await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    console.error(`isoklo: the alert to ${new URL(url).hostname} failed; the check result stands.`);
  }
}
