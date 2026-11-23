/**
 * sec/prt-head-checkout and sec/workflow-injection for GitHub Actions workflows and composite actions, plus the static
 * (scan mode) view of v1's workflow-risk signals. A careful line reader, not a YAML parser: Isoklo has no dependencies,
 * and every signal here is visible on one line.
 */
import type { Finding } from "../../check/types.js";
import type { Mode } from "../../engine/registry.js";
import { clip, splitLines, type NumberedLine } from "../../engine/text.js";

/** Lines inside `run:` scripts and actions/github-script `script:` blocks, with their line numbers. */
export function scriptLines(yaml: string): NumberedLine[] {
  const out: NumberedLine[] = [];
  let blockIndent = -1;
  for (const l of splitLines(yaml)) {
    const indent = l.text.length - l.text.trimStart().length;
    if (blockIndent >= 0 && l.text.trim() !== "" && indent <= blockIndent) blockIndent = -1;
    const m = /^(\s*)(- )?(run|script):\s*(.*)$/.exec(l.text);
    if (m) {
      const value = (m[4] ?? "").trim();
      if (/^[|>][-+]?\d*$/.test(value)) blockIndent = (m[1] ?? "").length + (m[2] ? 2 : 0);
      else if (value !== "") out.push({ line: l.line, text: value });
      continue;
    }
    if (blockIndent >= 0) out.push(l);
  }
  return out;
}

/** Event fields an outsider controls: titles, bodies, branch names, commit messages, author names. */
export const UNTRUSTED_INPUT =
  /\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^}]*\.page_name|commits\.[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name))|workflow_run\.(head_branch|head_commit\.message|display_title))|github\.head_ref)\s*\}\}/;
// Not github.event.inputs: workflow_dispatch inputs come from people with write access, not from outsiders.

const PRT_TRIGGER = /^\s*(on:\s*)?(\[.*\bpull_request_target\b.*\]|-?\s*pull_request_target\s*:?\s*$|pull_request_target\s*:)|^\s*on:\s*pull_request_target\s*$/m;
const HEAD_CHECKOUT = /ref:\s*\$\{\{\s*(github\.event\.pull_request\.(head\.(sha|ref)|merge_commit_sha)|github\.head_ref)\s*\}\}|ref:\s*refs\/pull\/\$\{\{[^}]*\}\}\/(head|merge)|gh\s+pr\s+checkout\b|git\s+(fetch|checkout)[^\n]*(pull\/\$\{\{|github\.head_ref|pull_request\.head)/;

/**
 * @param added  check mode: the line numbers the change added (a finding needs one of its lines to be new). null in scan mode.
 */
export function workflowFindings(path: string, after: string, added: Set<number> | null, mode: Mode): Finding[] {
  const out: Finding[] = [];
  const lines = splitLines(after);
  const isNew = (n: number) => added === null || added.has(n);
  const code = (t: string) => t.replace(/(^|\s)#.*$/, "");

  // pull_request_target + checkout of the pull request's code: a stranger's code runs with secrets and write access.
  if (PRT_TRIGGER.test(after.split(/\r?\n/).map(code).join("\n"))) {
    const checkouts = lines.filter((l) => HEAD_CHECKOUT.test(code(l.text)));
    const trigger = lines.find((l) => /pull_request_target/.test(code(l.text)));
    const relevant = added === null || checkouts.some((l) => isNew(l.line)) || (trigger !== undefined && isNew(trigger.line));
    if (checkouts.length > 0 && relevant) {
      out.push({
        rule: "sec", id: "prt-head-checkout", level: "blocked",
        message: `${path} runs on pull_request_target and checks out the pull request's own code. Anyone who opens a pull request can run code with this workflow's secrets and write token.`,
        fix: "use the pull_request trigger for anything that builds or runs pull request code; keep pull_request_target for jobs that only label or comment, and never check out the head there.",
        evidence: checkouts.map((l) => ({ path, line: l.line, text: clip(l.text) })),
      });
    }
  }

  // ${{ github.event.* }} pasted into a shell script.
  const injected = scriptLines(after).filter((l) => UNTRUSTED_INPUT.test(l.text) && isNew(l.line));
  if (injected.length > 0) {
    out.push({
      rule: "sec", id: "workflow-injection", level: "blocked",
      message: `${path} pastes text an outsider controls (titles, bodies, branch names) straight into a script. A crafted pull request title can run commands with the workflow's token.`,
      fix: "pass the value through an environment variable (env: TITLE: ${{ github.event.pull_request.title }}) and use \"$TITLE\" in the script.",
      evidence: injected.map((l) => ({ path, line: l.line, text: clip(l.text) })),
    });
  }

  // Scan mode: v1's workflow-risk signals, as they stand today (check mode reports them through v1's agent-config rule).
  if (mode === "scan") {
    const writeAll = lines.filter((l) => /permissions:\s*write-all\b/.test(code(l.text)));
    if (writeAll.length > 0) {
      out.push({
        rule: "sec", id: "workflow-risk", level: "review", severity: "medium",
        message: `${path} gives its token write access to everything (permissions: write-all).`,
        fix: "grant only the permissions each job needs, for example permissions: { contents: read }.",
        evidence: writeAll.map((l) => ({ path, line: l.line, text: clip(l.text) })),
      });
    }
  }
  return out;
}
