/**
 * Turn GitHub's "list pull request files" answer into the same parsed diff `git diff` produces, so the GitHub App runs
 * exactly the rules the CLI runs. GitHub omits `patch` for binary files and very large diffs; for added or deleted
 * files the caller can rebuild the diff from the whole file (wholeFileDiff), and anything still unreadable is reported.
 */
import { parseDiff, type FileDiff } from "../check/diff.js";

export interface PullFile {
  filename: string;
  previous_filename?: string;
  status: "added" | "removed" | "modified" | "renamed" | "copied" | "changed" | "unchanged";
  patch?: string;
}

export interface PullDiff {
  files: FileDiff[];
  /** Files whose line changes GitHub did not return (binary, or a diff too large); rules cannot read them. */
  unreadable: string[];
}

function header(f: PullFile): string {
  const oldPath = f.previous_filename ?? f.filename;
  const lines = [`diff --git a/${oldPath} b/${f.filename}`];
  if (f.status === "added") lines.push("new file mode 100644", "--- /dev/null", `+++ b/${f.filename}`);
  else if (f.status === "removed") lines.push("deleted file mode 100644", `--- a/${f.filename}`, "+++ /dev/null");
  else {
    if (f.status === "renamed") lines.push(`rename from ${oldPath}`, `rename to ${f.filename}`);
    lines.push(`--- a/${oldPath}`, `+++ b/${f.filename}`);
  }
  return lines.join("\n");
}

export function fileDiffsFromPullFiles(files: PullFile[]): PullDiff {
  const out: FileDiff[] = [];
  const unreadable: string[] = [];
  for (const f of files) {
    if (f.status === "unchanged") continue;
    const parsed = parseDiff(`${header(f)}\n${f.patch ?? ""}\n`)[0];
    if (parsed === undefined) continue;
    if (f.patch === undefined && !(f.status === "renamed" || f.status === "copied")) {
      parsed.binary = true;
      unreadable.push(f.filename);
    }
    out.push(parsed);
  }
  return { files: out, unreadable };
}

/**
 * A diff rebuilt from both sides of a modified file, for when GitHub leaves the patch out (very large diffs). Lines are
 * matched by content, not position, so moved lines cancel and every new line is seen; line numbers are each side's own.
 */
export function rebuildDiff(diff: FileDiff, before: string, after: string): FileDiff {
  const split = (t: string) => {
    const lines = t.split("\n").map((l) => l.replace(/\r$/, ""));
    if (lines.at(-1) === "") lines.pop();
    return lines;
  };
  const a = split(before);
  const b = split(after);
  const left = new Map<string, number>();
  for (const l of a) left.set(l, (left.get(l) ?? 0) + 1);
  const right = new Map<string, number>();
  for (const l of b) right.set(l, (right.get(l) ?? 0) + 1);
  const added = b.flatMap((text, i) => {
    const n = left.get(text) ?? 0;
    if (n > 0) { left.set(text, n - 1); return []; }
    return [{ line: i + 1, text }];
  });
  const removed = a.flatMap((text, i) => {
    const n = right.get(text) ?? 0;
    if (n > 0) { right.set(text, n - 1); return []; }
    return [{ line: i + 1, text, newAt: Math.min(i + 1, Math.max(1, b.length)) }];
  });
  return { ...diff, binary: false, added, removed };
}

/** A diff rebuilt from a whole file: every line added (new file) or removed (deleted file). */
export function wholeFileDiff(diff: FileDiff, content: string): FileDiff {
  const lines = content.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (diff.status === "added") return { ...diff, binary: false, added: lines.map((text, i) => ({ line: i + 1, text: text.replace(/\r$/, "") })) };
  if (diff.status === "deleted") return { ...diff, binary: false, removed: lines.map((text, i) => ({ line: i + 1, text: text.replace(/\r$/, ""), newAt: 1 })) };
  return diff;
}
