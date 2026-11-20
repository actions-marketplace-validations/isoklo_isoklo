/**
 * A small, strict parser for `git diff --unified=0` output. Pure: text in, structure out.
 */

export interface DiffLine {
  /** Line number in the old file (removed lines) or the new file (added lines). */
  line: number;
  text: string;
  /** Removed lines only: where the removal sits in the NEW file, so GitHub can draw an annotation there. */
  newAt?: number;
}

export type FileStatus = "added" | "deleted" | "modified" | "renamed";

export interface FileDiff {
  oldPath: string | null;
  newPath: string | null;
  status: FileStatus;
  binary: boolean;
  removed: DiffLine[];
  added: DiffLine[];
}

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** Git writes "a/<path>" and "b/<path>"; /dev/null means the file does not exist on that side. */
function stripPrefix(raw: string): string | null {
  const p = raw.replace(/\t$/, "");
  if (p === "/dev/null") return null;
  const unquoted = p.startsWith('"') && p.endsWith('"') ? p.slice(1, -1) : p;
  return unquoted.replace(/^[ab]\//, "");
}

export function parseDiff(text: string): FileDiff[] {
  const files: FileDiff[] = [];
  let cur: FileDiff | null = null;
  let oldLine = 0;
  let newLine = 0;
  let removalAnchor = 1;

  for (const raw of text.split("\n")) {
    const lineText = raw.endsWith("\r") ? raw.slice(0, -1) : raw;

    if (lineText.startsWith("diff --git ")) {
      cur = { oldPath: null, newPath: null, status: "modified", binary: false, removed: [], added: [] };
      // Fallback paths from the header, in case there are no ---/+++ lines (pure renames, mode changes).
      const m = /^diff --git a\/(.*) b\/(.*)$/.exec(lineText);
      if (m) {
        cur.oldPath = m[1] ?? null;
        cur.newPath = m[2] ?? null;
      }
      files.push(cur);
      continue;
    }
    if (cur === null) continue;

    if (lineText.startsWith("new file mode")) cur.status = "added";
    else if (lineText.startsWith("deleted file mode")) cur.status = "deleted";
    else if (lineText.startsWith("rename from ")) { cur.status = "renamed"; cur.oldPath = lineText.slice(12); }
    else if (lineText.startsWith("rename to ")) { cur.status = "renamed"; cur.newPath = lineText.slice(10); }
    else if (lineText.startsWith("Binary files ")) cur.binary = true;
    else if (lineText.startsWith("--- ")) cur.oldPath = stripPrefix(lineText.slice(4));
    else if (lineText.startsWith("+++ ")) cur.newPath = stripPrefix(lineText.slice(4));
    else if (lineText.startsWith("@@")) {
      const h = HUNK.exec(lineText);
      if (h) {
        oldLine = Number(h[1]);
        newLine = Number(h[3]);
        // "+c,0" means the lines were removed after new line c; otherwise they were replaced at line c.
        removalAnchor = Math.max(1, newLine);
      }
    } else if (lineText.startsWith("-")) {
      cur.removed.push({ line: oldLine++, text: lineText.slice(1), newAt: removalAnchor });
    } else if (lineText.startsWith("+")) {
      cur.added.push({ line: newLine++, text: lineText.slice(1) });
    }
    // "\ No newline at end of file" and context lines (none with --unified=0) are ignored.
  }

  for (const f of files) {
    if (f.status === "added") f.oldPath = null;
    if (f.status === "deleted") f.newPath = null;
  }
  return files;
}
