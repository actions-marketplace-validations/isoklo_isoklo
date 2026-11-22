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

const ESCAPES: Record<string, number> = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, "\\": 92 };

/**
 * Git quotes paths that contain quotes, backslashes, control characters or (unless core.quotePath is false) non-ASCII
 * bytes, C-style: "caf\303\251.ts". Decode them back to the real path, so rules and scope see what is on disk.
 */
export function unquotePath(p: string): string {
  if (!(p.length >= 2 && p.startsWith('"') && p.endsWith('"'))) return p;
  const body = p.slice(1, -1);
  const bytes: number[] = [];
  for (let i = 0; i < body.length; i++) {
    const c = body[i] as string;
    if (c !== "\\") {
      for (const b of new TextEncoder().encode(c)) bytes.push(b);
      continue;
    }
    const next = body[i + 1] ?? "";
    const octal = /^[0-7]{3}/.exec(body.slice(i + 1, i + 4));
    if (octal) {
      bytes.push(parseInt(octal[0], 8));
      i += 3;
    } else if (ESCAPES[next] !== undefined) {
      bytes.push(ESCAPES[next] as number);
      i += 1;
    } else {
      bytes.push(92);
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/** Git writes "a/<path>" and "b/<path>"; /dev/null means the file does not exist on that side. */
function stripPrefix(raw: string): string | null {
  const p = raw.replace(/\t$/, "");
  if (p === "/dev/null") return null;
  return unquotePath(p).replace(/^[ab]\//, "");
}

/** The two paths of a `diff --git` header, quoted or not. */
function headerPaths(rest: string): [string, string] | null {
  const quoted = /^("(?:[^"\\]|\\.)*")\s+("(?:[^"\\]|\\.)*")$/.exec(rest);
  if (quoted) return [unquotePath(quoted[1] as string).replace(/^a\//, ""), unquotePath(quoted[2] as string).replace(/^b\//, "")];
  const mixed = /^(?:a\/(.*?)|("(?:[^"\\]|\\.)*")) (?:b\/(.*)|("(?:[^"\\]|\\.)*"))$/.exec(rest);
  if (mixed && (mixed[2] !== undefined || mixed[4] !== undefined)) {
    const a = mixed[2] !== undefined ? unquotePath(mixed[2]).replace(/^a\//, "") : (mixed[1] ?? "");
    const b = mixed[4] !== undefined ? unquotePath(mixed[4]).replace(/^b\//, "") : (mixed[3] ?? "");
    return [a, b];
  }
  const plain = /^a\/(.*) b\/(.*)$/.exec(rest);
  return plain ? [plain[1] ?? "", plain[2] ?? ""] : null;
}

export function parseDiff(text: string): FileDiff[] {
  const files: FileDiff[] = [];
  let cur: FileDiff | null = null;
  let oldLine = 0;
  let newLine = 0;
  let removalAnchor = 1;
  // Lines still expected in the current hunk, from its header. Inside a hunk every line is content, even one that
  // looks like a header ("--- " is a removed line starting with "-- ", such as an SQL comment).
  let oldLeft = 0;
  let newLeft = 0;

  for (const raw of text.split("\n")) {
    const lineText = raw.endsWith("\r") ? raw.slice(0, -1) : raw;

    if (cur !== null && (oldLeft > 0 || newLeft > 0)) {
      if (lineText.startsWith("-") && oldLeft > 0) {
        cur.removed.push({ line: oldLine++, text: lineText.slice(1), newAt: removalAnchor });
        oldLeft--;
        continue;
      }
      if (lineText.startsWith("+") && newLeft > 0) {
        cur.added.push({ line: newLine++, text: lineText.slice(1) });
        newLeft--;
        continue;
      }
      if (lineText.startsWith(" ") && oldLeft > 0 && newLeft > 0) {
        // Context line (patches from the GitHub API carry three): a removal after it sits after this new line.
        removalAnchor = newLine;
        oldLine++;
        newLine++;
        oldLeft--;
        newLeft--;
        continue;
      }
      if (lineText.startsWith("\\")) continue; // "\ No newline at end of file"
      // Anything else ends the hunk early (a truncated patch); fall through and read it as a header.
      oldLeft = 0;
      newLeft = 0;
    }

    if (lineText.startsWith("diff --git ")) {
      cur = { oldPath: null, newPath: null, status: "modified", binary: false, removed: [], added: [] };
      // Fallback paths from the header, in case there are no ---/+++ lines (pure renames, mode changes).
      const m = headerPaths(lineText.slice("diff --git ".length));
      if (m) {
        cur.oldPath = m[0];
        cur.newPath = m[1];
      }
      files.push(cur);
      continue;
    }
    if (cur === null) continue;

    if (lineText.startsWith("new file mode")) cur.status = "added";
    else if (lineText.startsWith("deleted file mode")) cur.status = "deleted";
    else if (lineText.startsWith("rename from ")) { cur.status = "renamed"; cur.oldPath = unquotePath(lineText.slice(12)); }
    else if (lineText.startsWith("rename to ")) { cur.status = "renamed"; cur.newPath = unquotePath(lineText.slice(10)); }
    else if (lineText.startsWith("Binary files ")) cur.binary = true;
    else if (lineText.startsWith("--- ")) cur.oldPath = stripPrefix(lineText.slice(4));
    else if (lineText.startsWith("+++ ")) cur.newPath = stripPrefix(lineText.slice(4));
    else if (lineText.startsWith("@@")) {
      const h = HUNK.exec(lineText);
      if (h) {
        oldLine = Number(h[1]);
        newLine = Number(h[3]);
        oldLeft = h[2] === undefined ? 1 : Number(h[2]);
        newLeft = h[4] === undefined ? 1 : Number(h[4]);
        // "+c,0" means the lines were removed after new line c; otherwise they were replaced at line c.
        removalAnchor = Math.max(1, newLine);
      }
    }
  }

  for (const f of files) {
    if (f.status === "added") f.oldPath = null;
    if (f.status === "deleted") f.newPath = null;
  }
  return files;
}
