/**
 * Small text helpers shared by the rules. Pure and portable: no Node-only APIs, so the same engine runs in the CLI and
 * in a Cloudflare Worker.
 */
import type { DiffLine, FileDiff } from "../check/diff.js";

export interface NumberedLine {
  line: number;
  text: string;
}

export const splitLines = (text: string): NumberedLine[] =>
  text.split("\n").map((t, i) => ({ line: i + 1, text: t.endsWith("\r") ? t.slice(0, -1) : t }));

/** Shannon entropy in bits per character: random keys score high (4+), words and placeholders low. */
export function entropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** True for text that is not worth reading as source: NUL bytes mean a binary file. */
export const looksBinary = (text: string) => text.slice(0, 8000).includes("\u0000");

export const basename = (path: string) => path.split("/").pop() ?? path;

export const extension = (path: string) => {
  const b = basename(path);
  const i = b.lastIndexOf(".");
  return i <= 0 ? "" : b.slice(i + 1).toLowerCase();
};

/** Prose files: install one-liners and mentions in docs are not code that runs. Agent instruction files are not prose. */
export const isDocPath = (path: string) => /\.(md|mdx|markdown|rst|txt|adoc|asciidoc|html?)$/i.test(path) || /(^|\/)(docs?|documentation)\//i.test(path);

/** Generated, vendored and minified files: rules about code an agent wrote do not apply to them. */
export const isGeneratedPath = (path: string) =>
  /(^|\/)(node_modules|vendor|dist|build|out|coverage|\.next|\.nuxt|target|__pycache__|\.venv|venv|third_party)\//.test(path) ||
  /\.(min\.js|min\.css|map|snap|lock)$/.test(path) ||
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/.test(path);

export const isLockfile = (path: string) =>
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|bun\.lockb|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/.test(path);

export const isManifest = (path: string) =>
  /(^|\/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|Cargo\.toml|go\.mod|composer\.json|Gemfile|setup\.py|setup\.cfg)$/.test(path);

/** Lines added by a change, with numbers in the new file. */
export const addedLines = (f: FileDiff): DiffLine[] => f.added;

/** The path a finding should point at: the new path, or the old one for deletions. */
export const pathOf = (f: FileDiff) => f.newPath ?? f.oldPath ?? "";

/** Lines that were moved, not added: identical text removed elsewhere in the same change. Rules about new code skip them. */
export function movedLines(files: FileDiff[]): Set<string> {
  const removed = new Map<string, number>();
  const norm = (s: string) => s.trim().replace(/\s+/g, " ");
  for (const f of files) for (const l of f.removed) removed.set(norm(l.text), (removed.get(norm(l.text)) ?? 0) + 1);
  const moved = new Set<string>();
  for (const f of files) {
    for (const l of f.added) {
      const n = removed.get(norm(l.text)) ?? 0;
      if (n > 0 && norm(l.text) !== "") { removed.set(norm(l.text), n - 1); moved.add(`${pathOf(f)}:${l.line}`); }
    }
  }
  return moved;
}

/** Keep evidence lines short and on one line. */
export const clip = (s: string, max = 160) => {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
};

/**
 * Where a comment starts on a line, for the common comment syntaxes (// /* # <!-- --), or -1. URLs (https://) and
 * escaped slashes inside regular expressions (\/\/) do not count, so rule sources that mention markers are not comments.
 */
const COMMENT_STARTS: readonly RegExp[] = [/(?<![:\\/])\/\//, /(?<!\\)\/\*/, /(?<=^|\s)#/, /<!--/, /(?<=^|\s)--\s/];

export function commentStart(line: string): number {
  let best = -1;
  for (const re of COMMENT_STARTS) {
    const m = re.exec(line);
    if (m !== null && (best < 0 || m.index < best)) best = m.index;
  }
  return best;
}

/** The comment part of a line (from the comment marker on), or "" when the line has no comment. */
export const commentOf = (line: string) => {
  const at = commentStart(line);
  return at < 0 ? "" : line.slice(at);
};

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
