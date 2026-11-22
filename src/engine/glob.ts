/**
 * Glob patterns for scope and policy, matched against repository-relative paths with forward slashes. Pure, and the
 * same in Node and Cloudflare Workers (node:path's matchesGlob is not available there).
 *
 *   **        any number of folders (including none)
 *   *         anything except /
 *   ?         one character except /
 *   {a,b}     either alternative
 *   [abc]     one of the characters ([!abc] or [^abc]: none of them)
 *   dir/      a trailing slash means everything inside the folder
 *   *.md      a pattern without / matches the file name at any depth, like .gitignore
 *   /README   a leading slash anchors the pattern to the repository root
 *   src\a\**  backslashes (Windows) are read as /
 *
 * Patterns come from pull request bodies, which anyone can write, so matching must never be slow and never throw: it
 * is a memoised walk over (pattern position, path position), linear in their product, with no regular expressions.
 * An unusable pattern (too long, too many alternatives) matches nothing, which keeps a declared scope closed.
 */

type Token =
  | { t: "lit"; c: string }
  | { t: "one" }
  | { t: "star" }
  | { t: "globstar" }
  | { t: "dirs" } // "**/": zero or more whole folders
  | { t: "class"; negate: boolean; ranges: [number, number][] };

export const MAX_PATTERN = 512;
const MAX_PATH = 4096;
const MAX_EXPANSIONS = 256;

/** Expand {a,b} alternatives (nested too) into plain patterns; null when there are too many. */
function expandBraces(p: string): string[] | null {
  const open = p.indexOf("{");
  if (open < 0) return [p];
  let depth = 0;
  let close = -1;
  const commas: number[] = [];
  for (let i = open; i < p.length; i++) {
    const c = p[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) { close = i; break; }
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close < 0) return [p]; // an unclosed brace is a literal character
  const parts: string[] = [];
  let start = open + 1;
  for (const c of [...commas, close]) {
    parts.push(p.slice(start, c));
    start = c + 1;
  }
  const head = p.slice(0, open);
  const tails = expandBraces(p.slice(close + 1));
  if (tails === null) return null;
  const out: string[] = [];
  for (const part of parts) {
    const inner = expandBraces(part);
    if (inner === null) return null;
    for (const i of inner) for (const t of tails) {
      out.push(head + i + t);
      if (out.length > MAX_EXPANSIONS) return null;
    }
  }
  return out;
}

function tokenize(p: string): Token[] {
  const out: Token[] = [];
  for (let i = 0; i < p.length; i++) {
    const c = p[i] as string;
    if (c === "*") {
      let j = i;
      while (p[j + 1] === "*") j++;
      if (j > i) {
        // ** (any run of two or more stars); "**/" is zero or more folders.
        if (p[j + 1] === "/") { out.push({ t: "dirs" }); i = j + 1; }
        else { out.push({ t: "globstar" }); i = j; }
      } else {
        if (out.at(-1)?.t !== "star") out.push({ t: "star" });
      }
    } else if (c === "?") {
      out.push({ t: "one" });
    } else if (c === "[") {
      const end = p.indexOf("]", i + 2);
      if (end < 0) { out.push({ t: "lit", c }); continue; }
      let body = p.slice(i + 1, end);
      const negate = body.startsWith("!") || body.startsWith("^");
      if (negate) body = body.slice(1);
      const ranges: [number, number][] = [];
      for (let k = 0; k < body.length; k++) {
        const a = body.codePointAt(k) as number;
        if (body[k + 1] === "-" && k + 2 < body.length) {
          const b = body.codePointAt(k + 2) as number;
          if (a <= b) ranges.push([a, b]); // a reversed range ([z-a]) matches nothing
          k += 2;
        } else ranges.push([a, a]);
      }
      out.push({ t: "class", negate, ranges });
      i = end;
    } else {
      out.push({ t: "lit", c });
    }
  }
  return out;
}

function compile(pattern: string): Token[][] {
  let p = pattern.trim().replace(/\\/g, "/");
  if (p === "" || p.length > MAX_PATTERN) return [];
  if (p.endsWith("/")) p += "**";
  let anyDepth = false;
  if (p.startsWith("/")) p = p.slice(1);
  else if (p.startsWith("./")) p = p.slice(2);
  else if (!p.includes("/")) anyDepth = true; // name-only patterns match at any depth
  const expanded = expandBraces(p);
  if (expanded === null) return [];
  return expanded.map((e) => {
    const tokens = tokenize(e);
    return anyDepth ? [{ t: "dirs" } as Token, ...tokens] : tokens;
  });
}

function run(tokens: Token[], s: string): boolean {
  const T = tokens.length;
  const n = s.length;
  const memo = new Uint8Array((T + 1) * (n + 1)); // 0 unknown, 1 true, 2 false
  const midMemo = new Uint8Array((T + 1) * (n + 1));
  const at = (i: number, j: number): boolean => {
    const k = i * (n + 1) + j;
    if (memo[k] !== 0) return memo[k] === 1;
    let ok: boolean;
    if (i === T) ok = j === n;
    else {
      const tok = tokens[i] as Token;
      const ch = s[j];
      switch (tok.t) {
        case "lit": ok = ch === tok.c && at(i + 1, j + 1); break;
        case "one": ok = j < n && ch !== "/" && at(i + 1, j + 1); break;
        case "class": {
          const cp = j < n ? (s.codePointAt(j) as number) : -1;
          const inside = tok.ranges.some(([a, b]) => cp >= a && cp <= b);
          ok = j < n && ch !== "/" && inside !== tok.negate && at(i + 1, j + 1);
          break;
        }
        case "star": ok = at(i + 1, j) || (j < n && ch !== "/" && at(i, j + 1)); break;
        case "globstar": ok = at(i + 1, j) || (j < n && at(i, j + 1)); break;
        case "dirs": ok = at(i + 1, j) || mid(i, j); break;
      }
    }
    memo[k] = ok ? 1 : 2;
    return ok;
  };
  // Inside "**/": consume one folder name up to and including its "/", then either stop or take another folder.
  const mid = (i: number, j: number): boolean => {
    const k = i * (n + 1) + j;
    if (midMemo[k] !== 0) return midMemo[k] === 1;
    const ok = j < n && (s[j] === "/" ? at(i, j + 1) : mid(i, j + 1));
    midMemo[k] = ok ? 1 : 2;
    return ok;
  };
  return at(0, 0);
}

const cache = new Map<string, Token[][]>();

export function matchesGlob(path: string, pattern: string): boolean {
  const p = path.replace(/\\/g, "/");
  if (p.length > MAX_PATH) return false;
  let compiled = cache.get(pattern);
  if (compiled === undefined) {
    compiled = compile(pattern);
    if (cache.size > 2000) cache.clear();
    cache.set(pattern, compiled);
  }
  return compiled.some((tokens) => run(tokens, p));
}

export const matchesAny = (path: string, patterns: readonly string[]) => patterns.some((p) => matchesGlob(path, p));
