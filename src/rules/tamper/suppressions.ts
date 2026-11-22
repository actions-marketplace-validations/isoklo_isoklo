/**
 * tamper/check-disabled-file, tamper/suppression-added, tamper/security-suppression: an agent asked to make CI green
 * can silence the checker instead of fixing the code. Only markers inside comments count, and only on lines the change
 * adds (moved lines are not new). Line-level suppressions in test files are common and legitimate, so they are skipped
 * there; whole-file and security suppressions count everywhere.
 *
 * Note for maintainers: markers are written with a character class (@ts-nochec[k]) so this file does not match itself.
 */
import { isTestPath } from "../../check/patterns.js";
import type { Finding } from "../../check/types.js";
import { clip, commentOf, isDocPath, isGeneratedPath, plural } from "../../engine/text.js";
import { findingFrom, type ContentUnit, type Hit } from "../content.js";

interface Marker { re: RegExp; what: string }

const FILE_WIDE: readonly Marker[] = [
  { re: /@ts-nochec[k]\b/, what: "@ts-nocheck turns off TypeScript for the whole file" },
  { re: /^(\/\*|\/\/)\s*eslint-disabl[e]\s*(\*\/)?\s*$/, what: "eslint-disable with no rule list turns off every ESLint rule for the whole file" },
  { re: /^(\/\*|\/\/)\s*oxlint-disabl[e]\s*(\*\/)?\s*$/, what: "oxlint-disable turns off every oxlint rule for the whole file" },
  { re: /biome-ignore-al[l]\b/, what: "biome-ignore-all turns Biome off for the whole file" },
  { re: /deno-lint-ignore-fil[e]\s*$/, what: "deno-lint-ignore-file turns off every Deno lint rule for the whole file" },
  { re: /^#\s*pylint:\s*skip-fil[e]\b/, what: "pylint: skip-file turns Pylint off for the whole file" },
  { re: /^#\s*(flake8|ruff):\s*noq[a]\s*$/i, what: "a file-level noqa turns the linter off for the whole file" },
  { re: /^#\s*mypy:\s*ignore-error[s]\b/, what: "mypy: ignore-errors turns type-checking off for the whole file" },
  { re: /^#\s*pyright:\s*basi[c]\b|^#\s*pyright:\s*strict\s*=\s*fals[e]/, what: "turns Pyright's strict checks off for the whole file" },
  { re: /(istanbul|c8|v8)\s+ignore\s+fil[e]\b/, what: "hides the whole file from coverage" },
  { re: /^\/\/\s*@flow\s+wea[k]\b/, what: "@flow weak turns most Flow checks off" },
];

const LINE_LEVEL: readonly Marker[] = [
  { re: /@ts-ignor[e]\b/, what: "@ts-ignore" },
  { re: /@ts-expect-erro[r]\b/, what: "@ts-expect-error" },
  { re: /eslint-disable-(next-)?lin[e]\b/, what: "eslint-disable-next-line" },
  { re: /^(\/\*|\/\/)\s*eslint-disabl[e]\s+[@\w]/, what: "eslint-disable (rules, to end of file)" },
  { re: /oxlint-disable-(next-)?lin[e]\b/, what: "oxlint-disable-next-line" },
  { re: /biome-ignor[e](?!-all)\b/, what: "biome-ignore" },
  { re: /deno-lint-ignor[e](?!-file)\b/, what: "deno-lint-ignore" },
  { re: /^#\s*noq[a]\b(?!:\s*S\d)/i, what: "# noqa" },
  { re: /^#\s*type:\s*ignor[e]\b/, what: "# type: ignore" },
  { re: /^#\s*pyright:\s*ignor[e]\b/, what: "# pyright: ignore" },
  { re: /^#\s*pylint:\s*disabl[e]\b/, what: "# pylint: disable" },
  { re: /(istanbul|c8|v8)\s+ignore\s+(nex[t]|if|else|start)\b/, what: "coverage ignore" },
  { re: /^\/\/\s*nolin[t]\b/i, what: "golangci-lint nolint" },
  { re: /^#\s*rubocop:\s*disabl[e]\b/, what: "rubocop:disable" },
  { re: /^\/\/\s*NOLIN[T]/, what: "NOLINT" },
  { re: /^\/\/\s*\$FlowFixM[e]|^\/\/\s*\$FlowIgnor[e]/, what: "$FlowFixMe" },
];

/** Code-level suppressions outside comments (Java, Rust, C#). */
const CODE_LEVEL: readonly Marker[] = [
  { re: /@SuppressWarning[s]\s*\(/, what: "@SuppressWarnings" },
  { re: /#!?\[allow\((?!dead_code|unused)/, what: "a Rust allow attribute" },
  { re: /#pragma\s+warning\s+disabl[e]\b/, what: "a C# pragma warning disable" },
];

const SECURITY: readonly Marker[] = [
  { re: /\bnose[c]\b/i, what: "nosec (Bandit or gosec)" },
  { re: /\bnosemgre[p]\b/, what: "nosemgrep" },
  { re: /\bNOSONA[R]\b/, what: "NOSONAR" },
  { re: /\bgitleaks:allo[w]\b/, what: "gitleaks:allow" },
  { re: /\btrufflehog:ignor[e]\b/, what: "trufflehog:ignore" },
  { re: /pragma:\s*allowlist[ -]secre[t]/, what: "detect-secrets allowlist" },
  { re: /^#\s*noqa:\s*S\d/i, what: "noqa for a Bandit (S) rule" },
  { re: /\b(lgtm|codeql)\s*\[/, what: "CodeQL suppression" },
  { re: /\bcheckov:skip=/, what: "checkov:skip" },
  { re: /\btfsec:ignore:/, what: "tfsec:ignore" },
  { re: /\btrivy:ignore:/, what: "trivy:ignore" },
  { re: /\bkics-scan\s+ignor[e]/, what: "kics-scan ignore" },
  { re: /\bsnyk:ignor[e]\b/i, what: "snyk ignore" },
];

/** A security suppression counts as explained when it carries words beyond rule codes ("nosec B602 - input is a constant"). */
export function hasReason(comment: string, marker: RegExp): boolean {
  const m = marker.exec(comment);
  if (m === null) return false;
  const rest = comment.slice(m.index + m[0].length)
    .replace(/\*\/|-->/g, " ")
    .replace(/\[[^\]]*\]|\([^)]*\)/g, " ")
    // Rule identifiers are not reasons: B602, S603, no-eval, javascript.lang.security.audit.eval-detected.
    .replace(/\b[\w-]+(?:\.[\w-]+)+\b|\b[A-Z]{1,6}\d{2,5}\b|\b[a-z]+(?:-[a-z]+)+\b|[=:,;-]/g, " ");
  return (rest.match(/\b[A-Za-z]{2,}\b/g) ?? []).length >= 2;
}

const OPENER = /\/\/+|\/\*+|#|<!--|--(?=\s)/g;
const LEAD = /^(\/\/+|\/\*+|#+|<!--|--)\s*/;

/**
 * A comment split at each comment opener, so a type-ignore marker followed by a second hash comment is two pieces. A
 * marker counts only at the start of a piece, as tools require; prose that mentions a marker mid-sentence is not one.
 */
export function commentPieces(comment: string): string[] {
  const starts = [...comment.matchAll(OPENER)].map((m) => m.index);
  return starts.map((s, i) => comment.slice(s, starts[i + 1] ?? comment.length).trim()).filter((p) => p !== "");
}

const opensWith = (piece: string, re: RegExp) => {
  const m = re.exec(piece);
  return m !== null && m.index <= (LEAD.exec(piece)?.[0].length ?? 0);
};

export function suppressions(u: ContentUnit): Finding[] {
  if (u.mode !== "check" || isGeneratedPath(u.path) || isDocPath(u.path)) return [];
  // Type tests (tsd, expect-type, vitest typecheck) use @ts-expect-error as their assertion.
  const test = isTestPath(u.path) || /(\.test-d|\.spec-d|\.types?\.test)\.[cm]?tsx?$|(^|\/)(__typetests__|type-tests|typetests)\//.test(u.path);
  const fileWide: Hit[] = [];
  const lineLevel: Hit[] = [];
  const security: (Hit & { reason: boolean })[] = [];
  for (const l of u.lines) {
    const pieces = commentPieces(commentOf(l.text));
    const text = clip(l.text);
    const find = (markers: readonly Marker[]) => {
      for (const p of pieces) for (const m of markers) if (opensWith(p, m.re)) return { marker: m, piece: p };
      return null;
    };
    const sec = find(SECURITY);
    if (sec) { security.push({ line: l.line, text, level: "blocked", severity: "high", what: sec.marker.what, reason: hasReason(sec.piece, sec.marker.re) }); continue; }
    const wide = find(FILE_WIDE);
    if (wide) { fileWide.push({ line: l.line, text, level: "blocked", severity: "high", what: wide.marker.what }); continue; }
    if (test) continue;
    const line = find(LINE_LEVEL)?.marker ?? CODE_LEVEL.find((s) => s.re.test(l.text));
    if (line) lineLevel.push({ line: l.line, text, level: "review", severity: "medium", what: line.what });
  }

  const out: Finding[] = [];
  const wideF = findingFrom("tamper", "check-disabled-file", u.path, fileWide,
    (whats) => `Checks turned off for all of ${u.path}: ${whats.join("; ")}.`,
    "remove the marker and fix the errors it hides; if one rule is wrong for this file, disable only that rule, with a reason.");
  if (wideF) out.push(wideF);

  const counts = new Map<string, number>();
  for (const h of lineLevel) counts.set(h.what, (counts.get(h.what) ?? 0) + 1);
  const lineF = findingFrom("tamper", "suppression-added", u.path, lineLevel,
    () => `${plural(lineLevel.length, "lint or type error")} suppressed in ${u.path}: ${[...counts].map(([w, n]) => `${n} ${w}`).join(", ")}.`,
    "fix the errors instead; where a suppression is truly needed, add a comment explaining why next to it.");
  if (lineF) out.push(lineF);

  if (security.length > 0) {
    const unexplained = security.filter((h) => !h.reason);
    const hits = security.map((h) => ({ ...h, level: h.reason ? ("review" as const) : ("blocked" as const) }));
    const f = findingFrom("tamper", "security-suppression", u.path, hits,
      () => unexplained.length > 0
        ? `Security scanner silenced without a reason in ${u.path}: ${[...new Set(unexplained.map((h) => h.what))].join(", ")}.`
        : `Security scanner silenced in ${u.path}, with a reason: ${[...new Set(security.map((h) => h.what))].join(", ")}.`,
      "fix the finding the scanner reported; if it is a false positive, keep the suppression and write why on the same line.");
    if (f) out.push(f);
  }
  return out;
}
