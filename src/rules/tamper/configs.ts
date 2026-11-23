/**
 * Guardrail configuration weakened in a change:
 *   tamper/type-check-weakened   tsconfig strict flags turned off, files excluded; mypy strict or ignore_errors
 *   tamper/lint-config-weakened  linter rules switched off or ignore lists widened
 *   tamper/coverage-lowered      a coverage threshold lowered or removed
 *   tamper/test-script-weakened  test, lint or type-check commands that can no longer fail
 *   tamper/gitignore-weakened    secret files no longer ignored
 *   tamper/isoklo-config-changed the merge gate's own policy edited
 */
import { isObject, parseJsonc } from "../../check/config/jsonc.js";
import type { Evidence, Finding } from "../../check/types.js";
import { CONFIG_FILES } from "../../engine/config.js";
import { basename, clip, plural } from "../../engine/text.js";
import type { FileChange } from "../change.js";
import { isWorkflow } from "../paths.js";

const ev = (path: string, line: number, text: string): Evidence => ({ path, line, text: clip(text) });
const dedupe = (es: Evidence[]) => [...new Map(es.map((e) => [`${e.path}:${e.line}`, e])).values()];
const added = (c: FileChange) => c.diff.added;
const removed = (c: FileChange) => c.diff.removed;
const firstLine = (text: string | null, re: RegExp) => {
  const lines = (text ?? "").split(/\r?\n/);
  const i = lines.findIndex((l) => re.test(l));
  return { line: i < 0 ? 1 : i + 1, text: i < 0 ? "" : (lines[i] ?? "").trim() };
};

// ---------------------------------------------------------------- TypeScript
const STRICT_FAMILY = ["noImplicitAny", "strictNullChecks", "strictFunctionTypes", "strictBindCallApply", "strictPropertyInitialization", "noImplicitThis", "alwaysStrict", "useUnknownInCatchVariables", "strictBuiltinIteratorReturn"];
const OTHER_FLAGS = ["strict", "noUncheckedIndexedAccess", "exactOptionalPropertyTypes", "noImplicitReturns", "noFallthroughCasesInSwitch", "noImplicitOverride", "noPropertyAccessFromIndexSignature", "checkJs", "noEmitOnError", "isolatedModules"];

export const isTsconfig = (path: string) => /(^|\/)(tsconfig|jsconfig)([.-][\w.-]+)?\.json$/.test(path);

function compilerOptions(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  const doc = parseJsonc(text);
  if (!isObject(doc)) return null;
  return isObject(doc["compilerOptions"]) ? doc["compilerOptions"] : {};
}

const effective = (o: Record<string, unknown>, flag: string) =>
  o[flag] === true || (o[flag] === undefined && STRICT_FAMILY.includes(flag) && o["strict"] === true);

function tsconfigFindings(c: FileChange): Finding[] {
  const out: Finding[] = [];
  if (c.status === "deleted") {
    out.push({
      rule: "tamper", id: "type-check-weakened", level: "review", severity: "medium",
      message: `TypeScript configuration deleted: ${c.oldPath}. Files it covered may no longer be type-checked.`,
      fix: "confirm another tsconfig still covers these files with the same strictness.",
      evidence: [ev(c.oldPath, 1, "")],
    });
    return out;
  }
  const before = compilerOptions(c.before);
  const after = compilerOptions(c.after);
  if (before === null || after === null) return out;
  const weakened = [...STRICT_FAMILY, ...OTHER_FLAGS].filter((f) => effective(before, f) && !effective(after, f));
  if (weakened.length > 0) {
    // Turning strict off switches its whole family off; name strict, count the family, list anything else by name.
    const strictOff = weakened.includes("strict");
    const family = weakened.filter((f) => STRICT_FAMILY.includes(f));
    const others = weakened.filter((f) => !STRICT_FAMILY.includes(f) && f !== "strict");
    const named = strictOff
      ? [`strict (and with it ${family.slice(0, 2).join(", ")}${family.length > 2 ? ` and ${family.length - 2} more` : ""})`, ...others]
      : weakened;
    out.push({
      rule: "tamper", id: "type-check-weakened", level: "blocked",
      message: `TypeScript checks turned off in ${c.path}: ${named.join(", ")} ${weakened.length === 1 ? "is" : "are"} no longer on.`,
      fix: "turn the checks back on and fix the type errors they report; loosening them hides bugs across the whole project.",
      evidence: dedupe(weakened.map((f) => {
        const own = firstLine(c.after, new RegExp(`"${f}"`));
        return { path: c.path, ...(own.text !== "" ? own : firstLine(c.after, /"strict"|"compilerOptions"/)) };
      })),
    });
  }
  const docB = parseJsonc(c.before ?? "{}");
  const docA = parseJsonc(c.after ?? "{}");
  const list = (d: unknown, k: string) => (isObject(d) && Array.isArray(d[k]) ? (d[k] as unknown[]).map(String) : []);
  const newExcludes = list(docA, "exclude").filter((x) => !list(docB, "exclude").includes(x));
  if (newExcludes.length > 0) {
    out.push({
      rule: "tamper", id: "type-check-weakened", level: "review", severity: "medium",
      message: `${plural(newExcludes.length, "path")} excluded from type-checking in ${c.path}: ${newExcludes.join(", ")}.`,
      fix: "keep source files type-checked; exclude only generated or vendored code.",
      evidence: [{ path: c.path, ...firstLine(c.after, /"exclude"/) }],
    });
  }
  if (isObject(docA) && isObject(docB) && docA["extends"] !== docB["extends"] && docB["extends"] !== undefined) {
    out.push({
      rule: "tamper", id: "type-check-weakened", level: "review", severity: "medium",
      message: `${c.path} now extends ${JSON.stringify(docA["extends"] ?? null)} instead of ${JSON.stringify(docB["extends"])}; inherited strictness may have changed.`,
      fix: "compare the two base configurations before merging.",
      evidence: [{ path: c.path, ...firstLine(c.after, /"extends"/) }],
    });
  }
  return out;
}

// ---------------------------------------------------------------- Python type checkers
const isPyConfig = (path: string) => /(^|\/)(pyproject\.toml|setup\.cfg|mypy\.ini|\.mypy\.ini|tox\.ini|pyrightconfig\.json)$/.test(path);
const MYPY_OFF = /^\s*(ignore_errors\s*=\s*true|strict\s*=\s*false|disallow_untyped_defs\s*=\s*false|check_untyped_defs\s*=\s*false|"typeCheckingMode"\s*:\s*"(off|basic)")/i;

function pyTypeFindings(c: FileChange): Finding[] {
  const hits = added(c).filter((l) => MYPY_OFF.test(l.text));
  if (hits.length === 0) return [];
  return [{
    rule: "tamper", id: "type-check-weakened", level: "blocked",
    message: `Python type-checking weakened in ${c.path}: ${hits.map((h) => h.text.trim()).join("; ")}.`,
    fix: "keep the checker strict and fix the errors; if one module needs an exception, scope it to that module with a reason.",
    evidence: hits.map((h) => ev(c.path, h.line, h.text)),
  }];
}

// ---------------------------------------------------------------- linters
const isLintConfig = (path: string) =>
  /(^|\/)(\.eslintrc(\.(json|js|cjs|mjs|ya?ml))?|eslint\.config\.(js|mjs|cjs|ts|mts|cts)|biome\.jsonc?|\.oxlintrc\.json|\.flake8|ruff\.toml|\.ruff\.toml|\.pylintrc|pylintrc|\.golangci\.ya?ml|\.rubocop\.yml|\.stylelintrc(\.\w+)?|deno\.jsonc?)$/.test(path) ||
  /(^|\/)(pyproject\.toml|setup\.cfg|tox\.ini)$/.test(path);

const RULE_OFF = /["']?([@\w/.-]+)["']?\s*:\s*\[?\s*(["']off["']|0)\s*[\],]?/;
const IGNORE_LIST = /^\s*["']?(ignores|ignorePatterns|ignore|extend-ignore|per-file-ignores|extend-per-file-ignores|disable)["']?\s*[:=]/i;
const RECOMMENDED_OFF = /["']recommended["']\s*:\s*false/;

function lintFindings(c: FileChange): Finding[] {
  if (c.status === "deleted") {
    return [{
      rule: "tamper", id: "lint-config-weakened", level: "review",
      message: `Linter configuration deleted: ${c.oldPath}.`,
      fix: "confirm the project is still linted with the same rules.",
      evidence: [ev(c.oldPath, 1, "")],
    }];
  }
  // A brand-new config loosens nothing that existed before (create-next-app ships rules set to "off").
  if (c.status === "added") return [];
  const removedText = new Set(removed(c).map((l) => l.text.trim()));
  const hits = added(c).filter((l) => !removedText.has(l.text.trim()) && (RULE_OFF.test(l.text) || IGNORE_LIST.test(l.text) || RECOMMENDED_OFF.test(l.text)));
  const offRules = hits.map((h) => RULE_OFF.exec(h.text)?.[1]).filter((x): x is string => x !== undefined && !/^(version|line|column|indent)$/.test(x));
  if (hits.length === 0) return [];
  return [{
    rule: "tamper", id: "lint-config-weakened", level: "review",
    message: `Linter loosened in ${c.path}: ${offRules.length > 0 ? `${offRules.join(", ")} turned off` : "ignore lists or rule sets changed"}${hits.some((h) => RECOMMENDED_OFF.test(h.text)) ? "; recommended rules disabled" : ""}.`,
    fix: "fix the code the rule flags instead of switching the rule off; if the rule is wrong for the project, say why in the pull request.",
    evidence: hits.map((h) => ev(c.path, h.line, h.text)),
  }];
}

// ---------------------------------------------------------------- coverage thresholds
const isCoverageConfig = (path: string) =>
  /(^|\/)(jest\.config\.\w+|vitest\.config\.\w+|vite\.config\.\w+|vitest\.workspace\.\w+|karma\.conf\.\w+|\.nycrc(\.json|\.ya?ml)?|\.c8rc(\.json)?|codecov\.ya?ml|\.codecov\.ya?ml|\.coveragerc|setup\.cfg|pyproject\.toml|tox\.ini|package\.json|\.github\/workflows\/[^/]+\.ya?ml)$/.test(path);
const THRESHOLD = /["']?(lines|branches|functions|statements|fail_under|fail-under|--cov-fail-under|min_coverage|minimum_coverage|coverage_threshold)["']?\s*(?:[:=]|\s)\s*["']?(\d+(?:\.\d+)?)%?["']?/i;
const CODECOV_THRESHOLD = /["']?(target|threshold)["']?\s*:\s*["']?(\d+(?:\.\d+)?)%?["']?/i;
const WORKFLOW_THRESHOLD = /(--cov-fail-under|fail[_-]under|min(?:imum)?[_-]coverage)["']?\s*(?:[:=]|\s)\s*["']?(\d+(?:\.\d+)?)/i;

/** The threshold pattern for a file, or null when a bare "lines: 80" there would not be a coverage threshold. */
function thresholdPattern(c: FileChange): RegExp | null {
  const path = c.status === "deleted" ? c.oldPath : c.path;
  if (/codecov\.ya?ml$/.test(path)) return CODECOV_THRESHOLD;
  if (isWorkflow(path)) return WORKFLOW_THRESHOLD;
  const text = `${c.before ?? ""}\n${c.after ?? ""}`;
  if (/(^|\/)(package\.json|vite\.config\.\w+|vitest\.workspace\.\w+)$/.test(path) && !/coverageThreshold|"nyc"|"c8"|coverage/.test(text)) return null;
  return THRESHOLD;
}

function coverageFindings(c: FileChange): Finding[] {
  const re = thresholdPattern(c);
  if (re === null) return [];
  const keyOf = (text: string) => re.exec(text)?.[1]?.toLowerCase();
  const before = new Map<string, number>();
  for (const l of removed(c)) {
    const m = re.exec(l.text);
    if (m) before.set((m[1] ?? "").toLowerCase(), Number(m[2]));
  }
  if (before.size === 0) return [];
  const after = new Map<string, { value: number; line: number; text: string }>();
  for (const l of added(c)) {
    const m = re.exec(l.text);
    if (m) after.set((m[1] ?? "").toLowerCase(), { value: Number(m[2]), line: l.line, text: l.text });
  }
  const lowered: string[] = [];
  const evidence: Evidence[] = [];
  for (const [key, was] of before) {
    const now = after.get(key);
    if (now === undefined) {
      // Only a removal if the key is gone from the file entirely, not just moved.
      if (c.after !== null && c.after.split(/\r?\n/).some((l) => keyOf(l) === key)) continue;
      lowered.push(`${key} ${was}% removed`);
      const r = removed(c).find((l) => keyOf(l.text) === key);
      if (r) evidence.push({ path: c.oldPath, line: r.line, text: clip(r.text), ...(r.newAt !== undefined ? { anchor: { path: c.path, line: r.newAt } } : {}) });
    } else if (now.value < was) {
      lowered.push(`${key} ${was}% → ${now.value}%`);
      evidence.push(ev(c.path, now.line, now.text));
    }
  }
  if (lowered.length === 0) return [];
  return [{
    rule: "tamper", id: "coverage-lowered", level: "blocked",
    message: `Coverage threshold lowered in ${c.path}: ${lowered.join(", ")}.`,
    fix: "restore the threshold and add tests for the uncovered code.",
    evidence,
  }];
}

// ---------------------------------------------------------------- test commands that cannot fail
const GUARD_SCRIPT = /^(test|tests|lint|typecheck|type-check|types|check|ci|verify|validate)([:-].*)?$/;
/** A command tail that makes failure impossible. */
const NEUTRALISED = /\|\|\s*(true|exit\s+0|:|echo\b)|;\s*(exit\s+0|true)\s*$|--passWithNoTests|--pass-with-no-tests|--no-fail-on-error|--max-warnings[=\s]+-1|--exit-zero\b|--noEmitOnError\s+false/;
/** A package.json script whose whole command is a no-op. */
const NO_OP_SCRIPT = /^\s*(echo|exit\s+0|true|:)(\s|$)/;
const TEST_COMMAND = /\b(npm|pnpm|yarn|bun|npx)\s+(run\s+)?(test|lint|typecheck|type-check|check)\b|\b(pytest|jest|vitest|mocha|ava|tap|tsc|eslint|ruff|mypy|pyright|flake8|go\s+test|cargo\s+(test|clippy)|make\s+(test|check|lint)|tox|rspec|phpunit|dotnet\s+test|gradle\w*\s+test|mvn\w*\s+test)\b/;

function scripts(text: string | null): Record<string, string> {
  const doc = text === null ? null : parseJsonc(text);
  if (!isObject(doc) || !isObject(doc["scripts"])) return {};
  return Object.fromEntries(Object.entries(doc["scripts"]).filter((e): e is [string, string] => typeof e[1] === "string"));
}

function testScriptFindings(c: FileChange): Finding[] {
  const evidence: Evidence[] = [];
  const what: string[] = [];
  if (basename(c.path) === "package.json" && c.status !== "deleted") {
    const before = scripts(c.before);
    const after = scripts(c.after);
    for (const [name, cmd] of Object.entries(before)) {
      if (!GUARD_SCRIPT.test(name)) continue;
      const now = after[name];
      // Renamed, not removed: the same command still runs under another check name ("typecheck" -> "type-check").
      const renamed = now === undefined && Object.entries(after).some(([n, c2]) => GUARD_SCRIPT.test(n) && c2.trim() === cmd.trim());
      if (now === undefined) {
        if (renamed) continue;
        what.push(`"${name}" script removed`);
        evidence.push({ path: c.path, ...firstLine(c.after, /"scripts"/) });
      } else if ((NEUTRALISED.test(now) || NO_OP_SCRIPT.test(now)) && !NEUTRALISED.test(cmd) && !NO_OP_SCRIPT.test(cmd)) {
        what.push(`"${name}" can no longer fail (${clip(now, 60)})`);
        evidence.push({ path: c.path, ...firstLine(c.after, new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\s*:`)) });
      }
    }
  } else {
    for (const l of added(c)) {
      if (TEST_COMMAND.test(l.text) && NEUTRALISED.test(l.text.replace(/^\s*(-\s*)?(run:\s*)?/, ""))) {
        what.push(`a check command can no longer fail`);
        evidence.push(ev(c.path, l.line, l.text));
      }
    }
  }
  if (what.length === 0) return [];
  return [{
    rule: "tamper", id: "test-script-weakened", level: "blocked",
    message: `Test or lint command neutralised in ${c.path}: ${[...new Set(what)].join("; ")}.`,
    fix: "restore the command so a failure fails the build; fix the failures it reports.",
    evidence,
  }];
}

const isCommandFile = (path: string) =>
  basename(path) === "package.json" || isWorkflow(path) || /(^|\/)(\.gitlab-ci\.yml|\.circleci\/config\.yml|azure-pipelines\.yml|bitbucket-pipelines\.yml|Jenkinsfile|Makefile|justfile|Taskfile\.ya?ml|tox\.ini|noxfile\.py|\.pre-commit-config\.yaml|lefthook\.ya?ml|\.husky\/[^/]+)$/.test(path);

// ---------------------------------------------------------------- .gitignore
const SECRET_IGNORE = /(^|\/|\*)\.env\b|\.pem\b|\.key\b|\.p12\b|\.pfx\b|id_rsa|id_ed25519|\bsecrets?\b|credentials|\.npmrc|\.pypirc|\.netrc|service[-_]?account|\.tfstate|\.tfvars|\.keystore|\.jks\b/i;
const SAFE_UNIGNORE = /\.(example|sample|template|dist|defaults?)\b/i;

function gitignoreFindings(c: FileChange): Finding[] {
  const addedText = new Set(added(c).map((l) => l.text.trim()));
  const unignored = removed(c).filter((l) => SECRET_IGNORE.test(l.text) && !l.text.trim().startsWith("#") && !l.text.trim().startsWith("!") && !addedText.has(l.text.trim()));
  const negated = added(c).filter((l) => l.text.trim().startsWith("!") && SECRET_IGNORE.test(l.text) && !SAFE_UNIGNORE.test(l.text));
  if (c.status === "deleted" && c.before !== null && SECRET_IGNORE.test(c.before)) {
    return [{
      rule: "tamper", id: "gitignore-weakened", level: "blocked",
      message: `${c.oldPath} deleted; it kept secret files (${c.before.split(/\r?\n/).filter((l) => SECRET_IGNORE.test(l) && !l.startsWith("#")).slice(0, 4).join(", ")}) out of git.`,
      fix: "restore the file.",
      evidence: [ev(c.oldPath, 1, "")],
    }];
  }
  if (unignored.length + negated.length === 0) return [];
  return [{
    rule: "tamper", id: "gitignore-weakened", level: "blocked",
    message: `Secret files no longer ignored by ${c.path}: ${[...unignored.map((l) => `${l.text.trim()} removed`), ...negated.map((l) => `${l.text.trim()} added`)].join(", ")}.`,
    fix: "restore the ignore rule; to share settings, commit a .example file with placeholders instead.",
    evidence: [
      ...unignored.map((l) => ({ path: c.oldPath, line: l.line, text: l.text.trim(), ...(l.newAt !== undefined ? { anchor: { path: c.path, line: l.newAt } } : {}) })),
      ...negated.map((l) => ev(c.path, l.line, l.text)),
    ],
  }];
}

// ---------------------------------------------------------------- Isoklo's own policy
function isokloConfigFindings(c: FileChange): Finding[] {
  // A first policy loosens nothing that existed before (setting Isoklo up), so it is reviewed; editing or deleting an
  // existing policy changes what future pull requests are held to, so it blocks until a maintainer accepts it.
  return [{
    rule: "tamper", id: "isoklo-config-changed", level: c.status === "added" ? "review" : "blocked", severity: "high",
    message: `The merge gate's policy was ${c.status === "added" ? "added" : c.status === "deleted" ? "deleted" : "changed"} in this change: ${c.status === "deleted" ? c.oldPath : c.path}. It takes effect after merge; this change was still judged by the base branch's policy.`,
    fix: "have a maintainer make policy changes in their own pull request, and pass --allow-config-change (or the isoklo-allow-config label) to accept it.",
    evidence: (c.diff.added.length > 0 ? c.diff.added.slice(0, 8) : [{ line: 1, text: "" }]).map((l) => ev(c.status === "deleted" ? c.oldPath : c.path, l.line, l.text)),
  }];
}

export const isIsokloConfig = (path: string) => (CONFIG_FILES as readonly string[]).includes(path);

/** Which tamper rules need this file's content. */
export function tamperWants(path: string): boolean {
  return isTsconfig(path) || isPyConfig(path) || isLintConfig(path) || isCoverageConfig(path) || isCommandFile(path) || basename(path) === ".gitignore" || isIsokloConfig(path);
}

export function tamperConfigs(changes: FileChange[]): Finding[] {
  const out: Finding[] = [];
  for (const c of changes) {
    const path = c.status === "deleted" ? c.oldPath : c.path;
    if (c.diff.binary) continue;
    if (isTsconfig(path)) out.push(...tsconfigFindings(c));
    if (isPyConfig(path)) out.push(...pyTypeFindings(c));
    if (isLintConfig(path)) out.push(...lintFindings(c));
    if (isCoverageConfig(path)) out.push(...coverageFindings(c));
    if (isCommandFile(path)) out.push(...testScriptFindings(c));
    if (basename(path) === ".gitignore") out.push(...gitignoreFindings(c));
    if (isIsokloConfig(path)) out.push(...isokloConfigFindings(c));
  }
  return out;
}
