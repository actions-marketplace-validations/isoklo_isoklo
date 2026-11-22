#!/usr/bin/env node
/**
 * Isoklo command-line entry point.
 * Rules (from the brand voice, 06-voice.md): verdict first, then evidence, then the fix; no exclamation marks or emoji.
 * Output: results go to stdout; problems running Isoklo go to stderr.
 */
import { parseArgs } from "node:util";
import { appendFileSync, readFileSync } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { ExitCode } from "./exit.js";
import { readVersion } from "./version.js";
import { scan as scanInstructions, ScanError } from "./doctor/scan.js";
import { analyze } from "./doctor/analyze.js";
import * as doctorReport from "./doctor/report.js";
import { postureChecks } from "./doctor/posture.js";
import { grade, gradeAtLeast, type Grade } from "./doctor/grade.js";
import { diffPullRequest, git, GitError, headCommit, mergeBase, repoRoot, resolveBase, showFile } from "./check/git.js";
import { parseDiff } from "./check/diff.js";
import type { FetchLike } from "./check/packages/registry.js";
import * as checkReport from "./check/report.js";
import { annotations, couldNotRunAnnotation, jobSummary } from "./check/github.js";
import { runCheck } from "./engine/gate.js";
import { runScan } from "./engine/scan.js";
import { CONFIG_FILES, ConfigError, parseConfig, type IsokloConfig } from "./engine/config.js";
import { createReceipt, verifyReceipt, type Receipt } from "./engine/receipt.js";
import { RULES } from "./engine/registry.js";
import { toSarif } from "./output/sarif.js";
import { toHtml, type AuditInput } from "./output/html.js";
import { collect } from "./fs/collect.js";
import { detect, installCi, installConfig, installHook, parseRemote, requireCheck, type Step } from "./init/init.js";

const HELP = `isoklo: proof before merge. A deterministic merge gate for AI-written code.

Usage
  npx isoklo                 scan this repository now, with no setup
  npx isoklo <command> [path] [options]

Commands
  scan [path]      (default) Check the files as they are: secrets, committed .env files,
                   hidden Unicode and injected agent instructions, disabled agent approvals,
                   risky MCP servers and permissions, unsafe workflows, remote code execution,
                   exfiltration, untrusted lockfile sources.
  check [path]     Check this branch's changes against its base. Everything scan checks in
                   the lines the change adds, plus: weakened, skipped or deleted tests;
                   suppressed type and lint errors; weakened tsconfig, linter, coverage and
                   test scripts; invented, brand-new or install-script packages; agent and CI
                   configuration that widens what agents may do; out-of-scope edits.
  init [path]      Set Isoklo up in one command: a pre-push hook, a CI workflow, and a policy
                   file with today's findings as the baseline. Asks which, or use the flags.
  doctor [path]    Which agent reads which instruction file, plus the repository's AI-agent
                   security posture, graded A to F. Advisory; never blocks.
  report [path]    Write a standalone executive audit report (HTML, prints to PDF), with
                   the grade, summary, evidence and a remediation checklist.
  verify <file>    Check an evidence receipt's digest (and signature, with ISOKLO_RECEIPT_KEY).
  rules            List every rule with its id, severity and what it stops.

Options
  -h, --help                  Show this help.
  -v, --version               Show the version.
  --json                      Print a machine-readable report (scan, check, doctor, report, rules).
  --sarif <file>              Also write SARIF 2.1.0 for GitHub Code Scanning (scan, check, report).
  --html <file>               Also write the HTML audit report (scan, check; report writes one anyway).
  --receipt <file>            Also write the evidence receipt as JSON (scan, check, report).
  --sign                      Sign the receipt with HMAC-SHA256, using ISOKLO_RECEIPT_KEY.
  --policy <file>             scan, report: read policy from this file instead of isoklo.config.json.
  --brief                     Leave out the "why" line under each finding.

  check
  --base <ref>                The branch or commit to compare against (default: the pull request
                              base in GitHub Actions, then origin's default branch, main or master).
  --head <ref>                The commit to check (default: HEAD).
  --diff <base>...<head>      Same as --base and --head together. Also turns scan and report into
                              a check of that change.
  --staged                    Check the staged changes against HEAD (for a pre-commit hook).
  --scope <glob>              Declare which files this change may touch (repeatable). Files outside
                              are blocked. A pull request body can also declare
                              "isoklo-scope: src/cart/**, test/cart/**".
  --offline                   Do not contact package registries; new packages are listed as not
                              verified. (Only public package names are ever sent.)
  --allow-config-change <reason>
                              Accept blocked agent, CI and policy changes as reviewed (pass this only
                              from a maintainer-controlled source, such as a label).

  init
  --hook                      Install the git pre-push hook.
  --ci                        Write the CI workflow (GitHub Actions or GitLab CI).
  --config                    Write isoklo.config.json with today's findings as the baseline.
  --require                   Make the check required on the default branch (GitHub, uses gh).
  --all                       Hook, CI and config.
  -y, --yes                   Do not ask; use the recommended setup (hook and CI).
  --dry-run                   Show what would change, change nothing.
  --force                     Replace files that exist.

  doctor and report
  --strict                    doctor: exit 1 when instruction files have findings to review.
  --min-grade <A-F>           doctor: exit 1 when the posture grade is below this.
  --for <name>                report: who the report is prepared for.
  --by <name>                 report: who prepared it.

Exit codes
  0  passed
  1  blocked
  2  could not run (the gate fails closed: nothing is approved)

In GitHub Actions, check also annotates the pull request's changed lines and writes a job
summary. Or install the Isoklo GitHub App: no workflow file at all.
`;

function fail(message: string): ExitCode {
  process.stderr.write(`isoklo: ${message}\nRun \`isoklo --help\` to see what Isoklo can do.\n`);
  return ExitCode.CouldNotRun;
}

/** Colour only for a real terminal, never when the user asks for none (https://no-color.org); FORCE_COLOR forces it. */
function useColor(): boolean {
  if (process.env["NO_COLOR"] !== undefined) return false;
  if (process.env["FORCE_COLOR"] !== undefined && process.env["FORCE_COLOR"] !== "0") return true;
  return Boolean(process.stdout.isTTY);
}

/** True inside a GitHub Actions job (GitHub sets this variable on every runner). */
const inGitHubActions = () => process.env["GITHUB_ACTIONS"] === "true";

/** Append markdown to the job's summary page; a no-op outside Actions or if the file can't be written. */
function writeStepSummary(markdown: string): void {
  const file = process.env["GITHUB_STEP_SUMMARY"];
  if (!file) return;
  try {
    appendFileSync(file, `${markdown}\n`);
  } catch {
    process.stderr.write("isoklo: could not write the job summary; the verdict above still stands.\n");
  }
}

/** The pull request description, for an isoklo-scope declaration: env override, GitLab, or the GitHub event payload. */
function pullRequestBody(): string | null {
  const direct = process.env["ISOKLO_PR_BODY"] ?? process.env["CI_MERGE_REQUEST_DESCRIPTION"];
  if (direct !== undefined) return direct;
  const eventPath = process.env["GITHUB_EVENT_PATH"];
  if (!eventPath || !inGitHubActions()) return null;
  try {
    const event = JSON.parse(readFileSync(eventPath, "utf8")) as { pull_request?: { body?: unknown } };
    return typeof event.pull_request?.body === "string" ? event.pull_request.body : null;
  } catch {
    return null;
  }
}

/** owner/name of the origin remote, without any credentials in its URL. */
async function repositoryName(root: string): Promise<string | null> {
  try {
    return parseRemote((await git(root, ["remote", "get-url", "origin"])).trim()).repo;
  } catch {
    return null;
  }
}

async function commitSha(root: string, ref: string): Promise<string | null> {
  try {
    return (await git(root, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`])).trim() || null;
  } catch {
    return null;
  }
}

function printWarnings(warnings: string[]): void {
  for (const w of warnings) process.stderr.write(`isoklo: ${w}\n`);
}

interface Policy {
  config: IsokloConfig;
  source: string | null;
  text: string | null;
}

/** Policy for scan mode: --policy, else the first policy file in the folder. */
async function workingTreePolicy(root: string, explicit: string | undefined): Promise<Policy> {
  const candidates = explicit !== undefined ? [resolve(explicit)] : CONFIG_FILES.map((f) => join(root, f));
  for (const path of candidates) {
    let text: string;
    try {
      text = await readFile(path, "utf8");
    } catch {
      if (explicit !== undefined) throw new ConfigError(`cannot read the policy file "${explicit}".`);
      continue;
    }
    const source = relative(root, path).split("\\").join("/") || basename(path);
    const { config, warnings } = parseConfig(text, source);
    printWarnings(warnings);
    return { config, source, text };
  }
  return { config: parseConfig(null).config, source: null, text: null };
}

/** Policy for check mode: from the BASE commit, so the change cannot loosen the gate that judges it. */
async function basePolicy(root: string, baseRev: string): Promise<Policy> {
  for (const file of CONFIG_FILES) {
    const text = await showFile(root, baseRev, file);
    if (text === null) continue;
    const { config, warnings } = parseConfig(text, `${file} (from the base commit)`);
    printWarnings(warnings);
    return { config, source: file, text };
  }
  return { config: parseConfig(null).config, source: null, text: null };
}

interface Outputs {
  json: boolean;
  sarif: string | undefined;
  html: string | undefined;
  receipt: string | undefined;
  sign: boolean;
  brief: boolean;
}

function signingKey(sign: boolean): string | null {
  const key = process.env["ISOKLO_RECEIPT_KEY"];
  if (sign && !key) throw new ConfigError("--sign needs a key in the ISOKLO_RECEIPT_KEY environment variable.");
  return key ? key : null;
}

async function writeOut(path: string, content: string): Promise<void> {
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, content);
}

// ---------------------------------------------------------------- doctor posture and the audit report
async function postureOf(root: string, policyPath: string | undefined) {
  const policy = await workingTreePolicy(root, policyPath);
  const collected = await collect(root);
  const repo = await repositoryName(root);
  const scanSummary = await runScan(collected.files, { root: repo ?? basename(root), config: policy.config, configSource: policy.source });
  const findings = checkReport.findingsOf(scanSummary);
  const checks = await postureChecks(root, collected.files);
  return { posture: grade(findings, checks), findings, scanSummary, collected, repo, policy };
}

interface AuditOptions {
  policyPath: string | undefined;
  check?: checkReport.CheckSummary | undefined;
  preparedFor?: string | undefined;
  preparedBy?: string | undefined;
  sign: boolean;
}

async function buildAudit(root: string, o: AuditOptions): Promise<{ audit: AuditInput; combined: checkReport.CheckSummary; receipt: Receipt }> {
  const p = await postureOf(root, o.policyPath);
  let instructions;
  try {
    instructions = analyze(await scanInstructions(root));
  } catch {
    instructions = undefined;
  }
  // The change and the files can report the same problem; count it once, in the change, everywhere (cover, CLI, receipt).
  const seen = new Set<string>();
  const once = (results: checkReport.CheckSummary["results"]) => results.map((r) => ({
    ...r,
    findings: r.findings.filter((f) => {
      const key = f.fingerprint ?? `${f.ruleId}:${f.message}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  }));
  const combined: checkReport.CheckSummary = o.check === undefined ? p.scanSummary : {
    ...p.scanSummary,
    mode: "check",
    base: o.check.base,
    head: o.check.head,
    results: once([...o.check.results, ...p.scanSummary.results]),
    rulesRun: [...new Map([...(o.check.rulesRun ?? []), ...(p.scanSummary.rulesRun ?? [])].map((r) => [r.id, r])).values()],
  };
  const headSha = await commitSha(root, "HEAD");
  const baseSha = o.check === undefined ? null : await commitSha(root, o.check.base);
  const receipt = await createReceipt({
    summary: combined, engineVersion: readVersion(), repository: p.repo, headSha, baseSha, policyText: p.policy.text,
    signingKey: signingKey(o.sign),
  });
  const audit: AuditInput = {
    repository: p.repo ?? basename(root),
    generatedAt: new Date(receipt.createdAt),
    version: readVersion(),
    scan: p.scanSummary,
    posture: p.posture,
    receipt,
    commit: headSha,
  };
  if (o.preparedFor !== undefined) audit.preparedFor = o.preparedFor;
  if (o.preparedBy !== undefined) audit.preparedBy = o.preparedBy;
  if (o.check !== undefined) audit.check = o.check;
  if (instructions !== undefined) audit.instructions = instructions;
  return { audit, combined, receipt };
}

async function writeSideOutputs(summary: checkReport.CheckSummary, receipt: Receipt, out: Outputs, root: string): Promise<void> {
  if (out.sarif !== undefined) await writeOut(out.sarif, toSarif(summary, readVersion()));
  if (out.receipt !== undefined) await writeOut(out.receipt, JSON.stringify(receipt, null, 2) + "\n");
  if (out.html !== undefined) {
    const built = await buildAudit(root, { policyPath: undefined, check: summary.mode === "check" ? summary : undefined, sign: out.sign });
    await writeOut(out.html, toHtml(built.audit));
  }
}

// ---------------------------------------------------------------- scan
async function scanCommand(pathArg: string | undefined, out: Outputs, policyPath: string | undefined): Promise<ExitCode> {
  const root = resolve(pathArg ?? ".");
  try {
    const info = await stat(root).catch(() => null);
    if (info === null || !info.isDirectory()) return fail(`cannot read "${root}": no such folder.`);
    const policy = await workingTreePolicy(root, policyPath);
    const collected = await collect(root);
    const repo = await repositoryName(root);
    const summary = await runScan(collected.files, { root: repo ?? basename(root), config: policy.config, configSource: policy.source });
    const receipt = await createReceipt({
      summary, engineVersion: readVersion(), repository: repo, headSha: collected.inGit ? await commitSha(root, "HEAD") : null,
      policyText: policy.text, signingKey: signingKey(out.sign),
    });
    await writeSideOutputs(summary, receipt, out, root);
    const verdict = checkReport.verdictOf(summary);
    if (out.json) process.stdout.write(checkReport.toJson(summary, readVersion(), { receipt }));
    else {
      process.stdout.write(checkReport.toText(summary, { color: useColor(), why: !out.brief }));
      if (collected.skipped > 0) process.stdout.write(`${collected.skipped} large or unreadable files were not read.\n`);
      if (!collected.inGit) process.stdout.write("Not a git repository: only scan applies here. `isoklo check` compares changes between commits.\n");
      else process.stdout.write("Scanned the files as they are. To check this branch's changes (tests, packages, configs), run `npx isoklo check`.\n");
    }
    return verdict === "blocked" ? ExitCode.Blocked : ExitCode.Passed;
  } catch (error) {
    if (error instanceof ConfigError || error instanceof GitError) return fail(error.message);
    throw error;
  }
}

// ---------------------------------------------------------------- check
interface CheckFlags {
  allowConfigReason: string | undefined;
  base: string | undefined;
  head: string;
  offline: boolean;
  staged: boolean;
  scope: string[];
}

interface CheckRun {
  summary: checkReport.CheckSummary;
  root: string;
  baseSha: string | null;
  headSha: string | null;
  policyText: string | null;
}

async function checkSummary(cwd: string, o: CheckFlags): Promise<CheckRun> {
  const root = await repoRoot(cwd);
  let baseLabel: string;
  let headLabel: string;
  let beforeRev: string;
  let afterRev: string;
  let diffText: string;
  if (o.staged) {
    const hasHead = (await commitSha(root, "HEAD")) !== null;
    baseLabel = "HEAD";
    headLabel = "staged";
    beforeRev = hasHead ? "HEAD" : "";
    afterRev = ""; // `git show :path` reads the index
    diffText = await git(root, ["diff", "--cached", "--no-ext-diff", "--unified=0", "--find-renames"]);
  } else {
    const { ref } = await resolveBase(root, o.base);
    await headCommit(root, o.head);
    baseLabel = ref;
    headLabel = o.head;
    beforeRev = await mergeBase(root, ref, o.head);
    afterRev = o.head;
    diffText = await diffPullRequest(root, ref, o.head);
  }
  const policy = beforeRev === "" ? { config: parseConfig(null).config, source: null, text: null } : await basePolicy(root, beforeRev);
  const summary = await runCheck(
    {
      files: parseDiff(diffText),
      before: (p) => (beforeRev === "" ? Promise.resolve(null) : showFile(root, beforeRev, p)),
      after: (p) => showFile(root, afterRev, p),
    },
    {
      base: baseLabel, head: headLabel,
      fetch: globalThis.fetch as unknown as FetchLike,
      offline: o.offline || process.env["ISOKLO_OFFLINE"] === "1",
      now: new Date(),
      config: policy.config, configSource: policy.source,
      ...(o.allowConfigReason === undefined ? {} : { allowConfigReason: o.allowConfigReason }),
      scope: o.scope,
      prBody: pullRequestBody(),
    },
  );
  return {
    summary, root,
    baseSha: beforeRev === "" ? null : await commitSha(root, beforeRev),
    headSha: o.staged ? null : await commitSha(root, o.head),
    policyText: policy.text,
  };
}

async function checkCommand(pathArg: string | undefined, o: CheckFlags, out: Outputs): Promise<ExitCode> {
  const cwd = resolve(pathArg ?? ".");
  try {
    const { summary, root, baseSha, headSha, policyText } = await checkSummary(cwd, o);
    const repo = await repositoryName(root);
    const receipt = await createReceipt({
      summary, engineVersion: readVersion(), mode: inGitHubActions() ? "pull_request" : "check",
      repository: repo ?? process.env["GITHUB_REPOSITORY"] ?? null, baseSha, headSha, policyText, signingKey: signingKey(out.sign),
    });
    await writeSideOutputs(summary, receipt, out, root);
    process.stdout.write(out.json ? checkReport.toJson(summary, readVersion(), { receipt }) : checkReport.toText(summary, { color: useColor(), why: !out.brief }));
    if (inGitHubActions() && !out.json) {
      for (const a of annotations(summary)) process.stdout.write(`${a}\n`);
      writeStepSummary(`${jobSummary(summary)}\n<sub>Evidence receipt \`sha256:${receipt.integrity.digest}\`${receipt.integrity.signature ? " · signed" : ""}</sub>\n`);
    }
    return checkReport.verdictOf(summary) === "blocked" ? ExitCode.Blocked : ExitCode.Passed;
  } catch (error) {
    if (error instanceof GitError || error instanceof ConfigError) {
      if (inGitHubActions()) {
        process.stdout.write(`${couldNotRunAnnotation(error.message)}\n`);
        writeStepSummary(`## isoklo · could not run\n\n${error.message}\n\nThe check failed closed: nothing was approved.\n`);
      }
      return fail(error.message);
    }
    throw error;
  }
}

// ---------------------------------------------------------------- doctor and report
async function doctor(pathArg: string | undefined, json: boolean, strict: boolean, minGrade: Grade | undefined): Promise<ExitCode> {
  const root = resolve(pathArg ?? ".");
  let scanned;
  try {
    scanned = await scanInstructions(root);
  } catch (error) {
    if (error instanceof ScanError) return fail(error.message);
    throw error;
  }
  const report = analyze(scanned);
  let posture;
  try {
    const p = await postureOf(root, undefined);
    posture = { posture: p.posture, findings: p.findings };
  } catch (error) {
    if (error instanceof ConfigError) return fail(error.message);
    throw error;
  }
  process.stdout.write(json
    ? doctorReport.toJson(report, root, readVersion(), posture)
    : doctorReport.toText(report, { color: useColor(), root, posture }));
  const toReview = report.findings.some((f) => f.level === "review");
  if (strict && toReview) return ExitCode.Blocked;
  if (minGrade !== undefined && !gradeAtLeast(posture.posture.grade, minGrade)) return ExitCode.Blocked;
  return ExitCode.Passed;
}

async function reportCommand(
  pathArg: string | undefined,
  out: Outputs,
  o: { policyPath: string | undefined; preparedFor: string | undefined; preparedBy: string | undefined; diff: CheckFlags | null },
): Promise<ExitCode> {
  const root = resolve(pathArg ?? ".");
  try {
    const info = await stat(root).catch(() => null);
    if (info === null || !info.isDirectory()) return fail(`cannot read "${root}": no such folder.`);
    const check = o.diff === null ? undefined : (await checkSummary(root, o.diff)).summary;
    const built = await buildAudit(root, { policyPath: o.policyPath, check, preparedFor: o.preparedFor, preparedBy: o.preparedBy, sign: out.sign });
    const htmlPath = out.html ?? "isoklo-report.html";
    const receiptPath = out.receipt ?? join(dirname(htmlPath), "isoklo-receipt.json");
    await writeOut(htmlPath, toHtml(built.audit));
    await writeOut(receiptPath, JSON.stringify(built.receipt, null, 2) + "\n");
    if (out.sarif !== undefined) await writeOut(out.sarif, toSarif(built.combined, readVersion()));
    const verdict = checkReport.verdictOf(built.combined);
    if (out.json) {
      process.stdout.write(checkReport.toJson(built.combined, readVersion(), { receipt: built.receipt, posture: built.audit.posture, report: htmlPath }));
    } else {
      const a = built.audit;
      const findings = checkReport.findingsOf(built.combined).filter((f) => f.level !== "info");
      const blocking = findings.filter((f) => f.level === "blocked").length;
      process.stdout.write(
        `isoklo report · ${a.repository}\n\n` +
        `Grade ${a.posture.grade} · ${a.posture.score}/100 · ${verdict === "blocked" ? `${blocking} ${blocking === 1 ? "problem blocks" : "problems block"} a merge` : "nothing blocks a merge"} · ${findings.length} ${findings.length === 1 ? "finding" : "findings"}\n\n` +
        `Report   ${htmlPath}\nReceipt  ${receiptPath} (sha256:${built.receipt.integrity.digest.slice(0, 16)}…)\n` +
        (out.sarif !== undefined ? `SARIF    ${out.sarif}\n` : "") +
        `\nOpen the report in a browser, and print it to PDF to send it.\n`,
      );
    }
    return ExitCode.Passed;
  } catch (error) {
    if (error instanceof ConfigError || error instanceof GitError) return fail(error.message);
    throw error;
  }
}

// ---------------------------------------------------------------- verify and rules
async function verifyCommand(file: string | undefined): Promise<ExitCode> {
  if (file === undefined) return fail("verify needs a receipt file: isoklo verify isoklo-receipt.json");
  let doc: unknown;
  try {
    doc = JSON.parse(await readFile(file, "utf8"));
  } catch {
    return fail(`cannot read "${file}" as JSON.`);
  }
  const v = await verifyReceipt(doc, process.env["ISOKLO_RECEIPT_KEY"] ?? null);
  const ok = v.digestValid && v.signatureValid !== false;
  const r = doc as Partial<Receipt>;
  process.stdout.write(`${ok ? "valid" : "invalid"} · ${v.detail}\n`);
  if (ok && r.verdict !== undefined) {
    process.stdout.write(`${r.repository ?? "repository"} · ${r.mode} · verdict ${r.verdict} · ${r.findings?.length ?? 0} findings · isoklo ${r.engineVersion} · ${r.createdAt}\n`);
  }
  return ok ? ExitCode.Passed : ExitCode.Blocked;
}

function rulesCommand(json: boolean): ExitCode {
  if (json) {
    process.stdout.write(JSON.stringify({ tool: "isoklo", command: "rules", version: readVersion(), rules: RULES }, null, 2) + "\n");
    return ExitCode.Passed;
  }
  const width = Math.max(...RULES.map((r) => r.id.length));
  let suite = "";
  for (const r of RULES) {
    if (r.suite !== suite) {
      suite = r.suite;
      process.stdout.write(`\n${suite}\n`);
    }
    process.stdout.write(`  ${r.id.padEnd(width)}  ${r.severity.toUpperCase().padEnd(8)}  ${r.modes.join("+").padEnd(10)}  ${r.title}\n`);
  }
  process.stdout.write(`\n${RULES.length} rules. Every rule is deterministic; \`isoklo rules --json\` includes why each one matters.\n`);
  return ExitCode.Passed;
}

// ---------------------------------------------------------------- init
interface InitFlags {
  hook: boolean;
  ci: boolean;
  config: boolean;
  require: boolean;
  all: boolean;
  yes: boolean;
  dryRun: boolean;
  force: boolean;
}

async function initCommand(pathArg: string | undefined, o: InitFlags): Promise<ExitCode> {
  const cwd = resolve(pathArg ?? ".");
  let root: string;
  try {
    root = await repoRoot(cwd);
  } catch (error) {
    if (error instanceof GitError) return fail(`${error.message} Run \`git init\` first: Isoklo checks changes between commits.`);
    throw error;
  }
  const d = await detect(root);
  const version = readVersion();
  const hostName = { github: "GitHub", gitlab: "GitLab", bitbucket: "Bitbucket", other: "a git host", none: "no remote" }[d.host];
  process.stdout.write(`isoklo init · ${root}\nDetected  ${hostName}${d.repo ? ` (${d.repo})` : ""} · ${d.packageManager ?? "no package.json"} · hooks: ${d.hookManager}\n\n`);

  let want = { hook: o.hook || o.all, ci: o.ci || o.all, config: o.config || o.all, require: o.require };
  if (!(want.hook || want.ci || want.config || want.require)) {
    const recommended = { hook: true, ci: d.host === "github" || d.host === "gitlab" || d.hasGithubDir, config: false, require: false };
    if (o.yes || !process.stdin.isTTY || !process.stdout.isTTY) want = recommended;
    else {
      process.stdout.write(
        "What should Isoklo set up?\n" +
        "  1  pre-push hook    checks your branch before every push (local, nothing committed)\n" +
        `  2  CI workflow      ${d.host === "gitlab" ? "a .gitlab-ci.yml job" : ".github/workflows/isoklo.yml"}: checks every pull request\n` +
        "  3  policy file      isoklo.config.json, with today's findings as the baseline\n" +
        "  a  all three\n",
      );
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      const answer = (await rl.question(`Choose 1, 2, 3 or a, separated by commas [${recommended.ci ? "1,2" : "1"}]: `)).trim().toLowerCase();
      rl.close();
      if (answer === "") want = recommended;
      else {
        const picks = new Set(answer.split(/[\s,]+/));
        want = { hook: picks.has("1") || picks.has("a"), ci: picks.has("2") || picks.has("a"), config: picks.has("3") || picks.has("a"), require: false };
        if (!want.hook && !want.ci && !want.config) return fail(`"${answer}" is not one of 1, 2, 3 or a.`);
      }
      process.stdout.write("\n");
    }
  }

  let baseline: string[] = [];
  if (want.config) {
    const collected = await collect(root);
    const summary = await runScan(collected.files, { root: d.repo ?? basename(root), config: parseConfig(null).config });
    // Leaked secrets are never baselined: they must be rotated, not accepted.
    baseline = checkReport.findingsOf(summary)
      .filter((f) => f.level !== "info" && f.ruleId !== "sec/secret-leaked" && f.ruleId !== "sec/env-file-committed" && f.ruleId !== "mcp/plaintext-secret")
      .map((f) => f.fingerprint ?? "").filter((x) => x !== "");
  }
  const opts = { version, force: o.force, dryRun: o.dryRun, baseline };
  const steps: Step[] = [];
  if (want.hook) steps.push(await installHook(d, opts));
  if (want.ci) steps.push(await installCi(d, opts));
  if (want.config) steps.push(await installConfig(d, opts));
  if (want.require) steps.push(await requireCheck(d, opts));

  const width = Math.max(...steps.map((s) => s.status.length));
  for (const s of steps) {
    const mark = s.status === "failed" ? "✕" : s.status === "skipped" ? "·" : "✓";
    process.stdout.write(`${mark} ${s.status.padEnd(width)}  ${s.what}${s.path ? `  ${s.path}` : ""}${s.note ? `\n  ${" ".repeat(width + 2)}${s.note}` : ""}\n`);
  }
  if (want.config && baseline.length > 0) {
    process.stdout.write(`\n${baseline.length} existing ${baseline.length === 1 ? "finding is" : "findings are"} recorded as the baseline: they report as info, and new ones still block. Leaked secrets are never baselined.\n`);
  }
  const next: string[] = [];
  if (steps.some((s) => s.what.includes("workflow") || s.what.includes("GitLab"))) {
    next.push("Commit the new files and open a pull request: Isoklo checks it, and every pull request after it.");
    if (!want.require && d.host === "github") next.push("To make GitHub refuse to merge until Isoklo passes: npx isoklo init --require");
  }
  if (d.host === "github") next.push("For no workflow file at all, install the Isoklo GitHub App on the repository or organisation instead.");
  if (next.length > 0) process.stdout.write(`\nNext\n${next.map((n) => `  ${n}`).join("\n")}\n`);
  return steps.some((s) => s.status === "failed") ? ExitCode.CouldNotRun : ExitCode.Passed;
}

// ---------------------------------------------------------------- arguments
const COMMANDS = new Set(["scan", "check", "init", "doctor", "report", "verify", "rules"]);

/** --diff main...HEAD, main..HEAD, or just main. */
export function parseRange(range: string): { base: string; head: string } {
  const m = /^(.+?)\.\.\.?(.*)$/.exec(range);
  if (m === null) return { base: range, head: "HEAD" };
  return { base: m[1] as string, head: (m[2] ?? "") === "" ? "HEAD" : (m[2] as string) };
}

export async function main(argv: string[]): Promise<ExitCode> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
        json: { type: "boolean" },
        strict: { type: "boolean" },
        base: { type: "string" },
        head: { type: "string" },
        diff: { type: "string" },
        staged: { type: "boolean" },
        scope: { type: "string", multiple: true },
        offline: { type: "boolean" },
        "allow-config-change": { type: "string" },
        sarif: { type: "string" },
        html: { type: "string" },
        receipt: { type: "string" },
        sign: { type: "boolean" },
        policy: { type: "string" },
        brief: { type: "boolean" },
        hook: { type: "boolean" },
        ci: { type: "boolean" },
        config: { type: "boolean" },
        require: { type: "boolean" },
        all: { type: "boolean" },
        yes: { type: "boolean", short: "y" },
        "dry-run": { type: "boolean" },
        force: { type: "boolean" },
        "min-grade": { type: "string" },
        for: { type: "string" },
        by: { type: "string" },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return fail(detail.replace(/\.$/, "") + ".");
  }

  const { values, positionals } = parsed;

  if (values.version) {
    process.stdout.write(`${readVersion()}\n`);
    return ExitCode.Passed;
  }
  if (values.help) {
    process.stdout.write(HELP);
    return ExitCode.Passed;
  }

  let [command, ...rest] = positionals;
  // `npx isoklo` and `npx isoklo ./some/folder` scan.
  if (command === undefined) command = "scan";
  else if (!COMMANDS.has(command)) {
    const info = await stat(resolve(command)).catch(() => null);
    if (info?.isDirectory() === true) {
      rest = [command, ...rest];
      command = "scan";
    } else return fail(`unknown command "${command}".`);
  }
  if (command === "rules" ? rest.length > 0 : rest.length > 1) {
    return fail(`${command} takes ${command === "rules" ? "no arguments" : `at most one ${command === "verify" ? "file" : "path"}`}.`);
  }

  const out: Outputs = {
    json: values.json === true, sarif: values.sarif, html: values.html, receipt: values.receipt,
    sign: values.sign === true, brief: values.brief === true,
  };
  const range = values.diff === undefined ? null : parseRange(values.diff);
  const checkFlags = (): CheckFlags => ({
    base: range?.base ?? values.base,
    head: range?.head ?? values.head ?? "HEAD",
    offline: values.offline === true,
    staged: values.staged === true,
    scope: values.scope ?? [],
    allowConfigReason: values["allow-config-change"],
  });

  switch (command) {
    case "scan":
      if (range !== null || values.staged === true || values.base !== undefined) return checkCommand(rest[0], checkFlags(), out);
      return scanCommand(rest[0], out, values.policy);
    case "check":
      return checkCommand(rest[0], checkFlags(), out);
    case "init":
      return initCommand(rest[0], {
        hook: values.hook === true, ci: values.ci === true, config: values.config === true, require: values.require === true,
        all: values.all === true, yes: values.yes === true, dryRun: values["dry-run"] === true, force: values.force === true,
      });
    case "doctor": {
      const min = values["min-grade"]?.toUpperCase();
      if (min !== undefined && !/^[A-DF]$/.test(min)) return fail("--min-grade must be A, B, C, D or F.");
      return doctor(rest[0], out.json, values.strict === true, min as Grade | undefined);
    }
    case "report":
      return reportCommand(rest[0], out, {
        policyPath: values.policy, preparedFor: values.for, preparedBy: values.by,
        diff: range !== null || values.base !== undefined ? checkFlags() : null,
      });
    case "verify":
      return verifyCommand(rest[0]);
    case "rules":
      return rulesCommand(out.json);
    default:
      return fail(`unknown command "${command}".`);
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    // A bug in Isoklo, not a verdict on the user's code: say so plainly and exit 2.
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    process.stderr.write(`isoklo: unexpected error. This is a bug in Isoklo, not a problem with your code.\n${detail}\n`);
    process.exitCode = ExitCode.CouldNotRun;
  },
);
