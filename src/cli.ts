#!/usr/bin/env node
/**
 * Isoklo command-line entry point.
 * Rules (from the brand voice, 06-voice.md): verdict first, then evidence, then the fix; no exclamation marks or emoji.
 * Output: results go to stdout; problems running Isoklo go to stderr.
 */
import { parseArgs } from "node:util";
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { ExitCode } from "./exit.js";
import { readVersion } from "./version.js";
import { scan, ScanError } from "./doctor/scan.js";
import { analyze } from "./doctor/analyze.js";
import { toJson, toText } from "./doctor/report.js";
import { diffPullRequest, GitError, headCommit, mergeBase, repoRoot, resolveBase, showFile } from "./check/git.js";
import { parseDiff, type FileDiff } from "./check/diff.js";
import { weakenedTests } from "./check/weakened-tests.js";
import { manifestKind } from "./check/packages/manifests.js";
import { readNpmrc, unknownPackages, type ManifestChange } from "./check/packages/rule.js";
import type { FetchLike } from "./check/packages/registry.js";
import { classify } from "./check/config/knowledge.js";
import { agentConfig, type ConfigChange } from "./check/config/rule.js";
import * as checkReport from "./check/report.js";
import { annotations, couldNotRunAnnotation, jobSummary } from "./check/github.js";

const HELP = `isoklo: proof before merge.

Usage
  isoklo <command> [options]

Commands
  check [path]     Check this branch's changes against its base branch. Blocks when
                   tests were deleted, weakened, skipped or focused, when a new
                   package does not exist on npm or PyPI, or when agent or CI
                   configuration widens what agents and CI may do.
  doctor [path]    Check a repo's agent instruction files: which agent reads which,
                   what is ignored, and what it costs. Advisory; never blocks.

Options
  -h, --help       Show this help.
  -v, --version    Show the version.
  --base <ref>     check: the branch or commit to compare against
                   (default: the pull request base in GitHub Actions, then main or master).
  --head <ref>     check: the commit to check (default: HEAD).
  --offline        check: do not contact package registries; new packages are
                   listed as not verified. (Only public package names are ever sent.)
  --allow-config-change <reason>
                   check: accept blocked agent or CI configuration changes as
                   reviewed (pass this only from a maintainer-controlled source).
  --json           Print a machine-readable report.
  --strict         doctor: exit 1 when there are findings to review.

Exit codes
  0  passed
  1  blocked
  2  could not run

In GitHub Actions, check also annotates the pull request's changed lines and writes a
job summary. See action.yml and examples/github/isoklo.yml.
`;

function fail(message: string): ExitCode {
  process.stderr.write(`isoklo: ${message}\nRun \`isoklo --help\` to see what Isoklo can do.\n`);
  return ExitCode.CouldNotRun;
}

/** Colour only for a real terminal, and never when the user asks for none (https://no-color.org). */
function useColor(): boolean {
  return Boolean(process.stdout.isTTY) && process.env["NO_COLOR"] === undefined;
}

async function doctor(pathArg: string | undefined, json: boolean, strict: boolean): Promise<ExitCode> {
  const root = resolve(pathArg ?? ".");
  let scanned;
  try {
    scanned = await scan(root);
  } catch (error) {
    if (error instanceof ScanError) return fail(error.message);
    throw error;
  }
  const report = analyze(scanned);
  process.stdout.write(json ? toJson(report, root, readVersion()) : toText(report, { color: useColor(), root }));
  const toReview = report.findings.some((f) => f.level === "review");
  return strict && toReview ? ExitCode.Blocked : ExitCode.Passed;
}

/** The before and after content of every dependency manifest the change touched. */
async function manifestChanges(root: string, before: string, head: string, files: FileDiff[]): Promise<ManifestChange[]> {
  const out: ManifestChange[] = [];
  for (const f of files) {
    if (f.status === "deleted" || f.newPath === null || manifestKind(f.newPath) === null) continue;
    const after = await showFile(root, head, f.newPath);
    if (after === null) continue;
    const oldPath = f.oldPath ?? f.newPath;
    out.push({ path: f.newPath, before: f.status === "added" ? null : await showFile(root, before, oldPath), after });
  }
  return out;
}

/** Before and after content of every agent or CI configuration file the change touched. */
async function configChanges(root: string, before: string, head: string, files: FileDiff[]): Promise<ConfigChange[]> {
  const out: ConfigChange[] = [];
  for (const f of files) {
    const path = f.newPath ?? f.oldPath ?? "";
    const oldPath = f.oldPath ?? path;
    if (classify(f.status === "deleted" ? oldPath : path) === null) continue;
    out.push({
      path, oldPath, status: f.status, diff: f,
      before: f.status === "added" ? null : await showFile(root, before, oldPath),
      after: f.status === "deleted" ? null : await showFile(root, head, path),
    });
  }
  return out;
}

interface CheckOptions {
  allowConfigReason: string | undefined;
  base: string | undefined;
  head: string;
  json: boolean;
  offline: boolean;
}

async function check(pathArg: string | undefined, o: CheckOptions): Promise<ExitCode> {
  const cwd = resolve(pathArg ?? ".");
  try {
    const root = await repoRoot(cwd);
    const { ref: base } = await resolveBase(root, o.base);
    await headCommit(root, o.head);
    const files = parseDiff(await diffPullRequest(root, base, o.head));
    const before = await mergeBase(root, base, o.head);
    const npmrc = readNpmrc(await showFile(root, o.head, ".npmrc"));
    const packages = await unknownPackages(await manifestChanges(root, before, o.head, files), {
      fetch: globalThis.fetch as unknown as FetchLike,
      offline: o.offline || process.env["ISOKLO_OFFLINE"] === "1",
      now: new Date(),
      privateNpmScopes: npmrc.scopes,
      customNpmRegistry: npmrc.customRegistry,
    });
    const summary: checkReport.CheckSummary = {
      base, head: o.head, filesChanged: files.length,
      results: [
        weakenedTests(files),
        packages,
        agentConfig(await configChanges(root, before, o.head, files), o.allowConfigReason === undefined ? {} : { allowReason: o.allowConfigReason }),
      ],
    };
    const json = o.json;
    process.stdout.write(json ? checkReport.toJson(summary, readVersion()) : checkReport.toText(summary, useColor()));
    if (inGitHubActions() && !json) {
      for (const a of annotations(summary)) process.stdout.write(`${a}\n`);
      writeStepSummary(jobSummary(summary));
    }
    return checkReport.verdictOf(summary) === "blocked" ? ExitCode.Blocked : ExitCode.Passed;
  } catch (error) {
    if (error instanceof GitError) {
      if (inGitHubActions()) {
        process.stdout.write(`${couldNotRunAnnotation(error.message)}\n`);
        writeStepSummary(`## isoklo · could not run\n\n${error.message}\n\nThe check failed closed: nothing was approved.\n`);
      }
      return fail(error.message);
    }
    throw error;
  }
}

/** True inside a GitHub Actions job (GitHub sets this variable on every runner). */
function inGitHubActions(): boolean {
  return process.env["GITHUB_ACTIONS"] === "true";
}

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
        offline: { type: "boolean" },
        "allow-config-change": { type: "string" },
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

  const [command, ...rest] = positionals;
  if (values.help || command === undefined) {
    process.stdout.write(HELP);
    return ExitCode.Passed;
  }

  if (command === "check") {
    if (rest.length > 1) return fail("check takes at most one path.");
    return check(rest[0], {
      base: values.base, head: values.head ?? "HEAD", json: values.json === true, offline: values.offline === true,
      allowConfigReason: values["allow-config-change"],
    });
  }

  if (command === "doctor") {
    if (rest.length > 1) return fail("doctor takes at most one path.");
    return doctor(rest[0], values.json === true, values.strict === true);
  }

  return fail(`unknown command "${command}".`);
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
