// GitHub integration: annotation escaping and limits, the job summary, the CLI inside a simulated Actions job,
// and a lint that keeps action.yml and the workflows safe from script injection.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { annotations, escapeData, escapeProperty, jobSummary, PER_TYPE_LIMIT, couldNotRunAnnotation } from "../dist/check/github.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(ROOT, "dist", "cli.js");

const f = (level, path, line, message = "m", extra = {}) => ({
  rule: "weakened-tests", id: "x", ruleId: "tamper/assertions-removed", severity: "high", level, message, fix: "do the fix",
  evidence: path ? [{ path, line, text: "t" }] : [], ...extra,
});
const summary = (findings, passes = []) => ({
  base: "origin/main", head: "HEAD", filesChanged: 2, results: [{ rule: "weakened-tests", findings, passes, stats: {} }],
});

test("escaping follows GitHub's workflow-command rules", () => {
  assert.equal(escapeData("50% done\nnext"), "50%25 done%0Anext");
  assert.equal(escapeProperty("src/a,b:c.ts"), "src/a%2Cb%3Ac.ts");
});

test("annotations: level -> command, placed on the evidence line, message and fix escaped", () => {
  const out = annotations(summary([
    f("blocked", "test/a.test.js", 6, "Tests weakened: 1 assertion removed."),
    f("review", "package.json", 3),
    f("info", null, 0),
  ]));
  // The same title the GitHub App's check run uses, so a pull request reads the same either way.
  assert.equal(out[0], "::error file=test/a.test.js,line=6,title=Blocked · HIGH · tamper/assertions-removed::Tests weakened: 1 assertion removed.%0AFix: do the fix");
  assert.match(out[1], /^::warning file=package\.json,line=3,title=Review · HIGH · /);
  assert.match(out[2], /^::notice title=Note · HIGH · tamper\/assertions-removed::/);
});

test("annotations: at most 10 per type, blocked first; allowed findings show the reason", () => {
  const many = Array.from({ length: 14 }, (_, i) => f("blocked", `t/${i}.test.js`, 1));
  const out = annotations(summary([...many, f("review", "x", 1, "m", { allowedBecause: "label applied" })]));
  assert.equal(out.filter((l) => l.startsWith("::error")).length, PER_TYPE_LIMIT);
  assert.match(out.find((l) => l.startsWith("::warning")), /Allowed: label applied/);
});

test("annotations: one card per file, line and rule, never two identical cards on the same line", () => {
  // Two assertions removed side by side both anchor to the line where they were removed (the R24 case on isoklo-demo).
  const removed = f("blocked", "test/invoice.test.js", 25, "Tests weakened: 2 assertions removed.", {
    evidence: [
      { path: "test/invoice.test.js", line: 25, text: "assert.equal(invoice.tax, 11138);", anchor: { path: "test/invoice.test.js", line: 24 } },
      { path: "test/invoice.test.js", line: 26, text: "assert.equal(invoice.total, 146138);", anchor: { path: "test/invoice.test.js", line: 24 } },
    ],
  });
  const out = annotations(summary([removed, { ...removed, message: "Tests weakened: 2 assertions removed." }]));
  assert.equal(out.length, 1, out.join("\n"));
  assert.match(out[0], /^::error file=test\/invoice\.test\.js,line=24,/);
  assert.match(out[0], /Removed here: lines 25 and 26 of the previous version\./);
});

test("job summary lists every finding, escapes table cells, and shows the verdict", () => {
  const md = jobSummary(summary([
    ...Array.from({ length: 12 }, (_, i) => f("blocked", `t/${i}.test.js`, i + 1, `problem ${i}`)),
    f("review", "a|b.json", 2, "pipes | inside"),
  ]));
  assert.match(md, /^## isoklo · blocked/);
  assert.match(md, /\*\*12 problems must be fixed before merge\.\*\*/);
  assert.equal((md.match(/^\| ✕ blocked/gm) ?? []).length, 12);
  assert.match(md, /pipes \\\| inside/);
});

test("job summary for a pass lists what was checked", () => {
  const md = jobSummary(summary([], ["No test files changed.", "No new packages."]));
  assert.match(md, /## isoklo · passed/);
  assert.match(md, /- ✓ No new packages\./);
});

test("could-not-run annotation says the gate failed closed", () => {
  assert.match(couldNotRunAnnotation("base missing"), /^::error title=Isoklo could not run::base missing%0AThe check failed closed/);
});

// ---------------------------------------------------------------- the CLI inside a simulated Actions job
function blockedRepo(t) {
  const dir = mkdtempSync(join(tmpdir(), "isoklo-gh-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const git = (...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@isoklo.dev", "-c", "core.autocrlf=false", ...a], { cwd: dir, encoding: "utf8" });
  mkdirSync(join(dir, "test"));
  writeFileSync(join(dir, "test/a.test.js"), 'test("x", () => {\n  expect(a).toBe(1);\n  expect(b).toBe(2);\n});\n');
  git("init", "-q", "-b", "main"); git("add", "-A"); git("commit", "-q", "-m", "base"); git("checkout", "-q", "-b", "pr");
  writeFileSync(join(dir, "test/a.test.js"), 'test("x", () => {\n  expect(a).toBe(1);\n});\n');
  git("commit", "-q", "-am", "agent");
  return dir;
}

function inActions(t, dir, ...args) {
  const summaryFile = join(mkdtempSync(join(tmpdir(), "isoklo-sum-")), "summary.md");
  t.after(() => rmSync(join(summaryFile, ".."), { recursive: true, force: true }));
  writeFileSync(summaryFile, "");
  const r = spawnSync(process.execPath, [CLI, "check", dir, "--offline", ...args], {
    encoding: "utf8", env: { ...process.env, NO_COLOR: "1", GITHUB_ACTIONS: "true", GITHUB_STEP_SUMMARY: summaryFile, GITHUB_BASE_REF: "" },
  });
  return { code: r.status, out: r.stdout, err: r.stderr, summary: readFileSync(summaryFile, "utf8") };
}

test("in Actions: annotations on the changed line, job summary written, exit 1", (t) => {
  const r = inActions(t, blockedRepo(t));
  assert.equal(r.code, 1);
  // The removed assertion was old line 3; in the new file the removal sits after line 2, which is where GitHub can draw it.
  assert.match(r.out, /^::error file=test\/a\.test\.js,line=2,title=Blocked · HIGH · tamper\/assertions-removed::Tests weakened/m);
  assert.match(r.summary, /## isoklo · blocked/);
  assert.match(r.summary, /`test\/a\.test\.js:3`/);
});

test("in Actions with --json: machine output only, no annotations", (t) => {
  const r = inActions(t, blockedRepo(t), "--json");
  assert.doesNotMatch(r.out, /^::/m);
  assert.equal(JSON.parse(r.out).verdict, "blocked");
});

test("in Actions, could not run: visible error annotation, summary says failed closed, exit 2", (t) => {
  const r = inActions(t, blockedRepo(t), "--base", "no-such-branch");
  assert.equal(r.code, 2);
  assert.match(r.out, /^::error title=Isoklo could not run::/m);
  assert.match(r.summary, /could not run[\s\S]*failed closed/);
});

test("outside Actions: no workflow commands in the output", (t) => {
  const r = spawnSync(process.execPath, [CLI, "check", blockedRepo(t), "--offline"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", GITHUB_ACTIONS: "", GITHUB_BASE_REF: "" } });
  assert.equal(r.status, 1);
  assert.doesNotMatch(r.stdout, /^::/m);
});

// ---------------------------------------------------------------- injection-safety lint
/** Lines inside `run:` scripts of a workflow or action file. */
function runLines(yaml) {
  const out = [];
  let runIndent = -1;
  for (const line of yaml.split(/\r?\n/)) {
    const indent = line.length - line.trimStart().length;
    if (runIndent >= 0 && line.trim() !== "" && indent <= runIndent) runIndent = -1;
    const m = /^(\s*)(- )?run:\s*(.*)$/.exec(line);
    if (m) {
      if (m[3] === "|" || m[3] === ">") runIndent = m[1].length + (m[2] ? 2 : 0);
      else out.push(m[3]);
      continue;
    }
    if (runIndent >= 0) out.push(line);
  }
  return out;
}

for (const file of ["action.yml", "examples/github/isoklo.yml", ".github/workflows/ci.yml"]) {
  test(`lint ${file}: no \${{ }} expressions inside run scripts`, () => {
    const lines = runLines(readFileSync(join(ROOT, file), "utf8"));
    assert.ok(lines.length > 0 || file !== "action.yml", "action.yml must have a run script");
    const bad = lines.filter((l) => l.includes("${{"));
    assert.deepEqual(bad, [], `expressions in run scripts can inject shell commands: ${bad.join(" | ")}`);
  });
}

test("lint: workflows use pull_request (never pull_request_target), read-only contents, full history for the gate", () => {
  for (const file of ["examples/github/isoklo.yml", ".github/workflows/ci.yml"]) {
    const y = readFileSync(join(ROOT, file), "utf8");
    assert.doesNotMatch(y.replace(/#.*$/gm, ""), /pull_request_target/, file);
    assert.match(y, /permissions:\s*\n\s+contents: read/, file);
  }
  assert.match(readFileSync(join(ROOT, "examples/github/isoklo.yml"), "utf8"), /fetch-depth: 0/);
});
