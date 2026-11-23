// `isoklo check` against real throwaway git repos: a base on main, a pull-request branch with one kind of change.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, unlinkSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDiff } from "../dist/check/diff.js";
import { isAssertion, isTautology, disables, isTestPath } from "../dist/check/patterns.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

const AUTH_TEST = `import { login } from "../src/auth.js";

test("rate limits after 5 attempts", () => {
  const res = login("a", "wrong");
  expect(res.status).toBe(401);
  expect(res.attempts).toBe(1);
  expect(res.locked).toBe(false);
});
`;

function sh(cwd, ...args) {
  return execFileSync("git", ["-c", "user.name=Isoklo Test", "-c", "user.email=test@isoklo.dev", ...args], { cwd, encoding: "utf8" });
}

function write(dir, files) {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
}

/** Base commit on main, then a "pr" branch where `change(dir)` runs and is committed. */
function pr(t, base, change) {
  const dir = mkdtempSync(join(tmpdir(), "isoklo-check-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  sh(dir, "init", "-q", "-b", "main");
  write(dir, base);
  sh(dir, "add", "-A");
  sh(dir, "commit", "-q", "-m", "base");
  sh(dir, "checkout", "-q", "-b", "pr");
  change(dir);
  sh(dir, "add", "-A");
  sh(dir, "commit", "-q", "--allow-empty", "-m", "agent change");
  return dir;
}

function check(dir, ...flags) {
  const r = spawnSync(process.execPath, [CLI, "check", dir, ...flags], {
    encoding: "utf8",
    // The ceiling stops git from finding a repository above the temp folder (some home folders are git repos).
    env: { ...process.env, NO_COLOR: "1", GITHUB_BASE_REF: "", GITHUB_ACTIONS: "", GIT_CEILING_DIRECTORIES: tmpdir() },
  });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function result(dir) {
  const r = check(dir, "--json");
  assert.notEqual(r.code, 2, r.err);
  return { code: r.code, ...JSON.parse(r.out) };
}

const findings = (r) => r.results.flatMap((x) => x.findings);
const ids = (r) => findings(r).map((f) => `${f.id}:${f.level}`);

test("source-only change passes", (t) => {
  const dir = pr(t, { "src/auth.js": "export const a = 1;\n", "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "src/auth.js": "export const a = 2;\n" }));
  const r = result(dir);
  assert.equal(r.code, 0);
  assert.equal(r.verdict, "passed");
  assert.deepEqual(findings(r), []);
});

test("removing assertions blocks, with exact old line numbers as evidence", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": AUTH_TEST.replace("  expect(res.attempts).toBe(1);\n", "").replace("  expect(res.locked).toBe(false);\n", "") }));
  const r = result(dir);
  assert.equal(r.code, 1);
  const f = findings(r).find((x) => x.id === "assertions-removed");
  assert.equal(f.level, "blocked");
  assert.deepEqual(f.evidence.map((e) => `${e.path}:${e.line}`), ["test/auth.test.js:6", "test/auth.test.js:7"]);
  assert.match(f.message, /2 assertions removed, 0 added in their place, 2 checks fewer/);
});

test("commenting an assertion out counts as removing it", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": AUTH_TEST.replace("  expect(res.locked)", "  // expect(res.locked)") }));
  assert.deepEqual(ids(result(dir)), ["assertions-removed:blocked"]);
});

test("reformatting assertions (whitespace, trailing semicolon) passes", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": AUTH_TEST.replace("  expect(res.status).toBe(401);", "    expect(res.status).toBe(401)") }));
  const r = result(dir);
  assert.equal(r.code, 0, JSON.stringify(findings(r)));
});

test("moving an assertion to another test file passes", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) => {
    write(d, {
      "test/auth.test.js": AUTH_TEST.replace("  expect(res.locked).toBe(false);\n", ""),
      "test/lock.test.js": 'test("lock", () => {\n  const res = login("a", "wrong");\n  expect(res.locked).toBe(false);\n});\n',
    });
  });
  assert.equal(result(dir).code, 0);
});

test("deleting a test file with assertions blocks", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST, "src/auth.js": "x\n" }, (d) => unlinkSync(join(d, "test/auth.test.js")));
  const r = result(dir);
  assert.equal(r.code, 1);
  assert.deepEqual(ids(r), ["test-file-deleted:blocked"]);
  assert.match(findings(r)[0].message, /had 3 assertions/);
});

test("renaming a test file is not a deletion", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) => {
    mkdirSync(join(d, "test/unit"), { recursive: true });
    renameSync(join(d, "test/auth.test.js"), join(d, "test/unit/auth.test.js"));
  });
  assert.equal(result(dir).code, 0);
});

test("adding .skip or .only blocks", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": AUTH_TEST.replace('test("rate', 'test.skip("rate') + 'it.only("x", () => {\n  expect(1).toBe(2);\n});\n' }));
  const r = result(dir);
  assert.equal(r.code, 1);
  const disabled = findings(r).filter((f) => f.id === "test-disabled");
  assert.equal(disabled.length, 2);
  assert.match(disabled.map((f) => f.message).join(" "), /focuses one test/);
});

test("replacing real assertions with ones that cannot fail blocks", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": AUTH_TEST.replace("expect(res.status).toBe(401);", "expect(true).toBe(true);") }));
  const r = result(dir);
  assert.equal(r.code, 1);
  assert.deepEqual(ids(r).sort(), ["assertions-removed:blocked", "tautology:blocked"]);
});

test("a reasoned allow marker turns the block into review and passes", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, {
      "test/auth.test.js": "// isoklo: allow-test-change attempts counter removed by issue #42\n" +
        AUTH_TEST.replace("  expect(res.attempts).toBe(1);\n", ""),
    }));
  const r = result(dir);
  assert.equal(r.code, 0);
  const f = findings(r).find((x) => x.id === "assertions-removed");
  assert.equal(f.level, "review");
  assert.equal(f.allowedBecause, "attempts counter removed by issue #42");
});

test("an allow marker without a reason does not unblock", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": "// isoklo: allow-test-change\n" + AUTH_TEST.replace("  expect(res.attempts).toBe(1);\n", "") }));
  const r = result(dir);
  assert.equal(r.code, 1);
  assert.match(findings(r)[0].fix, /needs a reason/);
});

test("python: removing an assert from test_*.py blocks", (t) => {
  const base = "def test_total():\n    total = add(2, 2)\n    assert total == 4\n    assert isinstance(total, int)\n";
  const dir = pr(t, { "tests/test_math.py": base }, (d) =>
    write(d, { "tests/test_math.py": base.replace("    assert isinstance(total, int)\n", "") }));
  assert.equal(result(dir).code, 1);
});

test("commits that land on main after branching are not blamed on the pull request", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) => write(d, { "README.md": "docs\n" }));
  sh(dir, "checkout", "-q", "main");
  write(dir, { "test/auth.test.js": AUTH_TEST.replace("  expect(res.locked).toBe(false);\n", "") });
  sh(dir, "commit", "-q", "-am", "main moved on");
  sh(dir, "checkout", "-q", "pr");
  assert.equal(result(dir).code, 0);
});

test("text output: verdict, evidence with file:line, fix, and the blocked footer", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) =>
    write(d, { "test/auth.test.js": AUTH_TEST.replace("  expect(res.attempts).toBe(1);\n", "") }));
  const r = check(dir);
  assert.equal(r.code, 1);
  assert.match(r.out, /✕ blocked {2}Tests weakened/);
  assert.match(r.out, /test\/auth\.test\.js:6 +expect\(res\.attempts\)\.toBe\(1\);/);
  assert.match(r.out, /fix: restore the removed assertions/);
  assert.match(r.out, /blocked · 1 problem must be fixed before merge\./);
});

test("base is found automatically (main) when --base is not given", (t) => {
  const dir = pr(t, { "test/auth.test.js": AUTH_TEST }, (d) => write(d, { "src/x.js": "1\n" }));
  const r = check(dir);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /isoklo check · main\.\.\.HEAD/);
});

test("not a git repository: could not run (exit 2), not a pass", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "isoklo-nogit-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = check(dir);
  assert.equal(r.code, 2);
  assert.match(r.err, /not inside a git repository/);
});

test("missing base: could not run (exit 2) with the names it tried", (t) => {
  const dir = pr(t, { "a.txt": "a\n" }, () => {});
  const r = check(dir, "--base", "does-not-exist");
  assert.equal(r.code, 2);
  assert.match(r.err, /base "does-not-exist" is not a commit/);
});

test("diff parser: hunk line numbers, renames, deletions", () => {
  const d = parseDiff([
    "diff --git a/t/a.test.js b/t/a.test.js",
    "--- a/t/a.test.js",
    "+++ b/t/a.test.js",
    "@@ -10,2 +10 @@",
    "-  expect(a).toBe(1);",
    "-  expect(b).toBe(2);",
    "+  expect(c).toBe(3);",
    "diff --git a/old.test.js b/new.test.js",
    "similarity index 100%",
    "rename from old.test.js",
    "rename to new.test.js",
    "diff --git a/gone.test.js b/gone.test.js",
    "deleted file mode 100644",
    "--- a/gone.test.js",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    "-expect(x).toBe(1);",
  ].join("\n"));
  assert.deepEqual(d[0].removed.map((l) => l.line), [10, 11]);
  assert.deepEqual(d[0].added.map((l) => l.line), [10]);
  assert.equal(d[1].status, "renamed");
  assert.equal(d[1].oldPath, "old.test.js");
  assert.equal(d[1].newPath, "new.test.js");
  assert.equal(d[2].status, "deleted");
  assert.equal(d[2].newPath, null);
});

test("patterns", () => {
  assert.ok(isTestPath("src/__tests__/a.ts"));
  assert.ok(isTestPath("pkg/math_test.go"));
  assert.ok(isTestPath("tests/test_api.py"));
  assert.ok(!isTestPath("src/testing-utils.ts"));
  assert.ok(isAssertion("  expect(x).toEqual(y)"));
  assert.ok(isAssertion("    assert total == 4"));
  assert.ok(isAssertion('\tt.Errorf("bad %d", n)'));
  assert.ok(!isAssertion("  // expect(x).toEqual(y)"));
  assert.ok(isTautology("expect(true).toBe(true);"));
  assert.ok(!isTautology("expect(res.ok).toBe(true);"));
  assert.ok(disables("describe.only('x', () => {"));
  assert.ok(disables("@pytest.mark.skip(reason='flaky')"));
  assert.equal(disables("const skip = 3;"), null);
});

test("diff parser: removed lines know where they sit in the new file", () => {
  const d = parseDiff("diff --git a/t.test.js b/t.test.js\n--- a/t.test.js\n+++ b/t.test.js\n@@ -7,2 +6,0 @@\n-  expect(a).toBe(1);\n-  expect(b).toBe(2);\n@@ -20 +18 @@\n-  expect(c).toBe(3);\n+  expect(c).toBe(4);\n");
  assert.deepEqual(d[0].removed.map((l) => [l.line, l.newAt]), [[7, 6], [8, 6], [20, 18]]);
});
