// `isoklo doctor` against throwaway repos: each test builds a temp folder, runs the real command, and cleans up.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { analyze, estimateTokens, importsAgentsMd } from "../dist/doctor/analyze.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "isoklo-doctor-"));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

function doctor(dir, ...flags) {
  const r = spawnSync(process.execPath, [CLI, "doctor", dir, ...flags], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function json(dir) {
  const r = doctor(dir, "--json");
  assert.equal(r.code, 0, r.err);
  return JSON.parse(r.out);
}

const ids = (report) => report.findings.map((f) => f.id);

test("empty repo: nothing found, info only, exit 0", (t) => {
  const dir = repo({});
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = json(dir);
  assert.deepEqual(r.files, []);
  assert.deepEqual(ids(r), ["no-instructions"]);
});

test("AGENTS.md alone: Claude Code falls back to it, no findings", (t) => {
  const dir = repo({ "AGENTS.md": "# Rules\nUse pnpm.\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = json(dir);
  assert.deepEqual(r.files[0].readBy, ["Claude Code", "Codex", "Cursor", "GitHub Copilot", "Antigravity CLI", "Devin Desktop"]);
  assert.deepEqual(ids(r), []);
});

test("CLAUDE.md shadows AGENTS.md: flagged with the fix", (t) => {
  const dir = repo({ "AGENTS.md": "Use pnpm.\n", "CLAUDE.md": "Prefer small diffs.\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = json(dir);
  const agents = r.files.find((f) => f.path === "AGENTS.md");
  assert.ok(!agents.readBy.includes("Claude Code"));
  const f = r.findings.find((x) => x.id === "agents-md-shadowed");
  assert.ok(f);
  assert.match(f.fix, /@AGENTS\.md/);
});

test("CLAUDE.md that imports @AGENTS.md is fine", (t) => {
  const dir = repo({ "AGENTS.md": "Use pnpm.\n", "CLAUDE.md": "@AGENTS.md\n\nPrefer small diffs.\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = json(dir);
  assert.ok(!ids(r).includes("agents-md-shadowed"));
  assert.ok(r.files.find((f) => f.path === "AGENTS.md").readBy.includes("Claude Code"));
});

test(".claude/CLAUDE.md also shadows AGENTS.md", (t) => {
  const dir = repo({ "AGENTS.md": "Use pnpm.\n", ".claude/CLAUDE.md": "Prefer small diffs.\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  assert.ok(ids(json(dir)).includes("agents-md-shadowed"));
});

test("identical copies are flagged as drift risk", (t) => {
  const text = "Use pnpm. Run tests before committing.\n";
  const dir = repo({ "AGENTS.md": text, "GEMINI.md": text });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const f = json(dir).findings.find((x) => x.id === "duplicate-content");
  assert.deepEqual(f.paths, ["AGENTS.md", "GEMINI.md"]);
});

test("empty and large files are flagged; token counts are estimates", (t) => {
  const dir = repo({ "GEMINI.md": "   \n", "AGENTS.md": "x".repeat(4 * 1600) });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = json(dir);
  assert.ok(ids(r).includes("empty-file"));
  assert.ok(ids(r).includes("large-file"));
  assert.equal(r.tokensAreEstimates, true);
  assert.equal(r.files.find((f) => f.path === "AGENTS.md").tokens, 1600);
});

test("rule folders: only matching extensions, sorted, forward slashes", (t) => {
  const dir = repo({
    ".cursor/rules/b.mdc": "B rule\n", ".cursor/rules/a.mdc": "A rule\n", ".cursor/rules/notes.txt": "ignore me\n",
    ".github/instructions/api.instructions.md": "API rule\n",
  });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const paths = json(dir).files.map((f) => f.path);
  assert.deepEqual(paths, [".cursor/rules/a.mdc", ".cursor/rules/b.mdc", ".github/instructions/api.instructions.md"]);
});

test("legacy .cursorrules next to .cursor/rules is flagged for review", (t) => {
  const dir = repo({ ".cursorrules": "old\n", ".cursor/rules/x.mdc": "new\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const f = json(dir).findings.find((x) => x.id === "cursorrules-legacy");
  assert.equal(f.level, "review");
});

test("wrong-case file names are not reported (Linux agents would not read them)", (t) => {
  const dir = repo({ "claude.md": "lowercase name\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  assert.deepEqual(json(dir).files, []);
});

test("CLAUDE.md symlinked to AGENTS.md counts as an import", (t) => {
  const dir = repo({ "AGENTS.md": "Use pnpm.\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  try {
    symlinkSync("AGENTS.md", join(dir, "CLAUDE.md"));
  } catch {
    t.skip("this OS account cannot create symlinks (common on Windows without Developer Mode)");
    return;
  }
  const r = json(dir);
  assert.ok(!ids(r).includes("agents-md-shadowed"));
  assert.ok(!ids(r).includes("duplicate-content"));
});

test("text report: verdict, fix and the advisory footer; no exclamation punctuation", (t) => {
  const dir = repo({ "AGENTS.md": "Use pnpm.\n", "CLAUDE.md": "Prefer small diffs.\n" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = doctor(dir);
  assert.equal(r.code, 0);
  assert.match(r.out, /Claude Code ignores AGENTS\.md here/);
  assert.match(r.out, /fix: add the line `@AGENTS\.md`/);
  assert.match(r.out, /Doctor is advisory and never blocks a merge\./);
  assert.doesNotMatch(r.out.replace(/! review/g, ""), /!/);
});

test("--strict turns review findings into exit 1; a clean repo still passes", (t) => {
  const bad = repo({ "AGENTS.md": "Use pnpm.\n", "CLAUDE.md": "Prefer small diffs.\n" });
  const good = repo({ "AGENTS.md": "Use pnpm.\n" });
  t.after(() => { rmSync(bad, { recursive: true, force: true }); rmSync(good, { recursive: true, force: true }); });
  assert.equal(doctor(bad, "--strict").code, 1);
  assert.equal(doctor(good, "--strict").code, 0);
});

test("a missing folder cannot run: exit 2 on stderr", () => {
  const r = doctor(join(tmpdir(), "isoklo-does-not-exist-" + Date.now()));
  assert.equal(r.code, 2);
  assert.match(r.err, /no such folder/);
  assert.equal(r.out, "");
});

test("pure helpers", () => {
  assert.equal(estimateTokens("abcd"), 1);
  assert.equal(estimateTokens("abcde"), 2);
  assert.ok(importsAgentsMd("@AGENTS.md"));
  assert.ok(importsAgentsMd("See @./AGENTS.md for rules"));
  assert.ok(!importsAgentsMd("email me@AGENTS.md.example"));
  assert.deepEqual(analyze([]).files, []);
});

test("vendor facts checked 2026-11-20: nested Copilot and Cursor rules, Antigravity, Devin and Claude rule folders", (t) => {
  const dir = repo({
    ".github/instructions/api/routes.instructions.md": "Use zod.\n",
    ".cursor/rules/frontend/components.mdc": "Use tabs.\n",
    ".cursor/rules/notes.md": "Cursor ignores plain .md here.\n",
    ".agents/rules/style.md": "Short names.\n",
    ".agents/rules/deep/skip.md": "Antigravity reads top-level rules only.\n",
    ".devin/rules/a.md": "Prefer pnpm.\n",
    ".claude/rules/testing.md": "Run tests first.\n",
    "GEMINI.md": "Gemini rules.\n",
  });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = json(dir);
  const paths = r.files.map((f) => f.path).sort();
  assert.deepEqual(paths, [
    ".agents/rules/style.md", ".claude/rules/testing.md", ".cursor/rules/frontend/components.mdc", ".devin/rules/a.md",
    ".github/instructions/api/routes.instructions.md", "GEMINI.md",
  ]);
  assert.deepEqual(r.files.find((f) => f.path === "GEMINI.md").readBy, ["Gemini CLI", "Antigravity CLI", "GitHub Copilot"]);
});
