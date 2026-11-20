// Runs the real, built command (dist/cli.js) the way a user or CI would, and checks output streams and exit codes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const PKG = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function run(...args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("--version prints the package.json version and passes", () => {
  const r = run("--version");
  assert.equal(r.code, 0);
  assert.equal(r.out.trim(), PKG.version);
  assert.equal(r.err, "");
});

test("-v is the short form of --version", () => {
  assert.equal(run("-v").out.trim(), PKG.version);
});

test("--help prints usage with the tagline and the exit-code contract", () => {
  const r = run("--help");
  assert.equal(r.code, 0);
  assert.match(r.out, /proof before merge/);
  assert.match(r.out, /0 {2}passed/);
  assert.match(r.out, /1 {2}blocked/);
  assert.match(r.out, /2 {2}could not run/);
});

test("no arguments shows help and passes", () => {
  const r = run();
  assert.equal(r.code, 0);
  assert.match(r.out, /Usage/);
});

test("an unknown command cannot run: exit 2, message on stderr, nothing on stdout", () => {
  const r = run("frobnicate");
  assert.equal(r.code, 2);
  assert.equal(r.out, "");
  assert.match(r.err, /unknown command "frobnicate"/);
});

test("an unknown option cannot run: exit 2 on stderr", () => {
  const r = run("--nope");
  assert.equal(r.code, 2);
  assert.match(r.err, /^isoklo: /);
});

test("the built entry starts with an LF shebang (a CRLF one breaks npx on macOS and Linux)", () => {
  const head = readFileSync(CLI, "utf8").slice(0, 40);
  assert.ok(head.startsWith("#!/usr/bin/env node\n"), JSON.stringify(head));
});

test("voice: no exclamation marks in user-facing output", () => {
  for (const args of [["--help"], ["frobnicate"]]) {
    const r = run(...args);
    assert.doesNotMatch(r.out + r.err, /!/);
  }
});
