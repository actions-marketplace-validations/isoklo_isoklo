// Rule 2 (unknown or brand-new packages): manifest parsing, registry answers from a FAKE registry (no internet),
// and the CLI end to end with --offline on a real temporary git repo.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { addedPackages, npmPackages, pyprojectPackages, requirementsPackages, normalizePypi, manifestKind } from "../dist/check/packages/manifests.js";
import { unknownPackages, readNpmrc } from "../dist/check/packages/rule.js";
import { lookupNpm, lookupPypi } from "../dist/check/packages/registry.js";

const NOW = new Date("2026-11-20T09:00:00Z");
const daysAgo = (d) => new Date(NOW.getTime() - d * 86_400_000).toISOString();

/** A fake registry: URL -> { status, body }. Records every URL it was asked for. */
function fakeRegistry(routes) {
  const asked = [];
  const fetch = async (url) => {
    asked.push(url);
    for (const [prefix, answer] of Object.entries(routes)) {
      if (url === prefix || url.startsWith(prefix + "?")) {
        if (answer === "network-error") throw new TypeError("fetch failed");
        return { status: answer.status, json: async () => answer.body };
      }
    }
    return { status: 404, json: async () => ({}) };
  };
  return { fetch, asked };
}

const NPM = "https://registry.npmjs.org/";
const DL = "https://api.npmjs.org/downloads/point/last-week/";
const PYPI = "https://pypi.org/pypi/";

const opts = (fetch, extra = {}) => ({ fetch, offline: false, now: NOW, privateNpmScopes: new Set(), customNpmRegistry: false, ...extra });

const pkgJson = (deps, dev = {}) => JSON.stringify({ name: "app", scripts: { build: "tsc" }, dependencies: deps, devDependencies: dev }, null, 2) + "\n";

// ---------------------------------------------------------------- manifests
test("package.json: only real dependency sections; scripts are not packages", () => {
  const f = npmPackages(pkgJson({ react: "^19.0.0" }, { vitest: "^3" }));
  assert.deepEqual([...f.packages.keys()].sort(), ["react", "vitest"]);
});

test("package.json: version bumps are not new; aliases resolve; git/file/workspace are skipped", () => {
  const before = npmPackages(pkgJson({ react: "^18.0.0" }));
  const after = npmPackages(pkgJson({
    react: "^19.0.0", "my-lodash": "npm:lodash@^4", local: "file:../local", mono: "workspace:*", gh: "user/repo#main", "left-pad-pro": "^1.0.0",
  }));
  assert.deepEqual(addedPackages(before, after).map((p) => p.name).sort(), ["left-pad-pro", "lodash"]);
});

test("package.json evidence points at the declaring line", () => {
  const p = npmPackages(pkgJson({ "left-pad-pro": "^1.0.0" })).packages.get("left-pad-pro");
  assert.equal(p.text, '"left-pad-pro": "^1.0.0"');
  assert.ok(p.line > 1);
});

test("requirements.txt: names normalised; options, URLs and paths skipped; private index noticed", () => {
  const f = requirementsPackages("--extra-index-url https://pkgs.example.com/simple\nDjango>=5 # web\nrequests[socks]==2.32\n-e .\n./vendor/pkg\nfoo @ https://x/y.whl\nTyping_Extensions\n");
  assert.deepEqual([...f.packages.keys()], ["django", "requests", "typing-extensions"]);
  assert.equal(f.privateIndex, true);
});

test("pyproject.toml: [project] dependencies, optional groups and Poetry tables", () => {
  const f = pyprojectPackages(`[project]
name = "svc"
dependencies = [
  "fastapi>=0.110",
  "pydantic_core",
]

[project.optional-dependencies]
dev = ["pytest>=8", 'ruff']

[tool.poetry.dependencies]
python = "^3.12"
httpx = "^0.27"
mylib = { path = "../mylib" }
`);
  assert.deepEqual([...f.packages.keys()], ["fastapi", "pydantic-core", "pytest", "ruff", "httpx"]);
});

test("manifest kinds and PyPI normalisation", () => {
  assert.equal(manifestKind("apps/web/package.json"), "package.json");
  assert.equal(manifestKind("node_modules/x/package.json"), null);
  assert.equal(manifestKind("requirements-dev.txt"), "requirements");
  assert.equal(normalizePypi("Foo_Bar.baz"), "foo-bar-baz");
});

// ---------------------------------------------------------------- registry
test("npm: 404 is missing; small packages also fetch their creation date", async () => {
  const { fetch } = fakeRegistry({
    [NPM + "ghost-pkg"]: { status: 404, body: {} },
    [NPM + "tiny-new"]: { status: 200, body: { name: "tiny-new", time: { created: daysAgo(3) } } },
    [DL + "tiny-new"]: { status: 200, body: { downloads: 12 } },
  });
  assert.equal((await lookupNpm("ghost-pkg", fetch, NOW)).status, "missing");
  const l = await lookupNpm("tiny-new", fetch, NOW);
  assert.equal(l.status, "exists");
  assert.equal(l.createdAt, daysAgo(3));
});

test("npm: popular packages skip the big document; scoped names are encoded", async () => {
  const { fetch, asked } = fakeRegistry({
    [NPM + "react"]: { status: 200, body: { name: "react" } },
    [DL + "react"]: { status: 200, body: { downloads: 50_000_000 } },
    [NPM + "@acme%2Fui"]: { status: 404, body: {} },
  });
  const l = await lookupNpm("react", fetch, NOW);
  assert.equal(l.createdAt, undefined);
  assert.equal(asked.filter((u) => u === NPM + "react").length, 1);
  assert.equal((await lookupNpm("@acme/ui", fetch, NOW)).status, "missing");
});

test("npm: rate limits and network errors are unverified, never missing", async () => {
  const { fetch } = fakeRegistry({ [NPM + "busy"]: { status: 429, body: {} }, [NPM + "down"]: "network-error" });
  const busy = await lookupNpm("busy", fetch, NOW);
  assert.equal(busy.status, "unverified");
  assert.match(busy.detail, /rate-limiting/);
  assert.equal((await lookupNpm("down", fetch, NOW)).status, "unverified");
});

test("PyPI: first upload across all releases is the creation date", async () => {
  const { fetch } = fakeRegistry({
    [PYPI + "fresh/json"]: { status: 200, body: { releases: { "0.2": [{ upload_time_iso_8601: daysAgo(1) }], "0.1": [{ upload_time_iso_8601: daysAgo(5) }] } } },
  });
  assert.equal((await lookupPypi("fresh", fetch, NOW)).createdAt, daysAgo(5));
});

// ---------------------------------------------------------------- rule
const change = (path, before, after) => ({ path, before, after });

test("a package that does not exist on npm is blocked, with the declaring line as evidence", async () => {
  const { fetch } = fakeRegistry({ [NPM + "left-pad-pro"]: { status: 404, body: {} } });
  const r = await unknownPackages([change("package.json", pkgJson({}), pkgJson({ "left-pad-pro": "^1.0.0" }))], opts(fetch));
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].id, "package-does-not-exist");
  assert.equal(r.findings[0].level, "blocked");
  assert.match(r.findings[0].message, /left-pad-pro is not on npm \(checked 2026-11-20 09:00 UTC\)/);
  assert.equal(r.findings[0].evidence[0].path, "package.json");
});

test("a brand-new package is flagged for review with its age", async () => {
  const { fetch } = fakeRegistry({
    [NPM + "tiny-new"]: { status: 200, body: { time: { created: daysAgo(6) } } },
    [DL + "tiny-new"]: { status: 200, body: { downloads: 3 } },
  });
  const r = await unknownPackages([change("package.json", pkgJson({}), pkgJson({ "tiny-new": "1.0.0" }))], opts(fetch));
  assert.equal(r.findings[0].id, "package-brand-new");
  assert.equal(r.findings[0].level, "review");
  assert.match(r.findings[0].message, /6 days ago/);
});

test("established packages pass, and only added ones are looked up", async () => {
  const { fetch, asked } = fakeRegistry({
    [NPM + "zod"]: { status: 200, body: {} },
    [DL + "zod"]: { status: 200, body: { downloads: 9_000_000 } },
  });
  const r = await unknownPackages([change("package.json", pkgJson({ react: "^18" }), pkgJson({ react: "^19", zod: "^3" }))], opts(fetch));
  assert.deepEqual(r.findings, []);
  assert.ok(asked.every((u) => !u.includes("react")), "react was only bumped, so it must not be looked up");
  assert.match(r.passes.join(" "), /1 new package found on npm/);
});

test("scoped names: private scopes in .npmrc are never sent; unknown scoped names are review, not blocked", async () => {
  const { fetch, asked } = fakeRegistry({ [NPM + "@other%2Futil"]: { status: 404, body: {} } });
  const npmrc = readNpmrc("@acme:registry=https://npm.acme.dev/\n");
  const r = await unknownPackages(
    [change("package.json", pkgJson({}), pkgJson({ "@acme/ui": "^1", "@other/util": "^1" }))],
    opts(fetch, { privateNpmScopes: npmrc.scopes }),
  );
  assert.ok(asked.every((u) => !u.includes("acme")), "a private scope must never be sent to the public registry");
  assert.deepEqual(r.findings.map((f) => `${f.id}:${f.level}`), ["package-not-found-maybe-private:review"]);
});

test("PyPI: missing names are blocked, unless the file uses a private index", async () => {
  const { fetch } = fakeRegistry({ [PYPI + "fastapi-auth-helperz/json"]: { status: 404, body: {} } });
  const plain = await unknownPackages([change("requirements.txt", "fastapi\n", "fastapi\nfastapi_auth_helperz\n")], opts(fetch));
  assert.equal(plain.findings[0].level, "blocked");
  const priv = await unknownPackages([change("requirements.txt", "--extra-index-url https://x/simple\n", "--extra-index-url https://x/simple\nfastapi_auth_helperz\n")], opts(fetch));
  assert.equal(priv.findings[0].level, "review");
});

test("registry trouble is review, never a pass and never a block", async () => {
  const { fetch } = fakeRegistry({ [NPM + "some-lib"]: "network-error" });
  const r = await unknownPackages([change("package.json", pkgJson({}), pkgJson({ "some-lib": "^1" }))], opts(fetch));
  assert.deepEqual(r.findings.map((f) => `${f.id}:${f.level}`), ["package-unverified:review"]);
});

test("offline: nothing is sent, and the report says the packages were not verified", async () => {
  const { fetch, asked } = fakeRegistry({});
  const r = await unknownPackages([change("package.json", pkgJson({}), pkgJson({ "some-lib": "^1" }))], opts(fetch, { offline: true }));
  assert.equal(asked.length, 0);
  assert.equal(r.findings[0].level, "info");
});

test("an unparseable package.json is review, not silently skipped", async () => {
  const { fetch } = fakeRegistry({});
  const r = await unknownPackages([change("package.json", pkgJson({}), "{ not json")], opts(fetch));
  assert.equal(r.findings[0].id, "manifest-unreadable");
});

// ---------------------------------------------------------------- CLI, offline, real git
test("CLI: a new dependency shows in the header and as not verified with --offline", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "isoklo-pkg-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const git = (...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@isoklo.dev", ...a], { cwd: dir, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(dir, "package.json"), pkgJson({ react: "^18" }));
  git("add", "-A"); git("commit", "-q", "-m", "base"); git("checkout", "-q", "-b", "pr");
  writeFileSync(join(dir, "package.json"), pkgJson({ react: "^19", "left-pad-pro": "^1" }));
  git("commit", "-q", "-am", "add dep");
  const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
  const r = spawnSync(process.execPath, [cli, "check", dir, "--offline"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", GITHUB_BASE_REF: "" } });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /1 new package\b/);
  assert.match(r.stdout, /· info +1 new package not checked against the registries \(offline\)/);
  assert.match(r.stdout, /package\.json:\d+ +"left-pad-pro": "\^1"/);
});
