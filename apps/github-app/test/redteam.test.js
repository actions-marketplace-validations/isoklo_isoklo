// Red team: a hostile engineer trying to break, bypass or abuse the GitHub App. Each test is a hole that was found
// and closed; the app must fail closed (never approve what it could not read) and never act on unsigned input.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createApp } from "../dist/index.js";
import { appKeys, fakeGitHub, MemoryKV, pullRequestEvent, stripeRequest, webhook } from "./fake-github.js";

const SECRET = "webhook-secret-for-redteam";
const NOW = new Date("2026-11-22T10:00:00Z");
const keys = appKeys();
const BASE = { "src/a.ts": "export const a = 1;\n", "test/a.test.ts": 'test("a", () => {\n  expect(a).toBe(1);\n});\n' };
// Assembled at run time so this file passes Isoklo's own gate.
const KEY = ["gh", "p_", "Zq8Lm2Vx7Pk4Rt9Wb3Ny6Hc1Jd5Fg0Ks9q2W"].join("");

function setup({ head = BASE, base = BASE, env = {}, pr = {}, gh: ghOptions = {}, kv = new MemoryKV() } = {}) {
  const repos = { "acme/shop": { commits: { base1: base, head1: head }, pulls: { 7: { base: "base1", head: "head1", body: "", ...pr } } } };
  const gh = fakeGitHub({ publicKey: keys.publicKey, appId: "123", repos, ...ghOptions });
  const app = createApp({ fetch: gh.fetch, now: () => NOW });
  const ENV = {
    GITHUB_APP_ID: "123", GITHUB_APP_PRIVATE_KEY: keys.privateKey, GITHUB_WEBHOOK_SECRET: SECRET,
    GITHUB_API_URL: "https://api.github.test", ONLINE: "false", ISOKLO_KV: kv, ...env,
  };
  const send = (event, payload) => app.fetch(webhook(SECRET, event, payload), ENV);
  const event = (extra = {}) => pullRequestEvent({ pr: { base: "base1", head: "head1", body: "", ...pr, ...extra } });
  return { app, gh, ENV, send, event, kv };
}
const runs = (gh) => gh.writes.filter((w) => w.path.startsWith("/check-runs"));
const completed = (gh) => runs(gh).filter((w) => w.body.status === "completed").at(-1)?.body;

// ---------------------------------------------------------------- signatures and payloads
test("redteam: an app with no webhook secret configured refuses every delivery (never accepts unsigned input)", async () => {
  const { app, ENV, gh } = setup();
  const res = await app.fetch(webhook(SECRET, "pull_request", { action: "opened" }), { ...ENV, GITHUB_WEBHOOK_SECRET: "" });
  assert.equal(res.status, 401);
  assert.equal(gh.writes.length, 0);
});

test("redteam: a valid signature for a different body is refused", async () => {
  const { app, ENV } = setup();
  const signedFor = JSON.stringify({ action: "closed" });
  const sig = `sha256=${createHmac("sha256", SECRET).update(signedFor).digest("hex")}`;
  const req = new Request("https://app.isoklo.test/webhooks/github", {
    method: "POST", headers: { "x-github-event": "pull_request", "x-hub-signature-256": sig }, body: JSON.stringify({ action: "opened" }),
  });
  assert.equal((await app.fetch(req, ENV)).status, 401);
});

test("redteam: a signed body that is not JSON is a 400, not a crash", async () => {
  const { app, ENV } = setup();
  const body = "not json {";
  const req = new Request("https://app.isoklo.test/webhooks/github", {
    method: "POST", headers: { "x-github-event": "pull_request", "x-hub-signature-256": `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}` }, body,
  });
  assert.equal((await app.fetch(req, ENV)).status, 400);
});

test("redteam: pull_request events without an installation, or with a SHA that would change the API path, are refused", async () => {
  const { send, event, gh } = setup();
  const noInstall = { ...event() };
  delete noInstall.installation;
  assert.equal((await send("pull_request", noInstall)).status, 400);
  const traversal = event();
  traversal.pull_request.head.sha = "../../../app/installations";
  assert.equal((await send("pull_request", traversal)).status, 400);
  assert.equal(gh.writes.length, 0);
});

// ---------------------------------------------------------------- what the app could not read never passes
test("redteam: an empty pull request (no file changes) passes cleanly", async () => {
  const { send, event, gh } = setup({ head: BASE });
  await send("pull_request", event());
  assert.equal(completed(gh).conclusion, "success");
});

test("redteam: a binary-only pull request passes; binaries are not text that could hide code", async () => {
  const { send, event, gh } = setup({ head: { ...BASE, "public/logo.png": "PNGDATA" }, gh: { omitPatch: ["public/logo.png"] } });
  await send("pull_request", event());
  assert.equal(completed(gh).conclusion, "success");
});

test("redteam: a secret hidden in a modified file whose diff GitHub left out is still found (diff rebuilt)", async () => {
  const big = Array.from({ length: 50 }, (_, i) => `export const v${i} = ${i};`).join("\n") + "\n";
  const { send, event, gh } = setup({
    base: { ...BASE, "src/data.ts": big },
    head: { ...BASE, "src/data.ts": big.replace("v25 = 25;", `v25 = 25; const token = "${KEY}";`) },
    gh: { omitPatch: ["src/data.ts"] },
  });
  await send("pull_request", event());
  const done = completed(gh);
  assert.equal(done.conclusion, "action_required");
  assert.ok(done.output.annotations.some((a) => a.path === "src/data.ts" && a.start_line === 26 && /sec\/secret-leaked/.test(a.title)));
});

test("redteam: more files than GitHub lists (over 3,000) can never pass", async () => {
  const { send, event, gh } = setup({ head: { ...BASE, "src/b.ts": "export const b = 2;\n" }, pr: { changedFiles: 3500 } });
  await send("pull_request", event());
  const done = completed(gh);
  assert.equal(done.conclusion, "action_required");
  assert.match(done.output.title, /^Not fully checked: 3499 files could not be read$/);
  assert.match(done.output.summary, /3499 files of 3500 were not listed/);
});

test("redteam: text files whose diffs cannot be read beyond the rebuild budget make the check action_required", async () => {
  const head = { ...BASE };
  const base = { ...BASE };
  const omit = [];
  for (let i = 0; i < 22; i++) {
    base[`src/gen${i}.ts`] = `export const g${i} = 0;\n`;
    head[`src/gen${i}.ts`] = `export const g${i} = 1;\n`;
    omit.push(`src/gen${i}.ts`);
  }
  const { send, event, gh } = setup({ base, head, gh: { omitPatch: omit } });
  await send("pull_request", event());
  const done = completed(gh);
  assert.equal(done.conclusion, "action_required");
  assert.match(done.output.title, /Not fully checked: 2 files could not be read/);
});

// ---------------------------------------------------------------- rate limits and partial failures
test("redteam: a short secondary rate limit is waited out once, and the check completes", async () => {
  const { send, event, gh } = setup({ gh: { failures: [{ re: /^GET \/repos\/acme\/shop\/pulls\/7\/files/, times: 1, status: 429, headers: { "retry-after": "0" } }] } });
  await send("pull_request", event());
  assert.equal(completed(gh).conclusion, "success");
});

test("redteam: a hard rate limit fails closed with a clear reason, never a pass or a stuck check", async () => {
  const { send, event, gh } = setup({ gh: { failures: [{ re: /pulls\/7\/files/, times: 5, status: 403, headers: { "x-ratelimit-remaining": "0", "retry-after": "600" }, body: { message: "API rate limit exceeded" } }] } });
  await send("pull_request", event());
  const done = completed(gh);
  assert.equal(done.conclusion, "failure");
  assert.match(done.output.summary, /rate limit was reached/);
});

test("redteam: the summary marker pasted by a person or another bot is never edited; the app posts its own comment", async () => {
  const head = { ...BASE, "test/a.test.ts": BASE["test/a.test.ts"].replace("  expect(a).toBe(1);\n", "") };
  const seedComments = {
    "acme/shop#7": [
      { id: 1, body: "<!-- isoklo:summary -->\nfake all clear", user: { type: "User", login: "mallory" } },
      { id: 2, body: "<!-- isoklo:summary -->\nfrom another app", user: { type: "Bot", login: "other[bot]" }, performed_via_github_app: { id: 999 } },
    ],
  };
  const { send, event, gh } = setup({ head, gh: { seedComments } });
  await send("pull_request", event());
  assert.equal(completed(gh).conclusion, "action_required");
  assert.equal(gh.writes.filter((w) => w.method === "PATCH" && w.path.startsWith("/issues/comments/")).length, 0);
  assert.equal(gh.writes.filter((w) => w.method === "POST" && w.path === "/issues/7/comments").length, 1);
});

test("redteam: when the comment cannot be posted, the check run keeps its verdict instead of turning into 'could not run'", async () => {
  const head = { ...BASE, "test/a.test.ts": BASE["test/a.test.ts"].replace("  expect(a).toBe(1);\n", "") };
  const { send, event, gh, app } = setup({ head, gh: { failures: [{ re: /issues\/7\/comments/, times: 5, status: 500 }] } });
  await send("pull_request", event());
  assert.equal(completed(gh).conclusion, "action_required");
  assert.equal(app.outcomes[0].comment, "failed");
});

test("redteam: re-runs on fork pull requests (no pull_requests list) find the pull request by its head commit", async () => {
  const { send, gh } = setup();
  await send("check_run", {
    action: "rerequested", installation: { id: 99 },
    repository: { full_name: "acme/shop", private: false, owner: { id: 4242, login: "acme" } },
    check_run: { head_sha: "head1", pull_requests: [] },
  });
  assert.equal(completed(gh).conclusion, "success");
});

// ---------------------------------------------------------------- comment and alert injection
test("redteam: repository text cannot mention people, link issues, embed images or break the comment table", async () => {
  const name = "src/@octocat|#12[x](https://evil.example)<img src=x>.ts";
  const { send, event, gh } = setup({ head: { ...BASE, [name]: `const k = "${KEY}"; // @everyone #1 <img src=https://evil.example/t.png>\n` } });
  await send("pull_request", event());
  const body = gh.writes.find((w) => w.path === "/issues/7/comments").body.body;
  // Mentions, links and HTML never trigger inside code: fenced blocks (the receipt JSON) and inline code spans.
  const prose = body.replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "");
  assert.doesNotMatch(prose, /@(octocat|everyone)\b/);
  assert.doesNotMatch(prose, /(^|\s)#1\b/);
  assert.doesNotMatch(prose, /<img/i);
  assert.doesNotMatch(prose, /(?<!\\)\]\(https?:\/\/evil/, "no working Markdown link to the attacker's URL");
  assert.doesNotMatch(prose, /https?:\/\/evil/, "no autolink either");
  assert.ok(!body.includes(KEY));
  for (const row of body.split("\n").filter((l) => l.startsWith("| ✕"))) assert.equal(row.split(/(?<!\\)\|/).length, 6, row);
});

test("redteam: alerts cannot ping a Slack channel or everyone on Discord", async () => {
  const kv = new MemoryKV();
  const head = { ...BASE, "src/<!channel>.ts": `const k = "${KEY}";\n` };
  for (const url of ["https://hooks.example.dev/slack", "https://discord.com/api/webhooks/1/abc"]) {
    await kv.put("alerts:4242", url);
    const { send, event, gh } = setup({ head, kv, env: { BILLING_MODE: "off" } });
    await send("pull_request", event());
    const sent = gh.writes.find((w) => w.host === "hooks.example.dev" || w.host === "discord.com");
    if (url.includes("discord")) assert.deepEqual(sent.body.allowed_mentions, { parse: [] });
    else assert.doesNotMatch(sent.body.text, /<!channel>/);
  }
});

// ---------------------------------------------------------------- billing payloads
test("redteam: a paid Marketplace plan with an unknown name is never recorded as free", async () => {
  const { send, kv } = setup({ env: { BILLING_MODE: "on" } });
  await send("marketplace_purchase", { action: "purchased", marketplace_purchase: { account: { id: 4242, login: "acme" }, plan: { id: 77, name: "Growth", price_model: "FLAT_RATE", monthly_price_in_cents: 4900 } } });
  assert.equal(JSON.parse(await kv.get("plan:4242")).plan, "team");
  const bad = await send("marketplace_purchase", { action: "purchased" });
  assert.equal(bad.status, 400);
});

test("redteam: signed Stripe events with missing fields or a non-JSON body never crash the worker", async () => {
  const { app, ENV } = setup({ env: { STRIPE_WEBHOOK_SECRET: "whsec_test" } });
  const now = Math.floor(NOW.getTime() / 1000);
  const empty = await app.fetch(stripeRequest("whsec_test", { type: "checkout.session.completed" }, now), ENV);
  assert.equal(empty.status, 200);
  assert.equal((await empty.json()).handled, false);
  const noAccount = await app.fetch(stripeRequest("whsec_test", { type: "checkout.session.completed", data: { object: {} } }, now), ENV);
  assert.equal((await noAccount.json()).handled, false);
  const raw = "{oops";
  const sig = createHmac("sha256", "whsec_test").update(`${now}.${raw}`).digest("hex");
  const notJson = await app.fetch(new Request("https://app.isoklo.test/webhooks/stripe", { method: "POST", headers: { "stripe-signature": `t=${now},v1=${sig}` }, body: raw }), ENV);
  assert.equal(notJson.status, 400);
});
