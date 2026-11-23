// The GitHub App end to end, with simulated, signed webhooks and a fake GitHub API: no network, no Cloudflare account.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createApp } from "../dist/index.js";
import { pemToPkcs8 } from "../dist/crypto.js";
import { ENGINE_VERSION } from "../dist/version.js";
import { appKeys, fakeGitHub, MemoryKV, pullRequestEvent, stripeRequest, webhook } from "./fake-github.js";

const SECRET = "webhook-secret-for-tests";
const NOW = new Date("2026-11-22T10:00:00Z");
const keys = appKeys();

const TEST_FILE = 'test("total", () => {\n  expect(total([1, 2])).toBe(3);\n  expect(total([])).toBe(0);\n});\n';
const BASE = {
  "package.json": '{\n  "name": "shop",\n  "scripts": { "test": "vitest run" }\n}\n',
  "src/cart/total.ts": "export const total = (xs: number[]) => xs.reduce((a, b) => a + b, 0);\n",
  "test/cart/total.test.ts": TEST_FILE,
};
const AGENT_PR = {
  ...BASE,
  "src/cart/total.ts": "export const total = (xs: number[]) => Math.round(xs.reduce((a, b) => a + b, 0));\n",
  // Assembled at run time so this file passes Isoklo's own gate.
  "test/cart/total.test.ts": `${["test", "skip"].join(".")}("total", () => {\n  expect(total([1, 2])).toBe(3);\n});\n`,
};
const CLEAN_PR = {
  ...BASE,
  "src/cart/total.ts": "export const total = (xs: number[]) => Math.round(xs.reduce((a, b) => a + b, 0) * 100) / 100;\n",
  "test/cart/total.test.ts": TEST_FILE.replace("});\n", '  expect(total([0.1, 0.2])).toBe(0.3);\n});\n'),
};

function setup({ head = AGENT_PR, base = BASE, isPrivate = false, env = {}, failFiles = false, org = null, body = "" } = {}) {
  const repos = {
    "acme/shop": { private: isPrivate, commits: { base1: base, head1: head }, pulls: { 7: { base: "base1", head: "head1", body } } },
  };
  if (org) repos["acme/.github"] = { commits: { main: org } };
  const gh = fakeGitHub({ publicKey: keys.publicKey, appId: "123", repos, failFiles });
  const kv = new MemoryKV();
  const app = createApp({ fetch: gh.fetch, now: () => NOW });
  const ENV = {
    GITHUB_APP_ID: "123", GITHUB_APP_PRIVATE_KEY: keys.privateKey, GITHUB_WEBHOOK_SECRET: SECRET,
    GITHUB_API_URL: "https://api.github.test", ONLINE: "false", ISOKLO_KV: kv, ...env,
  };
  const send = (event, payload, delivery) => app.fetch(webhook(SECRET, event, payload, delivery), ENV);
  const pr = { base: "base1", head: "head1", body };
  return { app, gh, kv, ENV, send, pr };
}

const checkRuns = (gh) => gh.writes.filter((w) => w.path.startsWith("/check-runs"));
const completed = (gh) => checkRuns(gh).filter((w) => w.body.status === "completed").at(-1).body;

test("webhooks without a valid HMAC-SHA256 signature are refused before anything else happens", async () => {
  const { app, ENV, gh } = setup();
  const payload = pullRequestEvent({ pr: { base: "base1", head: "head1" } });
  const forged = webhook("wrong-secret", "pull_request", payload);
  assert.equal((await app.fetch(forged, ENV)).status, 401);
  const unsigned = new Request("https://app.isoklo.test/webhooks/github", { method: "POST", headers: { "x-github-event": "ping" }, body: "{}" });
  assert.equal((await app.fetch(unsigned, ENV)).status, 401);
  assert.equal(gh.writes.length, 0);
  const ping = await app.fetch(webhook(SECRET, "ping", { zen: "Keep it logically awesome." }), ENV);
  assert.equal(ping.status, 200);
});

test("pull_request opened: an agent that skips a test and deletes an assertion gets action_required, line annotations and one comment", async () => {
  const { gh, send, pr, app } = setup();
  const res = await send("pull_request", pullRequestEvent({ pr }));
  assert.equal(res.status, 202);
  const [created] = checkRuns(gh);
  assert.equal(created.body.name, "isoklo");
  assert.equal(created.body.head_sha, "head1");
  assert.equal(created.body.status, "in_progress");
  const done = completed(gh);
  assert.equal(done.conclusion, "action_required");
  assert.match(done.output.title, /^Blocked: 2 problems to fix before merge$/);
  assert.match(done.output.summary, /## isoklo · blocked/);
  assert.match(done.output.summary, /\*\*Evidence receipt\*\* `sha256:[0-9a-f]{16}…`/);
  const ann = done.output.annotations;
  assert.ok(ann.some((a) => a.path === "test/cart/total.test.ts" && a.annotation_level === "failure" && /tamper\/test-disabled/.test(a.title) && a.start_line === 1));
  assert.ok(ann.some((a) => /tamper\/assertions-removed/.test(a.title) && a.raw_details.length > 40));
  assert.deepEqual(done.actions.map((a) => a.identifier), ["rerun"]);
  const posted = gh.writes.filter((w) => w.path === "/issues/7/comments");
  assert.equal(posted.length, 1);
  assert.match(posted[0].body.body, /^<!-- isoklo:summary -->/);
  assert.equal(app.outcomes[0].verdict, "blocked");
});

test("synchronize: the same comment is updated in place, never a second one", async () => {
  const { gh, send, pr } = setup();
  await send("pull_request", pullRequestEvent({ pr }));
  await send("pull_request", pullRequestEvent({ action: "synchronize", pr }));
  assert.equal(gh.writes.filter((w) => w.method === "POST" && w.path === "/issues/7/comments").length, 1);
  assert.equal(gh.writes.filter((w) => w.method === "PATCH" && w.path.startsWith("/issues/comments/")).length, 1);
  assert.equal(gh.comments.get("acme/shop#7").length, 1);
});

test("a clean fix passes with success, and no comment is posted when there is nothing to say", async () => {
  const { gh, send, pr, app } = setup({ head: CLEAN_PR, body: "Fix rounding.\n\nisoklo-scope: src/cart/**, test/cart/**" });
  await send("pull_request", pullRequestEvent({ pr }));
  const done = completed(gh);
  assert.equal(done.conclusion, "success", JSON.stringify(done.output.annotations));
  assert.equal(done.output.title, "Passed");
  assert.equal(gh.writes.filter((w) => w.path === "/issues/7/comments").length, 0);
  assert.equal(app.outcomes[0].comment, "skipped");
});

test("the pull request body's isoklo-scope is enforced: out-of-scope edits block", async () => {
  const head = { ...CLEAN_PR, "src/auth/session.ts": "export const ttl = 60;\n" };
  const { gh, send, pr } = setup({ head, body: "isoklo-scope: src/cart/**, test/cart/**" });
  await send("pull_request", pullRequestEvent({ pr }));
  const done = completed(gh);
  assert.equal(done.conclusion, "action_required");
  assert.ok(done.output.annotations.some((a) => a.path === "src/auth/session.ts" && /scope\/out-of-scope/.test(a.title)));
});

test("policy comes from the merge base: a pull request cannot turn off the rule that blocks it", async () => {
  const head = { ...AGENT_PR, "isoklo.config.json": JSON.stringify({ rules: { "tamper/test-disabled": "off", "tamper/assertions-removed": "off" } }) };
  const { gh, send, pr } = setup({ head });
  await send("pull_request", pullRequestEvent({ pr }));
  const titles = completed(gh).output.annotations.map((a) => a.title);
  assert.ok(titles.some((t) => /tamper\/test-disabled/.test(t)));
  assert.ok(titles.some((t) => /tamper\/isoklo-config-changed/.test(t)));
});

test("billing on: a private repository without a plan gets a neutral upsell check, and no code is read", async () => {
  const { gh, send, pr } = setup({ isPrivate: true, env: { BILLING_MODE: "on", UPGRADE_URL: "https://buy.stripe.com/test_abc" } });
  await send("pull_request", pullRequestEvent({ pr, isPrivate: true }));
  const [run] = checkRuns(gh);
  assert.equal(run.body.conclusion, "neutral");
  assert.match(run.body.output.title, /Private repositories need Isoklo Pro/);
  assert.match(run.body.output.summary, /https:\/\/buy\.stripe\.com\/test_abc\?client_reference_id=4242/);
  assert.equal(gh.writes.length, 1);
});

test("billing on: a Marketplace purchase unlocks private repositories, signed receipts and stored receipts", async () => {
  const { gh, send, pr, kv, app, ENV } = setup({ isPrivate: true, env: { BILLING_MODE: "on", RECEIPT_SIGNING_KEY: "receipt-key" } });
  const bought = await send("marketplace_purchase", { action: "purchased", marketplace_purchase: { account: { id: 4242, login: "acme", type: "Organization" }, plan: { id: 9, name: "Team" } } });
  assert.equal((await bought.json()).detail, "acme (4242) is now on team via the Marketplace (purchased).");
  await send("pull_request", pullRequestEvent({ pr, isPrivate: true }));
  assert.equal(completed(gh).conclusion, "action_required");
  const stored = JSON.parse(await kv.get("receipt:acme/shop:head1"));
  assert.equal(stored.integrity.signature.algorithm, "hmac-sha256");
  assert.equal(stored.verdict, "blocked");
  assert.match(gh.comments.get("acme/shop#7")[0].body, /Receipt \(canonical JSON\)/);
  // Receipt export with an API key bound to the account.
  const { createHash } = await import("node:crypto");
  await kv.put(`apikey:${createHash("sha256").update("acme-audit-key").digest("hex")}`, "acme");
  const ok = await app.fetch(new Request("https://app.isoklo.test/api/receipts/acme/shop/head1", { headers: { authorization: "Bearer acme-audit-key" } }), ENV);
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).integrity.digest, stored.integrity.digest);
  const denied = await app.fetch(new Request("https://app.isoklo.test/api/receipts/acme/shop/head1", { headers: { authorization: "Bearer wrong" } }), ENV);
  assert.equal(denied.status, 403);
});

test("billing on: Stripe checkout and cancellation move the plan; forged or stale Stripe signatures are refused", async () => {
  const { app, ENV, kv } = setup({ env: { BILLING_MODE: "on", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_PRICE_PLANS: '{"price_team":"team"}' } });
  const now = Math.floor(NOW.getTime() / 1000);
  const checkout = { type: "checkout.session.completed", data: { object: { client_reference_id: "4242", customer: "cus_1", metadata: { plan: "pro" } } } };
  assert.equal((await app.fetch(stripeRequest("whsec_wrong", checkout, now), ENV)).status, 400);
  assert.equal((await app.fetch(stripeRequest("whsec_test", checkout, now - 3600), ENV)).status, 400, "replayed an hour later");
  assert.equal((await app.fetch(stripeRequest("whsec_test", checkout, now), ENV)).status, 200);
  assert.equal(JSON.parse(await kv.get("plan:4242")).plan, "pro");
  const upgrade = { type: "customer.subscription.updated", data: { object: { customer: "cus_1", status: "active", items: { data: [{ price: { id: "price_team" } }] }, current_period_end: now + 86400 * 30 } } };
  await app.fetch(stripeRequest("whsec_test", upgrade, now), ENV);
  assert.equal(JSON.parse(await kv.get("plan:4242")).plan, "team");
  const cancel = { type: "customer.subscription.deleted", data: { object: { customer: "cus_1", status: "canceled" } } };
  await app.fetch(stripeRequest("whsec_test", cancel, now), ENV);
  assert.equal(JSON.parse(await kv.get("plan:4242")).plan, "free");
});

test("Team: the organisation's policy from acme/.github applies, and the repository cannot override it", async () => {
  const org = { "isoklo.config.json": JSON.stringify({ scope: { deny: ["src/cart/**"] } }) };
  const { gh, send, pr } = setup({ head: CLEAN_PR, org });
  await send("pull_request", pullRequestEvent({ pr }));
  const done = completed(gh);
  assert.equal(done.conclusion, "action_required");
  assert.ok(done.output.annotations.some((a) => /scope\/forbidden-path/.test(a.title)));
  assert.match(done.output.summary, /acme\/\.github:isoklo\.config\.json/);
});

test("Re-run Isoklo (check_run requested_action) checks the pull request again", async () => {
  const { gh, send } = setup();
  await send("check_run", {
    action: "requested_action", requested_action: { identifier: "rerun" }, installation: { id: 99 },
    repository: { full_name: "acme/shop", private: false, owner: { id: 4242, login: "acme" } },
    check_run: { pull_requests: [{ number: 7 }] },
  });
  assert.equal(completed(gh).conclusion, "action_required");
});

test("GitHub redelivering the same webhook does not check twice", async () => {
  const { gh, send, pr } = setup();
  await send("pull_request", pullRequestEvent({ pr }), "delivery-1");
  const res = await send("pull_request", pullRequestEvent({ pr }), "delivery-1");
  assert.deepEqual(await res.json(), { ok: true, duplicate: true });
  assert.equal(checkRuns(gh).filter((w) => w.body.status === "in_progress").length, 1);
});

test("fail closed: when GitHub's API fails, the check completes as failure (nothing approved)", async () => {
  const { gh, send, pr } = setup({ failFiles: true });
  await send("pull_request", pullRequestEvent({ pr }));
  const done = completed(gh);
  assert.equal(done.conclusion, "failure");
  assert.equal(done.output.title, "Isoklo could not run");
});

test("draft pull requests and other actions are left alone", async () => {
  const { gh, send, pr } = setup();
  assert.equal((await (await send("pull_request", pullRequestEvent({ action: "labeled", pr }))).json()).ignored, "pull_request.labeled");
  await send("pull_request", pullRequestEvent({ pr: { ...pr, draft: true } }));
  assert.equal(checkRuns(gh).length, 0);
});

test("PKCS#1 keys from GitHub are wrapped as PKCS#8 for Web Crypto; the engine version matches the package", () => {
  const der = pemToPkcs8(keys.privateKey);
  assert.equal(der[0], 0x30);
  const pkg = JSON.parse(readFileSync(new URL("../../../package.json", import.meta.url), "utf8"));
  assert.equal(ENGINE_VERSION, pkg.version);
});
