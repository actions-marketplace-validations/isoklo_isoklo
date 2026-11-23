// The GitHub App end to end, with simulated, signed webhooks and a fake GitHub API: no network, no Cloudflare account.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createApp } from "../dist/index.js";
import { pemToPkcs8 } from "../dist/crypto.js";
import { ENGINE_VERSION } from "../dist/version.js";
import { appKeys, fakeGitHub, issueCommentEvent, MemoryKV, pullRequestEvent, stripeRequest, webhook } from "./fake-github.js";
import { ed25519GenerateJwk, trustedKeysFrom, verifyReceipt } from "isoklo/engine";

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

const COLLABORATORS = { maintainer: "write", owner: "admin", reader: "read", "agent-dev": "write" };

function setup({ head = AGENT_PR, base = BASE, isPrivate = false, env = {}, failFiles = false, org = null, body = "", collaborators = COLLABORATORS } = {}) {
  const repos = {
    "acme/shop": { private: isPrivate, collaborators, commits: { base1: base, head1: head }, pulls: { 7: { base: "base1", head: "head1", body } } },
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

test("billing on, free plan: up to two private repositories are checked; a third gets a neutral upsell and no code is read", async () => {
  const { gh, send, pr, kv } = setup({ isPrivate: true, env: { BILLING_MODE: "on", UPGRADE_URL: "https://buy.stripe.com/test_abc" } });
  // This account already uses its two private repositories.
  await kv.put("private-repos:4242", JSON.stringify(["1001", "1002"]));
  await send("pull_request", pullRequestEvent({ pr, isPrivate: true }));
  const [run] = checkRuns(gh);
  assert.equal(run.body.conclusion, "neutral");
  assert.match(run.body.output.title, /Private repository limit reached on the free plan/);
  assert.match(run.body.output.summary, /up to 2 private repositories per account; this account already uses 2/);
  assert.match(run.body.output.summary, /https:\/\/buy\.stripe\.com\/test_abc\?client_reference_id=4242/);
  assert.equal(gh.writes.length, 1);
});

test("billing on, free plan: a first private repository is checked, signed, and counted", async () => {
  const { gh, send, pr, kv } = setup({ isPrivate: true, env: { BILLING_MODE: "on", RECEIPT_SIGNING_KEY: "receipt-key" } });
  await send("pull_request", pullRequestEvent({ pr, isPrivate: true }));
  assert.equal(completed(gh).conclusion, "action_required");
  assert.deepEqual(JSON.parse(await kv.get("private-repos:4242")), ["acme/shop"]);
  // Signed receipts are on the free plan too; stored receipts are not.
  assert.match(gh.comments.get("acme/shop#7")[0].body, /HMAC-signed/);
  assert.equal(await kv.get("receipt:acme/shop:head1"), null);
  // Public repositories never count.
  const pub = setup({ env: { BILLING_MODE: "on" } });
  await pub.send("pull_request", pullRequestEvent({ pr: pub.pr }));
  assert.equal(await pub.kv.get("private-repos:4242"), null);
});

test("billing off (launch): private repositories are checked with every feature, whatever the account", async () => {
  const { gh, send, pr, kv } = setup({ isPrivate: true });
  await kv.put("private-repos:4242", JSON.stringify(["1001", "1002"]));
  await send("pull_request", pullRequestEvent({ pr, isPrivate: true }));
  assert.equal(completed(gh).conclusion, "action_required");
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
  // "pro" was the plan's name before 0.3: it reads as team.
  assert.equal(JSON.parse(await kv.get("plan:4242")).plan, "team");
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

// ---------------------------------------------------------------- annotations: one card per line and rule
test("two assertions removed side by side draw one annotation, not two identical cards on the same line", async () => {
  const head = { ...BASE, "test/cart/total.test.ts": 'test("total", () => {\n});\n' };
  const { gh, send, pr } = setup({ head });
  await send("pull_request", pullRequestEvent({ pr }));
  const ann = completed(gh).output.annotations;
  const removed = ann.filter((a) => /tamper\/assertions-removed/.test(a.title));
  assert.equal(removed.length, 1, JSON.stringify(removed, null, 2));
  assert.equal(removed[0].title, "Blocked · HIGH · tamper/assertions-removed");
  assert.match(removed[0].message, /Removed here: lines 2 and 3 of the previous version\./);
  const keys = ann.map((a) => `${a.path}:${a.start_line}:${a.title}`);
  assert.equal(new Set(keys).size, keys.length, "no two annotations share a file, line and title");
});

// ---------------------------------------------------------------- waivers
const waive = (body, extra = {}) => issueCommentEvent({ body, ...extra });

test("waivers: a maintainer waives both findings, the check passes, and the record shows who and why", async () => {
  const { gh, send, pr, kv, app } = setup();
  await send("pull_request", pullRequestEvent({ pr }));
  assert.equal(completed(gh).conclusion, "action_required");
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled the flaky total test moved to test/cart/total.e2e.ts in #12"));
  await send("issue_comment", waive("/isoklo waive tamper/assertions-removed total([]) is now covered by the property test in #12", { id: 5556 }));
  const done = completed(gh);
  assert.equal(done.conclusion, "success");
  assert.equal(done.output.title, "Passed · 2 waived");
  assert.match(done.output.summary, /\*\*Waived by maintainers\*\* \(2\)/);
  assert.ok(done.output.annotations.every((a) => a.annotation_level === "notice"));
  assert.ok(done.output.annotations.some((a) => /^Waived by @maintainer: the flaky total test moved/.test(a.message.split("\n").at(-1))));
  // Recorded: a reaction on each command, the waivers in the store, and in the receipt (stored on Team).
  assert.equal(gh.writes.filter((w) => /\/reactions$/.test(w.path)).length, 2);
  assert.equal(JSON.parse(await kv.get("waivers:acme/shop#7")).length, 2);
  const receipt = JSON.parse(await kv.get("receipt:acme/shop:head1"));
  assert.equal(receipt.verdict, "passed");
  assert.deepEqual(receipt.waivers.map((w) => [w.target, w.by]).sort(), [["tamper/assertions-removed", "@maintainer"], ["tamper/test-disabled", "@maintainer"]]);
  assert.deepEqual(app.waivers.map((w) => w.status), ["recorded", "recorded"]);
  // Revoking puts the block back.
  await send("issue_comment", waive("/isoklo revoke tamper/test-disabled", { id: 5557 }));
  assert.equal(completed(gh).conclusion, "action_required");
});

test("waivers are refused for readers, for the author, for bots and without a reason; nothing changes", async () => {
  const { gh, send, pr, kv, app } = setup();
  await send("pull_request", pullRequestEvent({ pr }));
  const replies = () => gh.writes.filter((w) => w.method === "POST" && w.path === "/issues/7/comments" && /isoklo:waiver-reply/.test(w.body.body)).map((w) => w.body.body);
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled I can read this repository", { login: "reader" }));
  assert.match(replies().at(-1), /only people with write access to acme\/shop can waive/);
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled my own pull request is fine, honestly", { login: "agent-dev" }));
  assert.match(replies().at(-1), /the author of a pull request cannot waive its findings/);
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled ok"));
  assert.match(replies().at(-1), /needs a reason of at least 10 characters/);
  const before = replies().length;
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled a bot thinks this is fine to merge", { login: "helper[bot]", type: "Bot" }));
  assert.equal(replies().length, before, "bots are never answered");
  assert.equal(await kv.get("waivers:acme/shop#7"), null);
  assert.equal(completed(gh).conclusion, "action_required");
  assert.deepEqual(app.waivers.map((w) => w.status), ["refused", "refused", "refused", "ignored"]);
  // Ordinary comments cost nothing: no token, no API call.
  const writes = gh.writes.length;
  const res = await send("issue_comment", waive("Looks good to me, thanks!"));
  assert.equal((await res.json()).ignored, "not an /isoklo command");
  assert.equal(gh.writes.length, writes);
});

test("waivers: a single-maintainer repository can let the author waive, through the base branch's policy", async () => {
  const policy = { "isoklo.config.json": JSON.stringify({ waivers: { allowAuthor: true } }) };
  const { gh, send, pr } = setup({ base: { ...BASE, ...policy }, head: { ...AGENT_PR, ...policy } });
  await send("pull_request", pullRequestEvent({ pr }));
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled skipped on purpose until the fixture lands", { login: "agent-dev" }));
  await send("issue_comment", waive("/isoklo waive tamper/assertions-removed covered again in the follow-up pull request", { login: "agent-dev", id: 5556 }));
  assert.equal(completed(gh).conclusion, "success");
});

test("waivers on the free plan point to the base branch's policy instead (billing on)", async () => {
  const { gh, send, pr } = setup({ env: { BILLING_MODE: "on" } });
  await send("pull_request", pullRequestEvent({ pr }));
  await send("issue_comment", waive("/isoklo waive tamper/test-disabled the test moved to the e2e suite in #12"));
  const reply = gh.writes.filter((w) => w.method === "POST" && w.path === "/issues/7/comments").at(-1).body.body;
  assert.match(reply, /Waivers are part of Isoklo Team/);
  assert.equal(completed(gh).conclusion, "action_required");
});

// ---------------------------------------------------------------- receipts anyone can verify
test("Ed25519 receipts: the public key is published, the comment's receipt verifies against it, the private key never leaks", async () => {
  const jwk = await ed25519GenerateJwk();
  const { gh, send, pr, app, ENV, kv } = setup({ env: { RECEIPT_SIGNING_JWK: JSON.stringify(jwk), RECEIPT_SIGNING_KEY: "older-hmac-key" } });
  const res = await app.fetch(new Request("https://app.isoklo.test/.well-known/isoklo-receipt-keys.json"), ENV);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.ok(!text.includes(jwk.d), "only the public half is published");
  const jwks = JSON.parse(text);
  assert.deepEqual(jwks.keys.map((k) => [k.kty, k.crv, k.x, k.kid, k.alg]), [["OKP", "Ed25519", jwk.x, jwk.kid, "EdDSA"]]);

  await send("pull_request", pullRequestEvent({ pr }));
  const comment = gh.comments.get("acme/shop#7")[0].body;
  assert.match(comment, /Ed25519-signed \(key `[0-9a-f]{16}`\)/);
  assert.match(comment, /npx isoklo@latest verify receipt\.json/);
  const receipt = JSON.parse(/```json\n([\s\S]*?)\n```/.exec(comment)[1]);
  const v = await verifyReceipt(receipt, { trustedKeys: trustedKeysFrom(jwks, "the Isoklo GitHub App's published key") });
  assert.deepEqual([v.digestValid, v.signatureValid, v.trusted], [true, true, true]);
  assert.ok(!comment.includes(jwk.d));

  // Receipt history for audits, with an API key bound to the account.
  const { createHash } = await import("node:crypto");
  await kv.put(`apikey:${createHash("sha256").update("acme-audit-key").digest("hex")}`, "acme");
  const list = await app.fetch(new Request("https://app.isoklo.test/api/receipts/acme/shop", { headers: { authorization: "Bearer acme-audit-key" } }), ENV);
  assert.equal(list.status, 200);
  const history = await list.json();
  assert.equal(history.receipts.length, 1);
  assert.equal(history.receipts[0].integrity.digest, receipt.integrity.digest);
  assert.equal((await app.fetch(new Request("https://app.isoklo.test/api/receipts/acme/shop"), ENV)).status, 401);
});

test("without a signing key the key set is empty, so verify reports an unsigned or HMAC receipt honestly", async () => {
  const { app, ENV } = setup();
  const res = await app.fetch(new Request("https://app.isoklo.test/.well-known/isoklo-receipt-keys.json"), ENV);
  assert.deepEqual(await res.json(), { keys: [] });
});

test("PKCS#1 keys from GitHub are wrapped as PKCS#8 for Web Crypto; the engine version matches the package", () => {
  const der = pemToPkcs8(keys.privateKey);
  assert.equal(der[0], 0x30);
  const pkg = JSON.parse(readFileSync(new URL("../../../package.json", import.meta.url), "utf8"));
  assert.equal(ENGINE_VERSION, pkg.version);
});
