/**
 * The Isoklo GitHub App: install it on a repository or an organisation and every pull request gets a deterministic
 * merge gate, with no workflow file and no YAML.
 *
 *   POST /webhooks/github   pull_request, issue_comment (/isoklo waive), check_run, check_suite, marketplace_purchase,
 *                           installation events
 *   POST /webhooks/stripe   Stripe subscription events (plans)
 *   GET  /api/receipts/:owner/:repo           receipt history for a repository (Team plan, API key)
 *   GET  /api/receipts/:owner/:repo/:sha      one stored evidence receipt (Team plan, API key)
 *   GET  /.well-known/isoklo-receipt-keys.json   the public keys receipts are signed with (JWKS), for `isoklo verify`
 *   GET  /health
 */
import { Hono, type Context } from "hono";
import { ed25519KeyId, isEd25519Jwk, mergeOrgPolicy, sha256Hex } from "isoklo/engine";
import { handleMarketplace, handleStripeEvent } from "./billing.js";
import { verifyGithubSignature, verifyStripeSignature } from "./crypto.js";
import type { Env } from "./env.js";
import { GitHub } from "./github.js";
import { entitlementsFor } from "./plans.js";
import { handlePullRequest, policyAt, type Deps, type Outcome, type PullRequestEvent } from "./pr.js";
import { ENGINE_VERSION } from "./version.js";
import { allowAuthorFrom, handleWaiverComment, type IssueCommentEvent, type WaiverOutcome } from "./waivers.js";

const PR_ACTIONS = new Set(["opened", "synchronize", "reopened", "ready_for_review"]);

/** The fields a pull_request event must carry before anything is fetched on its behalf. */
function isPullRequestEvent(p: Record<string, unknown>): p is Record<string, unknown> & PullRequestEvent {
  const e = p as Partial<PullRequestEvent>;
  return typeof e.installation?.id === "number"
    && typeof e.repository?.full_name === "string" && /^[\w.-]+\/[\w.-]+$/.test(e.repository.full_name)
    && typeof e.repository.owner?.id === "number"
    && typeof e.pull_request?.number === "number"
    // SHAs go into API paths: no slashes or other characters that could change which endpoint is called.
    && typeof e.pull_request.head?.sha === "string" && /^[\w.-]{1,64}$/.test(e.pull_request.head.sha)
    && typeof e.pull_request.base?.sha === "string" && /^[\w.-]{1,64}$/.test(e.pull_request.base.sha);
}

type App = Hono<{ Bindings: Env }>;
type Ctx = Context<{ Bindings: Env }>;

/** Run work after answering GitHub (it waits at most 10 seconds); without a Workers context (tests), run it inline. */
async function background(c: Ctx, work: Promise<unknown>): Promise<"queued" | "done"> {
  let ctx: { waitUntil(p: Promise<unknown>): void } | undefined;
  try {
    ctx = c.executionCtx;
  } catch {
    ctx = undefined;
  }
  if (ctx !== undefined) {
    ctx.waitUntil(work);
    return "queued";
  }
  await work;
  return "done";
}

export function createApp(overrides: Partial<Deps> = {}): App {
  const deps: Deps = { fetch: overrides.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a)), now: overrides.now ?? (() => new Date()) };
  const app: App = new Hono<{ Bindings: Env }>();
  const results: Outcome[] = [];
  const waiverResults: WaiverOutcome[] = [];

  app.get("/", (c) => c.text(`isoklo github app ${ENGINE_VERSION}: proof before merge.\n`));
  app.get("/health", (c) => c.json({ ok: true, engine: ENGINE_VERSION }));

  // The public half of the receipt signing key, so anyone can check a receipt: npx isoklo verify receipt.json.
  app.get("/.well-known/isoklo-receipt-keys.json", async (c) => {
    const keys: Record<string, string>[] = [];
    const raw = c.env.RECEIPT_SIGNING_JWK;
    if (raw) {
      try {
        const jwk: unknown = JSON.parse(raw);
        if (isEd25519Jwk(jwk, true)) keys.push({ kty: "OKP", crv: "Ed25519", x: jwk.x, kid: await ed25519KeyId(jwk.x), use: "sig", alg: "EdDSA" });
      } catch {
        console.error("isoklo: RECEIPT_SIGNING_JWK is not valid JSON; no public key is published.");
      }
    }
    return c.json({ keys }, 200, { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" });
  });

  app.post("/webhooks/github", async (c) => {
    const body = await c.req.text();
    if (!(await verifyGithubSignature(c.env.GITHUB_WEBHOOK_SECRET, body, c.req.header("x-hub-signature-256")))) {
      return c.json({ error: "invalid signature" }, 401);
    }
    const event = c.req.header("x-github-event") ?? "";
    const delivery = c.req.header("x-github-delivery");
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return c.json({ error: "body is not JSON" }, 400);
    }

    // GitHub redelivers on timeouts; a delivery already handled is acknowledged, not repeated.
    if (delivery && c.env.ISOKLO_KV) {
      const key = `delivery:${delivery}`;
      if (await c.env.ISOKLO_KV.get(key)) return c.json({ ok: true, duplicate: true }, 200);
      await c.env.ISOKLO_KV.put(key, "1", { expirationTtl: 60 * 60 * 24 * 3 });
    }

    const action = typeof payload["action"] === "string" ? payload["action"] : "";
    const run = async (e: PullRequestEvent) => {
      try {
        results.push(await handlePullRequest(c.env, e, deps));
      } catch (error) {
        console.error(`isoklo: could not check ${e.repository.full_name}#${e.pull_request.number}: ${error instanceof Error ? error.message : String(error)}`);
        results.push({ status: "failed", checkRunId: null, error: String(error) });
      }
    };

    if (event === "ping") return c.json({ ok: true, zen: payload["zen"] ?? null });

    if (event === "pull_request") {
      if (!PR_ACTIONS.has(action)) return c.json({ ok: true, ignored: `pull_request.${action}` }, 202);
      if (!isPullRequestEvent(payload)) return c.json({ error: "pull_request event without installation, repository or head" }, 400);
      const state = await background(c, run(payload));
      return c.json({ ok: true, state }, 202);
    }

    // A maintainer's waiver: `/isoklo waive <rule-id or fingerprint> <reason>` on the pull request.
    if (event === "issue_comment") {
      const e = payload as Partial<IssueCommentEvent>;
      if (typeof e.installation?.id !== "number" || typeof e.repository?.full_name !== "string" || !/^[\w.-]+\/[\w.-]+$/.test(e.repository.full_name)
        || typeof e.repository.owner?.id !== "number" || typeof e.issue?.number !== "number" || typeof e.comment?.id !== "number"
        || typeof e.comment.body !== "string" || typeof e.comment.user?.login !== "string") {
        return c.json({ ok: true, ignored: "issue_comment without the fields a waiver needs" }, 202);
      }
      // Most comments are not commands: answer GitHub at once and fetch nothing.
      if (!/^\s*\/isoklo\b/im.test(e.comment.body) || e.issue.pull_request == null) return c.json({ ok: true, ignored: "not an /isoklo command" }, 202);
      const ev = e as IssueCommentEvent;
      const gh = new GitHub(c.env, deps.fetch as unknown as ConstructorParameters<typeof GitHub>[1], () => deps.now().getTime());
      const work = handleWaiverComment(c.env, ev, {
        github: gh,
        now: deps.now,
        entitlements: (account) => entitlementsFor(c.env, account, deps.now()),
        allowAuthor: async (token, repo, pr, ent) => {
          const base = await policyAt(gh, token, repo, pr.base.sha);
          const org = ent.orgPolicy ? await policyAt(gh, token, `${ev.repository.owner.login}/.github`, undefined) : null;
          return allowAuthorFrom(base.config, org?.source ? mergeOrgPolicy(org.config, base.config) : null);
        },
        recheck: async (pr) => {
          await run({ installation: ev.installation, repository: ev.repository, pull_request: pr });
          const last = results.at(-1);
          return last?.status === "checked" ? last.waived : null;
        },
      }).then((r) => { waiverResults.push(r); }, (error: unknown) => {
        console.error(`isoklo: waiver on ${ev.repository.full_name}#${ev.issue.number} failed: ${error instanceof Error ? error.message : String(error)}`);
      });
      const state = await background(c, work);
      return c.json({ ok: true, state }, 202);
    }

    // "Re-run" in the GitHub UI, and the check run's own "Re-run Isoklo" button.
    if ((event === "check_run" && (action === "rerequested" || (action === "requested_action" && (payload["requested_action"] as { identifier?: string } | undefined)?.identifier === "rerun")))
      || (event === "check_suite" && action === "rerequested")) {
      const holder = (payload["check_run"] ?? payload["check_suite"]) as { pull_requests?: { number: number }[]; head_sha?: string } | undefined;
      const installation = payload["installation"] as { id: number } | undefined;
      const repository = payload["repository"] as PullRequestEvent["repository"] | undefined;
      if (typeof installation?.id !== "number" || typeof repository?.full_name !== "string") return c.json({ error: "event without installation or repository" }, 400);
      let numbers = (holder?.pull_requests ?? []).map((p) => p.number);
      const work = (async () => {
        const gh = new GitHub(c.env, deps.fetch as unknown as ConstructorParameters<typeof GitHub>[1], () => deps.now().getTime());
        const token = await gh.installationToken(installation.id);
        // Pull requests from forks are not listed on check events; find them by the commit instead.
        if (numbers.length === 0 && typeof holder?.head_sha === "string") numbers = await gh.pullsForCommit(token, repository.full_name, holder.head_sha);
        for (const n of numbers) {
          const pr = await gh.pullRequest(token, repository.full_name, n);
          if (pr) await run({ installation, repository, pull_request: pr });
        }
      })();
      const state = await background(c, work.catch((error: unknown) => {
        console.error(`isoklo: re-run on ${repository.full_name} failed: ${error instanceof Error ? error.message : String(error)}`);
      }));
      return c.json({ ok: true, state }, 202);
    }

    if (event === "marketplace_purchase") {
      const mp = payload["marketplace_purchase"] as { account?: { id?: unknown }; plan?: { name?: unknown } } | undefined;
      if (typeof mp?.account?.id !== "number" || typeof mp.plan?.name !== "string") return c.json({ error: "marketplace_purchase without an account or plan" }, 400);
      const r = await handleMarketplace(c.env, payload as unknown as Parameters<typeof handleMarketplace>[1], deps.now());
      return c.json({ ok: true, ...r });
    }

    if (event === "installation" || event === "installation_repositories") {
      const inst = payload["installation"] as { id: number; account?: { id: number; login: string } } | undefined;
      if (inst?.account && c.env.ISOKLO_KV) {
        await c.env.ISOKLO_KV.put(`installation:${inst.account.id}`, JSON.stringify({ id: inst.id, login: inst.account.login, action, at: deps.now().toISOString() }));
      }
      return c.json({ ok: true, recorded: event });
    }

    return c.json({ ok: true, ignored: event }, 202);
  });

  app.post("/webhooks/stripe", async (c) => {
    const body = await c.req.text();
    const nowSeconds = Math.floor(deps.now().getTime() / 1000);
    if (!(await verifyStripeSignature(c.env.STRIPE_WEBHOOK_SECRET ?? "", body, c.req.header("stripe-signature"), nowSeconds))) {
      return c.json({ error: "invalid signature" }, 400);
    }
    let event: unknown;
    try {
      event = JSON.parse(body);
    } catch {
      return c.json({ error: "body is not JSON" }, 400);
    }
    const e = event as { type?: unknown; data?: { object?: unknown } } | null;
    // A signed but unexpected event is acknowledged (so Stripe stops retrying) and changes nothing.
    if (typeof e?.type !== "string" || typeof e.data?.object !== "object" || e.data.object === null) {
      return c.json({ received: true, handled: false, detail: "event without a type or data object." });
    }
    const r = await handleStripeEvent(c.env, e as Parameters<typeof handleStripeEvent>[1], deps.now());
    return c.json({ received: true, ...r });
  });

  /** An API key (stored hashed, as `apikey:<sha256>` -> owner login) that may read this owner's receipts. */
  const authorised = async (c: Ctx, owner: string): Promise<Response | null> => {
    const key = /^Bearer\s+(.+)$/.exec(c.req.header("authorization") ?? "")?.[1];
    if (!key || !c.env.ISOKLO_KV) return c.json({ error: "an API key is required" }, 401);
    const holder = await c.env.ISOKLO_KV.get(`apikey:${await sha256Hex(key)}`);
    if (holder === null || holder.toLowerCase() !== owner.toLowerCase()) return c.json({ error: "this key cannot read that repository's receipts" }, 403);
    return null;
  };

  app.get("/api/receipts/:owner/:repo/:sha", async (c) => {
    const { owner: o, repo, sha } = c.req.param();
    const denied = await authorised(c, o);
    if (denied) return denied;
    const receipt = await c.env.ISOKLO_KV?.get(`receipt:${o}/${repo}:${sha}`);
    return receipt == null ? c.json({ error: "no receipt stored for that commit" }, 404) : c.body(receipt, 200, { "content-type": "application/json" });
  });

  // Receipt history for audits: up to 100 receipts per page; follow `cursor` for more.
  app.get("/api/receipts/:owner/:repo", async (c) => {
    const { owner: o, repo } = c.req.param();
    const denied = await authorised(c, o);
    if (denied) return denied;
    const kv = c.env.ISOKLO_KV;
    if (kv?.list === undefined) return c.json({ error: "this installation's store cannot list receipts" }, 501);
    const cursor = c.req.query("cursor");
    const page = await kv.list({ prefix: `receipt:${o}/${repo}:`, limit: 100, ...(cursor ? { cursor } : {}) });
    const receipts: unknown[] = [];
    for (const k of page.keys) {
      const text = await kv.get(k.name);
      if (text === null) continue;
      try {
        receipts.push(JSON.parse(text));
      } catch {
        // a damaged entry is skipped, not served
      }
    }
    return c.json({ repository: `${o}/${repo}`, receipts, cursor: page.list_complete ? null : page.cursor ?? null });
  });

  /** For tests and the local simulator: what each pull request check and each waiver command concluded. */
  const exposed = app as App & { outcomes: Outcome[]; waivers: WaiverOutcome[] };
  exposed.outcomes = results;
  exposed.waivers = waiverResults;
  return app;
}

const app = createApp();
export default app;
