/**
 * Plans and what they unlock. Billing is a switch: with BILLING_MODE "off" (the default, for launch) every
 * installation gets every feature; with "on", the account's plan record decides.
 *
 *   free        public repositories without limit, up to 2 private repositories, all rules, signed receipts
 *   team        + every private repository, organisation-wide policy (the org's .github repository), maintainer
 *               waivers with an audit trail, stored receipts and the receipts API, Slack or Discord alerts
 *   enterprise  team, sold by hand (LICENSES) with a self-hosted Worker, your own signing key and an SLA
 *
 * Public repositories are free forever: no plan check ever stands between a public repository and its verdict.
 *
 * Plan records come from, in order: the KV store (written by the Stripe and GitHub Marketplace webhooks), the LICENSES
 * setting (licences sold by hand), then free.
 */
import { jsonSetting, type Env, type KV } from "./env.js";

export type Plan = "free" | "team" | "enterprise";

export interface Entitlements {
  plan: Plan;
  source: "billing-off" | "stripe" | "marketplace" | "license" | "default";
  /** How many private repositories the App checks for the account; null for no limit. */
  privateRepoLimit: number | null;
  orgPolicy: boolean;
  waivers: boolean;
  alerts: boolean;
  signedReceipts: boolean;
  /** Receipts kept for 400 days and readable through the receipts API. */
  storedReceipts: boolean;
}

export const FREE_PRIVATE_REPOS = 2;

const TEAM = { privateRepoLimit: null, orgPolicy: true, waivers: true, alerts: true, signedReceipts: true, storedReceipts: true } as const;
const FEATURES: Record<Plan, Omit<Entitlements, "plan" | "source">> = {
  free: { privateRepoLimit: FREE_PRIVATE_REPOS, orgPolicy: false, waivers: false, alerts: false, signedReceipts: true, storedReceipts: false },
  team: TEAM,
  enterprise: TEAM,
};

export interface PlanRecord {
  plan: Plan;
  source: "stripe" | "marketplace";
  updatedAt: string;
  /** Paid until (ISO date); a record past this date counts as free. */
  until?: string | null;
  stripeCustomer?: string;
  login?: string;
}

export const planKey = (accountId: number) => `plan:${accountId}`;

/** A plan name from a record, a setting or a payment: "pro" (the name before 0.3) reads as team. */
export function toPlan(p: unknown): Plan | null {
  if (p === "free" || p === "team" || p === "enterprise") return p;
  if (p === "pro") return "team";
  return null;
}

export const isPlan = (p: unknown): p is Plan => p === "free" || p === "team" || p === "enterprise";

export async function entitlementsFor(env: Env, account: { id: number; login: string }, now: Date): Promise<Entitlements> {
  if ((env.BILLING_MODE ?? "off") !== "on") return { plan: "team", source: "billing-off", ...FEATURES.team };
  const raw = await env.ISOKLO_KV?.get(planKey(account.id));
  if (raw) {
    try {
      const rec = JSON.parse(raw) as { plan?: unknown; source?: PlanRecord["source"]; until?: string | null };
      const plan = toPlan(rec.plan);
      const expired = rec.until != null && Date.parse(rec.until) < now.getTime();
      if (plan !== null && !expired) return { plan, source: rec.source === "marketplace" ? "marketplace" : "stripe", ...FEATURES[plan] };
    } catch {
      console.error(`isoklo: plan record for account ${account.id} is not valid JSON; treating it as free.`);
    }
  }
  const licences = jsonSetting(env.LICENSES, "LICENSES");
  const licensed = toPlan(licences[String(account.id)] ?? licences[account.login] ?? licences[account.login.toLowerCase()]);
  if (licensed !== null) return { plan: licensed, source: "license", ...FEATURES[licensed] };
  return { plan: "free", source: "default", ...FEATURES.free };
}

export async function savePlan(env: Env, accountId: number, record: PlanRecord): Promise<void> {
  if (env.ISOKLO_KV === undefined) throw new Error("ISOKLO_KV is not bound, so plan changes cannot be stored.");
  await env.ISOKLO_KV.put(planKey(accountId), JSON.stringify(record));
}

export const privateReposKey = (accountId: number) => `private-repos:${accountId}`;

/**
 * Metering for private repositories on a plan with a limit. A repository the App already checks for the account keeps
 * being checked; a new one counts against the limit, first come first served, and over the limit gets an upgrade note
 * instead of a verdict. Public repositories never reach this function.
 */
export async function privateRepoAllowed(
  kv: KV | undefined, accountId: number, repo: string, ent: Entitlements,
): Promise<{ allowed: boolean; used: number; limit: number | null }> {
  const limit = ent.privateRepoLimit;
  if (limit === null) return { allowed: true, used: 0, limit };
  // Without the store there is no count to keep, so nothing beyond the plan can be promised.
  if (kv === undefined) return { allowed: false, used: 0, limit };
  let repos: string[] = [];
  try {
    const parsed: unknown = JSON.parse((await kv.get(privateReposKey(accountId))) ?? "[]");
    if (Array.isArray(parsed)) repos = parsed.filter((r): r is string => typeof r === "string");
  } catch {
    repos = [];
  }
  if (repos.includes(repo)) return { allowed: true, used: repos.length, limit };
  if (repos.length >= limit) return { allowed: false, used: repos.length, limit };
  repos.push(repo);
  await kv.put(privateReposKey(accountId), JSON.stringify(repos));
  return { allowed: true, used: repos.length, limit };
}
