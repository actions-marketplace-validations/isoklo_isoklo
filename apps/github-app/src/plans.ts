/**
 * Plans and what they unlock. Billing is a switch: with BILLING_MODE "off" (the default, for launch) every repository
 * gets every feature; with "on", the plan record decides.
 *
 *   free   public repositories, unlimited
 *   pro    + private repositories, signed evidence receipts, Slack or Discord alerts
 *   team   + organisation-wide policy from the org's .github repository, stored receipts for audits
 *
 * Plan records come from, in order: the KV store (written by the Stripe and GitHub Marketplace webhooks), the LICENSES
 * setting (licences sold by hand), then free.
 */
import { jsonSetting, type Env } from "./env.js";

export type Plan = "free" | "pro" | "team";

export interface Entitlements {
  plan: Plan;
  source: "billing-off" | "stripe" | "marketplace" | "license" | "default";
  privateRepos: boolean;
  orgPolicy: boolean;
  alerts: boolean;
  signedReceipts: boolean;
  storedReceipts: boolean;
}

const FEATURES: Record<Plan, Omit<Entitlements, "plan" | "source">> = {
  free: { privateRepos: false, orgPolicy: false, alerts: false, signedReceipts: false, storedReceipts: false },
  pro: { privateRepos: true, orgPolicy: false, alerts: true, signedReceipts: true, storedReceipts: false },
  team: { privateRepos: true, orgPolicy: true, alerts: true, signedReceipts: true, storedReceipts: true },
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

export const isPlan = (p: unknown): p is Plan => p === "free" || p === "pro" || p === "team";

export async function entitlementsFor(env: Env, account: { id: number; login: string }, now: Date): Promise<Entitlements> {
  if ((env.BILLING_MODE ?? "off") !== "on") return { plan: "team", source: "billing-off", ...FEATURES.team };
  const raw = await env.ISOKLO_KV?.get(planKey(account.id));
  if (raw) {
    try {
      const rec = JSON.parse(raw) as PlanRecord;
      const expired = rec.until != null && Date.parse(rec.until) < now.getTime();
      if (isPlan(rec.plan) && !expired) return { plan: rec.plan, source: rec.source, ...FEATURES[rec.plan] };
    } catch {
      console.error(`isoklo: plan record for account ${account.id} is not valid JSON; treating it as free.`);
    }
  }
  const licences = jsonSetting(env.LICENSES, "LICENSES");
  const licensed = licences[String(account.id)] ?? licences[account.login] ?? licences[account.login.toLowerCase()];
  if (isPlan(licensed)) return { plan: licensed, source: "license", ...FEATURES[licensed] };
  return { plan: "free", source: "default", ...FEATURES.free };
}

export async function savePlan(env: Env, accountId: number, record: PlanRecord): Promise<void> {
  if (env.ISOKLO_KV === undefined) throw new Error("ISOKLO_KV is not bound, so plan changes cannot be stored.");
  await env.ISOKLO_KV.put(planKey(accountId), JSON.stringify(record));
}
