/**
 * Payment webhooks that set an account's plan. Both are ready to go live: point Stripe or the GitHub Marketplace at
 * this Worker, set the secrets, and switch BILLING_MODE to "on".
 *
 * Stripe: send buyers to a Payment Link or Checkout Session with client_reference_id set to their GitHub account id
 * (the upgrade link in the app's check run does this). Price ids map to plans with STRIPE_PRICE_PLANS.
 * GitHub Marketplace: marketplace_purchase events arrive on the app's normal webhook; plan names map to plans with
 * MARKETPLACE_PLAN_MAP, or by name ("Team", "Pro", "Free").
 */
import { jsonSetting, type Env } from "./env.js";
import { isPlan, savePlan, type Plan } from "./plans.js";

const customerKey = (customer: string) => `stripe-customer:${customer}`;

/**
 * A Marketplace plan's tier: the map, then the name. A plan the customer pays for is never read as free, whatever it
 * is called ("Startup", "Growth"): it counts as Pro until MARKETPLACE_PLAN_MAP says otherwise.
 */
function planFromName(name: string, map: Record<string, string>, paid: boolean): Plan {
  const mapped = map[name];
  if (isPlan(mapped)) return mapped;
  const n = name.toLowerCase();
  if (n.includes("team") || n.includes("business") || n.includes("enterprise") || n.includes("org")) return "team";
  if (n.includes("pro") || paid) return "pro";
  return "free";
}

// ---------------------------------------------------------------- Stripe
interface StripeEvent {
  type: string;
  data: { object: Record<string, unknown> };
}

export async function handleStripeEvent(env: Env, event: StripeEvent, now: Date): Promise<{ handled: boolean; detail: string }> {
  const o = event.data.object;
  const prices = jsonSetting(env.STRIPE_PRICE_PLANS, "STRIPE_PRICE_PLANS");
  const str = (v: unknown) => (typeof v === "string" ? v : undefined);
  const meta = (typeof o["metadata"] === "object" && o["metadata"] !== null ? o["metadata"] : {}) as Record<string, string>;

  if (event.type === "checkout.session.completed") {
    const account = Number(str(o["client_reference_id"]) ?? meta["github_account_id"]);
    if (!Number.isInteger(account) || account <= 0) return { handled: false, detail: "checkout session has no GitHub account id (client_reference_id)." };
    const plan = isPlan(meta["plan"]) ? meta["plan"] : "pro";
    const customer = str(o["customer"]);
    await savePlan(env, account, { plan, source: "stripe", updatedAt: now.toISOString(), ...(customer ? { stripeCustomer: customer } : {}) });
    if (customer) await env.ISOKLO_KV?.put(customerKey(customer), String(account));
    return { handled: true, detail: `account ${account} is now on ${plan}.` };
  }

  if (event.type.startsWith("customer.subscription.")) {
    const customer = str(o["customer"]);
    const account = Number(meta["github_account_id"] ?? (customer ? await env.ISOKLO_KV?.get(customerKey(customer)) : undefined));
    if (!Number.isInteger(account) || account <= 0) return { handled: false, detail: "subscription is not linked to a GitHub account." };
    const status = str(o["status"]);
    const items = (o["items"] as { data?: { price?: { id?: string } }[] } | undefined)?.data ?? [];
    const priced = items.map((i) => prices[i.price?.id ?? ""]).find(isPlan);
    const active = event.type !== "customer.subscription.deleted" && (status === "active" || status === "trialing");
    const plan: Plan = active ? priced ?? (isPlan(meta["plan"]) ? meta["plan"] : "pro") : "free";
    const periodEnd = typeof o["current_period_end"] === "number" ? new Date((o["current_period_end"] as number) * 1000).toISOString() : null;
    await savePlan(env, account, { plan, source: "stripe", updatedAt: now.toISOString(), until: active ? periodEnd : null, ...(customer ? { stripeCustomer: customer } : {}) });
    return { handled: true, detail: `account ${account} is now on ${plan} (${status ?? "deleted"}).` };
  }
  return { handled: false, detail: `ignored ${event.type}.` };
}

// ---------------------------------------------------------------- GitHub Marketplace
interface MarketplacePurchase {
  action: string;
  marketplace_purchase: {
    account: { id: number; login: string; type?: string };
    plan: { id?: number; name: string; price_model?: string; monthly_price_in_cents?: number; yearly_price_in_cents?: number };
    on_free_trial?: boolean;
    next_billing_date?: string | null;
    free_trial_ends_on?: string | null;
  };
}

export async function handleMarketplace(env: Env, p: MarketplacePurchase, now: Date): Promise<{ handled: boolean; detail: string }> {
  const purchase = p.marketplace_purchase;
  const account = purchase.account;
  if (p.action === "pending_change" || p.action === "pending_change_cancelled") {
    return { handled: false, detail: `${p.action}: the plan changes at the next billing date, when GitHub sends "changed".` };
  }
  const map = jsonSetting(env.MARKETPLACE_PLAN_MAP, "MARKETPLACE_PLAN_MAP");
  const plan: Plan = p.action === "cancelled" ? "free" : map[String(purchase.plan.id)] !== undefined && isPlan(map[String(purchase.plan.id)])
    ? (map[String(purchase.plan.id)] as Plan)
    : planFromName(purchase.plan.name, map, (purchase.plan.monthly_price_in_cents ?? 0) > 0 || (purchase.plan.yearly_price_in_cents ?? 0) > 0 || (purchase.plan.price_model !== undefined && purchase.plan.price_model !== "FREE"));
  // No expiry: a trial that converts sends no event, and a cancellation always does ("cancelled" above).
  await savePlan(env, account.id, { plan, source: "marketplace", updatedAt: now.toISOString(), until: null, login: account.login });
  return { handled: true, detail: `${account.login} (${account.id}) is now on ${plan} via the Marketplace (${p.action}).` };
}
