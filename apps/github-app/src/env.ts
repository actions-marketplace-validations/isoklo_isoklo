/** Bindings and settings of the Worker. Everything secret is a Worker secret, never a [vars] entry. */

/** The part of Cloudflare's KVNamespace the app uses, so tests can pass an in-memory map. */
export interface KV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface Env {
  /** Numeric GitHub App id, from the app's settings page. */
  GITHUB_APP_ID: string;
  /** The app's private key, PEM (GitHub downloads PKCS#1; PKCS#8 also works). Secret. */
  GITHUB_APP_PRIVATE_KEY: string;
  /** The webhook secret set on the app. Secret. */
  GITHUB_WEBHOOK_SECRET: string;
  /** API base for GitHub Enterprise Server (default https://api.github.com). */
  GITHUB_API_URL?: string;
  APP_SLUG?: string;
  PUBLIC_URL?: string;
  /** Where "upgrade" links point: the Marketplace listing or a Stripe Checkout link. */
  UPGRADE_URL?: string;
  /** "off": every repository gets every feature. "on": plans are enforced. */
  BILLING_MODE?: string;
  /** JSON object: account login or id to plan, for licences sold by hand. */
  LICENSES?: string;
  /** HMAC key for signed evidence receipts (paid plans). Secret. */
  RECEIPT_SIGNING_KEY?: string;
  /** Stripe webhook signing secret (whsec_...). Secret. */
  STRIPE_WEBHOOK_SECRET?: string;
  /** JSON object: Stripe price id to plan. */
  STRIPE_PRICE_PLANS?: string;
  /** JSON object: GitHub Marketplace plan name or id to plan. */
  MARKETPLACE_PLAN_MAP?: string;
  /** "false" turns npm and PyPI lookups off. */
  ONLINE?: string;
  /** "true" posts a pull request comment even when everything passes. */
  COMMENT_ON_PASS?: string;
  ISOKLO_KV?: KV;
}

/** Parse a JSON object setting; a broken value counts as empty (and is logged), never as a crash. */
export function jsonSetting(value: string | undefined, name: string): Record<string, string> {
  if (value === undefined || value.trim() === "") return {};
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return Object.fromEntries(Object.entries(parsed).filter((e): e is [string, string] => typeof e[1] === "string"));
    }
  } catch {
    // fall through
  }
  console.error(`isoklo: the ${name} setting is not a JSON object of strings; it was ignored.`);
  return {};
}
