/** Bindings and settings of the Worker. Everything secret is a Worker secret, never a [vars] entry. */

/** The part of Cloudflare's KVNamespace the app uses, so tests can pass an in-memory map. */
export interface KV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete?(key: string): Promise<void>;
  list?(options: { prefix: string; limit?: number; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }>;
}

/** Where "upgrade" and "pricing" links point when UPGRADE_URL is not set. */
export const DEFAULT_UPGRADE_URL = "https://euklo.com/isoklo/#pricing";

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
  /** Where "upgrade" links point: a Stripe Payment Link, the Marketplace listing, or the pricing page (the default). */
  UPGRADE_URL?: string;
  /** "off": every repository gets every feature. "on": plans are enforced. */
  BILLING_MODE?: string;
  /** JSON object: account login or id to plan, for licences sold by hand. */
  LICENSES?: string;
  /**
   * Ed25519 private key (a JWK, from `npx isoklo keygen`) for evidence receipts anyone can verify; its public half is
   * served at /.well-known/isoklo-receipt-keys.json. Takes precedence over RECEIPT_SIGNING_KEY. Secret.
   */
  RECEIPT_SIGNING_JWK?: string;
  /** HMAC key for signed evidence receipts, used when RECEIPT_SIGNING_JWK is not set. Secret. */
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
