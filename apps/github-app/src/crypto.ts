/**
 * Webhook signatures (GitHub, Stripe) and the GitHub App's RS256 JWT, with Web Crypto only (Workers have no node:crypto).
 */
import { hmacSha256Hex, timingSafeEqual } from "isoklo/engine";

/** GitHub signs the raw body with HMAC-SHA256 and sends `X-Hub-Signature-256: sha256=<hex>`. */
export async function verifyGithubSignature(secret: string, body: string, header: string | undefined | null): Promise<boolean> {
  if (!secret || !header || !header.startsWith("sha256=")) return false;
  const expected = `sha256=${await hmacSha256Hex(secret, body)}`;
  return timingSafeEqual(expected, header);
}

/**
 * Stripe signs `${timestamp}.${body}` and sends `Stripe-Signature: t=<ts>,v1=<hex>[,v1=<hex>]`. A signature older than
 * the tolerance is refused, so a captured event cannot be replayed later.
 */
export async function verifyStripeSignature(secret: string, body: string, header: string | undefined | null, nowSeconds: number, toleranceSeconds = 300): Promise<boolean> {
  if (!secret || !header) return false;
  const parts = header.split(",").map((p) => p.trim().split("=") as [string, string]);
  const t = Number(parts.find(([k]) => k === "t")?.[1]);
  const signatures = parts.filter(([k]) => k === "v1").map(([, v]) => v);
  if (!Number.isFinite(t) || signatures.length === 0 || Math.abs(nowSeconds - t) > toleranceSeconds) return false;
  const expected = await hmacSha256Hex(secret, `${t}.${body}`);
  return signatures.some((s) => timingSafeEqual(expected, s));
}

// ---------------------------------------------------------------- RS256 JWT for the GitHub App
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlText = (s: string) => b64url(new TextEncoder().encode(s));

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let x = n; x > 0; x >>= 8) bytes.unshift(x & 0xff);
  return [0x80 | bytes.length, ...bytes];
}
const der = (tag: number, content: number[]) => [tag, ...derLength(content.length), ...content];

/** GitHub hands out PKCS#1 keys ("BEGIN RSA PRIVATE KEY"); Web Crypto imports PKCS#8. Wrap one in the other. */
export function pemToPkcs8(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END)[^-]+-----/g, "").replace(/\\n/g, "").replace(/\s+/g, "");
  const raw = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  if (!/BEGIN RSA PRIVATE KEY/.test(pem)) return raw;
  const rsaAlgorithm = der(0x30, [...der(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), 0x05, 0x00]);
  return Uint8Array.from(der(0x30, [...der(0x02, [0x00]), ...rsaAlgorithm, ...der(0x04, [...raw])]));
}

/** A short-lived JWT the app uses to ask GitHub for installation tokens. */
export async function appJwt(appId: string, privateKeyPem: string, nowSeconds: number): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", pemToPkcs8(privateKeyPem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  // iat 60 s in the past absorbs clock drift; GitHub allows at most 10 minutes.
  const header = b64urlText(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64urlText(JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 540, iss: appId }));
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${header}.${payload}`)));
  return `${header}.${payload}.${b64url(signature)}`;
}
