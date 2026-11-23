/**
 * Hashing and signing with Web Crypto (globalThis.crypto.subtle), which Node 22 and Cloudflare Workers both provide.
 * Used for evidence receipts, finding fingerprints and baselines.
 */

const encoder = new TextEncoder();

const toHex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (s === undefined) throw new Error("Web Crypto is not available in this runtime.");
  return s;
}

export async function sha256Hex(data: string): Promise<string> {
  return toHex(await subtle().digest("SHA-256", encoder.encode(data)));
}

export async function hmacSha256Hex(key: string, data: string): Promise<string> {
  const k = await subtle().importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await subtle().sign("HMAC", k, encoder.encode(data)));
}

// ---------------------------------------------------------------- Ed25519 (public-key signatures for receipts)

/** An Ed25519 key as a JSON Web Key (RFC 8037). `d` is present only on the private half. */
export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  /** The public key, base64url. */
  x: string;
  /** The private key, base64url. Never published. */
  d?: string;
  kid?: string;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url text.");
  const t = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** True when the value is an Ed25519 JWK (with the private half, if asked). */
export function isEd25519Jwk(v: unknown, needPrivate = false): v is Ed25519Jwk {
  if (typeof v !== "object" || v === null) return false;
  const k = v as Record<string, unknown>;
  const b64 = (s: unknown) => typeof s === "string" && /^[A-Za-z0-9_-]{43}$/.test(s); // 32 bytes, unpadded
  return k["kty"] === "OKP" && k["crv"] === "Ed25519" && b64(k["x"]) && (!needPrivate || b64(k["d"]));
}

// Workers runtimes from before the standard name used "NODE-ED25519"; the standard name is tried first.
const ED25519_PARAMS = [{ name: "Ed25519" }, { name: "NODE-ED25519", namedCurve: "NODE-ED25519" }] as const;

async function importEd25519(jwk: Ed25519Jwk, use: "sign" | "verify"): Promise<{ key: CryptoKey; algorithm: { name: string } }> {
  // Only the key material: key_ops, alg or ext copied from another tool must not make the import fail.
  const clean = (use === "sign" ? { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d } : { kty: "OKP", crv: "Ed25519", x: jwk.x }) as JsonWebKey;
  let last: unknown;
  for (const params of ED25519_PARAMS) {
    try {
      const key = await subtle().importKey("jwk", clean, params as unknown as AlgorithmIdentifier, false, [use]);
      return { key, algorithm: { name: params.name } };
    } catch (error) {
      last = error;
    }
  }
  throw new Error(`this runtime cannot use Ed25519 keys (${last instanceof Error ? last.message : String(last)}).`);
}

/** Sign text with an Ed25519 private JWK; the signature is base64url. */
export async function ed25519Sign(privateJwk: Ed25519Jwk, data: string): Promise<string> {
  if (!isEd25519Jwk(privateJwk, true)) throw new Error("not an Ed25519 private key (a JWK with kty OKP, crv Ed25519, x and d).");
  const { key, algorithm } = await importEd25519(privateJwk, "sign");
  return base64UrlEncode(new Uint8Array(await subtle().sign(algorithm, key, encoder.encode(data))));
}

/** Check a base64url Ed25519 signature over text against a base64url public key. Malformed input is just invalid. */
export async function ed25519Verify(publicKeyX: string, data: string, signature: string): Promise<boolean> {
  try {
    const jwk: Ed25519Jwk = { kty: "OKP", crv: "Ed25519", x: publicKeyX };
    if (!isEd25519Jwk(jwk)) return false;
    const sig = base64UrlDecode(signature);
    if (sig.length !== 64) return false;
    const { key, algorithm } = await importEd25519(jwk, "verify");
    return await subtle().verify(algorithm, key, sig, encoder.encode(data));
  } catch {
    return false;
  }
}

/** A short, stable id for a public key: the first 16 hex digits of SHA-256 over its base64url text. */
export async function ed25519KeyId(publicKeyX: string): Promise<string> {
  return (await sha256Hex(`ed25519:${publicKeyX}`)).slice(0, 16);
}

/** A new Ed25519 key pair, as a private JWK with its kid. Keep it secret; publish only `x`. */
export async function ed25519GenerateJwk(): Promise<Ed25519Jwk & { d: string; kid: string }> {
  const pair = (await subtle().generateKey({ name: "Ed25519" } as unknown as AlgorithmIdentifier, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await subtle().exportKey("jwk", pair.privateKey)) as { x?: string; d?: string };
  if (typeof jwk.x !== "string" || typeof jwk.d !== "string") throw new Error("this runtime did not export an Ed25519 key.");
  return { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d, kid: await ed25519KeyId(jwk.x) };
}

/** Compare two strings in time that does not depend on where they differ. */
export function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

/**
 * Canonical JSON: object keys sorted by code point, no whitespace, arrays in order (RFC 8785 for the values Isoklo
 * writes: strings, integers, booleans, null). The same receipt always hashes to the same digest on every machine.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("canonical JSON cannot hold NaN or Infinity.");
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}
