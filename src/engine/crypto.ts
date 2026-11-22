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
