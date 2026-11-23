/**
 * Evidence receipts: a canonical JSON record of one Isoklo run, with a SHA-256 digest over its canonical form and an
 * optional signature.
 *
 *   digest    anyone can recompute it (`isoklo verify`): it proves the receipt was not edited after it was issued.
 *   ed25519   a public-key signature. Anyone can check it, and `isoklo verify` also says whether the key is one you
 *             trust (the Isoklo GitHub App's published key, or a key you pass). Use this for audits.
 *   hmac      a shared-secret signature, for a team that holds the key itself. Only key holders can check it.
 *
 * Findings appear by rule, level, location and fingerprint, never with their evidence text, so a receipt can be shared
 * without sharing code. Waivers appear with who granted them and why.
 */
import type { CheckSummary } from "../check/report.js";
import { countBySeverity, findingsOf, verdictOf } from "../check/report.js";
import type { Level, Severity } from "../check/types.js";
import {
  canonicalJson, ed25519KeyId, ed25519Sign, ed25519Verify, hmacSha256Hex, isEd25519Jwk, sha256Hex, timingSafeEqual, type Ed25519Jwk,
} from "./crypto.js";
import type { Waiver } from "./waivers.js";

export const RECEIPT_SCHEMA = "https://isoklo.dev/schemas/receipt/v1";

/** Where the Isoklo GitHub App publishes the public keys its receipts are signed with (a JWKS document). */
export const APP_RECEIPT_KEYS_URL = "https://isoklo-github-app.manishguptha188.workers.dev/.well-known/isoklo-receipt-keys.json";

export interface ReceiptBody {
  schema: typeof RECEIPT_SCHEMA;
  tool: "isoklo";
  engineVersion: string;
  mode: "check" | "scan" | "pull_request";
  repository: string | null;
  base: { ref: string; sha: string | null } | null;
  head: { ref: string; sha: string | null };
  createdAt: string;
  policy: { source: string | null; sha256: string | null };
  rules: { id: string; version: number }[];
  verdict: "passed" | "blocked";
  counts: { byLevel: Record<Level, number>; bySeverity: Record<Severity, number> };
  findings: { ruleId: string; level: Level; severity: Severity; path: string | null; line: number | null; fingerprint: string; waivedBy?: string }[];
  /** Maintainer waivers that applied to this run: what, who, why and when. */
  waivers?: { target: string; by: string; reason: string; at: string | null }[];
}

export type ReceiptSignature =
  | { algorithm: "hmac-sha256"; keyId: string; value: string }
  | { algorithm: "ed25519"; keyId: string; publicKey: string; value: string };

export interface Receipt extends ReceiptBody {
  integrity: {
    algorithm: "sha256";
    canonicalization: "RFC 8785 (JCS)";
    digest: string;
    signature?: ReceiptSignature;
  };
}

export interface ReceiptInput {
  summary: CheckSummary;
  engineVersion: string;
  mode?: ReceiptBody["mode"];
  repository?: string | null;
  baseSha?: string | null;
  headSha?: string | null;
  createdAt?: Date;
  policyText?: string | null;
  /**
   * The signing key: an Ed25519 private JWK (JSON text, as `isoklo keygen` writes it) for a public-key signature, or
   * any other string for HMAC-SHA256. Null or empty: unsigned.
   */
  signingKey?: string | null;
  waivers?: readonly Waiver[];
}

/** Read a signing key: Ed25519 when it is a private JWK, HMAC otherwise. */
export function parseSigningKey(raw: string): { kind: "ed25519"; jwk: Ed25519Jwk } | { kind: "hmac"; secret: string } {
  const t = raw.trim();
  if (t.startsWith("{")) {
    let doc: unknown;
    try {
      doc = JSON.parse(t);
    } catch {
      throw new Error("the signing key looks like JSON but is not valid JSON.");
    }
    if (isEd25519Jwk(doc, true)) return { kind: "ed25519", jwk: doc };
    throw new Error("the signing key is JSON but not an Ed25519 private key (a JWK with kty OKP, crv Ed25519, x and d).");
  }
  return { kind: "hmac", secret: raw };
}

export async function createReceipt(i: ReceiptInput): Promise<Receipt> {
  const s = i.summary;
  const findings = findingsOf(s);
  const levelCount = (l: Level) => findings.filter((f) => f.level === l).length;
  const applied = (i.waivers ?? []).filter((w) => findings.some((f) => f.waiver !== undefined && (f.fingerprint === w.target || f.ruleId === w.target)));
  const body: ReceiptBody = {
    schema: RECEIPT_SCHEMA,
    tool: "isoklo",
    engineVersion: i.engineVersion,
    mode: i.mode ?? s.mode ?? "check",
    repository: i.repository ?? null,
    base: s.mode === "scan" ? null : { ref: s.base, sha: i.baseSha ?? null },
    head: { ref: s.mode === "scan" ? "working tree" : s.head, sha: i.headSha ?? null },
    createdAt: (i.createdAt ?? new Date()).toISOString(),
    policy: { source: s.configSource ?? null, sha256: i.policyText ? await sha256Hex(i.policyText) : null },
    rules: s.rulesRun ?? [],
    verdict: verdictOf(s),
    counts: {
      byLevel: { blocked: levelCount("blocked"), review: levelCount("review"), info: levelCount("info") },
      bySeverity: countBySeverity(findings),
    },
    findings: findings.map((f) => ({
      ruleId: f.ruleId ?? `${f.rule}/${f.id}`,
      level: f.level,
      severity: f.severity ?? "info",
      path: f.evidence[0]?.path ?? null,
      line: f.evidence[0]?.line ?? null,
      fingerprint: f.fingerprint ?? "",
      ...(f.waiver !== undefined ? { waivedBy: f.waiver.by } : {}),
    })),
    ...(applied.length > 0 ? { waivers: applied.map((w) => ({ target: w.target, by: w.by, reason: w.reason, at: w.at ?? null })) } : {}),
  };
  const canonical = canonicalJson(body);
  const receipt: Receipt = { ...body, integrity: { algorithm: "sha256", canonicalization: "RFC 8785 (JCS)", digest: await sha256Hex(canonical) } };
  if (i.signingKey) {
    const key = parseSigningKey(i.signingKey);
    receipt.integrity.signature = key.kind === "ed25519"
      ? { algorithm: "ed25519", keyId: await ed25519KeyId(key.jwk.x), publicKey: key.jwk.x, value: await ed25519Sign(key.jwk, canonical) }
      : { algorithm: "hmac-sha256", keyId: (await sha256Hex(key.secret)).slice(0, 12), value: await hmacSha256Hex(key.secret, canonical) };
  }
  return receipt;
}

/** A public key you trust, for example from the GitHub App's JWKS document. */
export interface TrustedKey {
  /** The Ed25519 public key, base64url (a JWK's `x`). */
  x: string;
  /** Who it belongs to, for the report ("Isoklo GitHub App"). */
  label?: string;
}

export interface VerifyOptions {
  /** The shared secret for an HMAC signature. */
  hmacKey?: string | null;
  /** Ed25519 keys you trust. Undefined or null: not checked against any (the report says so). */
  trustedKeys?: readonly TrustedKey[] | null;
}

export interface Verification {
  digestValid: boolean;
  /** null: no signature, or no key to check it with. */
  signatureValid: boolean | null;
  algorithm: ReceiptSignature["algorithm"] | null;
  keyId: string | null;
  /** Ed25519 only: is the signing key one of the trusted keys? null when no trusted keys were given. */
  trusted: boolean | null;
  /** The trusted key's label, when it matched. */
  signer: string | null;
  detail: string;
}

/** Keys from a JWKS document (`{ "keys": [...] }`), a single JWK, or a bare base64url public key. */
export function trustedKeysFrom(doc: unknown, label?: string): TrustedKey[] {
  const tag = (x: string, kid?: unknown): TrustedKey => (label !== undefined ? { x, label } : typeof kid === "string" ? { x, label: `key ${kid}` } : { x });
  if (typeof doc === "string") return /^[A-Za-z0-9_-]{43}$/.test(doc.trim()) ? [tag(doc.trim())] : [];
  if (isEd25519Jwk(doc)) return [tag(doc.x, doc.kid)];
  if (typeof doc === "object" && doc !== null && Array.isArray((doc as { keys?: unknown }).keys)) {
    return ((doc as { keys: unknown[] }).keys).filter((k): k is Ed25519Jwk => isEd25519Jwk(k)).map((k) => tag(k.x, k.kid));
  }
  return [];
}

export async function verifyReceipt(receipt: unknown, options?: string | null | VerifyOptions): Promise<Verification> {
  const o: VerifyOptions = typeof options === "string" || options === null || options === undefined ? { hmacKey: options ?? null } : options;
  const none = { signatureValid: null, algorithm: null, keyId: null, trusted: null, signer: null } as const;
  if (typeof receipt !== "object" || receipt === null || !("integrity" in receipt)) {
    return { digestValid: false, ...none, detail: "not an Isoklo receipt: it has no integrity block." };
  }
  const { integrity, ...body } = receipt as Receipt;
  if (typeof integrity?.digest !== "string") return { digestValid: false, ...none, detail: "the integrity block has no digest." };
  const canonical = canonicalJson(body);
  const digestValid = timingSafeEqual(await sha256Hex(canonical), integrity.digest);
  const sig = integrity.signature;
  if (!digestValid) {
    return { digestValid, ...none, algorithm: sig?.algorithm ?? null, keyId: sig?.keyId ?? null, detail: "the digest does not match: the receipt was changed after it was issued." };
  }
  if (sig === undefined) return { digestValid, ...none, detail: "the digest matches; the receipt is unsigned." };

  if (sig.algorithm === "ed25519") {
    const consistent = typeof sig.publicKey === "string" && sig.keyId === (await ed25519KeyId(sig.publicKey));
    const signatureValid = consistent && (await ed25519Verify(sig.publicKey, canonical, sig.value));
    const match = o.trustedKeys ? o.trustedKeys.find((k) => k.x === sig.publicKey) : undefined;
    const trusted = o.trustedKeys ? match !== undefined : null;
    const who = match?.label ?? null;
    const detail = !signatureValid
      ? `the digest matches, but the Ed25519 signature does not: it was not made by key ${sig.keyId}.`
      : trusted === true
        ? `the digest and the Ed25519 signature match, and key ${sig.keyId} is ${who ?? "a key you trust"}.`
        : trusted === false
          ? `the digest and the Ed25519 signature match, but key ${sig.keyId} is not one you trust: anyone can make a key, so this proves nothing about who issued it.`
          : `the digest and the Ed25519 signature match (key ${sig.keyId}); not checked against a trusted key. Pass --key or --jwks, or go online to check it against the Isoklo GitHub App's keys.`;
    return { digestValid, signatureValid, algorithm: "ed25519", keyId: sig.keyId, trusted, signer: who, detail };
  }

  let signatureValid: boolean | null = null;
  if (o.hmacKey) {
    const keyId = (await sha256Hex(o.hmacKey)).slice(0, 12);
    signatureValid = keyId === sig.keyId && timingSafeEqual(await hmacSha256Hex(o.hmacKey, canonical), sig.value);
  }
  const detail = signatureValid === false
    ? "the digest matches, but the HMAC signature does not: it was not signed with this key."
    : signatureValid === true
      ? "the digest and the HMAC signature match."
      : "the digest matches; set ISOKLO_RECEIPT_KEY to the shared secret to check the HMAC signature too.";
  return { digestValid, signatureValid, algorithm: "hmac-sha256", keyId: sig.keyId, trusted: null, signer: null, detail };
}
