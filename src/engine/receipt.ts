/**
 * Evidence receipts: a canonical JSON record of one Isoklo run, with a SHA-256 digest over its canonical form, and an
 * optional HMAC-SHA256 signature for teams that keep an audit trail. Anyone can check the digest (`isoklo verify`);
 * only holders of the key can check the signature. Findings appear by rule, level, location and fingerprint, never
 * with their evidence text, so a receipt can be shared without sharing code.
 */
import type { CheckSummary } from "../check/report.js";
import { countBySeverity, findingsOf, verdictOf } from "../check/report.js";
import type { Level, Severity } from "../check/types.js";
import { canonicalJson, hmacSha256Hex, sha256Hex, timingSafeEqual } from "./crypto.js";

export const RECEIPT_SCHEMA = "https://isoklo.dev/schemas/receipt/v1";

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
  findings: { ruleId: string; level: Level; severity: Severity; path: string | null; line: number | null; fingerprint: string }[];
}

export interface Receipt extends ReceiptBody {
  integrity: {
    algorithm: "sha256";
    canonicalization: "RFC 8785 (JCS)";
    digest: string;
    signature?: { algorithm: "hmac-sha256"; keyId: string; value: string };
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
  /** HMAC key for a signed receipt (paid plans, or ISOKLO_RECEIPT_KEY on the command line). */
  signingKey?: string | null;
}

export async function createReceipt(i: ReceiptInput): Promise<Receipt> {
  const s = i.summary;
  const findings = findingsOf(s);
  const levelCount = (l: Level) => findings.filter((f) => f.level === l).length;
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
    })),
  };
  const canonical = canonicalJson(body);
  const receipt: Receipt = { ...body, integrity: { algorithm: "sha256", canonicalization: "RFC 8785 (JCS)", digest: await sha256Hex(canonical) } };
  if (i.signingKey) {
    receipt.integrity.signature = {
      algorithm: "hmac-sha256",
      keyId: (await sha256Hex(i.signingKey)).slice(0, 12),
      value: await hmacSha256Hex(i.signingKey, canonical),
    };
  }
  return receipt;
}

export interface Verification {
  digestValid: boolean;
  /** null: no signature, or no key to check it with. */
  signatureValid: boolean | null;
  detail: string;
}

export async function verifyReceipt(receipt: unknown, key?: string | null): Promise<Verification> {
  if (typeof receipt !== "object" || receipt === null || !("integrity" in receipt)) {
    return { digestValid: false, signatureValid: null, detail: "not an Isoklo receipt: it has no integrity block." };
  }
  const { integrity, ...body } = receipt as Receipt;
  if (typeof integrity?.digest !== "string") return { digestValid: false, signatureValid: null, detail: "the integrity block has no digest." };
  const canonical = canonicalJson(body);
  const digestValid = timingSafeEqual(await sha256Hex(canonical), integrity.digest);
  let signatureValid: boolean | null = null;
  if (integrity.signature !== undefined && key) {
    const keyId = (await sha256Hex(key)).slice(0, 12);
    signatureValid = keyId === integrity.signature.keyId && timingSafeEqual(await hmacSha256Hex(key, canonical), integrity.signature.value);
  }
  const detail = !digestValid
    ? "the digest does not match: the receipt was changed after it was issued."
    : signatureValid === false
      ? "the digest matches, but the signature does not: it was not signed with this key."
      : signatureValid === true
        ? "the digest and the signature match."
        : integrity.signature !== undefined
          ? "the digest matches; set ISOKLO_RECEIPT_KEY to check the signature too."
          : "the digest matches; the receipt is unsigned.";
  return { digestValid, signatureValid, detail };
}
