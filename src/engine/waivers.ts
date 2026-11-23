/**
 * Maintainer waivers: a person with write access accepts one finding on one pull request, with a reason, and the
 * acceptance is recorded in the check, the comment and the evidence receipt.
 *
 * Why not an inline `// isoklo-ignore` comment? The change being judged can write any comment it likes, so a comment
 * inside the change can never accept that change: an agent would simply write one. A waiver has to come from outside
 * the change (a maintainer's command, checked against GitHub's permissions) or from the base branch's policy
 * (`rules`, `ignorePaths`, `baseline`), which only changes through a reviewed merge.
 */

export interface Waiver {
  /** A rule id (`tamper/assertions-removed`: every finding of that rule) or one finding's 16-digit fingerprint. */
  target: string;
  reason: string;
  /** Who waived it, as shown to reviewers (for example "@octocat"). */
  by: string;
  /** When (ISO 8601). */
  at?: string;
}

export type WaiverCommand =
  | { action: "waive"; target: string; reason: string }
  | { action: "revoke"; target: string }
  | { action: "error"; message: string };

const RULE_ID = /^[a-z]+\/[a-z0-9-]+$/;
const FINGERPRINT = /^[0-9a-f]{16}$/;
/** A reason long enough to mean something to the next reader. */
export const MIN_REASON_LENGTH = 10;

export const isWaiverTarget = (t: string) => RULE_ID.test(t) || FINGERPRINT.test(t);

/**
 * Read a waiver command from a pull request comment: the first line that starts with `/isoklo`.
 *
 *   /isoklo waive tamper/assertions-removed the totals moved to test/totals.test.js in #41
 *   /isoklo waive 3f9c2a61b0d4e7a8 fixture key from Stripe's documentation
 *   /isoklo revoke tamper/assertions-removed
 *
 * Returns null when the comment holds no Isoklo command at all.
 */
export function parseWaiverCommand(body: string): WaiverCommand | null {
  const line = body.split(/\r?\n/).map((l) => l.trim()).find((l) => /^\/isoklo\b/i.test(l));
  if (line === undefined) return null;
  const [, verb = "", target = "", ...rest] = line.split(/\s+/);
  const reason = rest.join(" ").replace(/^[:—–-]\s*/, "").trim();
  const usage = "Use `/isoklo waive <rule-id or fingerprint> <reason>` or `/isoklo revoke <rule-id or fingerprint>`.";
  if (!/^(waive|revoke)$/i.test(verb)) return { action: "error", message: `Isoklo did not understand \`${verb || "/isoklo"}\`. ${usage}` };
  if (!isWaiverTarget(target)) {
    return { action: "error", message: `\`${target || "(nothing)"}\` is not a rule id (like \`tamper/assertions-removed\`) or a finding fingerprint (16 hex digits). ${usage}` };
  }
  if (verb.toLowerCase() === "revoke") return { action: "revoke", target };
  if (reason.length < MIN_REASON_LENGTH) {
    return { action: "error", message: `A waiver needs a reason of at least ${MIN_REASON_LENGTH} characters, so the next reader knows why. ${usage}` };
  }
  return { action: "waive", target, reason: reason.slice(0, 500) };
}

/** Apply a waive or revoke command to a pull request's waiver list (the newest waiver for a target wins). */
export function updateWaivers(list: Waiver[], cmd: WaiverCommand, by: string, at: string): Waiver[] {
  if (cmd.action === "error") return list;
  const others = list.filter((w) => w.target !== cmd.target);
  return cmd.action === "revoke" ? others : [...others, { target: cmd.target, reason: cmd.reason, by, at }];
}
