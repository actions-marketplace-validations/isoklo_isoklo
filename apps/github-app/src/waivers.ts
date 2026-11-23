/**
 * Maintainer waivers, end to end: a pull request comment `/isoklo waive <rule-id or fingerprint> <reason>`, checked
 * against GitHub's own permissions, stored per pull request, applied on the next check, and recorded in the check run,
 * the summary comment and the evidence receipt.
 *
 * Who may waive: a person (never a bot) with write or admin access to the repository, who is not the pull request's
 * author. Agents often open pull requests with their owner's account, so an author waiving their own findings is the
 * one path an agent could use; a repository with a single maintainer turns it on with `waivers.allowAuthor` in the
 * base branch's isoklo.config.json (or the organisation's policy).
 */
import { parseWaiverCommand, updateWaivers, type IsokloConfig, type Waiver, type WaiverCommand } from "isoklo/engine";
import type { Env } from "./env.js";
import type { GitHub, PullRequest } from "./github.js";
import type { Entitlements } from "./plans.js";

const MAX_WAIVERS = 50;
const WAIVER_TTL = 60 * 60 * 24 * 400;

export const waiversKey = (repo: string, pr: number) => `waivers:${repo.toLowerCase()}#${pr}`;

export async function loadWaivers(env: Env, repo: string, pr: number): Promise<Waiver[]> {
  const raw = await env.ISOKLO_KV?.get(waiversKey(repo, pr));
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((w): w is Waiver =>
      typeof w === "object" && w !== null && typeof (w as Waiver).target === "string" && typeof (w as Waiver).reason === "string" && typeof (w as Waiver).by === "string");
  } catch {
    console.error(`isoklo: the waivers for ${repo}#${pr} are not valid JSON; none were applied.`);
    return [];
  }
}

export interface IssueCommentEvent {
  action: string;
  installation: { id: number };
  repository: { id?: number; full_name: string; private: boolean; owner: { id: number; login: string } };
  issue: { number: number; pull_request?: unknown; user?: { login: string } };
  comment: { id: number; body: string; user: { login: string; type?: string } };
}

export type WaiverOutcome =
  | { status: "ignored"; reason: string }
  | { status: "refused"; reason: string }
  | { status: "recorded"; command: Exclude<WaiverCommand, { action: "error" }>; applied: boolean };

export interface WaiverDeps {
  github: GitHub;
  now: () => Date;
  entitlements: (account: { id: number; login: string }) => Promise<Entitlements>;
  /** The policy at a ref, with the organisation's merged in when the plan includes it. */
  allowAuthor: (token: string, repo: string, pr: PullRequest, ent: Entitlements) => Promise<boolean>;
  /** Check the pull request again; resolves to the targets that the new check actually waived. */
  recheck: (pr: PullRequest) => Promise<string[] | null>;
}

const reply = async (gh: GitHub, token: string, e: IssueCommentEvent, text: string) => {
  try {
    await gh.createComment(token, e.repository.full_name, e.issue.number, `<!-- isoklo:waiver-reply -->\n${text}`);
  } catch (error) {
    console.error(`isoklo: could not answer a waiver comment on ${e.repository.full_name}#${e.issue.number}: ${error instanceof Error ? error.message : String(error)}`);
  }
};

export async function handleWaiverComment(env: Env, e: IssueCommentEvent, d: WaiverDeps): Promise<WaiverOutcome> {
  if (e.action !== "created") return { status: "ignored", reason: `issue_comment.${e.action}` };
  if (e.issue.pull_request === undefined || e.issue.pull_request === null) return { status: "ignored", reason: "not a pull request" };
  const cmd = parseWaiverCommand(e.comment.body ?? "");
  if (cmd === null) return { status: "ignored", reason: "no /isoklo command" };
  // Never a conversation with a bot, including this app: no loops, and no agent can waive.
  if (e.comment.user.type === "Bot" || /\[bot\]$/i.test(e.comment.user.login)) return { status: "ignored", reason: "comment by a bot" };

  const gh = d.github;
  const repo = e.repository.full_name;
  const token = await gh.installationToken(e.installation.id);
  const who = e.comment.user.login;
  if (cmd.action === "error") {
    await reply(gh, token, e, `@${who} ${cmd.message}`);
    return { status: "refused", reason: cmd.message };
  }

  const ent = await d.entitlements(e.repository.owner);
  if (!ent.waivers) {
    const text = "Waivers are part of Isoklo Team. On the free plan, accept a finding in the base branch's `isoklo.config.json` (`rules`, `ignorePaths` or `baseline`), which merges through review like any other change.";
    await reply(gh, token, e, `@${who} ${text}`);
    return { status: "refused", reason: "plan" };
  }

  const permission = await gh.collaboratorPermission(token, repo, who);
  if (permission !== "admin" && permission !== "write") {
    await reply(gh, token, e, `@${who} only people with write access to ${repo} can waive Isoklo findings. Nothing was changed.`);
    return { status: "refused", reason: `permission ${permission}` };
  }

  const pr = await gh.pullRequest(token, repo, e.issue.number);
  if (pr === null) return { status: "ignored", reason: "pull request not found" };
  const author = pr.user?.login ?? e.issue.user?.login ?? "";
  if (author.toLowerCase() === who.toLowerCase() && !(await d.allowAuthor(token, repo, pr, ent))) {
    await reply(gh, token, e,
      `@${who} the author of a pull request cannot waive its findings: agents often open pull requests with their owner's account. ` +
      "Ask another maintainer, or, for a repository with a single maintainer, set `\"waivers\": { \"allowAuthor\": true }` in `isoklo.config.json` on the base branch.");
    return { status: "refused", reason: "author" };
  }

  const at = d.now().toISOString();
  const list = updateWaivers(await loadWaivers(env, repo, e.issue.number), cmd, `@${who}`, at).slice(-MAX_WAIVERS);
  if (env.ISOKLO_KV === undefined) {
    await reply(gh, token, e, `@${who} this Isoklo installation has no storage (ISOKLO_KV), so waivers cannot be recorded.`);
    return { status: "refused", reason: "no storage" };
  }
  await env.ISOKLO_KV.put(waiversKey(repo, e.issue.number), JSON.stringify(list), { expirationTtl: WAIVER_TTL });
  await gh.addReaction(token, repo, e.comment.id, "+1").catch(() => undefined);

  const applied = await d.recheck(pr);
  const matched = cmd.action === "waive" && applied !== null && applied.includes(cmd.target);
  if (cmd.action === "waive" && applied !== null && !matched) {
    await reply(gh, token, e, `@${who} recorded, but no open finding on this pull request matches \`${cmd.target}\` right now. Check the rule id or fingerprint in the isoklo check.`);
  }
  return { status: "recorded", command: cmd, applied: matched };
}

/** The base branch's waiver policy, with the organisation's (Team) taking precedence where it speaks. */
export function allowAuthorFrom(repoPolicy: Pick<IsokloConfig, "waivers">, orgPolicy: Pick<IsokloConfig, "waivers"> | null): boolean {
  if (orgPolicy === null) return repoPolicy.waivers.allowAuthor === true;
  return (orgPolicy.waivers.allowAuthor ?? repoPolicy.waivers.allowAuthor) === true;
}
