/**
 * One pull request, end to end: plan check, a check run in progress, the change read through GitHub's API, the same
 * engine the CLI runs, then the finished check run with line annotations, one summary comment, a receipt, and (paid)
 * alerts. Any failure completes the check as "failure": the gate fails closed and nothing is approved.
 */
import {
  CONFIG_FILES, ConfigError, createReceipt, fileDiffsFromPullFiles, mergeOrgPolicy, parseConfig, rebuildDiff, runCheck, verdictOf, wholeFileDiff,
  type FetchLike, type IsokloConfig,
} from "isoklo/engine";
import type { Env } from "./env.js";
import { GitHub, type PullRequest } from "./github.js";
import { entitlementsFor } from "./plans.js";
import { alert, CHECK_NAME, checkRunOutput, COMMENT_MARKER, commentBody, couldNotRunOutput, upsellOutput } from "./render.js";
import { ENGINE_VERSION } from "./version.js";

export interface Deps {
  fetch: typeof fetch;
  now: () => Date;
}

export interface PullRequestEvent {
  installation: { id: number };
  repository: { full_name: string; private: boolean; owner: { id: number; login: string } };
  pull_request: PullRequest;
}

export type Outcome =
  | { status: "checked"; verdict: "passed" | "blocked"; checkRunId: number; comment: string; receiptDigest: string }
  | { status: "upsell"; checkRunId: number }
  | { status: "failed"; checkRunId: number | null; error: string }
  | { status: "skipped"; reason: string };

/** Text files whose diff GitHub left out that are rebuilt from both versions; more than this cannot pass. */
export const MAX_REBUILT_FILES = 20;
/** New packages looked up on npm and PyPI per pull request; the rest are reported as not verified. */
export const MAX_REGISTRY_LOOKUPS = 25;

const TEXT_FILE =/\.(m?[jt]sx?|cjs|cts|json|jsonc|ya?ml|toml|md|mdc|txt|py|rb|go|rs|java|kt|cs|php|sh|ps1|env|cfg|ini|lock|sql|tf|html?|css|scss|vue|svelte)$|(^|\/)(\.[\w.-]+|Dockerfile|Makefile|Jenkinsfile|CODEOWNERS)$/i;

async function policyAt(gh: GitHub, token: string, repo: string, ref: string | undefined): Promise<{ config: IsokloConfig; source: string | null; text: string | null }> {
  for (const file of CONFIG_FILES) {
    const text = await gh.content(token, repo, file, ref);
    if (text === null) continue;
    return { config: parseConfig(text, `${repo}:${file}`).config, source: `${repo}:${file}`, text };
  }
  return { config: parseConfig(null).config, source: null, text: null };
}

export async function handlePullRequest(env: Env, e: PullRequestEvent, deps: Deps): Promise<Outcome> {
  const repo = e.repository.full_name;
  const pr = e.pull_request;
  if (pr.draft === true) return { status: "skipped", reason: "draft pull request" };
  const gh = new GitHub(env, deps.fetch as unknown as ConstructorParameters<typeof GitHub>[1], () => deps.now().getTime());
  const token = await gh.installationToken(e.installation.id);
  const ent = await entitlementsFor(env, e.repository.owner, deps.now());

  if (e.repository.private && !ent.privateRepos) {
    const id = await gh.createCheckRun(token, repo, {
      name: CHECK_NAME, head_sha: pr.head.sha, status: "completed", conclusion: "neutral",
      output: upsellOutput(env.UPGRADE_URL ?? "https://github.com/marketplace/isoklo", e.repository.owner.id),
    });
    return { status: "upsell", checkRunId: id };
  }

  const checkRunId = await gh.createCheckRun(token, repo, { name: CHECK_NAME, head_sha: pr.head.sha, status: "in_progress", started_at: deps.now().toISOString() });
  try {
    const mergeBase = await gh.mergeBase(token, repo, pr.base.sha, pr.head.sha);
    const listed = await gh.pullFiles(token, repo, pr.number);
    const pulled = fileDiffsFromPullFiles(listed);
    const before = (p: string) => gh.content(token, repo, p, mergeBase);
    const after = (p: string) => gh.content(token, repo, p, pr.head.sha);

    // GitHub leaves out patches for binary files and very large diffs. Text files are rebuilt from their contents
    // (up to a budget); whatever still cannot be read keeps the check from passing, so nothing hides in a huge diff.
    const unreadable: string[] = [];
    const files = [];
    let rebuilt = 0;
    for (const f of pulled.files) {
      const path = f.newPath ?? f.oldPath ?? "";
      if (f.binary && TEXT_FILE.test(path) && pulled.unreadable.includes(path)) {
        if (rebuilt < MAX_REBUILT_FILES) {
          rebuilt++;
          if (f.status === "added" || f.status === "deleted") {
            const text = f.status === "added" ? await after(path) : await before(path);
            if (text !== null) { files.push(wholeFileDiff(f, text)); continue; }
          } else {
            const [b, a] = [await before(f.oldPath ?? path), await after(path)];
            if (b !== null && a !== null) { files.push(rebuildDiff(f, b, a)); continue; }
          }
        }
        unreadable.push(path);
      }
      files.push(f);
    }
    // The files API lists at most 3,000 files; GitHub's own count says whether some were never listed.
    const total = pr.changed_files ?? listed.length;
    const coverage = { listed: listed.length, total, unreadable };

    // Policy from the merge base (never the pull request), plus the organisation's on Team.
    const policy = await policyAt(gh, token, repo, mergeBase);
    let config = policy.config;
    let subtitle = policy.source;
    if (ent.orgPolicy) {
      const org = await policyAt(gh, token, `${e.repository.owner.login}/.github`, undefined);
      if (org.source !== null) {
        config = mergeOrgPolicy(org.config, config);
        subtitle = `${org.source} + ${policy.source ?? "no repository policy"}`;
      }
    }

    const summary = await runCheck(
      { files, before, after },
      {
        base: pr.base.ref, head: pr.head.ref,
        fetch: deps.fetch as unknown as FetchLike,
        offline: env.ONLINE === "false",
        now: deps.now(),
        config, configSource: subtitle,
        prBody: pr.body ?? null,
        // Each lookup is up to three requests; stay well inside a Worker's request budget.
        maxLookups: MAX_REGISTRY_LOOKUPS,
      },
    );
    const receipt = await createReceipt({
      summary, engineVersion: ENGINE_VERSION, mode: "pull_request", repository: repo, baseSha: mergeBase, headSha: pr.head.sha,
      policyText: policy.text, signingKey: ent.signedReceipts ? env.RECEIPT_SIGNING_KEY ?? null : null, createdAt: deps.now(),
    });
    if (ent.storedReceipts && env.ISOKLO_KV) {
      await env.ISOKLO_KV.put(`receipt:${repo}:${pr.head.sha}`, JSON.stringify(receipt), { expirationTtl: 60 * 60 * 24 * 400 });
    }

    const { conclusion, output } = checkRunOutput(summary, receipt, ent, coverage);
    await gh.completeCheckRun(token, repo, checkRunId, {
      status: "completed", conclusion, completed_at: deps.now().toISOString(), output,
      ...(conclusion === "action_required" ? { actions: [{ label: "Re-run Isoklo", description: "Check this pull request again", identifier: "rerun" }] } : {}),
    });

    // The verdict is on the check run now. The comment and alerts are courtesy: if GitHub refuses them (rate limits,
    // permissions), say so in the logs and keep the verdict instead of turning it into "could not run".
    const verdict = verdictOf(summary);
    const hasSomethingToSay = summary.results.some((r) => r.findings.some((f) => f.level !== "info"));
    const checkUrl = pr.html_url ? `${pr.html_url}/checks?check_run_id=${checkRunId}` : null;
    let comment: "created" | "updated" | "skipped" | "failed";
    try {
      comment = await gh.upsertComment(token, repo, pr.number, COMMENT_MARKER, commentBody(summary, receipt, ent, checkUrl), hasSomethingToSay || env.COMMENT_ON_PASS === "true");
    } catch (error) {
      comment = "failed";
      console.error(`isoklo: the summary comment on ${repo}#${pr.number} failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    if (ent.alerts && verdict === "blocked" && env.ISOKLO_KV) {
      try {
        const url = await env.ISOKLO_KV.get(`alerts:${e.repository.owner.id}`);
        if (url && /^https:\/\//.test(url)) await alert(url, summary, repo, pr.html_url ?? repo, deps.fetch);
      } catch {
        console.error(`isoklo: the alert for ${repo}#${pr.number} failed; the check result stands.`);
      }
    }
    return { status: "checked", verdict, checkRunId, comment, receiptDigest: receipt.integrity.digest };
  } catch (error) {
    const message = error instanceof ConfigError ? error.message : error instanceof Error ? error.message : String(error);
    await gh.completeCheckRun(token, repo, checkRunId, { status: "completed", conclusion: "failure", completed_at: deps.now().toISOString(), output: couldNotRunOutput(message) })
      .catch(() => undefined);
    return { status: "failed", checkRunId, error: message };
  }
}
