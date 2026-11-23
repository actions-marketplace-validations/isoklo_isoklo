/**
 * A small GitHub REST client for exactly what the app needs: installation tokens, pull request files, file contents,
 * check runs and one issue comment. fetch is injected, so tests run against a fake GitHub with no network.
 */
import type { PullFile } from "isoklo/engine";
import { appJwt } from "./crypto.js";
import type { Env } from "./env.js";

export type Fetch = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<Response>;

export class GitHubError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const USER_AGENT = "isoklo-github-app";
const MAX_FILE_PAGES = 30; // GitHub lists at most 3,000 files for a pull request
const MAX_CONTENT_BYTES = 1024 * 1024;

export interface CheckRunOutput {
  title: string;
  summary: string;
  text?: string;
  annotations?: Annotation[];
}

export interface Annotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  title: string;
  message: string;
  raw_details?: string;
}

export class GitHub {
  private readonly api: string;
  private tokens = new Map<number, { token: string; expires: number }>();

  constructor(private readonly env: Env, private readonly fetchImpl: Fetch, private readonly now: () => number = () => Date.now()) {
    this.api = (env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");
  }

  private async call<T>(auth: string, method: string, path: string, body?: unknown, accept = "application/vnd.github+json"): Promise<{ status: number; data: T; text: string }> {
    let res: Response;
    let text: string;
    for (let attempt = 0; ; attempt++) {
      res = await this.fetchImpl(`${this.api}${path}`, {
        method,
        headers: {
          accept,
          authorization: auth,
          "user-agent": USER_AGENT,
          "x-github-api-version": "2022-11-28",
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      text = await res.text();
      // Primary (403 + x-ratelimit-remaining: 0) and secondary (429, or 403 "secondary rate limit") limits: wait once
      // if GitHub asks for only a few seconds, otherwise stop with a clear message. The check then fails closed.
      const limited = res.status === 429 || (res.status === 403 && (res.headers.get("x-ratelimit-remaining") === "0" || /rate limit/i.test(text)));
      if (!limited) break;
      const wait = Number(res.headers.get("retry-after") ?? "60");
      if (attempt === 0 && Number.isFinite(wait) && wait <= 5) {
        await new Promise((resolve) => setTimeout(resolve, Math.max(0, wait) * 1000));
        continue;
      }
      throw new GitHubError(res.status, `GitHub's API rate limit was reached (${method} ${path.split("?")[0]}). Nothing was approved; re-run the check in a few minutes.`);
    }
    if (res.status >= 400 && res.status !== 404) {
      let detail = text.slice(0, 300);
      try {
        detail = (JSON.parse(text) as { message?: string }).message ?? detail;
      } catch {
        // keep the raw text
      }
      throw new GitHubError(res.status, `GitHub answered ${res.status} to ${method} ${path}: ${detail}`);
    }
    let data: T = null as T;
    if (accept.includes("json") && text !== "") {
      try {
        data = JSON.parse(text) as T;
      } catch {
        data = null as T;
      }
    }
    return { status: res.status, data, text };
  }

  async installationToken(installationId: number): Promise<string> {
    const cached = this.tokens.get(installationId);
    if (cached && cached.expires - 60_000 > this.now()) return cached.token;
    const jwt = await appJwt(this.env.GITHUB_APP_ID, this.env.GITHUB_APP_PRIVATE_KEY, Math.floor(this.now() / 1000));
    const r = await this.call<{ token: string; expires_at: string }>(`Bearer ${jwt}`, "POST", `/app/installations/${installationId}/access_tokens`);
    if (r.status === 404 || !r.data?.token) throw new GitHubError(r.status, `no installation ${installationId} for this app.`);
    this.tokens.set(installationId, { token: r.data.token, expires: Date.parse(r.data.expires_at) || this.now() + 3_000_000 });
    return r.data.token;
  }

  private auth = (token: string) => `token ${token}`;

  async pullRequest(token: string, repo: string, number: number): Promise<PullRequest | null> {
    const r = await this.call<PullRequest>(this.auth(token), "GET", `/repos/${repo}/pulls/${number}`);
    return r.status === 404 ? null : r.data;
  }

  async pullFiles(token: string, repo: string, number: number): Promise<PullFile[]> {
    const out: PullFile[] = [];
    for (let page = 1; page <= MAX_FILE_PAGES; page++) {
      const r = await this.call<PullFile[]>(this.auth(token), "GET", `/repos/${repo}/pulls/${number}/files?per_page=100&page=${page}`);
      const batch = r.data ?? [];
      out.push(...batch);
      if (batch.length < 100) break;
    }
    return out;
  }

  /** The commit where the pull request left its base: the "before" side Isoklo compares against. */
  async mergeBase(token: string, repo: string, base: string, head: string): Promise<string> {
    const r = await this.call<{ merge_base_commit?: { sha?: string } }>(this.auth(token), "GET", `/repos/${repo}/compare/${base}...${head}`);
    return r.data?.merge_base_commit?.sha ?? base;
  }

  /** A file's text at a commit, or null when it does not exist there (or is a folder, or too large to judge). */
  async content(token: string, repo: string, path: string, ref?: string): Promise<string | null> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const query = ref === undefined ? "" : `?ref=${encodeURIComponent(ref)}`;
    const r = await this.call<unknown>(this.auth(token), "GET", `/repos/${repo}/contents/${encoded}${query}`, undefined, "application/vnd.github.raw");
    if (r.status === 404 || r.text.length > MAX_CONTENT_BYTES) return null;
    return r.text;
  }

  async defaultBranch(token: string, repo: string): Promise<string | null> {
    const r = await this.call<{ default_branch?: string }>(this.auth(token), "GET", `/repos/${repo}`);
    return r.status === 404 ? null : r.data?.default_branch ?? null;
  }

  async createCheckRun(token: string, repo: string, body: Record<string, unknown>): Promise<number> {
    const r = await this.call<{ id: number }>(this.auth(token), "POST", `/repos/${repo}/check-runs`, body);
    return r.data.id;
  }

  /** Update a check run; GitHub takes at most 50 annotations per request, so the rest go in follow-up updates. */
  async completeCheckRun(token: string, repo: string, id: number, body: Record<string, unknown> & { output: CheckRunOutput }): Promise<void> {
    const all = body.output.annotations ?? [];
    await this.call(this.auth(token), "PATCH", `/repos/${repo}/check-runs/${id}`, { ...body, output: { ...body.output, annotations: all.slice(0, 50) } });
    for (let i = 50; i < all.length; i += 50) {
      await this.call(this.auth(token), "PATCH", `/repos/${repo}/check-runs/${id}`, { output: { title: body.output.title, summary: body.output.summary, annotations: all.slice(i, i + 50) } });
    }
  }

  /**
   * A person's access to a repository, as GitHub reports it: "admin", "write" (which includes maintain), "read" (which
   * includes triage) or "none". Waivers need write or admin.
   */
  async collaboratorPermission(token: string, repo: string, login: string): Promise<"admin" | "write" | "read" | "none"> {
    const r = await this.call<{ permission?: string }>(this.auth(token), "GET", `/repos/${repo}/collaborators/${encodeURIComponent(login)}/permission`);
    const p = r.status === 404 ? "none" : r.data?.permission;
    return p === "admin" || p === "write" || p === "read" ? p : "none";
  }

  /** A plain reply on a pull request (waiver answers); the summary comment uses upsertComment. */
  async createComment(token: string, repo: string, number: number, bodyText: string): Promise<void> {
    await this.call(this.auth(token), "POST", `/repos/${repo}/issues/${number}/comments`, { body: bodyText });
  }

  /** React to a comment: 👍 when a waiver is recorded. Best effort. */
  async addReaction(token: string, repo: string, commentId: number, content: "+1" | "-1" | "eyes"): Promise<void> {
    await this.call(this.auth(token), "POST", `/repos/${repo}/issues/comments/${commentId}/reactions`, { content });
  }

  /** Pull requests a commit belongs to: re-runs on fork pull requests carry no pull_requests list, only the head SHA. */
  async pullsForCommit(token: string, repo: string, sha: string): Promise<number[]> {
    const r = await this.call<{ number: number; state?: string }[]>(this.auth(token), "GET", `/repos/${repo}/commits/${encodeURIComponent(sha)}/pulls`);
    return (r.data ?? []).filter((p) => p.state === undefined || p.state === "open").map((p) => p.number);
  }

  /**
   * Create the app's one summary comment on a pull request, or update it in place: never a second comment. Only a
   * comment this app wrote counts (its app id, or its bot login): anyone else, people or other bots, can paste the
   * marker into a comment, and editing theirs would fail and could take the check down with it.
   */
  async upsertComment(token: string, repo: string, number: number, marker: string, bodyText: string, createIfMissing: boolean): Promise<"created" | "updated" | "skipped"> {
    const appId = Number(this.env.GITHUB_APP_ID);
    const botLogin = `${(this.env.APP_SLUG ?? "isoklo").toLowerCase()}[bot]`;
    type Comment = { id: number; body?: string; user?: { type?: string; login?: string }; performed_via_github_app?: { id?: number } | null };
    const ours = (c: Comment) =>
      c.user?.type === "Bot" && (c.performed_via_github_app?.id === appId || (c.user.login ?? "").toLowerCase() === botLogin);
    let existing: Comment | undefined;
    for (let page = 1; page <= 10 && existing === undefined; page++) {
      const r = await this.call<Comment[]>(this.auth(token), "GET", `/repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`);
      const batch = r.data ?? [];
      existing = batch.find((c) => (c.body ?? "").startsWith(marker) && ours(c));
      if (batch.length < 100) break;
    }
    if (existing !== undefined) {
      await this.call(this.auth(token), "PATCH", `/repos/${repo}/issues/comments/${existing.id}`, { body: bodyText });
      return "updated";
    }
    if (!createIfMissing) return "skipped";
    await this.call(this.auth(token), "POST", `/repos/${repo}/issues/${number}/comments`, { body: bodyText });
    return "created";
  }
}

export interface PullRequest {
  number: number;
  draft?: boolean;
  /** Total files GitHub says the pull request changes (the files API lists at most 3,000). */
  changed_files?: number;
  body?: string | null;
  html_url?: string;
  /** Who opened it. An author may not waive their own pull request's findings unless the policy allows it. */
  user?: { login: string; type?: string };
  base: { sha: string; ref: string };
  head: { sha: string; ref: string };
}
