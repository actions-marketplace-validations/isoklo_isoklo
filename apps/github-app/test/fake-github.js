// A fake GitHub REST API and an in-memory KV for the app's tests and the local simulator. It checks the app's JWT
// signature with the app's public key, as GitHub does, and records every write so tests can assert on them.
import { createHmac, createVerify, generateKeyPairSync } from "node:crypto";

export function appKeys() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" }, // what GitHub hands out
  });
}

export class MemoryKV {
  constructor() { this.map = new Map(); }
  async get(key) { return this.map.has(key) ? this.map.get(key) : null; }
  async put(key, value) { this.map.set(key, String(value)); }
  async delete(key) { this.map.delete(key); }
  /** Like Cloudflare KV's list: keys by prefix, sorted, in pages. */
  async list({ prefix, limit = 1000, cursor }) {
    const all = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const keys = all.slice(start, start + limit).map((name) => ({ name }));
    const done = start + limit >= all.length;
    return { keys, list_complete: done, ...(done ? {} : { cursor: String(start + limit) }) };
  }
}

/** A patch with full context, as GitHub's API returns, built from a longest-common-subsequence line diff. */
export function patchOf(before, after) {
  const a = before === null ? [] : before.replace(/\n$/, "").split("\n");
  const b = after === null ? [] : after.replace(/\n$/, "").split("\n");
  if (before === "") a.length = 0;
  if (after === "") b.length = 0;
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const lines = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) { lines.push(` ${a[i]}`); i++; j++; }
    else if (j < b.length && (i >= a.length || dp[i][j + 1] >= dp[i + 1][j])) { lines.push(`+${b[j]}`); j++; }
    else { lines.push(`-${a[i]}`); i++; }
  }
  return `@@ -${a.length === 0 ? 0 : 1},${a.length} +${b.length === 0 ? 0 : 1},${b.length} @@\n${lines.join("\n")}`;
}

/**
 * repos: { "acme/shop": { private, defaultBranch, commits: { [sha]: { [path]: content } }, pulls: { [n]: { base, head, body } } } }
 */
export function fakeGitHub({
  publicKey, appId, repos, failFiles = false, registry = {},
  /** [{ re: RegExp on "METHOD /path", times: n, status, headers, body }]: answer the first n matching requests so. */
  failures = [],
  /** Files whose patch GitHub "leaves out", as for very large diffs. */
  omitPatch = [],
  /** Comments already on the pull request, from people or other bots. */
  seedComments = {},
}) {
  const writes = [];
  const comments = new Map(Object.entries(seedComments)); // repo#n -> [{ id, body, user }]
  let nextId = 1000;
  const json = (status, data, extra = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", ...extra } });

  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? "GET";
    const headers = Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (u.hostname === "registry.npmjs.org" || u.hostname === "api.npmjs.org" || u.hostname === "pypi.org") {
      const doc = registry[url];
      return doc ? json(200, doc) : json(404, {});
    }
    if (u.hostname === "hooks.example.dev" || u.hostname === "discord.com") { writes.push({ method, host: u.hostname, path: u.pathname, body }); return json(200, {}); }
    if (u.hostname !== "api.github.test") throw new Error(`unexpected request to ${url}`);
    const path = u.pathname;
    for (const f of failures) {
      if (f.times > 0 && f.re.test(`${method} ${path}`)) {
        f.times--;
        return json(f.status, f.body ?? { message: "fake failure" }, f.headers ?? {});
      }
    }

    // App JWT -> installation token. The signature is checked like GitHub checks it.
    let m = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(path);
    if (m) {
      const jwt = (headers.authorization ?? "").replace(/^Bearer /, "");
      const [h, p, s] = jwt.split(".");
      const ok = createVerify("RSA-SHA256").update(`${h}.${p}`).verify(publicKey, Buffer.from(s ?? "", "base64url"));
      const claims = JSON.parse(Buffer.from(p ?? "", "base64url").toString());
      if (!ok || claims.iss !== appId || claims.exp - claims.iat > 600) return json(401, { message: "A JSON web token could not be decoded" });
      return json(201, { token: `ghs_installation_${m[1]}`, expires_at: new Date(Date.now() + 3600_000).toISOString() });
    }
    if (!/^token ghs_installation_\d+$/.test(headers.authorization ?? "")) return json(401, { message: "Bad credentials" });

    m = /^\/repos\/([^/]+\/[^/]+)(\/.*)?$/.exec(path);
    if (!m) return json(404, { message: "Not Found" });
    const full = m[1];
    const rest = m[2] ?? "";
    const repo = repos[full];
    if (!repo) return json(404, { message: "Not Found" });

    if (rest === "") return json(200, { default_branch: repo.defaultBranch ?? "main", private: repo.private === true });
    // Access levels as GitHub reports them: admin, write (maintain), read (triage), none.
    if ((m = /^\/collaborators\/([^/]+)\/permission$/.exec(rest))) {
      return json(200, { permission: repo.collaborators?.[decodeURIComponent(m[1])] ?? "none" });
    }
    if ((m = /^\/issues\/comments\/(\d+)\/reactions$/.exec(rest)) && method === "POST") {
      writes.push({ method, path: rest, body });
      return json(201, { id: nextId++, content: body.content });
    }
    if ((m = /^\/pulls\/(\d+)$/.exec(rest))) {
      const pr = repo.pulls[m[1]];
      return pr ? json(200, prObject(full, Number(m[1]), pr)) : json(404, {});
    }
    if ((m = /^\/pulls\/(\d+)\/files$/.exec(rest))) {
      if (failFiles) return json(500, { message: "Server Error" });
      const pr = repo.pulls[m[1]];
      const page = Number(u.searchParams.get("page") ?? "1");
      if (page > 1) return json(200, []);
      const base = repo.commits[pr.base];
      const head = repo.commits[pr.head];
      const files = [...new Set([...Object.keys(base), ...Object.keys(head)])].sort().filter((p) => base[p] !== head[p]).map((p) => {
        const status = base[p] === undefined ? "added" : head[p] === undefined ? "removed" : "modified";
        return omitPatch.includes(p) ? { filename: p, status } : { filename: p, status, patch: patchOf(base[p] ?? null, head[p] ?? null) };
      });
      return json(200, files);
    }
    if ((m = /^\/commits\/([^/]+)\/pulls$/.exec(rest))) {
      const numbers = Object.entries(repo.pulls).filter(([, pr]) => pr.head === m[1]).map(([n]) => ({ number: Number(n), state: "open" }));
      return json(200, numbers);
    }
    if ((m = /^\/compare\/([^.]+)\.\.\.(.+)$/.exec(rest))) return json(200, { merge_base_commit: { sha: m[1] } });
    if ((m = /^\/contents\/(.+)$/.exec(rest))) {
      // No ref means the default branch, keyed by its name in `commits`.
      const ref = u.searchParams.get("ref") ?? repo.defaultBranch ?? "main";
      const file = repo.commits[ref]?.[m[1].split("/").map(decodeURIComponent).join("/")];
      return file === undefined ? json(404, { message: "Not Found" }) : new Response(file, { status: 200 });
    }
    if (rest === "/check-runs" && method === "POST") {
      const id = nextId++;
      writes.push({ method, path: rest, id, body });
      return json(201, { id });
    }
    if ((m = /^\/check-runs\/(\d+)$/.exec(rest)) && method === "PATCH") {
      writes.push({ method, path: rest, id: Number(m[1]), body });
      return json(200, { id: Number(m[1]) });
    }
    if ((m = /^\/issues\/(\d+)\/comments$/.exec(rest))) {
      const key = `${full}#${m[1]}`;
      if (method === "GET") return json(200, comments.get(key) ?? []);
      const c = { id: nextId++, body: body.body, user: { type: "Bot", login: "isoklo[bot]" }, performed_via_github_app: { id: Number(appId) } };
      comments.set(key, [...(comments.get(key) ?? []), c]);
      writes.push({ method, path: rest, body });
      return json(201, c);
    }
    if ((m = /^\/issues\/comments\/(\d+)$/.exec(rest)) && method === "PATCH") {
      const target = [...comments.values()].flat().find((c) => c.id === Number(m[1]));
      // Like GitHub: an app can only edit its own comments.
      if (target?.performed_via_github_app?.id !== Number(appId)) return json(403, { message: "Resource not accessible by integration" });
      target.body = body.body;
      writes.push({ method, path: rest, body });
      return json(200, {});
    }
    return json(404, { message: `no fake route for ${method} ${rest}` });
  };
  return { fetch, writes, comments };
}

function prObject(full, number, pr) {
  return {
    number, draft: pr.draft === true, body: pr.body ?? null, html_url: `https://github.com/${full}/pull/${number}`,
    user: { login: pr.author ?? "agent-dev", type: "User" },
    base: { sha: pr.base, ref: "main" }, head: { sha: pr.head, ref: pr.headRef ?? "agent/change" },
    ...(pr.changedFiles !== undefined ? { changed_files: pr.changedFiles } : {}),
  };
}

export function pullRequestEvent({ action = "opened", full = "acme/shop", ownerId = 4242, isPrivate = false, number = 7, pr }) {
  return {
    action,
    installation: { id: 99 },
    repository: { full_name: full, private: isPrivate, owner: { id: ownerId, login: full.split("/")[0] } },
    pull_request: prObject(full, number, pr),
  };
}

/** A comment on a pull request, as GitHub's issue_comment event carries it. */
export function issueCommentEvent({ full = "acme/shop", ownerId = 4242, isPrivate = false, number = 7, body, login = "maintainer", type = "User", id = 5555, author = "agent-dev" }) {
  return {
    action: "created",
    installation: { id: 99 },
    repository: { full_name: full, private: isPrivate, owner: { id: ownerId, login: full.split("/")[0] } },
    issue: { number, pull_request: { url: `https://api.github.test/repos/${full}/pulls/${number}` }, user: { login: author } },
    comment: { id, body, user: { login, type } },
  };
}

/** A signed GitHub webhook request, as GitHub sends it. */
export function webhook(secret, event, payload, delivery = crypto.randomUUID()) {
  const body = JSON.stringify(payload);
  const sig = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  return new Request("https://app.isoklo.test/webhooks/github", {
    method: "POST",
    headers: { "content-type": "application/json", "x-github-event": event, "x-github-delivery": delivery, "x-hub-signature-256": sig },
    body,
  });
}

export function stripeRequest(secret, event, nowSeconds) {
  const body = JSON.stringify(event);
  const sig = createHmac("sha256", secret).update(`${nowSeconds}.${body}`).digest("hex");
  return new Request("https://app.isoklo.test/webhooks/stripe", { method: "POST", headers: { "stripe-signature": `t=${nowSeconds},v1=${sig}` }, body });
}
