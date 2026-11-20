/**
 * Ask the public registries whether a package exists and when it was first published.
 * Only public package names leave the machine. Every network problem becomes "unverified", never a pass or a block.
 * `fetch` is injected so tests can use a fake registry and never touch the internet.
 */
import type { Ecosystem } from "./manifests.js";

export type FetchLike = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal }) => Promise<{
  status: number;
  json(): Promise<unknown>;
}>;

export interface Lookup {
  ecosystem: Ecosystem;
  name: string;
  status: "exists" | "missing" | "unverified";
  /** ISO date of the first publish, when known. */
  createdAt?: string;
  weeklyDownloads?: number;
  /** For unverified: what went wrong, in plain words. */
  detail?: string;
  /** When this answer was obtained: registries change, so every answer is dated. */
  checkedAt: string;
}

export const TIMEOUT_MS = 8000;
/** Below this many weekly downloads, also fetch the npm package's creation date (the full document is small for small packages). */
export const LOW_DOWNLOADS = 1000;

const npmPath = (name: string) => (name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name));

async function get(f: FetchLike, url: string, accept = "application/json") {
  try {
    const res = await f(url, { headers: { accept, "user-agent": "isoklo (merge gate for AI coding agents)" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    return { res, error: null as string | null };
  } catch (e) {
    const timeout = e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
    return { res: null, error: timeout ? `no answer within ${TIMEOUT_MS / 1000} seconds` : "the registry could not be reached" };
  }
}

/** A registry answer that is not valid JSON is treated as no answer, never as a verdict. */
async function safeJson(res: { json(): Promise<unknown> }): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

const unverified = (ecosystem: Ecosystem, name: string, detail: string, checkedAt: string): Lookup =>
  ({ ecosystem, name, status: "unverified", detail, checkedAt });

const statusDetail = (s: number) => (s === 429 ? "the registry is rate-limiting requests (429)" : `the registry answered ${s}`);

export async function lookupNpm(name: string, f: FetchLike, now: Date): Promise<Lookup> {
  const checkedAt = now.toISOString();
  const base = `https://registry.npmjs.org/${npmPath(name)}`;
  // The abbreviated document is small even for huge packages: enough to know the package exists.
  const head = await get(f, base, "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8");
  if (head.res === null) return unverified("npm", name, head.error ?? "unknown error", checkedAt);
  if (head.res.status === 404) return { ecosystem: "npm", name, status: "missing", checkedAt };
  if (head.res.status !== 200) return unverified("npm", name, statusDetail(head.res.status), checkedAt);

  const result: Lookup = { ecosystem: "npm", name, status: "exists", checkedAt };
  const dl = await get(f, `https://api.npmjs.org/downloads/point/last-week/${name}`);
  if (dl.res?.status === 200) {
    const body = (await safeJson(dl.res)) as { downloads?: unknown } | null;
    if (typeof body?.downloads === "number") result.weeklyDownloads = body.downloads;
  }
  if (result.weeklyDownloads === undefined || result.weeklyDownloads < LOW_DOWNLOADS) {
    const full = await get(f, base);
    if (full.res?.status === 200) {
      const doc = (await safeJson(full.res)) as { time?: { created?: unknown } } | null;
      if (typeof doc?.time?.created === "string") result.createdAt = doc.time.created;
    }
  }
  return result;
}

export async function lookupPypi(name: string, f: FetchLike, now: Date): Promise<Lookup> {
  const checkedAt = now.toISOString();
  const r = await get(f, `https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (r.res === null) return unverified("pypi", name, r.error ?? "unknown error", checkedAt);
  if (r.res.status === 404) return { ecosystem: "pypi", name, status: "missing", checkedAt };
  if (r.res.status !== 200) return unverified("pypi", name, statusDetail(r.res.status), checkedAt);
  const doc = (await safeJson(r.res)) as { releases?: Record<string, { upload_time_iso_8601?: string }[]> } | null;
  if (doc === null) return unverified("pypi", name, "the registry's answer could not be read", checkedAt);
  const times = Object.values(doc.releases ?? {}).flat().map((x) => x.upload_time_iso_8601).filter((t): t is string => typeof t === "string");
  const result: Lookup = { ecosystem: "pypi", name, status: "exists", checkedAt };
  if (times.length > 0) result.createdAt = times.sort()[0] as string;
  return result;
}

/** Look up many packages, at most `limit` at a time, each name once. */
export async function lookupAll(
  wanted: { ecosystem: Ecosystem; name: string }[],
  f: FetchLike,
  now: Date,
  limit = 4,
): Promise<Map<string, Lookup>> {
  const key = (e: Ecosystem, n: string) => `${e}:${n}`;
  const unique = [...new Map(wanted.map((w) => [key(w.ecosystem, w.name), w])).values()];
  const out = new Map<string, Lookup>();
  let next = 0;
  const worker = async () => {
    while (next < unique.length) {
      const w = unique[next++] as { ecosystem: Ecosystem; name: string };
      const l = w.ecosystem === "npm" ? await lookupNpm(w.name, f, now) : await lookupPypi(w.name, f, now);
      out.set(key(w.ecosystem, w.name), l);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, unique.length) }, worker));
  return out;
}

export const lookupKey = (e: Ecosystem, n: string) => `${e}:${n}`;
