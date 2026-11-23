/**
 * Scope: a change should touch only what its task is about.
 *
 *   scope/out-of-scope             a file outside the declared scope (CLI --scope, the pull request body, or policy)
 *   scope/forbidden-path           a file matching the policy's deny list
 *   scope/too-many-files           more files than the policy's maxFiles
 *   scope/sensitive-zone           with no declared scope: auth, billing, infrastructure or secrets changed
 *                                  alongside unrelated work
 *   scope/lockfile-without-manifest  a lockfile changed with no manifest change
 *
 * Declared scope can only narrow. A pull request body is written by whoever opened it (often the agent), so it may
 * restrict a change further but never widens what the base branch's policy allows. Every source that declares globs
 * must match: CLI ∩ pull request body ∩ policy.
 */
import type { FileDiff } from "../../check/diff.js";
import { isTestPath } from "../../check/patterns.js";
import type { Evidence, Finding } from "../../check/types.js";
import type { ScopePolicy } from "../../engine/config.js";
import { matchesAny } from "../../engine/glob.js";
import { isDocPath, isLockfile, isManifest, pathOf, plural } from "../../engine/text.js";

export const DEFAULT_SENSITIVE: Record<string, string[]> = {
  auth: ["**/{auth,authn,authz,authentication,authorization,oauth,sso,saml,login,session,sessions,permissions,rbac,acl,iam}/**", "**/{auth,session,permissions,rbac,middleware}.{ts,tsx,js,jsx,mjs,cjs,py,go,rb,java,kt,cs,php,rs}"],
  billing: ["**/{billing,payment,payments,checkout,invoice,invoices,subscription,subscriptions,stripe,pricing,wallet}/**", "**/{billing,payments,checkout,stripe,pricing}.{ts,tsx,js,jsx,mjs,cjs,py,go,rb,java,kt,cs,php,rs}"],
  // Infrastructure as code only. Dockerfiles, compose files, platform configs and database migrations change with
  // ordinary feature work far too often to flag by default; add them under scope.sensitive if you want them watched.
  infrastructure: ["{infra,infrastructure,terraform,k8s,kubernetes,helm,charts,ansible,pulumi,cdk}/**", "**/*.tf", "**/*.tfvars"],
  secrets: ["**/.env", "**/.env.{local,production,prod,staging,development.local,production.local}", "**/secrets/**", "**/*.{pem,key,p12,pfx}"],
};

/** Read the scope a pull request body declares: `isoklo-scope: src/cart/**, test/cart/**` or `<!-- isoklo:scope … -->`. */
export function scopeFromBody(body: string | null | undefined): string[] {
  if (!body) return [];
  const out: string[] = [];
  for (const m of body.matchAll(/^\s*(?:[-*]\s*)?isoklo[-_ ]scope\s*:\s*(.+)$/gim)) out.push(...(m[1] ?? "").split(/[,\s]+/));
  for (const m of body.matchAll(/<!--\s*isoklo:scope\s+([\s\S]*?)-->/gi)) out.push(...(m[1] ?? "").split(/[,\s]+/));
  return [...new Set(out.map((g) => g.trim().replace(/^`|`$/g, "")).filter((g) => g !== ""))];
}

export interface ScopeInput {
  files: FileDiff[];
  policy: ScopePolicy;
  cli: string[];
  prBody: string | null | undefined;
}

const firstAdded = (f: FileDiff) => f.added[0] ?? { line: 1, text: "" };
const evidenceFor = (f: FileDiff): Evidence => ({ path: pathOf(f), line: firstAdded(f).line, text: f.status === "deleted" ? "(deleted)" : f.status === "renamed" ? `(renamed from ${f.oldPath})` : firstAdded(f).text.trim().slice(0, 160) });

/** Top two folders of a path: src/cart/total.ts → src/cart. Files at the root are their own area. */
const area = (path: string) => path.split("/").slice(0, Math.min(2, path.split("/").length - 1)).join("/") || path;

export function scopeFindings(input: ScopeInput): Finding[] {
  const out: Finding[] = [];
  const { files, policy } = input;
  const paths = (f: FileDiff) => [...new Set([f.newPath, f.oldPath].filter((p): p is string => p !== null))];

  // Declared scope: every source that speaks must allow the file.
  const sources: { name: string; globs: string[] }[] = [];
  if (input.cli.length > 0) sources.push({ name: "--scope", globs: input.cli });
  const body = scopeFromBody(input.prBody);
  if (body.length > 0) sources.push({ name: "the pull request's isoklo-scope", globs: body });
  if (policy.allow.length > 0) sources.push({ name: "policy scope.allow", globs: policy.allow });
  if (sources.length > 0) {
    const outside = files.filter((f) => paths(f).some((p) => sources.some((s) => !matchesAny(p, s.globs))));
    if (outside.length > 0) {
      const named = sources.map((s) => `${s.name} (${s.globs.join(", ")})`).join(" and ");
      out.push({
        rule: "scope", id: "out-of-scope", level: "blocked",
        message: `${plural(outside.length, "file")} changed outside the declared scope, ${named}: ${outside.slice(0, 6).map(pathOf).join(", ")}${outside.length > 6 ? ", …" : ""}.`,
        fix: "revert the unrelated edits and open a separate pull request for them, or widen the scope deliberately where you declared it.",
        evidence: outside.map(evidenceFor),
      });
    }
  }

  const denied = policy.deny.length === 0 ? [] : files.filter((f) => paths(f).some((p) => matchesAny(p, policy.deny)));
  if (denied.length > 0) {
    out.push({
      rule: "scope", id: "forbidden-path", level: "blocked",
      message: `${plural(denied.length, "file")} changed in an area the policy forbids (${policy.deny.join(", ")}): ${denied.slice(0, 6).map(pathOf).join(", ")}${denied.length > 6 ? ", …" : ""}.`,
      fix: "revert these files; changes there need a pull request written and approved for that purpose.",
      evidence: denied.map(evidenceFor),
    });
  }

  if (policy.maxFiles !== null && files.length > policy.maxFiles) {
    out.push({
      rule: "scope", id: "too-many-files", level: "blocked",
      message: `Change too large: ${files.length} files changed, and the policy allows at most ${policy.maxFiles}.`,
      fix: "split it into smaller pull requests that each do one thing.",
      evidence: files.slice(0, 10).map(evidenceFor),
    });
  }

  // Smart defaults, only when nothing declared a scope: a sensitive area changed as a side effect of other work.
  const zones = policy.sensitive ?? DEFAULT_SENSITIVE;
  if (sources.length === 0 && Object.keys(zones).length > 0) {
    const ordinary = (f: FileDiff) => !isTestPath(pathOf(f)) && !isDocPath(pathOf(f)) && !isLockfile(pathOf(f)) && !isManifest(pathOf(f));
    const zoneOf = (f: FileDiff) => Object.entries(zones).find(([, globs]) => paths(f).some((p) => matchesAny(p, globs)))?.[0];
    const inZone = new Map<string, FileDiff[]>();
    // Files the policy already forbids are reported once, as forbidden.
    for (const f of files.filter((x) => !denied.includes(x))) {
      const z = zoneOf(f);
      if (z !== undefined) inZone.set(z, [...(inZone.get(z) ?? []), f]);
    }
    for (const [zone, zoneFiles] of inZone) {
      const zoneAreas = new Set(zoneFiles.map((f) => area(pathOf(f))));
      const unrelated = files.filter((f) => ordinary(f) && zoneOf(f) === undefined && !zoneAreas.has(area(pathOf(f))));
      if (unrelated.length === 0) continue;
      out.push({
        rule: "scope", id: "sensitive-zone", level: "review",
        message: `Sensitive area (${zone}) changed alongside unrelated work: ${zoneFiles.slice(0, 4).map(pathOf).join(", ")}, in a change that also edits ${[...new Set(unrelated.map((f) => area(pathOf(f))))].slice(0, 3).join(", ")}.`,
        fix: `move the ${zone} changes into their own pull request, or declare the scope (isoklo-scope: … in the pull request body) so reviewers know it is intended.`,
        evidence: zoneFiles.map(evidenceFor),
      });
    }
  }

  // A lockfile edited with no manifest beside it.
  const lockfiles = files.filter((f) => f.status !== "deleted" && isLockfile(pathOf(f)) && !pathOf(f).endsWith(".lockb"));
  if (lockfiles.length > 0 && !files.some((f) => isManifest(pathOf(f)))) {
    out.push({
      rule: "scope", id: "lockfile-without-manifest", level: "review",
      message: `Lockfile changed without any manifest change: ${lockfiles.map(pathOf).join(", ")}. Versions or download sources can change with nothing visible in package.json.`,
      fix: "confirm the lockfile was regenerated by the package manager (an automated update, for example), not edited by hand.",
      evidence: lockfiles.map(evidenceFor),
    });
  }
  return out;
}
