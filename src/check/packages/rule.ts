/**
 * Rule 2: unknown or brand-new packages. Takes the manifests a change touched (before and after), finds the packages
 * it adds, and asks the public registries about them.
 *   - Not on the public registry: blocked (likely a hallucinated name; attackers register these: "slopsquatting").
 *     Exception: a scoped npm name or a PyPI manifest with a private index may be private, so that is "review".
 *   - First published under NEW_PACKAGE_DAYS ago: review.
 *   - Registry unreachable or offline: review or info, never a silent pass and never a false block.
 */
import { addedPackages, manifestKind, readManifest, type DeclaredPackage } from "./manifests.js";
import { LOW_DOWNLOADS, lookupAll, lookupKey, type FetchLike, type Lookup } from "./registry.js";
import { typosquatOf } from "../../rules/deps/typosquat.js";
import type { Finding, RuleResult } from "../types.js";

export const NEW_PACKAGE_DAYS = 30;

export interface ManifestChange {
  path: string;
  /** Content before the change (null if the manifest is new). */
  before: string | null;
  /** Content after the change. */
  after: string;
}

export interface PackageRuleOptions {
  fetch: FetchLike;
  offline: boolean;
  now: Date;
  /** npm scopes that .npmrc sends to a private registry, e.g. "@acme". */
  privateNpmScopes: Set<string>;
  /** .npmrc replaces the default registry entirely. */
  customNpmRegistry: boolean;
  /**
   * Most packages to look up in one change (default 100). Beyond it the rest are reported as not verified (review):
   * never silently passed. The GitHub App sets a lower limit to stay inside a Worker's request budget.
   */
  maxLookups?: number;
}

/** Scopes and registries configured in an .npmrc file. */
export function readNpmrc(text: string | null): { scopes: Set<string>; customRegistry: boolean } {
  const scopes = new Set<string>();
  let customRegistry = false;
  for (const raw of (text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    const scoped = /^(@[^:\s]+):registry\s*=/.exec(line);
    if (scoped?.[1]) scopes.add(scoped[1].toLowerCase());
    else if (/^registry\s*=/.test(line) && !/registry\.npmjs\.org/.test(line)) customRegistry = true;
  }
  return { scopes, customRegistry };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const where = (e: string) => (e === "npm" ? "npm" : "PyPI");

export async function unknownPackages(changes: ManifestChange[], opts: PackageRuleOptions): Promise<RuleResult> {
  // 1. Which packages does this change add, and where are they declared?
  const added: (DeclaredPackage & { path: string; maybePrivate: boolean; skipped: boolean })[] = [];
  let unreadable = 0;
  for (const c of changes) {
    const kind = manifestKind(c.path);
    if (kind === null) continue;
    const after = readManifest(kind, c.after);
    if (after === null) { unreadable++; continue; }
    const before = c.before === null ? null : readManifest(kind, c.before);
    for (const p of addedPackages(before, after)) {
      const scope = p.ecosystem === "npm" && p.name.startsWith("@") ? (p.name.split("/")[0] ?? "").toLowerCase() : "";
      const skipped = scope !== "" && opts.privateNpmScopes.has(scope);
      const maybePrivate = p.ecosystem === "npm" ? scope !== "" || opts.customNpmRegistry : after.privateIndex;
      added.push({ ...p, path: c.path, maybePrivate, skipped });
    }
  }

  const findings: Finding[] = [];
  const passes: string[] = [];
  const toCheck = added.filter((p) => !p.skipped);
  const skippedCount = added.length - toCheck.length;

  if (unreadable > 0) {
    findings.push({
      rule: "unknown-packages", id: "manifest-unreadable", level: "review",
      message: `${plural(unreadable, "manifest")} could not be parsed, so ${unreadable === 1 ? "its" : "their"} new packages were not checked.`,
      fix: "fix the syntax (for package.json, it must be valid JSON) and run the check again.",
      evidence: changes.filter((c) => { const k = manifestKind(c.path); return k !== null && readManifest(k, c.after) === null; })
        .map((c) => ({ path: c.path, line: 1, text: "" })),
    });
  }

  if (added.length === 0) {
    passes.push("No new packages.");
    return { rule: "unknown-packages", findings, passes, stats: { packagesAdded: 0 } };
  }

  // v2: names one typo away from a popular package. Works offline, so it runs before any lookup.
  const typosquats: Finding[] = [];
  for (const p of toCheck) {
    const imitates = typosquatOf(p.ecosystem, p.name);
    if (imitates === null) continue;
    typosquats.push({
      rule: "unknown-packages", id: "typosquat", level: "review", severity: "high",
      message: `Possible typo-squat: ${p.name} is one character away from the popular ${where(p.ecosystem)} package ${imitates}.`,
      fix: `if you meant ${imitates}, fix the name; if ${p.name} is intended, confirm who publishes it.`,
      evidence: [{ path: p.path, line: p.line, text: p.text }],
    });
  }

  // 2. Offline: say plainly that nothing was verified.
  if (opts.offline) {
    findings.push({
      rule: "unknown-packages", id: "packages-not-verified", level: "info",
      message: `${plural(toCheck.length, "new package")} not checked against the registries (offline).`,
      fix: "run without --offline to confirm they exist.",
      evidence: toCheck.map((p) => ({ path: p.path, line: p.line, text: p.text })),
    });
    findings.push(...typosquats);
    return { rule: "unknown-packages", findings, passes, stats: { packagesAdded: added.length } };
  }

  // 3. Ask the registries (public names only), up to the lookup budget.
  const budget = Math.max(0, opts.maxLookups ?? 100);
  const looked = toCheck.slice(0, budget);
  const overflow = toCheck.slice(budget);
  const answers = await lookupAll(
    looked.map((p) => (p.exactVersion === undefined ? { ecosystem: p.ecosystem, name: p.name } : { ecosystem: p.ecosystem, name: p.name, exactVersion: p.exactVersion })),
    opts.fetch, opts.now,
  );
  if (overflow.length > 0) {
    findings.push({
      rule: "unknown-packages", id: "package-unverified", level: "review",
      message: `${plural(overflow.length, "new package")} not looked up: this change adds more than ${budget}, the most Isoklo checks against the registries in one run.`,
      fix: "split the change, or run `npx isoklo check` locally, where the limit is higher, to verify the rest.",
      evidence: overflow.map((p) => ({ path: p.path, line: p.line, text: p.text })),
    });
  }
  const ageDays = (l: Lookup) =>
    l.createdAt === undefined ? null : Math.floor((opts.now.getTime() - Date.parse(l.createdAt)) / 86_400_000);

  let fine = 0;
  for (const p of toCheck) {
    const l = answers.get(lookupKey(p.ecosystem, p.name));
    const ev = [{ path: p.path, line: p.line, text: p.text }];
    if (l === undefined) continue;
    if (l.status === "missing") {
      findings.push(p.maybePrivate
        ? {
          rule: "unknown-packages", id: "package-not-found-maybe-private", level: "review",
          message: `Package not found on public ${where(p.ecosystem)}: ${p.name}. It may be private.`,
          fix: p.ecosystem === "npm"
            ? `if ${p.name.split("/")[0]} is a private scope, declare its registry in .npmrc; otherwise check the name.`
            : "if it comes from a private index, nothing to do; otherwise check the name.",
          evidence: ev,
        }
        : {
          rule: "unknown-packages", id: "package-does-not-exist", level: "blocked",
          message: `Package does not exist: ${p.name} is not on ${where(p.ecosystem)} (checked ${l.checkedAt.slice(0, 16).replace("T", " ")} UTC).`,
          fix: "check the name; an agent may have invented it, and someone could register it with malicious code.",
          evidence: ev,
        });
      continue;
    }
    if (l.status === "unverified") {
      findings.push({
        rule: "unknown-packages", id: "package-unverified", level: "review",
        message: `Could not verify ${p.name} on ${where(p.ecosystem)}: ${l.detail}.`,
        fix: "run the check again when the registry is reachable.",
        evidence: ev,
      });
      continue;
    }
    const days = ageDays(l);
    const brandNew = days !== null && days < NEW_PACKAGE_DAYS;
    const fewDownloads = l.weeklyDownloads !== undefined && l.weeklyDownloads < LOW_DOWNLOADS;
    // v2: install scripts run with full access on npm install; on a new or little-used package that is malware's shape.
    if (l.hasInstallScript === true) {
      const risky = brandNew || fewDownloads;
      findings.push({
        rule: "unknown-packages", id: "install-script", level: risky ? "blocked" : "review", severity: risky ? "critical" : "medium",
        message: `New package runs code on install: ${p.name}${l.version ? `@${l.version}` : ""} has a preinstall, install or postinstall script` +
          (risky ? `, and it is ${[brandNew ? `${days === 0 ? "published today" : `${plural(days ?? 0, "day")} old`}` : "", fewDownloads ? `downloaded ${plural(l.weeklyDownloads ?? 0, "time")} last week` : ""].filter(Boolean).join(" and ")}.` : "."),
        fix: risky
          ? "do not install it until someone has read its install script; prefer an established package, or install with --ignore-scripts."
          : "read what the script does; established packages often build native code this way.",
        evidence: ev,
      });
    }
    if (brandNew) {
      findings.push({
        rule: "unknown-packages", id: "package-brand-new", level: "review",
        message: `Brand-new package: ${p.name} was first published on ${where(p.ecosystem)} ${days === 0 ? "today" : `${plural(days, "day")} ago`}` +
          `${l.weeklyDownloads !== undefined ? `, with ${plural(l.weeklyDownloads, "download")} last week` : ""}.`,
        fix: "confirm it is the package you meant and who publishes it before merging.",
        evidence: ev,
      });
      continue;
    }
    // The package exists, but its age could not be read and nothing says it is widely used: do not claim it is old.
    if (days === null && (l.weeklyDownloads === undefined || l.weeklyDownloads < LOW_DOWNLOADS)) {
      findings.push({
        rule: "unknown-packages", id: "package-unverified", level: "review",
        message: `Could not confirm when ${p.name} was first published on ${where(p.ecosystem)}${l.weeklyDownloads !== undefined ? `, and it was downloaded ${plural(l.weeklyDownloads, "time")} last week` : ""}.`,
        fix: "check the package's page and publisher before merging, or run the check again.",
        evidence: ev,
      });
      continue;
    }
    if (l.hasInstallScript !== true) fine++;
  }
  findings.push(...typosquats);

  if (fine > 0) passes.push(`${plural(fine, "new package")} found on ${[...new Set(toCheck.map((p) => where(p.ecosystem)))].join(" and ")}, older than ${NEW_PACKAGE_DAYS} days.`);
  if (skippedCount > 0) passes.push(`${plural(skippedCount, "package")} in private scopes from .npmrc, not sent to the public registry.`);
  return { rule: "unknown-packages", findings, passes, stats: { packagesAdded: added.length } };
}
