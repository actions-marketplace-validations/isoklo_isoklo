/**
 * Check mode: judge a change. The same function runs behind `isoklo check` (git), the GitHub Action, and the GitHub App
 * (GitHub's API): each supplies the parsed diff and a way to read a file before and after the change. Nothing here
 * touches the file system, git or Node-only APIs.
 */
import type { FileDiff } from "../check/diff.js";
import { weakenedTests } from "../check/weakened-tests.js";
import { manifestKind } from "../check/packages/manifests.js";
import { readNpmrc, unknownPackages, type ManifestChange } from "../check/packages/rule.js";
import type { FetchLike } from "../check/packages/registry.js";
import { classify } from "../check/config/knowledge.js";
import { agentConfig, type ConfigChange } from "../check/config/rule.js";
import type { CheckSummary } from "../check/report.js";
import type { Finding, RuleResult, Suite } from "../check/types.js";
import { approvalsDisabled, hiddenUnicode, promptInjection } from "../rules/agent/content.js";
import type { FileChange } from "../rules/change.js";
import type { ContentUnit } from "../rules/content.js";
import { isTextLockfile, lifecycleScripts, lockfileSources, registryChanged } from "../rules/deps/files.js";
import { mcpServerFindings } from "../rules/mcp/servers.js";
import { isActionFile, isMcpFile, isWorkflow } from "../rules/paths.js";
import { scopeFindings } from "../rules/scope/scope.js";
import { envExfiltration, envFileCommitted, exfilEndpoint, remoteCodeExec, secretLeaked } from "../rules/sec/content.js";
import { workflowFindings } from "../rules/sec/workflows.js";
import { tamperConfigs, tamperWants } from "../rules/tamper/configs.js";
import { suppressions } from "../rules/tamper/suppressions.js";
import type { IsokloConfig } from "./config.js";
import { finalize } from "./finalize.js";
import { matchesAny } from "./glob.js";
import { CONFIG_CHANGE_RULES, canonicalId, rulesFor } from "./registry.js";
import { basename, movedLines, pathOf } from "./text.js";

export interface ChangeSource {
  files: FileDiff[];
  /** A file's content before the change (at the merge base), or null if it did not exist. */
  before(path: string): Promise<string | null>;
  /** A file's content after the change (at head), or null if it does not exist. */
  after(path: string): Promise<string | null>;
}

export interface CheckOptions {
  /** Labels for the report: the base and head refs as the user named them. */
  base: string;
  head: string;
  fetch: FetchLike;
  offline: boolean;
  now: Date;
  /** Policy, read from the BASE commit by the caller. */
  config: IsokloConfig;
  configSource?: string | null;
  /** A maintainer's reason to accept deliberate configuration changes. */
  allowConfigReason?: string;
  /** Scope globs declared on the command line or by the App's caller. */
  scope?: string[];
  /** The pull request description, for an isoklo-scope declaration. */
  prBody?: string | null;
  /** Most new packages to look up on the registries in this run (default 100; the GitHub App uses fewer). */
  maxLookups?: number;
}

const SUITES: readonly Suite[] = ["agent", "mcp", "tamper", "deps", "sec", "scope"];

const PASSES: Record<Suite, string> = {
  agent: "No hidden Unicode, prompt-override text or disabled agent approvals added.",
  mcp: "No unpinned, secret-bearing or over-reaching MCP servers added.",
  tamper: "No checks suppressed, guardrail configs weakened or coverage lowered.",
  deps: "No untrusted lockfile sources, install-time scripts or registry changes.",
  sec: "No secrets, remote code execution, exfiltration or unsafe workflow triggers added.",
  scope: "No out-of-scope edits or sensitive areas changed alongside unrelated work.",
};

/** One reader per side, so a file needed by several rules is fetched once (this matters for the GitHub API). */
function cached(read: (path: string) => Promise<string | null>) {
  const memo = new Map<string, Promise<string | null>>();
  return (path: string) => {
    let p = memo.get(path);
    if (p === undefined) { p = read(path); memo.set(path, p); }
    return p;
  };
}

export async function runCheck(src: ChangeSource, o: CheckOptions): Promise<CheckSummary> {
  const before = cached((p) => src.before(p));
  const after = cached((p) => src.after(p));
  const files = src.files;

  // ---------------------------------------------------------------- v1 rules, unchanged
  const manifests: ManifestChange[] = [];
  for (const f of files) {
    if (f.status === "deleted" || f.newPath === null || manifestKind(f.newPath) === null) continue;
    const a = await after(f.newPath);
    if (a === null) continue;
    manifests.push({ path: f.newPath, before: f.status === "added" ? null : await before(f.oldPath ?? f.newPath), after: a });
  }
  const configs: ConfigChange[] = [];
  for (const f of files) {
    const path = f.newPath ?? f.oldPath ?? "";
    const oldPath = f.oldPath ?? path;
    if (classify(f.status === "deleted" ? oldPath : path) === null) continue;
    configs.push({
      path, oldPath, status: f.status, diff: f,
      before: f.status === "added" ? null : await before(oldPath),
      after: f.status === "deleted" ? null : await after(path),
    });
  }
  const npmrc = readNpmrc(await after(".npmrc"));
  const packages = await unknownPackages(manifests, {
    fetch: o.fetch,
    offline: o.offline || !o.config.online,
    now: o.now,
    privateNpmScopes: npmrc.scopes,
    customNpmRegistry: npmrc.customRegistry,
    ...(o.maxLookups === undefined ? {} : { maxLookups: o.maxLookups }),
  });
  const v1: RuleResult[] = [
    weakenedTests(files),
    packages,
    agentConfig(configs, o.allowConfigReason === undefined ? {} : { allowReason: o.allowConfigReason }),
  ];

  // ---------------------------------------------------------------- v2 rules
  const found: Finding[] = [];
  const moved = movedLines(files);
  const ignored = (path: string) => o.config.ignorePaths.length > 0 && matchesAny(path, o.config.ignorePaths);

  for (const f of files) {
    if (f.binary || f.status === "deleted" || f.newPath === null) continue;
    const path = f.newPath;
    const lines = f.added.filter((l) => !moved.has(`${path}:${l.line}`)).map((l) => ({ line: l.line, text: l.text }));
    const unit: ContentUnit = { path, lines, mode: "check", status: f.status };
    if (lines.length > 0 && !ignored(path)) {
      for (const rule of [hiddenUnicode, promptInjection, approvalsDisabled, secretLeaked, remoteCodeExec, envExfiltration, exfilEndpoint]) {
        const r = rule(unit);
        if (r) found.push(r);
      }
      found.push(...suppressions(unit));
    }
    // .env files: every added assignment counts, moved or not.
    const env = envFileCommitted({ ...unit, lines: f.added.map((l) => ({ line: l.line, text: l.text })) });
    if (env) found.push(env);
    if (isTextLockfile(path)) {
      const r = lockfileSources({ ...unit, lines: f.added.map((l) => ({ line: l.line, text: l.text })) }, o.config.trustedRegistries);
      if (r) found.push(r);
    }
    const reg = registryChanged({ ...unit, lines: f.added.map((l) => ({ line: l.line, text: l.text })) });
    if (reg) found.push(reg);
  }

  // Rules that compare whole files before and after.
  const changes: FileChange[] = [];
  for (const f of files) {
    const path = f.newPath ?? f.oldPath ?? "";
    const oldPath = f.oldPath ?? path;
    const p = f.status === "deleted" ? oldPath : path;
    if (!(tamperWants(p) || isMcpFile(p) || isWorkflow(p) || isActionFile(p) || basename(p) === "package.json")) continue;
    changes.push({
      path, oldPath, status: f.status, diff: f,
      before: f.status === "added" ? null : await before(oldPath),
      after: f.status === "deleted" ? null : await after(path),
    });
  }
  found.push(...tamperConfigs(changes));
  for (const c of changes) {
    const lc = lifecycleScripts(c);
    if (lc) found.push(lc);
    if (c.after === null) continue;
    if (isMcpFile(c.path)) found.push(...mcpServerFindings(c.path, c.after, c.before, "check", o.config.trustedMcpPackages));
    if (isWorkflow(c.path) || isActionFile(c.path)) {
      found.push(...workflowFindings(c.path, c.after, new Set(c.diff.added.map((l) => l.line)), "check"));
    }
  }

  found.push(...scopeFindings({ files, policy: o.config.scope, cli: o.scope ?? [], prBody: o.prBody }));

  // A maintainer's reason accepts deliberate configuration changes, as v1 does for its own rules.
  const reason = o.allowConfigReason?.trim();
  if (reason) {
    for (const f of found) {
      const id = canonicalId(f);
      if (f.level === "blocked" && id !== null && CONFIG_CHANGE_RULES.has(id)) { f.level = "review"; f.allowedBecause = reason; }
    }
  }

  const v2: RuleResult[] = SUITES.map((suite) => {
    const findings = found.filter((f) => f.rule === suite);
    return { rule: suite, findings, passes: findings.length === 0 ? [PASSES[suite]] : [], stats: {} };
  });

  return {
    mode: "check",
    base: o.base,
    head: o.head,
    filesChanged: files.length,
    results: await finalize([...v1, ...v2], o.config),
    rulesRun: rulesFor("check"),
    configSource: o.configSource ?? null,
  };
}

/** Paths a change touches, for callers that report what was checked. */
export const changedPaths = (files: FileDiff[]) => files.map(pathOf);
