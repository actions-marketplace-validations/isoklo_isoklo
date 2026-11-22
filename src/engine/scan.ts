/**
 * Scan mode: judge the files as they are, with no change to compare. This is what `npx isoklo` does with no
 * arguments: secrets, committed .env files, hidden Unicode, injected agent instructions, disabled approvals, risky MCP
 * servers and agent permissions, unsafe workflows, remote code execution, exfiltration and untrusted lockfile sources.
 * Pure: the caller reads the files.
 */
import type { CheckSummary } from "../check/report.js";
import type { Finding, RuleResult, Suite } from "../check/types.js";
import { classify } from "../check/config/knowledge.js";
import { approvalsDisabled, hiddenUnicode, promptInjection } from "../rules/agent/content.js";
import { claudeSettingsStatic } from "../rules/agent/settings.js";
import type { ContentUnit } from "../rules/content.js";
import { isTextLockfile, lockfileSources } from "../rules/deps/files.js";
import { mcpServerFindings } from "../rules/mcp/servers.js";
import { isActionFile, isMcpFile, isWorkflow } from "../rules/paths.js";
import { envExfiltration, envFileCommitted, exfilEndpoint, remoteCodeExec, secretLeaked } from "../rules/sec/content.js";
import { workflowFindings } from "../rules/sec/workflows.js";
import type { IsokloConfig } from "./config.js";
import { finalize } from "./finalize.js";
import { matchesAny } from "./glob.js";
import { rulesFor } from "./registry.js";
import { isGeneratedPath, looksBinary, splitLines } from "./text.js";

export interface ScanFile {
  /** Repository-relative path with forward slashes. */
  path: string;
  text: string;
  /** Tracked by git (false: untracked but not ignored). Outside git, every file counts as tracked. */
  tracked: boolean;
}

export interface ScanOptions {
  /** Label for the report: the folder that was scanned. */
  root: string;
  config: IsokloConfig;
  configSource?: string | null;
}

const SUITES: readonly Suite[] = ["agent", "mcp", "tamper", "deps", "sec", "scope"];
const SCAN_PASSES: Partial<Record<Suite, string>> = {
  agent: "No hidden Unicode, prompt-override text, disabled approvals or wide agent permissions.",
  mcp: "No unpinned, secret-bearing or over-reaching MCP servers.",
  deps: "No lockfile entries from untrusted sources.",
  sec: "No secrets, committed .env files, remote code execution, exfiltration or unsafe workflows.",
};

export async function runScan(files: ScanFile[], o: ScanOptions): Promise<CheckSummary> {
  const found: Finding[] = [];
  const ignored = (path: string) => o.config.ignorePaths.length > 0 && matchesAny(path, o.config.ignorePaths);
  let read = 0;
  for (const file of files) {
    if (looksBinary(file.text)) continue;
    read++;
    const unit: ContentUnit = { path: file.path, lines: splitLines(file.text), mode: "scan", tracked: file.tracked };
    if (!ignored(file.path)) {
      const secret = secretLeaked(unit);
      if (secret) found.push(secret);
      if (!isGeneratedPath(file.path)) {
        for (const rule of [hiddenUnicode, promptInjection, approvalsDisabled, remoteCodeExec, envExfiltration, exfilEndpoint]) {
          const r = rule(unit);
          if (r) found.push(r);
        }
      }
    }
    const env = envFileCommitted(unit);
    if (env) found.push(env);
    if (isTextLockfile(file.path)) {
      const r = lockfileSources(unit, o.config.trustedRegistries);
      if (r) found.push(r);
    }
    if (isMcpFile(file.path)) found.push(...mcpServerFindings(file.path, file.text, null, "scan", o.config.trustedMcpPackages));
    if (classify(file.path) === "claude-settings") found.push(...claudeSettingsStatic(file.path, file.text));
    if (isWorkflow(file.path) || isActionFile(file.path)) found.push(...workflowFindings(file.path, file.text, null, "scan"));
  }

  const results: RuleResult[] = SUITES.map((suite) => {
    const findings = found.filter((f) => f.rule === suite);
    const pass = SCAN_PASSES[suite];
    return { rule: suite, findings, passes: findings.length === 0 && pass !== undefined ? [pass] : [], stats: {} };
  });

  return {
    mode: "scan",
    base: o.root,
    head: "",
    filesChanged: read,
    results: await finalize(results, o.config),
    rulesRun: rulesFor("scan"),
    configSource: o.configSource ?? null,
  };
}
