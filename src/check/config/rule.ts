/**
 * Rule 3: agent and CI configuration changes. Files that decide what an agent may run and what CI trusts are rarely
 * read in review, and a prompt injection can talk an agent into widening its own power. So:
 *   blocked: a new or changed MCP server, wide or risky permissions, hooks added, permission bypass, all project MCP
 *            servers enabled, pull_request_target, write-all, and any change that removes Isoklo from CI;
 *   review:  narrower permission changes, MCP environment changes (names only, never values), any workflow or
 *            other CI change, agent instruction changes, CODEOWNERS changes, files that could not be parsed.
 * A maintainer can pass --allow-config-change "<reason>" (for example from a label only maintainers can apply);
 * blocks then become "review" with the reason shown.
 */
import type { FileDiff } from "../diff.js";
import type { Evidence, Finding, Level, RuleResult } from "../types.js";
import { allowRisk, classify, SECRET_USE, WORKFLOW_SIGNALS, type ConfigKind } from "./knowledge.js";
import { isObject, keyLine, parseJsonc, valueLine } from "./jsonc.js";

export interface ConfigChange {
  path: string;
  /** Path before the change (differs for renames). */
  oldPath: string;
  status: FileDiff["status"];
  before: string | null;
  after: string | null;
  diff: FileDiff;
}

export interface ConfigRuleOptions {
  /** Set by a maintainer to accept config changes deliberately. */
  allowReason?: string;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const ID = "agent-config" as const;

const SENSITIVE = "(?:[A-Za-z0-9_-]*(?:token|secret|password|passwd|api[_-]?key|apikey|auth|bearer|cookie|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_-]*)";

/**
 * Config files can hold secrets. Everything this rule prints goes through here: values of sensitive-looking keys in
 * JSON, YAML and command-line flags, and bearer tokens, become ***. Names stay visible; values never do.
 */
export function redact(text: string): string {
  return text
    .replace(new RegExp(`("${SENSITIVE}"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"`, "gi"), '$1"***"')
    .replace(new RegExp(`(^|\\s)(${SENSITIVE}\\s*:\\s*)(?!\\$\\{\\{)(\\S.*)$`, "gim"), "$1$2***")
    .replace(new RegExp(`(--?${SENSITIVE}[=\\s])[^\\s\`'"]+`, "gi"), "$1***")
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/g, "$1 ***")
    .replace(/\b(sk|pk|ghp|gho|github_pat|xox[abp]|AKIA)[A-Za-z0-9_-]{8,}/g, "***");
}

function finding(id: string, level: Level, message: string, fix: string, evidence: Evidence[]): Finding {
  return { rule: ID, id, level, message, fix, evidence };
}

// ---------------------------------------------------------------- MCP servers
interface Server { runs: string; env: string[]; headers: string[] }

function servers(text: string | null): Map<string, Server> | null {
  if (text === null) return new Map();
  const doc = parseJsonc(text);
  if (!isObject(doc)) return null;
  const table = isObject(doc["mcpServers"]) ? doc["mcpServers"] : isObject(doc["servers"]) ? doc["servers"] : {};
  const out = new Map<string, Server>();
  for (const [name, raw] of Object.entries(table)) {
    if (!isObject(raw)) continue;
    const args = Array.isArray(raw["args"]) ? raw["args"].map(String) : [];
    // Remote servers: "url" (most tools), "httpUrl" (Gemini CLI), "serverUrl" (Antigravity).
    const url = ["url", "httpUrl", "serverUrl"].map((k) => raw[k]).find((v) => typeof v === "string");
    const runs = typeof url === "string" ? `connects to ${url}`
      : typeof raw["command"] === "string" ? `runs \`${[raw["command"], ...args].join(" ")}\``
      : "has no command or url";
    const env = isObject(raw["env"]) ? Object.entries(raw["env"]).map(([k, v]) => `${k}=${JSON.stringify(v)}`) : [];
    const headers = isObject(raw["headers"]) ? Object.entries(raw["headers"]).map(([k, v]) => `${k}=${JSON.stringify(v)}`) : [];
    out.set(name, { runs, env, headers });
  }
  return out;
}

function mcpFindings(c: ConfigChange): Finding[] {
  const before = servers(c.before);
  const after = servers(c.after);
  if (before === null || after === null) {
    return [finding("config-unreadable", "review", `${c.path} could not be parsed, so its MCP servers were not compared.`,
      "fix the JSON and run the check again; until then, read the change by hand.", [{ path: c.path, line: 1, text: "" }])];
  }
  const out: Finding[] = [];
  const text = c.after ?? "";
  for (const [name, s] of after) {
    const prev = before.get(name);
    const where = keyLine(text, name);
    const ev = [{ path: c.path, ...where }];
    if (prev === undefined) {
      out.push(finding("mcp-server-added", "blocked", `New MCP server added: "${name}" ${s.runs}. Agents in this repo can now call it.`,
        "confirm who publishes it and why the agent needs it; a maintainer should add MCP servers, not an agent.", ev));
      continue;
    }
    if (prev.runs !== s.runs) {
      out.push(finding("mcp-server-changed", "blocked", `MCP server "${name}" now ${s.runs} (before: ${prev.runs.replace(/^runs |^connects to /, "")}).`,
        "confirm the new command or address is trusted.", ev));
    }
    // Names only: values may be secrets and never appear in a report.
    const keys = (xs: string[]) => new Set(xs);
    const changedNames = (now: string[], was: string[]) => {
      const w = keys(was);
      return [...new Set(now.filter((x) => !w.has(x)).map((x) => x.split("=")[0] as string))];
    };
    const envChanged = changedNames(s.env, prev.env);
    const headerChanged = changedNames(s.headers, prev.headers);
    if (envChanged.length + headerChanged.length > 0) {
      out.push(finding("mcp-server-env-changed", "review",
        `MCP server "${name}" has new or changed settings: ${[...envChanged, ...headerChanged].join(", ")} (values not shown).`,
        "check where these values point; a changed token or address can send the agent's data elsewhere.", ev));
    }
  }
  const removed = [...before.keys()].filter((n) => !after.has(n));
  if (removed.length > 0) {
    out.push(finding("mcp-server-removed", "info", `${plural(removed.length, "MCP server")} removed: ${removed.join(", ")}.`,
      "nothing to do unless something relied on it.", [{ path: c.path, line: 1, text: "" }]));
  }
  return out;
}

// ---------------------------------------------------------------- Claude Code settings
const asStrings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

function claudeFindings(c: ConfigChange): Finding[] {
  const before = c.before === null ? {} : parseJsonc(c.before);
  const after = c.after === null ? {} : parseJsonc(c.after);
  if (!isObject(before) || !isObject(after)) {
    return [finding("config-unreadable", "review", `${c.path} could not be parsed, so its permissions were not compared.`,
      "fix the JSON and run the check again; until then, read the change by hand.", [{ path: c.path, line: 1, text: "" }])];
  }
  const out: Finding[] = [];
  const text = c.after ?? "";
  const perms = (o: Record<string, unknown>) => (isObject(o["permissions"]) ? o["permissions"] : {});
  const pb = perms(before);
  const pa = perms(after);

  const newAllows = asStrings(pa["allow"]).filter((a) => !asStrings(pb["allow"]).includes(a));
  const wide = newAllows.filter((a) => allowRisk(a) !== null);
  const narrow = newAllows.filter((a) => allowRisk(a) === null);
  if (wide.length > 0) {
    out.push(finding("permission-wide", "blocked",
      `Agent permissions widened: ${wide.map((w) => `"${w}"`).join(", ")} ${wide.length === 1 ? "lets" : "let"} the agent run ${wide.some((w) => allowRisk(w) === "wide") ? "anything" : "risky commands"} without asking.`,
      "allow only the specific commands the project needs, and have a maintainer make this change.",
      wide.map((w) => ({ path: c.path, ...valueLine(text, w) }))));
  }
  if (narrow.length > 0) {
    out.push(finding("permission-added", "review", `${plural(narrow.length, "new agent permission")}: ${narrow.map((w) => `"${w}"`).join(", ")}.`,
      "confirm each one is needed.", narrow.map((w) => ({ path: c.path, ...valueLine(text, w) }))));
  }
  const removedDenies = asStrings(pb["deny"]).filter((d) => !asStrings(pa["deny"]).includes(d));
  if (removedDenies.length > 0) {
    out.push(finding("deny-removed", "blocked", `Agent safety rules removed: ${removedDenies.map((d) => `"${d}"`).join(", ")} ${removedDenies.length === 1 ? "is" : "are"} no longer denied.`,
      "restore the deny rules, or have a maintainer remove them deliberately.", [{ path: c.path, ...keyLine(text, "deny") }]));
  }
  const modeA = pa["defaultMode"];
  if (modeA !== pb["defaultMode"] && typeof modeA === "string") {
    out.push(finding("permission-mode", modeA === "bypassPermissions" ? "blocked" : "review",
      modeA === "bypassPermissions"
        ? "Agent permission checks turned off: defaultMode is now bypassPermissions. Claude Code 2.1.257 and later ignore this in project settings; older versions obey it."
        : `Agent permission mode changed to ${modeA}.`,
      "keep permission prompts on for shared settings.", [{ path: c.path, ...keyLine(text, "defaultMode") }]));
  }
  if (after["enableAllProjectMcpServers"] === true && before["enableAllProjectMcpServers"] !== true) {
    out.push(finding("mcp-all-enabled", "blocked", "Every MCP server in the project is now enabled automatically, including ones added later.",
      "list the servers you trust in enabledMcpjsonServers instead.", [{ path: c.path, ...keyLine(text, "enableAllProjectMcpServers") }]));
  }
  const hooksB = JSON.stringify(before["hooks"] ?? null);
  const hooksA = JSON.stringify(after["hooks"] ?? null);
  if (hooksA !== hooksB) {
    const added = hooksA !== "null" && (hooksB === "null" || hooksA.length > hooksB.length);
    out.push(added
      ? finding("hook-added", "blocked", "Agent hooks added or changed: they run shell commands automatically on agent events.",
        "read every hook command; a maintainer should add hooks, not an agent.", [{ path: c.path, ...keyLine(text, "hooks") }])
      : finding("hook-removed", "review", "Agent hooks removed or reduced; any safety check they ran no longer runs.",
        "confirm the hooks were not protecting anything.", [{ path: c.path, ...keyLine(c.before ?? "", "hooks") }]));
  }
  return out;
}

// ---------------------------------------------------------------- workflows and CI
function workflowFindings(c: ConfigChange): Finding[] {
  const out: Finding[] = [];
  const code = (l: string) => l.replace(/^\s*#.*$/, "");
  const removedIsoklo = c.diff.removed.filter((l) => /isoklo/i.test(code(l.text)));
  const deletedWithIsoklo = c.status === "deleted" && /isoklo/i.test(c.before ?? "");
  if (removedIsoklo.length > 0 || deletedWithIsoklo) {
    out.push(finding("isoklo-removed-from-ci", "blocked",
      deletedWithIsoklo ? `The workflow that runs Isoklo was deleted: ${c.oldPath}.` : `Isoklo's own check was removed or changed in ${c.path}.`,
      "a change should not be able to switch off the gate that checks it; a maintainer must make this change.",
      removedIsoklo.map((l) => ({ path: c.oldPath, line: l.line, text: l.text.trim() }))));
  }
  for (const s of WORKFLOW_SIGNALS) {
    const hits = c.diff.added.filter((l) => s.re.test(code(l.text)));
    if (hits.length > 0) {
      out.push(finding("workflow-risk", s.level, `CI workflow ${c.path} ${s.what}.`,
        "confirm this is intended; workflow changes run with the repository's credentials.",
        hits.map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
    }
  }
  const secretNames = new Set<string>();
  const secretLines = c.diff.added.filter((l) => {
    const found = [...code(l.text).matchAll(SECRET_USE)].map((m) => m[1] as string);
    found.forEach((n) => secretNames.add(n));
    return found.length > 0;
  });
  if (secretNames.size > 0) {
    out.push(finding("workflow-secrets", "review", `CI workflow ${c.path} now uses ${plural(secretNames.size, "secret")} (${[...secretNames].join(", ")}).`,
      "confirm the workflow needs them and cannot leak them to pull request code.",
      secretLines.map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
  }
  if (out.length === 0 && c.status !== "deleted") {
    out.push(finding("workflow-changed", "review",
      `CI workflow ${c.status === "added" ? "added" : "changed"}: ${c.path} (${plural(c.diff.added.length, "line")} added, ${c.diff.removed.length} removed).`,
      "read it: workflows run with the repository's credentials.",
      c.diff.added.slice(0, 8).map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
  }
  return out;
}

// ---------------------------------------------------------------- the rule
export function agentConfig(changes: ConfigChange[], opts: ConfigRuleOptions = {}): RuleResult {
  const findings: Finding[] = [];
  const kinds = new Map<ConfigKind, number>();
  for (const c of changes) {
    const kind = classify(c.status === "deleted" ? c.oldPath : c.path);
    if (kind === null) continue;
    kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
    const lines = `${plural(c.diff.added.length, "line")} added, ${c.diff.removed.length} removed`;
    if (kind === "mcp") findings.push(...mcpFindings(c));
    else if (kind === "claude-settings") findings.push(...claudeFindings(c));
    else if (kind === "workflow") findings.push(...workflowFindings(c));
    else if (kind === "agent-settings") {
      findings.push(finding("agent-settings-changed", "review", `Agent settings changed: ${c.path} (${lines}).`,
        "read it: agent settings decide what the agent may do.", c.diff.added.slice(0, 8).map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
    } else if (kind === "ci-other") {
      findings.push(finding("ci-changed", "review", `CI configuration changed: ${c.path} (${lines}).`,
        "read it: CI runs with the repository's credentials.", c.diff.added.slice(0, 8).map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
    } else if (kind === "instructions") {
      findings.push(finding("instructions-changed", "review", `Agent instructions ${c.status === "added" ? "added" : c.status === "deleted" ? "deleted" : "changed"}: ${c.status === "deleted" ? c.oldPath : c.path} (${lines}).`,
        "read the new instructions; text in these files steers every future agent run.",
        c.diff.added.slice(0, 8).map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
    } else if (kind === "codeowners") {
      findings.push(finding("codeowners-changed", "review", `Code owners changed: ${c.path} (${lines}).`,
        "confirm who must now review what.", c.diff.added.slice(0, 8).map((l) => ({ path: c.path, line: l.line, text: l.text.trim() }))));
    }
  }

  for (const f of findings) {
    f.message = redact(f.message);
    for (const e of f.evidence) e.text = redact(e.text);
  }

  const reason = opts.allowReason?.trim();
  if (reason) {
    for (const f of findings) {
      if (f.level === "blocked") { f.level = "review"; f.allowedBecause = reason; }
    }
  }

  const total = [...kinds.values()].reduce((a, b) => a + b, 0);
  const passes = total === 0 ? ["No agent or CI configuration changed."] : [];
  return { rule: ID, findings, passes, stats: { configFiles: total } };
}
