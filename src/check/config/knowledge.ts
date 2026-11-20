/**
 * Which files control what AI agents and CI are allowed to do. Kept as data, like the doctor's table.
 * Checked against vendor docs on 2026-11-20:
 *   Claude Code   https://code.claude.com/docs/en/mcp, /settings and /permissions
 *   Cursor        https://cursor.com/docs/context/mcp, https://cursor.com/docs/cloud-agent/setup
 *   VS Code       https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
 *   Gemini CLI    https://geminicli.com/docs/reference/configuration/
 *   Antigravity   https://antigravity.google/docs/cli/gcli-migration
 *   Devin Desktop https://docs.devin.ai/desktop/cascade/memories (it was Windsurf until 2026-06-02)
 *   Codex         https://learn.chatgpt.com/docs/config-file/config-basic
 */
import { FILE_SPECS } from "../../doctor/knowledge.js";

export type ConfigKind =
  | "mcp" // MCP server definitions: each server is a program or URL the agent can call
  | "claude-settings" // Claude Code permissions, hooks, MCP enablement
  | "agent-settings" // other agents' settings files
  | "workflow" // GitHub Actions
  | "ci-other" // other CI systems
  | "instructions" // AGENTS.md, CLAUDE.md, rules: what agents are told to do
  | "codeowners"; // who must review what

const MCP_FILES = [
  ".mcp.json", // Claude Code, and VS Code's Copilot harness
  ".cursor/mcp.json",
  ".vscode/mcp.json", // "servers" instead of "mcpServers"
  ".gemini/settings.json",
  ".agents/mcp_config.json", // Antigravity
  ".devin/mcp_config.json",
  ".devin/mcp_config.local.json",
  ".roo/mcp.json", // Roo Code shut down on 2026-05-15; kept because old repos still carry the file
];
const CLAUDE_SETTINGS = [".claude/settings.json", ".claude/settings.local.json"];
const AGENT_SETTINGS = [
  ".codex/config.toml", // loaded for trusted projects
  ".cursor/environment.json", // Cursor Cloud Agents: its install, start and terminal entries run commands
  ".devin/config.json", // can turn on reading other agents' rules
  ".devin/hooks.v1.json", // hooks run commands on agent events
];
const CI_OTHER = [".gitlab-ci.yml", ".circleci/config.yml", "azure-pipelines.yml", "Jenkinsfile", "bitbucket-pipelines.yml"];

export function classify(path: string): ConfigKind | null {
  if (MCP_FILES.includes(path)) return "mcp";
  if (CLAUDE_SETTINGS.includes(path)) return "claude-settings";
  if (AGENT_SETTINGS.includes(path)) return "agent-settings";
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(path)) return "workflow";
  if (CI_OTHER.includes(path)) return "ci-other";
  if (/^(\.github\/|docs\/)?CODEOWNERS$/.test(path)) return "codeowners";
  for (const spec of FILE_SPECS) {
    if (spec.extension === undefined ? path === spec.path : path.startsWith(spec.path + "/") && path.endsWith(spec.extension)) {
      return "instructions";
    }
  }
  return null;
}

/**
 * A permission rule in Claude Code's `permissions.allow` that hands over too much: any command, or a risky one.
 * `WebFetch(domain:*)` matches every domain. `Bash(cmd:*)` and `Bash(cmd *)` mean the same thing.
 */
const WIDE_ALLOW = /^(\*|Bash|Bash\(\s*\*?\s*\)|mcp__\*|mcp__[^_]+__\*|WebFetch(\(\s*(domain:\s*)?\*?\s*\))?)$/;
const RISKY_COMMAND = /^Bash\(\s*(curl|wget|rm|sudo|su|ssh|scp|rsync|nc|ncat|bash|sh|zsh|eval|exec|chmod|chown|dd|git push|npm publish|pnpm publish|yarn publish|docker|kubectl|aws|gcloud|az)\b/;

export const allowRisk = (entry: string): "wide" | "risky" | null =>
  WIDE_ALLOW.test(entry.trim()) ? "wide" : RISKY_COMMAND.test(entry.trim()) ? "risky" : null;

/** Lines in a workflow that change what CI trusts. */
export const WORKFLOW_SIGNALS: readonly { re: RegExp; level: "blocked" | "review"; what: string }[] = [
  { re: /\bpull_request_target\b/, level: "blocked", what: "runs on pull_request_target, with write access and secrets, for code from forks" },
  { re: /permissions:\s*write-all\b/, level: "blocked", what: "gives the workflow write access to everything" },
  { re: /^\s*(contents|actions|id-token|packages|pull-requests|security-events|deployments|checks|statuses|issues):\s*write\b/, level: "review", what: "grants write permission" },
  { re: /continue-on-error:\s*true\b/, level: "review", what: "lets a failing step pass" },
  { re: /^\s*if:\s*(false|\$\{\{\s*false\s*\}\})\s*$/, level: "review", what: "switches a step or job off" },
];

export const SECRET_USE = /\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g;
