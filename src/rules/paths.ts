/** Which paths are agent-facing: instruction files, rules, MCP configs and agent settings. */
import { classify } from "../check/config/knowledge.js";

/** Agent-facing files the v1 table does not list: subagents, slash commands, skills, prompts and other tools' rules. */
const EXTRA_AGENT_FILES: readonly RegExp[] = [
  /^\.claude\/(commands|agents)\/.+\.md$/,
  /^\.claude\/skills\/.+\.md$/,
  /(^|\/)SKILL\.md$/,
  /^\.github\/(prompts|chatmodes|agents)\/.+\.md$/,
  /^\.cursor\/commands\/.+\.md$/,
  /^\.clinerules(\/.+)?$/,
  /^\.roo\/rules(-[\w-]+)?\/.+$/,
  /^\.kiro\/steering\/.+\.md$/,
  /^\.continue\/rules\/.+$/,
  /^\.junie\/guidelines\.md$/,
  /^\.goosehints$/,
  /^AGENT\.md$/,
  /^\.aider\.conf\.ya?ml$/,
];

export const MCP_EXTRA = ["mcp.json", "claude_desktop_config.json", ".windsurf/mcp_config.json", ".kiro/settings/mcp.json"];

export function isAgentFile(path: string): boolean {
  const kind = classify(path);
  if (kind === "instructions" || kind === "mcp" || kind === "claude-settings" || kind === "agent-settings") return true;
  return MCP_EXTRA.includes(path) || EXTRA_AGENT_FILES.some((re) => re.test(path));
}

/** Instruction text (prose an agent reads as instructions), as opposed to JSON or TOML settings. */
export function isAgentInstructions(path: string): boolean {
  return classify(path) === "instructions" || (EXTRA_AGENT_FILES.some((re) => re.test(path)) && !/\.(json|ya?ml|toml)$/.test(path));
}

export const isMcpFile = (path: string) => classify(path) === "mcp" || MCP_EXTRA.includes(path);

export const isWorkflow = (path: string) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path);

export const isActionFile = (path: string) => /(^|\/)action\.ya?ml$/.test(path);
