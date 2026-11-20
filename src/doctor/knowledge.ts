/**
 * Which coding agent reads which instruction file.
 *
 * This changes often, so it lives here as data, not in if-statements. Each entry says where the fact came from and
 * when it was last checked. When a vendor changes behaviour, update this table and its tests; nothing else should move.
 */

export type Agent =
  | "Claude Code"
  | "Codex"
  | "Cursor"
  | "GitHub Copilot"
  | "Gemini CLI"
  | "Antigravity CLI"
  | "Devin Desktop";

export interface FileSpec {
  /** Stable id used in findings and JSON output. */
  id: string;
  /** A path relative to the repo root, or a folder plus extension for rule folders. */
  path: string;
  /** Set for rule folders: every file in `path` ending with this extension. */
  extension?: string;
  /** Rule folders only: also read files in subfolders. Off unless the vendor documents it. */
  recursive?: boolean;
  /** Agents that read this file. Claude Code's AGENTS.md fallback is handled in analyze.ts, not here. */
  agents: Agent[];
  /** Short human note shown in reports. */
  note?: string;
  /** Where the fact came from, and when it was checked. */
  source: string;
}

/** The date every fact below was last checked against the vendor's own documentation. */
export const CHECKED = "2026-11-20";

const CLAUDE = `https://code.claude.com/docs/en/memory, checked ${CHECKED}`;
const COPILOT = `https://docs.github.com/en/copilot/reference/custom-instructions-support, checked ${CHECKED}`;
const CURSOR = `https://cursor.com/docs/context/rules, checked ${CHECKED}`;
const DEVIN = `https://docs.devin.ai/desktop/cascade/memories, checked ${CHECKED}`;
const ANTIGRAVITY = `https://antigravity.google/docs/rules.md, checked ${CHECKED}`;

export const FILE_SPECS: readonly FileSpec[] = [
  { id: "claude-md", path: "CLAUDE.md", agents: ["Claude Code", "GitHub Copilot"], source: `${CLAUDE}; ${COPILOT}` },
  { id: "claude-dir-md", path: ".claude/CLAUDE.md", agents: ["Claude Code"], source: CLAUDE },
  {
    id: "claude-local-md", path: "CLAUDE.local.md", agents: ["Claude Code"],
    note: "personal; usually not committed", source: CLAUDE,
  },
  { id: "claude-rules", path: ".claude/rules", extension: ".md", agents: ["Claude Code"], source: CLAUDE },
  {
    id: "agents-md", path: "AGENTS.md", agents: ["Codex", "Cursor", "GitHub Copilot", "Antigravity CLI", "Devin Desktop"],
    note: "the cross-agent standard",
    source: `https://learn.chatgpt.com/docs/agent-configuration/agents-md; ${CURSOR}; ${COPILOT}; ${ANTIGRAVITY}; ${DEVIN}`,
  },
  {
    id: "gemini-md", path: "GEMINI.md", agents: ["Gemini CLI", "Antigravity CLI", "GitHub Copilot"],
    note: "Gemini CLI was replaced by Antigravity CLI for free and consumer tiers on 2026-06-18",
    source: `https://geminicli.com/docs/cli/gemini-md/; ${ANTIGRAVITY}; ${COPILOT}`,
  },
  { id: "agents-rules", path: ".agents/rules", extension: ".md", agents: ["Antigravity CLI"], source: ANTIGRAVITY },
  {
    id: "cursorrules", path: ".cursorrules", agents: ["Cursor"],
    note: "legacy format; no longer in Cursor's docs and planned for deprecation",
    source: `https://forum.cursor.com/t/project-rule-in-cursorrules-not-applied-in-agent-chat-works-in-cursor-rules/154309, checked ${CHECKED}`,
  },
  // Cursor's docs show rules in subfolders (frontend/components.mdc); plain .md files in .cursor/rules are ignored.
  { id: "cursor-rules", path: ".cursor/rules", extension: ".mdc", recursive: true, agents: ["Cursor"], source: CURSOR },
  { id: "copilot-instructions", path: ".github/copilot-instructions.md", agents: ["GitHub Copilot"], source: COPILOT },
  {
    // Files "within or below" .github/instructions, so subfolders count.
    id: "copilot-path-instructions", path: ".github/instructions", extension: ".instructions.md", recursive: true,
    agents: ["GitHub Copilot"], note: "path-specific",
    source: `https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions, checked ${CHECKED}`,
  },
  { id: "devin-rules", path: ".devin/rules", extension: ".md", agents: ["Devin Desktop"], note: "formerly Windsurf", source: DEVIN },
  {
    id: "windsurf-rules", path: ".windsurf/rules", extension: ".md", agents: ["Devin Desktop"],
    note: "legacy Windsurf folder; still imported, .devin/rules wins", source: DEVIN,
  },
  {
    id: "windsurfrules", path: ".windsurfrules", agents: ["Devin Desktop"],
    note: "legacy Windsurf file; still imported", source: DEVIN,
  },
];

/**
 * Claude Code reads AGENTS.md (and .claude/AGENTS.md) only when none of these exist, from v2.1.277, unless its
 * "Project instructions" setting is `claude-md-and-agents-md`. Source: https://code.claude.com/docs/en/memory,
 * section "AGENTS.md", checked 2026-11-20.
 */
export const CLAUDE_PRIMARY_IDS = ["claude-md", "claude-dir-md", "claude-local-md"] as const;

/** Above this estimate a file is flagged for review: long instruction files are followed less reliably and cost tokens on every task. */
export const LARGE_FILE_TOKENS = 1500;
