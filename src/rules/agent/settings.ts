/**
 * Scan mode: Claude Code project settings as they stand. (Check mode compares before and after through v1's
 * agent-config rule, which reports the same rule ids.)
 */
import { allowRisk } from "../../check/config/knowledge.js";
import { isObject, keyLine, parseJsonc, valueLine } from "../../check/config/jsonc.js";
import type { Finding } from "../../check/types.js";

export function claudeSettingsStatic(path: string, text: string): Finding[] {
  const doc = parseJsonc(text);
  if (!isObject(doc)) return [];
  const out: Finding[] = [];
  const perms = isObject(doc["permissions"]) ? doc["permissions"] : {};
  const allow = Array.isArray(perms["allow"]) ? perms["allow"].filter((x): x is string => typeof x === "string") : [];
  const wide = allow.filter((a) => allowRisk(a) === "wide");
  const risky = allow.filter((a) => allowRisk(a) === "risky");
  if (wide.length + risky.length > 0) {
    // Settings a team committed on purpose: allowing everything blocks; specific risky commands (git push, docker)
    // are a deliberate choice often enough that they are reviewed. Adding either in a change still blocks (check mode).
    out.push({
      rule: "agent", id: "permission-wide", level: wide.length > 0 ? "blocked" : "review", severity: wide.length > 0 ? "critical" : "high",
      message: `Agent permissions in ${path} pre-approve ${wide.length > 0 ? "everything" : "risky commands"}: ${[...wide, ...risky].map((w) => `"${w}"`).join(", ")}. The agent runs them without asking.`,
      fix: "allow only the specific commands the project needs (for example \"Bash(npm run test:*)\").",
      evidence: [...wide, ...risky].map((w) => ({ path, ...valueLine(text, w) })),
    });
  }
  if (perms["defaultMode"] === "bypassPermissions") {
    out.push({
      rule: "agent", id: "permission-mode", level: "blocked", severity: "critical",
      message: `${path} sets defaultMode to bypassPermissions: every permission prompt is off for anyone on an older Claude Code.`,
      fix: "remove defaultMode, or set it to \"default\" or \"plan\".",
      evidence: [{ path, ...keyLine(text, "defaultMode") }],
    });
  }
  if (doc["enableAllProjectMcpServers"] === true) {
    out.push({
      rule: "agent", id: "mcp-all-enabled", level: "blocked",
      message: `${path} enables every project MCP server automatically, including any a later pull request adds.`,
      fix: "list the servers you trust in enabledMcpjsonServers instead.",
      evidence: [{ path, ...keyLine(text, "enableAllProjectMcpServers") }],
    });
  }
  return out;
}
