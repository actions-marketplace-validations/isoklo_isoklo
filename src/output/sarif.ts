/**
 * SARIF 2.1.0, as GitHub Code Scanning reads it: every registered rule with its explanation and a security-severity
 * score, every finding as a result on the exact line, with a stable fingerprint so alerts survive code moving around.
 * Upload with github/codeql-action/upload-sarif to see findings in the repository's Security tab.
 */
import type { CheckSummary } from "../check/report.js";
import { findingsOf } from "../check/report.js";
import type { Level, Severity } from "../check/types.js";
import { RULES } from "../engine/registry.js";

const SARIF_LEVEL: Record<Level, "error" | "warning" | "note"> = { blocked: "error", review: "warning", info: "note" };
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.0", info: "1.0" };

const pascal = (id: string) => id.split(/[/-]/).map((w) => (w[0] ?? "").toUpperCase() + w.slice(1)).join("");

export function toSarif(s: CheckSummary, version: string): string {
  const index = new Map(RULES.map((r, i) => [r.id, i]));
  const rules = RULES.map((r) => ({
    id: r.id,
    name: pascal(r.id),
    shortDescription: { text: r.title },
    fullDescription: { text: r.why },
    help: { text: r.why, markdown: `**${r.title}**\n\n${r.why}\n\nRule \`${r.id}\` v${r.version}. See https://github.com/isoklo/isoklo#rules.` },
    helpUri: "https://github.com/isoklo/isoklo#rules",
    defaultConfiguration: { level: r.severity === "info" ? "note" : r.severity === "medium" ? "warning" : "error" },
    properties: {
      tags: ["security", "ai-agents", r.suite],
      precision: "high",
      "security-severity": SECURITY_SEVERITY[r.severity],
    },
  }));

  const results = findingsOf(s).map((f) => {
    const loc = (e: (typeof f.evidence)[number]) => {
      const at = e.anchor ?? { path: e.path, line: e.line };
      return {
        physicalLocation: {
          artifactLocation: { uri: at.path, uriBaseId: "%SRCROOT%" },
          region: { startLine: Math.max(1, at.line), ...(e.text !== "" ? { snippet: { text: e.text } } : {}) },
        },
      };
    };
    const [first, ...rest] = f.evidence;
    const ruleId = f.ruleId ?? `${f.rule}/${f.id}`;
    return {
      ruleId,
      ...(index.has(ruleId) ? { ruleIndex: index.get(ruleId) } : {}),
      level: SARIF_LEVEL[f.level],
      message: { text: `${f.message} ${f.allowedBecause !== undefined ? `Allowed: ${f.allowedBecause}.` : `Fix: ${f.fix}`}` },
      locations: first === undefined ? [] : [loc(first)],
      ...(rest.length > 0 ? { relatedLocations: rest.slice(0, 20).map((e, i) => ({ id: i + 1, ...loc(e), message: { text: e.text || "related" } })) } : {}),
      partialFingerprints: { "isoklo/v1": f.fingerprint ?? "" },
      properties: { severity: f.severity ?? "info", verdict: f.level, ...(f.allowedBecause !== undefined ? { allowedBecause: f.allowedBecause } : {}) },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Isoklo", semanticVersion: version, informationUri: "https://github.com/isoklo/isoklo", rules } },
      automationDetails: { id: `isoklo/${s.mode ?? "check"}/` },
      results,
      properties: { mode: s.mode ?? "check", base: s.base, head: s.head },
    }],
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}
