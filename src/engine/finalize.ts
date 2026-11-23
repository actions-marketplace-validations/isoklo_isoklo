/**
 * The last step of every run, in both modes and in the GitHub App: give each finding its canonical rule id and
 * severity, mask any secret that reached a message or evidence line, apply the policy's per-rule settings and baseline,
 * and order findings so the most serious come first.
 */
import type { Finding, RuleResult } from "../check/types.js";
import { maskSecrets } from "../rules/sec/secrets.js";
import type { IsokloConfig } from "./config.js";
import { sha256Hex } from "./crypto.js";
import { canonicalId, ruleMeta, severityOf, severityRank } from "./registry.js";
import { visible } from "./visible.js";

const LEVEL_RANK = { blocked: 0, review: 1, info: 2 } as const;

/** A finding's stable id: rule, file and evidence text (not line numbers, so moving code keeps it). */
export async function fingerprintOf(f: Finding): Promise<string> {
  const path = f.evidence[0]?.path ?? "";
  const texts = f.evidence.map((e) => e.text.trim().replace(/\s+/g, " ")).sort();
  return (await sha256Hex([f.ruleId ?? `${f.rule}/${f.id}`, path, ...texts].join("\n"))).slice(0, 16);
}

export class UnregisteredRuleError extends Error {}

export async function finalize(results: RuleResult[], config: IsokloConfig): Promise<RuleResult[]> {
  const baseline = new Set(config.baseline);
  const out: RuleResult[] = [];
  for (const r of results) {
    const kept: Finding[] = [];
    for (const f of r.findings) {
      const id = canonicalId(f);
      if (id === null) throw new UnregisteredRuleError(`finding ${f.rule}:${f.id} has no entry in the rule registry.`);
      const meta = ruleMeta(id);
      if (meta === undefined) throw new UnregisteredRuleError(`rule ${id} is not registered.`);
      f.ruleId = id;
      // Everything printed comes from the repository being judged: mask secrets, then make control and invisible
      // characters visible, so no output (terminal, HTML, Markdown, SARIF) can be steered by the code it reports on.
      const safe = (s: string) => visible(maskSecrets(s));
      f.message = safe(f.message);
      f.fix = safe(f.fix);
      if (f.allowedBecause !== undefined) f.allowedBecause = safe(f.allowedBecause);
      for (const e of f.evidence) e.text = safe(e.text);
      f.severity ??= severityOf(meta, f.level, f.allowedBecause !== undefined);

      const setting = config.rules[id];
      if (setting === "off") continue;
      if (setting !== undefined && setting !== f.level) {
        if (LEVEL_RANK[setting] > LEVEL_RANK[f.level]) f.allowedBecause ??= `policy sets ${id} to ${setting}`;
        f.level = setting;
      }
      f.fingerprint = await fingerprintOf(f);
      if (baseline.has(f.fingerprint) && f.level !== "info") {
        f.level = "info";
        f.allowedBecause ??= "accepted in the baseline (isoklo.config.json)";
      }
      kept.push(f);
    }
    kept.sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level] || severityRank(a.severity ?? "info") - severityRank(b.severity ?? "info"));
    out.push({ ...r, findings: kept });
  }
  return out;
}
